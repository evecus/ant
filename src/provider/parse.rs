//! Subscription payload → `Vec<ProxyConfig>`.
//!
//! The pre-processing chain mirrors sub-store's `Clash Pre-processor`,
//! `Base64 Pre-processor`, `SSD Pre-processor` and `Fallback Base64
//! Pre-processor`, restricted to what ant can actually dial:
//!
//! 1. `ssd://<base64 JSON>` — expanded into SIP002 `ss://` links;
//! 2. Clash / mihomo YAML or JSON with a `proxies:` list (or a
//!    `payload:` / bare list of share links or node objects);
//! 3. base64 of (2) — the classic v2rayN subscription blob, including
//!    whitespace-wrapped and URL-safe/unpadded variants;
//! 4. plain newline-separated share links.
//!
//! Clash nodes are parsed **one by one** (like sub-store's per-line JSON
//! nodes): a node with an unsupported protocol/transport, a missing field or
//! a differently-typed scalar is warned about and skipped instead of dropping
//! the whole subscription.

use super::link;
use crate::config::ProxyConfig;
use anyhow::{bail, Result};
use regex::Regex;
use serde_yaml::{Mapping, Value};

/// Parse a raw provider payload (file content or HTTP response body).
pub fn parse_payload(provider: &str, data: &[u8]) -> Result<Vec<ProxyConfig>> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t.to_string(),
        Err(_) => String::from_utf8_lossy(data).into_owned(),
    };
    parse_text(provider, &text, 0)
}

fn parse_text(provider: &str, text: &str, depth: usize) -> Result<Vec<ProxyConfig>> {
    let t = text.trim().trim_start_matches('\u{feff}').trim();
    if t.is_empty() {
        bail!("proxy-provider `{provider}`: empty payload");
    }
    // sub-store drops HTML pages; ant reports them so a bad URL (or a missing
    // client User-Agent) is not mistaken for an empty subscription.
    let low = t.to_ascii_lowercase();
    if low.starts_with("<!doctype html") || low.starts_with("<html") {
        bail!(
            "proxy-provider `{provider}`: received an HTML page \
             (check the subscription URL / User-Agent)"
        );
    }
    // 1) SSD subscription (`ssd://<base64 JSON>`).
    if depth < 2 {
        if let Some(links) = ssd_links(t) {
            if let Ok(list) = parse_text(provider, &links, depth + 1) {
                return Ok(list);
            }
        }
    }
    // 2) Clash / mihomo document.
    if let Some(list) = yaml_proxies(provider, t) {
        return Ok(list);
    }
    // 3) Base64 blob (YAML document or link list).
    if depth < 2 {
        if let Some(decoded) = link::decode_b64(t) {
            if let Ok(list) = parse_text(provider, &decoded, depth + 1) {
                return Ok(list);
            }
        }
    }
    // 4) Plain newline-separated share links.
    let list = share_links(t);
    if !list.is_empty() {
        return Ok(list);
    }
    bail!(
        "proxy-provider `{provider}`: payload is neither a YAML/JSON \
         `proxies:`/`payload:` list, a base64 blob, an SSD subscription, \
         nor a share-link list"
    )
}

/// `ssd://<base64 JSON>` → newline-separated SIP002 links (sub-store's
/// `SSD Pre-processor`). Nodes with an unsupported `plugin` are left for
/// `link::from_link` to skip.
fn ssd_links(text: &str) -> Option<String> {
    let body = text.strip_prefix("ssd://")?;
    let json = link::decode_b64(body)?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    let servers = v.get("servers")?.as_array()?;
    let field = |k: &str, s: &serde_json::Value| -> Option<String> {
        s.get(k)
            .or_else(|| v.get(k))
            .and_then(|x| match x {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
    };
    let mut out = String::new();
    for (i, s) in servers.iter().enumerate() {
        let server = s.get("server").and_then(|x| x.as_str())?;
        let method = field("encryption", s)?;
        let password = field("password", s)?;
        let port = field("port", s)?;
        let remark = s.get("remarks").and_then(|x| x.as_str()).unwrap_or("");
        let name = if remark.is_empty() {
            format!("SSD {}", i + 1)
        } else {
            remark.to_string()
        };
        let ui = base64_encode(&format!("{method}:{password}"));
        out.push_str(&format!("ss://{ui}@{server}:{port}#{name}\n"));
    }
    Some(out)
}

fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// Parse a Clash/mihomo YAML (or JSON) document into nodes.
///
/// Accepts `proxies: [...]` (mihomo proxy-provider file), `payload: [...]`
/// (sub-store "Clash Provider" shape) and a bare sequence. Every entry is
/// parsed independently: unsupported/invalid entries are skipped.
fn yaml_proxies(provider: &str, text: &str) -> Option<Vec<ProxyConfig>> {
    let doc: Value = serde_yaml::from_str(text).ok()?;
    let seq: &Vec<Value> = match &doc {
        Value::Mapping(m) => {
            let proxies = Value::String("proxies".into());
            let payload = Value::String("payload".into());
            match m.get(&proxies).or_else(|| m.get(&payload)) {
                Some(Value::Sequence(s)) => s,
                _ => return None,
            }
        }
        Value::Sequence(s) => s,
        _ => return None,
    };
    let mut out = Vec::new();
    for (i, node) in seq.iter().enumerate() {
        // `payload:` entries (and `- link` list items) are share links.
        if let Some(s) = node.as_str() {
            if let Some(c) = link::from_link(s.trim()) {
                out.push(c);
            } else {
                tracing::warn!(
                    provider = %provider,
                    index = i,
                    "unsupported payload entry skipped"
                );
            }
            continue;
        }
        match clash_node(node.clone()) {
            Some(c) => out.push(c),
            None => tracing::warn!(
                provider = %provider,
                index = i,
                "unsupported or invalid Clash node skipped"
            ),
        }
    }
    Some(out)
}

/// One Clash node object → `ProxyConfig`, with sub-store/mihomo field
/// normalization applied before deserialization.
fn clash_node(v: Value) -> Option<ProxyConfig> {
    let mut m = v.as_mapping()?.clone();
    if !node_supported(&m) {
        return None;
    }
    normalize_clash(&mut m);
    serde_yaml::from_value::<ProxyConfig>(Value::Mapping(m)).ok()
}

/// Reject nodes ant has no outbound for *before* they reach `build_dialer`.
/// This mirrors sub-store's `include-unsupported-proxy: false` default.
fn node_supported(m: &Mapping) -> bool {
    let ty = str_field(m, "type").unwrap_or_default().to_ascii_lowercase();
    if matches!(
        ty.as_str(),
        "ssr" | "shadowsocksr" | "hysteria" | "http" | "https" | "snell"
            | "mieru" | "trusttunnel" | "h2-connect" | "direct" | "reject"
            | "block" | "relay" | "selector" | "url-test" | "fallback"
            | "load-balance"
    ) {
        return false;
    }
    // obfs / v2ray-plugin: no implementation in ant.
    if str_field(m, "plugin").map(|s| !s.is_empty()).unwrap_or(false) {
        return false;
    }
    let net = str_field(m, "network")
        .or_else(|| str_field(m, "net"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        net.as_str(),
        "grpc" | "httpupgrade" | "kcp" | "mkcp" | "quic" | "h2" | "http2" | "http"
    ) {
        return false;
    }
    if get(m, "grpc-opts").is_some() {
        return false;
    }
    if let Some(Value::Mapping(o)) = get(m, "ws-opts") {
        if o.get(Value::String("v2ray-http-upgrade".into()))
            .and_then(as_bool)
            .unwrap_or(false)
        {
            return false;
        }
    }
    true
}

/// Flatten sub-store/mihomo Clash fields onto ant's `ProxyConfig` schema and
/// coerce the scalar types that generators commonly emit differently
/// (`port: "443"`, `tls: "true"`, `alpn: h2,http/1.1`, `up: 100`, …).
fn normalize_clash(m: &mut Mapping) {
    // `net` (v2ray-style JSON) → `network`.
    if get(m, "network").is_none() {
        if let Some(v) = get(m, "net").cloned() {
            insert(m, "network", v);
        }
    }
    // Protocol aliases used by share links / other clients.
    if let Some(t) = str_field(m, "type") {
        let mapped = match t.to_ascii_lowercase().as_str() {
            "hy2" => Some("hysteria2"),
            "sq" => Some("shadowquic"),
            "wg" => Some("wireguard"),
            "ts" => Some("tailscale"),
            _ => None,
        };
        if let Some(x) = mapped {
            insert(m, "type", Value::String(x.into()));
        }
    }
    // mihomo uses `security` as a TLS hint on vless/trojan; ant aliases
    // `security` to `cipher`, so a TLS-ish value must be removed (otherwise
    // serde reports a duplicate field when `cipher` is also present).
    if let Some(sec) = str_field(m, "security") {
        let sec = sec.trim().to_ascii_lowercase();
        if matches!(sec.as_str(), "tls" | "xtls" | "reality" | "none" | "xtls-rprx-vision") {
            remove(m, "security");
            if sec.contains("tls") || sec == "reality" {
                insert(m, "tls", Value::Bool(true));
            }
        } else if get(m, "cipher").is_some() {
            // `security` is a serde alias of `cipher`. Keeping both makes
            // serde_yaml report a duplicate field and drop the whole node.
            remove(m, "security");
        }
    }
    // Cipher aliases. ant's vmess outbound uses the short name while SS uses
    // the long one, so the mapping depends on the node type.
    if let Some(c) = str_field(m, "cipher") {
        let ty = str_field(m, "type").unwrap_or_default().to_ascii_lowercase();
        let mapped = match (ty.as_str(), c.trim().to_ascii_lowercase().as_str()) {
            ("vmess", "chacha20-ietf-poly1305") => Some("chacha20-poly1305"),
            ("vmess", _) => None,
            (_, "chacha20-poly1305") => Some("chacha20-ietf-poly1305"),
            _ => None,
        };
        if let Some(x) = mapped {
            insert(m, "cipher", Value::String(x.into()));
        }
    }
    // `port` / `alter-id` may be strings.
    if let Some(v) = get(m, "port").cloned() {
        if let Some(s) = scalar_string(&v) {
            if let Ok(n) = s.trim().parse::<u16>() {
                insert(m, "port", Value::Number(serde_yaml::Number::from(n as u64)));
            }
        }
    }
    for k in ["alter-id", "alterId"] {
        if let Some(v) = get(m, k).cloned() {
            if let Some(s) = scalar_string(&v) {
                if let Ok(n) = s.trim().parse::<u32>() {
                    insert(m, k, Value::Number(serde_yaml::Number::from(n as u64)));
                }
            }
        }
    }
    // Booleans may be `"1"` / `1` / `"yes"`.
    for k in [
        "tls",
        "skip-cert-verify",
        "udp",
        "tfo",
        "fast-open",
        "disable-mtu-discovery",
        "over-stream",
        "zero-rtt",
        "ech",
        "ephemeral",
        "disable-sni",
    ] {
        if let Some(v) = get(m, k).cloned() {
            if let Some(b) = as_bool(&v) {
                insert(m, k, Value::Bool(b));
            }
        }
    }
    // String fields that generators sometimes emit as numbers/bools.
    for k in [
        "up",
        "down",
        "ports",
        "obfs",
        "obfs-password",
        "congestion-control",
        "heartbeat",
        "version",
        "ws-path",
        "ws-host",
        "xhttp-path",
        "xhttp-host",
        "xhttp-mode",
        "sni",
        "servername",
        "password",
        "uuid",
        "username",
        "flow",
        "client-fingerprint",
        "fingerprint",
        "reality-public-key",
        "reality-short-id",
        "private-key",
        "peer-public-key",
        "pre-shared-key",
        "auth-key",
        "control-url",
        "hostname",
        "client-name",
        "state-dir",
        "host-key",
    ] {
        if let Some(v) = get(m, k).cloned() {
            if matches!(v, Value::Number(_) | Value::Bool(_)) {
                insert(m, k, Value::String(scalar_string(&v).unwrap_or_default()));
            }
        }
    }
    // `alpn: h2,http/1.1` → list.
    if let Some(Value::String(s)) = get(m, "alpn").cloned() {
        let list: Vec<Value> = s
            .split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| Value::String(x.into()))
            .collect();
        insert(m, "alpn", Value::Sequence(list));
    }
    // `local-address: "10.0.0.2/32,fd42::2/128"` → list.
    if let Some(Value::String(s)) = get(m, "local-address").cloned() {
        let list: Vec<Value> = s
            .split(',')
            .map(|x| Value::String(x.trim().into()))
            .filter(|v| v.as_str().map(|x| !x.is_empty()).unwrap_or(false))
            .collect();
        insert(m, "local-address", Value::Sequence(list));
    }
    // Header maps: values must be strings.
    for k in ["ws-headers", "xhttp-headers"] {
        if let Some(Value::Mapping(h)) = get(m, k).cloned() {
            insert(m, k, Value::Mapping(stringify_map(&h)));
        }
    }
    // Nested `*-opts` → ant's flat fields.
    if let Some(Value::Mapping(o)) = get(m, "ws-opts").cloned() {
        if let Some(p) = o.get(Value::String("path".into())).cloned() {
            insert(m, "ws-path", p);
        }
        if let Some(Value::Mapping(h)) = o.get(Value::String("headers".into())).cloned() {
            if let Some(host) = h
                .get(Value::String("Host".into()))
                .or_else(|| h.get(Value::String("host".into())))
                .cloned()
            {
                insert(m, "ws-host", host);
            }
            insert(m, "ws-headers", Value::Mapping(stringify_map(&h)));
        }
    }
    if let Some(Value::Mapping(o)) = get(m, "xhttp-opts").cloned() {
        for (src, dst) in [
            ("path", "xhttp-path"),
            ("host", "xhttp-host"),
            ("mode", "xhttp-mode"),
        ] {
            if let Some(v) = o.get(Value::String(src.into())).cloned() {
                insert(m, dst, v);
            }
        }
        if let Some(Value::Mapping(h)) = o.get(Value::String("headers".into())).cloned() {
            insert(m, "xhttp-headers", Value::Mapping(stringify_map(&h)));
        }
    }
    if let Some(Value::Mapping(o)) = get(m, "reality-opts").cloned() {
        if let Some(v) = o.get(Value::String("public-key".into())).cloned() {
            insert(m, "reality-public-key", v);
        }
        if let Some(v) = o.get(Value::String("short-id".into())).cloned() {
            insert(m, "reality-short-id", v);
        }
    }

    // ── sub-store / mihomo 协议特有字段别名 ────────────────────────────
    // hysteria2 / tuic / anytls: `auth` / `auth-str` → `password`.
    if get(m, "password").is_none() {
        for k in ["auth", "auth-str", "auth_str"] {
            if let Some(v) = get(m, k).cloned() {
                if let Some(s) = scalar_string(&v).filter(|s| !s.is_empty()) {
                    insert(m, "password", Value::String(s));
                }
                break;
            }
        }
    }
    // TUIC: mihomo uses `congestion-controller`, ant uses `congestion-control`.
    if get(m, "congestion-control").is_none() {
        for k in ["congestion-controller", "congestion_controller"] {
            if let Some(v) = get(m, k).cloned() {
                if let Some(s) = scalar_string(&v).filter(|s| !s.is_empty()) {
                    insert(m, "congestion-control", Value::String(s));
                }
                break;
            }
        }
    }
    // sub-store's Clash Parser folds `server-cert-fingerprint` / `fingerprint`
    // into `tls-fingerprint`; ant stores the cert pin in `fingerprint`.
    if get(m, "fingerprint").is_none() {
        for k in ["tls-fingerprint", "server-cert-fingerprint"] {
            if let Some(v) = get(m, k).cloned() {
                if let Some(s) = scalar_string(&v).filter(|s| !s.is_empty()) {
                    insert(m, "fingerprint", Value::String(s));
                }
                break;
            }
        }
    }
    remove(m, "tls-fingerprint");
    remove(m, "server-cert-fingerprint");
    // mihomo's `servername` is the TLS SNI (ant's effective_sni falls back to
    // it, but keep `sni` populated for consistency with sub-store).
    if get(m, "sni").is_none() {
        if let Some(v) = get(m, "servername").cloned() {
            if let Some(s) = scalar_string(&v).filter(|s| !s.is_empty()) {
                insert(m, "sni", Value::String(s));
            }
        }
    }

    // ── WireGuard: mihomo / sub-store field names differ ───────────────
    let ty = str_field(m, "type").unwrap_or_default().to_ascii_lowercase();
    if ty == "wireguard" || ty == "wg" {
        // `peers:` (multi-peer) — ant dials a single peer, so lift the first
        // one onto the top level when those fields are missing.
        if let Some(Value::Sequence(peers)) = get(m, "peers").cloned() {
            if let Some(Value::Mapping(p)) = peers.first() {
                for (src, dst) in [
                    ("server", "server"),
                    ("port", "port"),
                    ("public-key", "public-key"),
                    ("pre-shared-key", "pre-shared-key"),
                ] {
                    if get(m, dst).is_none() {
                        if let Some(v) = p.get(Value::String(src.into())).cloned() {
                            insert(m, dst, v);
                        }
                    }
                }
            }
        }
        remove(m, "peers");
        // `public-key` is a serde alias of ant's `reality-public-key`; for WG
        // it is the *peer* public key. Rename it so it cannot land in the
        // REALITY field (which would leave `peer-public-key` unset).
        if let Some(v) = get(m, "public-key").cloned() {
            if get(m, "peer-public-key").is_none() {
                if let Some(s) = scalar_string(&v).filter(|s| !s.is_empty()) {
                    insert(m, "peer-public-key", Value::String(s));
                }
            }
            remove(m, "public-key");
        }
        // `ip` / `ipv6` / `address` (mihomo) → `local-address` (ant).
        if get(m, "local-address").is_none() {
            let mut addrs: Vec<String> = Vec::new();
            for k in ["ip", "ipv6", "address"] {
                if let Some(v) = get(m, k).cloned() {
                    let parts: Vec<String> = match v {
                        Value::String(s) => s
                            .split(',')
                            .map(|x| x.trim().to_string())
                            .filter(|x| !x.is_empty())
                            .collect(),
                        Value::Sequence(a) => a
                            .iter()
                            .filter_map(scalar_string)
                            .filter(|x| !x.is_empty())
                            .collect(),
                        other => scalar_string(&other)
                            .filter(|x| !x.is_empty())
                            .into_iter()
                            .collect(),
                    };
                    addrs.extend(parts.into_iter().map(|x| with_cidr(&x)));
                }
            }
            if !addrs.is_empty() {
                insert(
                    m,
                    "local-address",
                    Value::Sequence(addrs.into_iter().map(Value::String).collect()),
                );
            }
        }
    }

    // ── SSH: list fields / TOTP scalar ─────────────────────────────────
    // `host-key` and `host-key-algorithms` are `Vec<String>` in ProxyConfig;
    // YAML/link generators often emit a comma-separated string instead.
    for (src, dst) in [
        ("host-key", "host-key"),
        ("host_key", "host-key"),
        ("host-key-algorithms", "host-key-algorithms"),
        ("host_key_algorithms", "host-key-algorithms"),
    ] {
        if let Some(v) = get(m, src).cloned() {
            match v {
                Value::String(s) => {
                    let list: Vec<Value> = s
                        .split(',')
                        .map(|x| x.trim())
                        .filter(|x| !x.is_empty())
                        .map(|x| Value::String(x.into()))
                        .collect();
                    if !list.is_empty() {
                        insert(m, dst, Value::Sequence(list));
                    }
                }
                other if src != dst => {
                    insert(m, dst, other);
                }
                _ => {}
            }
            if src != dst {
                remove(m, src);
            }
        }
    }
    // `totp: <base32 secret>` → the `SshTotpConfig` mapping (defaults match
    // link.rs's `ssh()` conversion).
    if let Some(Value::String(s)) = get(m, "totp")
        .cloned()
        .or_else(|| get(m, "totp_opt").cloned())
    {
        let mut o = Mapping::new();
        o.insert(Value::String("secret".into()), Value::String(s));
        insert(m, "totp-opt", Value::Mapping(o));
        remove(m, "totp");
        remove(m, "totp_opt");
    }
    // `ProxyConfig::tls` defaults to **true** (ant's own dialer convention),
    // but mihomo/Clash defaults to false. For subscription nodes, infer TLS
    // the way sub-store/mihomo do when the field is absent.
    if get(m, "tls").is_none() {
        let ty = str_field(m, "type").unwrap_or_default().to_ascii_lowercase();
        let always_tls = matches!(
            ty.as_str(),
            "trojan" | "hysteria2" | "tuic" | "anytls" | "naive" | "shadowquic" | "spectre"
        );
        let explicit = get(m, "sni").is_some()
            || get(m, "servername").is_some()
            || get(m, "client-fingerprint").is_some();
        insert(m, "tls", Value::Bool(always_tls || explicit));
    }

    // link.rs defaults uTLS to `chrome` for TLS-enabled vless/vmess/trojan/
    // anytls/naive nodes. Apply the same default to file/YAML subscriptions
    // so the two sources produce identical node configs. Done *after* the
    // TLS inference above, otherwise the fingerprint would be mistaken for
    // an explicit TLS hint.
    if get(m, "client-fingerprint").is_none() {
        let ty = str_field(m, "type").unwrap_or_default().to_ascii_lowercase();
        let tls = get(m, "tls").and_then(as_bool).unwrap_or(false);
        if tls
            && matches!(
                ty.as_str(),
                "vless" | "vmess" | "trojan" | "anytls" | "naive"
            )
        {
            insert(m, "client-fingerprint", Value::String("chrome".into()));
        }
    }
}

fn stringify_map(h: &Mapping) -> Mapping {
    let mut out = Mapping::new();
    for (k, v) in h {
        out.insert(k.clone(), Value::String(scalar_string(v).unwrap_or_default()));
    }
    out
}

fn get<'a>(m: &'a Mapping, k: &str) -> Option<&'a Value> {
    m.get(Value::String(k.into()))
}

fn insert(m: &mut Mapping, k: &str, v: Value) {
    m.insert(Value::String(k.into()), v);
}

fn remove(m: &mut Mapping, k: &str) {
    m.remove(Value::String(k.into()));
}

fn str_field(m: &Mapping, k: &str) -> Option<String> {
    get(m, k).and_then(scalar_string)
}

fn scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => Some(n.as_f64().map(|f| f != 0.0).unwrap_or(false)),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" | "" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// mihomo's WG `ip` / `ipv6` may omit the prefix; ant requires CIDR addresses.
fn with_cidr(s: &str) -> String {
    let s = s.trim();
    if s.contains('/') {
        return s.to_string();
    }
    if s.contains(':') {
        format!("{s}/128")
    } else {
        format!("{s}/32")
    }
}

fn share_links(text: &str) -> Vec<ProxyConfig> {
    let mut out = Vec::new();
    for line in text.split(['\n', '\r']) {
        let mut line = line.trim();
        // tolerate `- <link>` list items and quoted `payload:` entries
        if let Some(rest) = line.strip_prefix("- ") {
            line = rest.trim();
        }
        let line = line.trim_matches(|c| c == '\'' || c == '"').trim();
        if line.is_empty() {
            continue;
        }
        match link::from_link(line) {
            Some(c) => out.push(c),
            None => {
                tracing::warn!(
                    scheme = link::scheme_of(line),
                    "unsupported share link skipped"
                );
            }
        }
    }
    out
}

/// Apply `filter` / `exclude-filter`, drop reserved names, and make every node
/// name unique (duplicates get a `_2`, `_3`, … suffix like mihomo).
pub fn finalize(
    provider: &str,
    list: Vec<ProxyConfig>,
    filter: Option<&str>,
    exclude: Option<&str>,
) -> Result<Vec<ProxyConfig>> {
    let include = compile_alts(filter)?;
    let exclude_regs = compile_alts(exclude)?;
    let mut out = Vec::with_capacity(list.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for mut c in list {
        c.name = c.name.trim().replace(['\n', '\r', '\t'], " ");
        if c.name.is_empty() {
            c.name = format!("{}:{}", c.server, c.port);
        }
        if crate::config::RESERVED_OUTBOUND_NAMES
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&c.name))
        {
            c.name.push_str("_node");
        }
        if !include.is_empty() && !include.iter().any(|r| r.is_match(&c.name)) {
            continue;
        }
        if exclude_regs.iter().any(|r| r.is_match(&c.name)) {
            continue;
        }
        let base_name = c.name.clone();
        let mut n = 1usize;
        while !seen.insert(c.name.to_ascii_lowercase()) {
            n += 1;
            c.name = format!("{base_name}_{n}");
        }
        if n > 1 {
            tracing::warn!(
                provider = %provider,
                name = %c.name,
                "duplicate node name renamed"
            );
        }
        out.push(c);
    }
    Ok(out)
}

fn compile_alts(pat: Option<&str>) -> Result<Vec<Regex>> {
    let Some(pat) = pat.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for part in pat.split('`') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(Regex::new(part).map_err(|e| anyhow::anyhow!("invalid regex `{part}`: {e}"))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn enc(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn parses_yaml_envelope() {
        let y = "proxies:\n  - name: a\n    type: socks5\n    server: 1.1.1.1\n    port: 1080\n";
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "a");
    }

    #[test]
    fn parses_base64_link_list() {
        let links = "hysteria2://pw@a.com:443#N1\ntrojan://pw@b.com:443#N2\n";
        let v = parse_payload("p", enc(links).as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "N1");
        assert_eq!(v[1].name, "N2");
    }

    #[test]
    fn parses_plain_link_list() {
        let v = parse_payload("p", b"ss://YWVzLTI1Ni1nY206cGFzcw@x.com:443#S\n").unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "S");
    }

    #[test]
    fn finalize_dedupes_and_filters() {
        let list = vec![
            ProxyConfig { name: "A".into(), ..sample() },
            ProxyConfig { name: "A".into(), ..sample() },
            ProxyConfig { name: "B".into(), ..sample() },
            ProxyConfig { name: "DIRECT".into(), ..sample() },
            ProxyConfig { name: "".into(), ..sample() },
        ];
        let out = finalize("p", list.clone(), Some("^(A|B)"), None).unwrap();
        assert_eq!(out.len(), 3); // A, A_2, B
        assert_eq!(out[0].name, "A");
        assert_eq!(out[1].name, "A_2");
        assert_eq!(out[2].name, "B");
        let out = finalize("p", list, None, Some("^B$")).unwrap();
        assert_eq!(out.len(), 4);
        assert!(out.iter().all(|c| c.name != "B"));
        let out = finalize("p", vec![ProxyConfig { name: "direct".into(), ..sample() }], None, None).unwrap();
        assert_eq!(out[0].name, "direct_node");
    }

    fn sample() -> ProxyConfig {
        ProxyConfig {
            ty: "socks5".into(),
            server: "1.1.1.1".into(),
            port: 1080,
            ..link::blank()
        }
    }

    // ── sub-store 兼容回归测试 ─────────────────────────────────────

    #[test]
    fn parses_clash_yaml_with_string_port_and_nested_opts() {
        // sub-store / mihomo emit `port` as a string and nest ws options.
        let y = r#"
proxies:
  - name: T1
    type: trojan
    server: t.example.com
    port: 443
    password: pw
    sni: real.com
  - name: S1
    type: ss
    server: s.example.com
    port: "8388"
    cipher: aes-256-gcm
    password: pw
  - name: V1
    type: vmess
    server: v.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    network: ws
    tls: false
    ws-opts:
      path: /ws
      headers:
        Host: cdn.com
"#;
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[1].port, 8388);
        assert_eq!(v[2].network, "ws");
        assert_eq!(v[2].ws_path.as_deref(), Some("/ws"));
        assert_eq!(v[2].ws_host.as_deref(), Some("cdn.com"));
        assert!(!v[2].tls);
    }

    #[test]
    fn parses_clash_provider_payload_list() {
        let y = "payload:\n  - 'trojan://pw@t.example.com:443?sni=real.com#T'\n  - 'ss://YWVzLTI1Ni1nY206cGFzcw@ss.example.com:8388#S'\n";
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].ty, "trojan");
        assert_eq!(v[1].ty, "shadowsocks");
    }

    #[test]
    fn parses_wrapped_base64_subscription() {
        let links = "trojan://pw@t.example.com:443#T\n";
        let b = enc(links);
        let wrapped = format!("{}\n{}\n", &b[..20], &b[20..]);
        let v = parse_payload("p", wrapped.as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "T");
    }

    #[test]
    fn skips_unsupported_yaml_nodes() {
        let y = "proxies:\n  - name: bad\n    type: ssr\n    server: x.com\n    port: 443\n  - name: good\n    type: socks5\n    server: y.com\n    port: 1080\n";
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "good");
    }

    #[test]
    fn parses_ssd_subscription() {
        let json = r#"{"airport":"demo","encryption":"aes-256-gcm","password":"pw","port":8388,"servers":[{"server":"s.example.com","remarks":"SSD1"}]}"#;
        let v = parse_payload("p", format!("ssd://{}", enc(json)).as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "SSD1");
        assert_eq!(v[0].port, 8388);
    }

    #[test]
    fn clash_tls_defaults_follow_mihomo() {
        // No `tls` key: a plain vmess node must NOT silently get TLS.
        let y = "proxies:\n  - name: V\n    type: vmess\n    server: v.com\n    port: 443\n    uuid: u\n    cipher: auto\n  - name: T\n    type: trojan\n    server: t.com\n    port: 443\n    password: pw\n";
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
        assert!(!v[0].tls);
        assert!(v[1].tls);
    }

    // ── 各协议字段映射回归（对齐 sub-store 的 Clash/URI 解析器输出） ────

    #[test]
    fn clash_yaml_maps_protocol_specific_fields() {
        // mihomo / sub-store 节点常用的字段名，必须正确落到 ProxyConfig。
        let y = r#"
proxies:
  - name: HY2
    type: hysteria2
    server: hy.example.com
    port: 443
    auth: token
    sni: real.example.com
    tls-fingerprint: PIN1
    skip-cert-verify: true
    up: "100"
    down: "200"
    ports: 1000-2000
  - name: TUIC
    type: tuic
    server: tu.example.com
    port: 443
    uuid: U
    password: pw
    congestion-controller: bbr
    alpn: [h3]
  - name: WG
    type: wireguard
    server: wg.example.com
    port: 51820
    private-key: PRIV
    public-key: PEERPUB
    ip: 10.7.0.2/32
    ipv6: fd42::2/128
    mtu: 1420
  - name: VM
    type: vmess
    server: vm.example.com
    port: 443
    uuid: U
    cipher: auto
    servername: cdn.example.com
    fingerprint: CERTPIN
    alpn: h2,http/1.1
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: ws.example.com
  - name: SS
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw
"#;
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 5, "all nodes must survive");
        // hysteria2: `auth` → password, `tls-fingerprint` → fingerprint
        assert_eq!(v[0].password.as_deref(), Some("token"));
        assert_eq!(v[0].fingerprint.as_deref(), Some("PIN1"));
        assert!(v[0].skip_cert_verify);
        assert_eq!(v[0].up.as_deref(), Some("100"));
        assert_eq!(v[0].down.as_deref(), Some("200"));
        assert_eq!(v[0].ports.as_deref(), Some("1000-2000"));
        // tuic: `congestion-controller` → congestion-control
        assert_eq!(v[1].congestion_control.as_deref(), Some("bbr"));
        assert_eq!(v[1].uuid.as_deref(), Some("U"));
        assert_eq!(v[1].password.as_deref(), Some("pw"));
        // wireguard: `public-key` → peer-public-key（不能落到 reality 公钥），
        // `ip`/`ipv6` → local-address
        assert_eq!(v[2].peer_public_key.as_deref(), Some("PEERPUB"));
        assert!(v[2].reality_public_key.is_none());
        assert_eq!(
            v[2].local_address,
            vec!["10.7.0.2/32".to_string(), "fd42::2/128".to_string()]
        );
        assert_eq!(v[2].private_key.as_deref(), Some("PRIV"));
        assert_eq!(v[2].wg_mtu, Some(1420));
        // vmess: `servername` → sni; `fingerprint` 保持; alpn 字符串 → list
        assert_eq!(v[3].sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(v[3].fingerprint.as_deref(), Some("CERTPIN"));
        assert_eq!(
            v[3].alpn.as_deref(),
            Some(&vec!["h2".to_string(), "http/1.1".to_string()][..])
        );
        assert_eq!(v[3].ws_path.as_deref(), Some("/ws"));
        assert_eq!(v[3].ws_host.as_deref(), Some("ws.example.com"));
        assert_eq!(v[3].cipher.as_deref(), Some("auto"));
        // ss
        assert_eq!(v[4].ty, "ss");
        assert_eq!(v[4].cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(v[4].password.as_deref(), Some("pw"));
    }

    #[test]
    fn clash_yaml_cipher_and_security_alias_do_not_conflict() {
        // `security` 是 ProxyConfig.cipher 的 serde alias；与 `cipher` 同时
        // 出现会触发 duplicate field 而丢掉整个节点。
        let y = r#"
proxies:
  - name: V
    type: vmess
    server: v.com
    port: 443
    uuid: U
    cipher: chacha20-ietf-poly1305
    security: auto
"#;
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 1, "duplicate alias must not drop the node");
        assert_eq!(v[0].cipher.as_deref(), Some("chacha20-poly1305"));
    }

    #[test]
    fn clash_yaml_wireguard_peers_and_multi_peer_fallback() {
        let y = r#"
proxies:
  - name: WG2
    type: wireguard
    private-key: PRIV
    ip: 10.7.0.2/32
    peers:
      - server: peer.example.com
        port: 51820
        public-key: PEER2
        pre-shared-key: PSK
"#;
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].server, "peer.example.com");
        assert_eq!(v[0].port, 51820);
        assert_eq!(v[0].peer_public_key.as_deref(), Some("PEER2"));
        assert_eq!(v[0].pre_shared_key.as_deref(), Some("PSK"));
        assert_eq!(v[0].local_address, vec!["10.7.0.2/32".to_string()]);
    }

    #[test]
    fn file_payload_with_bom_and_crlf_is_parsed() {
        let y = "\u{feff}proxies:\r\n  - name: T\r\n    type: trojan\r\n    server: t.com\r\n    port: 443\r\n    password: pw\r\n    sni: r.com\r\n";
        let v = parse_payload("file", y.as_bytes()).unwrap();
        let v = finalize("file", v, None, None).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "T");
        assert_eq!(v[0].sni.as_deref(), Some("r.com"));
        assert!(v[0].tls);
    }

    #[test]
    fn base64_subscription_maps_each_protocol_link() {
        use base64::Engine;
        let vmess_json = r#"{"add":"vm.com","port":443,"id":"U","net":"tcp","ps":"VM"}"#;
        let vmess = base64::engine::general_purpose::STANDARD.encode(vmess_json);
        let ss_ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let links = format!(
            "hysteria2://pw@hy.com:443?obfs=salamander&obfs-password=op&up=100&down=200&mport=1000-2000&sni=r.com&insecure=1#HY\n\
             tuic://U:P@tu.com:443?congestion_control=bbr&alpn=h3#TU\n\
             vless://U@vl.com:443?security=reality&pbk=PK&sid=abcd&sni=www.microsoft.com&type=xhttp&path=%2Fx&mode=stream-one#VL\n\
             vmess://{vmess}#VM\n\
             trojan://pw@tr.com:443?sni=r.com&type=ws&path=%2Fws&host=cdn.com#TR\n\
             ss://{ss_ui}@ss.com:8388#SS\n\
             anytls://pw@at.com:443?sni=r.com&fp=firefox#AT\n\
             socks5://u:p@so.com:1080#SO\n\
             ssr://skipme\n"
        );
        let v = parse_payload("sub", enc(&links).as_bytes()).unwrap();
        assert_eq!(v.len(), 8, "only the ssr link is skipped");
        assert_eq!(v[0].obfs.as_deref(), Some("salamander"));
        assert_eq!(v[0].obfs_password.as_deref(), Some("op"));
        assert_eq!(v[0].ports.as_deref(), Some("1000-2000"));
        assert_eq!(v[1].congestion_control.as_deref(), Some("bbr"));
        assert_eq!(v[2].reality_public_key.as_deref(), Some("PK"));
        assert_eq!(v[2].network, "xhttp");
        assert_eq!(v[2].xhttp_mode.as_deref(), Some("stream-one"));
        assert_eq!(v[3].name, "VM");
        assert_eq!(v[4].network, "ws");
        assert_eq!(v[4].ws_host.as_deref(), Some("cdn.com"));
        assert_eq!(v[5].cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(v[6].client_fingerprint.as_deref(), Some("firefox"));
        assert_eq!(v[7].username.as_deref(), Some("u"));
    }

    #[test]
    fn clash_yaml_native_protocol_fields() {
        let y = r#"
proxies:
  - name: N
    type: naive
    server: n.com
    port: 443
    username: u
    password: p
    sni: real.com
    skip-cert-verify: true
  - name: SQ
    type: shadowquic
    server: q.com
    port: 443
    username: u
    password: p
    sni: jls.com
    alpn: h3
    over-stream: true
    min-mtu: 1200
  - name: SP
    type: spectre
    server: sp.com
    port: 4433
    username: u
    password: p
    sni: echo.com
    up: 50mbps
    down: 200mbps
  - name: SSH
    type: ssh
    server: s.com
    port: 22
    username: alice
    password: secret
    private-key: /path/key
    host-key: ssh-ed25519 AAAA,ssh-rsa BBBB
    host-key-algorithms: ssh-ed25519
  - name: TS
    type: tailscale
    auth-key: tskey-xxx
    control-url: https://headscale.com
    hostname: ant-node
    state-dir: /var/lib/ant/ts
    ephemeral: true
  - name: SO
    type: socks5
    server: so.com
    port: 1080
    username: u
    password: p
"#;
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 6, "every native protocol node must survive");
        assert_eq!(v[0].username.as_deref(), Some("u"));
        assert_eq!(v[0].sni.as_deref(), Some("real.com"));
        assert!(v[0].skip_cert_verify);
        assert_eq!(v[1].sni.as_deref(), Some("jls.com"));
        assert_eq!(v[1].alpn.as_deref(), Some(&vec!["h3".to_string()][..]));
        assert!(v[1].over_stream);
        assert_eq!(v[1].min_mtu, Some(1200));
        assert_eq!(v[2].up.as_deref(), Some("50mbps"));
        assert_eq!(v[2].down.as_deref(), Some("200mbps"));
        assert_eq!(v[3].private_key.as_deref(), Some("/path/key"));
        assert_eq!(
            v[3].ssh_host_key.as_deref(),
            Some(&vec!["ssh-ed25519 AAAA".to_string(), "ssh-rsa BBBB".to_string()][..])
        );
        assert_eq!(
            v[3].ssh_host_key_algorithms.as_deref(),
            Some(&vec!["ssh-ed25519".to_string()][..])
        );
        assert_eq!(v[4].ts_auth_key.as_deref(), Some("tskey-xxx"));
        assert_eq!(v[4].ts_control_url.as_deref(), Some("https://headscale.com"));
        assert_eq!(v[4].ts_hostname.as_deref(), Some("ant-node"));
        assert_eq!(v[4].ts_state_dir.as_deref(), Some("/var/lib/ant/ts"));
        assert!(v[4].ts_ephemeral);
        assert_eq!(v[5].username.as_deref(), Some("u"));
        assert_eq!(v[5].password.as_deref(), Some("p"));
    }

    #[test]
    fn clash_yaml_vless_reality_and_xhttp() {
        let y = r#"
proxies:
  - name: R
    type: vless
    server: r.com
    port: 443
    uuid: U
    security: reality
    servername: www.microsoft.com
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: PUBKEY
      short-id: abcd
  - name: X
    type: vless
    server: x.com
    port: 443
    uuid: U
    network: xhttp
    xhttp-opts:
      path: /x
      host: cdn.com
      mode: stream-one
      headers:
        X-Custom: "yes"
"#;
        let v = parse_payload("p", y.as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
        assert!(v[0].tls);
        assert_eq!(v[0].reality_public_key.as_deref(), Some("PUBKEY"));
        assert_eq!(v[0].reality_short_id.as_deref(), Some("abcd"));
        assert_eq!(v[0].flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(v[0].sni.as_deref(), Some("www.microsoft.com"));
        assert_eq!(v[1].network, "xhttp");
        assert_eq!(v[1].xhttp_path.as_deref(), Some("/x"));
        assert_eq!(v[1].xhttp_host.as_deref(), Some("cdn.com"));
        assert_eq!(v[1].xhttp_mode.as_deref(), Some("stream-one"));
        assert_eq!(
            v[1].xhttp_headers
                .as_ref()
                .and_then(|h| h.get("X-Custom"))
                .map(String::as_str),
            Some("yes")
        );
    }

    #[test]
    fn file_yaml_and_link_subscription_agree() {
        // 同一节点写成 Clash YAML 文件与分享链接，解析结果必须一致。
        let y = "proxies:\n  - name: T\n    type: trojan\n    server: t.com\n    port: 443\n    password: pw\n    sni: r.com\n    network: ws\n    ws-opts:\n      path: /ws\n      headers:\n        Host: cdn.com\n    skip-cert-verify: true\n    alpn: h2,http/1.1\n";
        let link = "trojan://pw@t.com:443?type=ws&path=%2Fws&host=cdn.com&sni=r.com&allowInsecure=1&alpn=h2,http/1.1#T";
        let a = finalize("p", parse_payload("p", y.as_bytes()).unwrap(), None, None).unwrap();
        let b = finalize("p", parse_payload("p", link.as_bytes()).unwrap(), None, None).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        for (x, z) in [
            (&a[0].name, &b[0].name),
            (&a[0].ty, &b[0].ty),
            (&a[0].server, &b[0].server),
        ] {
            assert_eq!(x, z);
        }
        assert_eq!(a[0].port, b[0].port);
        assert_eq!(a[0].password, b[0].password);
        assert_eq!(a[0].sni, b[0].sni);
        assert_eq!(a[0].network, b[0].network);
        assert_eq!(a[0].ws_path, b[0].ws_path);
        assert_eq!(a[0].ws_host, b[0].ws_host);
        assert_eq!(a[0].skip_cert_verify, b[0].skip_cert_verify);
        assert_eq!(a[0].alpn, b[0].alpn);
        assert_eq!(a[0].tls, b[0].tls);
        assert_eq!(a[0].client_fingerprint, b[0].client_fingerprint);
    }
}
