//! Share-link → [`ProxyConfig`] conversion (mihomo `common/convert` equivalent).
//!
//! Coverage mirrors what ant can actually dial — adding a link format for a
//! protocol without an outbound would only produce undialable nodes.
//!
//! | scheme | notes |
//! |---|---|
//! | `hysteria2` / `hy2` | obfs, ports/mport, up/down, pinSHA256, alpn |
//! | `tuic` | v5 `uuid:password` only (v4 `token` has no outbound) |
//! | `anytls` | uTLS fingerprint |
//! | `vless` | tcp / ws / xhttp; TLS / uTLS / REALITY; flow=vision |
//! | `vmess` | base64 JSON (v2rayN) **and** Xray VMessAEAD link; tcp / ws / xhttp |
//! | `trojan` | tcp / ws / xhttp; TLS / uTLS |
//! | `ss` | SIP002 + legacy + AEAD-2022; tcp / ws / xhttp; TLS when sni/fp given |
//! | `socks` / `socks5` / `socks5h` | v5, optional user/pass |
//! | `socks4` / `socks4a` | v4(a), USERID only |
//! | `naive` `shadowquic` `spectre` `wireguard` `ssh` `tailscale` | ant-native formats (no cross-client standard exists；后三者需对应 build feature) |
//!
//! ant has **no** outbound for hysteria v1, ssr, http-proxy, and no `grpc` /
//! `httpupgrade` transport — those links are skipped with a warning so one bad
//! line can never drop a whole subscription.
//!
//! TLS parameters accepted on every TLS-capable scheme:
//! `sni`/`peer`, `alpn` (comma list), `fp` (uTLS: chrome/firefox/safari/edge/
//! ios/android/360/qq/random — `none` disables), `pcs`/`pinSHA256` (server cert
//! pin), `allowInsecure`/`insecure`/`skip-cert-verify`.
//! REALITY (vless): `security=reality` + `pbk`/`sid`.

use crate::config::ProxyConfig;
use crate::outbound::UtlsFingerprint;
use std::collections::HashMap;

/// Parsed share-link pieces.
struct Uri {
    scheme: String,
    /// Percent-decoded `userinfo` (everything before the last `@`).
    user: Option<String>,
    host: String,
    port: u16,
    /// `hysteria2://pw@host:1000-2000,3000` port-hop range (sub-store emits
    /// it in `ports:` / `mport:`). `port` above holds the first port.
    port_range: Option<String>,
    query: HashMap<String, String>,
    /// Percent-decoded fragment (node name).
    fragment: String,
}

impl Uri {
    fn q(&self, k: &str) -> Option<&String> {
        self.query.get(k).filter(|v| !v.is_empty())
    }
    fn q_lower(&self, k: &str) -> Option<String> {
        self.q(k).map(|v| v.to_ascii_lowercase())
    }
    fn flag(&self, keys: &[&str]) -> bool {
        keys.iter().any(|k| {
            matches!(
                self.query.get(*k).map(|v| v.as_str()),
                Some("1") | Some("true") | Some("True") | Some("TRUE") | Some("yes")
            )
        })
    }
    fn alpn(&self) -> Option<Vec<String>> {
        self.q("alpn").map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
    }
    /// `?type=` transport, defaulting to `tcp`.
    fn transport(&self) -> String {
        self.q_lower("type").unwrap_or_else(|| "tcp".into())
    }
}

/// Convert one share link. Returns `None` when the scheme/transport is not
/// supported by ant (caller logs and skips).
pub fn from_link(line: &str) -> Option<ProxyConfig> {
    let uri = parse_uri(line)?;
    match uri.scheme.as_str() {
        "hysteria2" | "hy2" => hysteria2(&uri),
        "tuic" => tuic(&uri),
        "anytls" => anytls(&uri),
        "vless" => vless(&uri),
        "vmess" => vmess(&uri, line),
        "trojan" => trojan(&uri),
        "ss" | "shadowsocks" => shadowsocks(&uri),
        "socks" | "socks5" | "socks5h" => socks(&uri, "socks5"),
        "socks4" | "socks4a" => socks(&uri, &uri.scheme.clone()),
        "naive" => naive(&uri),
        "shadowquic" | "sq" => shadowquic(&uri),
        "spectre" => spectre(&uri),
        "wireguard" | "wg" => wireguard(&uri),
        "ssh" => ssh(&uri),
        "tailscale" | "ts" => tailscale_link(&uri),
        _ => None,
    }
}

/// Scheme of a share link (lower-cased), used for "unsupported" diagnostics.
pub fn scheme_of(line: &str) -> String {
    line.split_once("://")
        .map(|(s, _)| s.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

// ── generic URI splitting ─────────────────────────────────────────

fn parse_uri(line: &str) -> Option<Uri> {
    let (scheme, rest) = line.split_once("://")?;
    let scheme = scheme.trim().to_ascii_lowercase();
    if scheme.is_empty() {
        return None;
    }
    let (rest, frag) = match rest.split_once('#') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((a, b)) => (Some(percent_decode(a)), b),
        None => (None, rest),
    };
    let (host, port, port_range) = split_host_port(hostport);
    if host.is_empty() {
        return None;
    }
    let port = port.unwrap_or_else(|| default_port(&scheme));
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((k, v)) => {
                map.insert(percent_decode(k), percent_decode(v));
            }
            None => {
                map.insert(percent_decode(pair), String::new());
            }
        }
    }
    Some(Uri {
        scheme,
        user,
        host,
        port,
        port_range,
        query: map,
        fragment: percent_decode(frag),
    })
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "socks" | "socks5" | "socks5h" | "socks4" | "socks4a" => 1080,
        "naive" => 443,
        "shadowquic" | "sq" => 443,
        "spectre" => 443,
        "wireguard" | "wg" => 51820,
        "ssh" => 22,
        "tailscale" | "ts" => 0,
        _ => 443,
    }
}

fn split_host_port(s: &str) -> (String, Option<u16>, Option<String>) {
    if let Some(rest) = s.strip_prefix('[') {
        // [::1]:443
        let (host, tail) = match rest.split_once(']') {
            Some((h, t)) => (h, t),
            None => (rest, ""),
        };
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        return (host.to_string(), port, None);
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            // `host:443/?insecure=1` — generators put a path separator before
            // the query; strip it so the port still parses (a base64 blob
            // legacy `ss://` payload never contains `:`, so this is safe).
            let p = p.strip_suffix('/').unwrap_or(p);
            if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
                (h.to_string(), p.parse().ok(), None)
            } else if is_port_range(p) {
                // `hysteria2://pw@host:1000-2000,3000` — sub-store puts the
                // whole range in `ports:` and uses the first port as `port`.
                // Treating the range as part of the hostname would produce a
                // bogus `server`.
                let first = p
                    .split([',', ';'])
                    .next()
                    .and_then(|x| x.split('-').next())
                    .and_then(|x| x.parse::<u16>().ok());
                (h.to_string(), first, Some(p.to_string()))
            } else {
                (s.to_string(), None, None)
            }
        }
        _ => (s.to_string(), None, None),
    }
}

fn is_port_range(p: &str) -> bool {
    !p.is_empty()
        && p.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ',' | ';'))
        && p.chars().any(|c| matches!(c, '-' | ',' | ';'))
        && p.chars().any(|c| c.is_ascii_digit())
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── shared TLS / transport plumbing ───────────────────────────────

/// Every field defaulted — the starting point for link conversion.
pub(crate) fn blank() -> ProxyConfig {
    ProxyConfig {
        name: String::new(),
        ty: String::new(),
        server: String::new(),
        port: 0,
        password: None,
        username: None,
        version: None,
        uuid: None,
        flow: None,
        cipher: None,
        alter_id: None,
        network: "tcp".into(),
        tls: false,
        sni: None,
        servername: None,
        alpn: None,
        skip_cert_verify: false,
        fingerprint: None,
        client_fingerprint: None,
        ws_path: None,
        ws_host: None,
        ws_headers: None,
        reality_public_key: None,
        reality_short_id: None,
        ech: false,
        ech_config: None,
        ech_config_path: None,
        ech_query_server_name: None,
        xhttp_path: None,
        xhttp_host: None,
        xhttp_mode: None,
        xhttp_headers: None,
        obfs: None,
        obfs_password: None,
        up: None,
        down: None,
        ports: None,
        ca: None,
        disable_mtu_discovery: false,
        udp_mtu: None,
        congestion_control: None,
        heartbeat: None,
        over_stream: false,
        zero_rtt: true,
        initial_mtu: None,
        min_mtu: None,
        private_key: None,
        peer_public_key: None,
        pre_shared_key: None,
        local_address: Vec::new(),
        wg_mtu: None,
        persistent_keepalive: None,
        ssh_private_key_passphrase: None,
        ssh_host_key: None,
        ssh_host_key_algorithms: None,
        ssh_totp: None,
        ts_auth_key: None,
        ts_control_url: None,
        ts_hostname: None,
        ts_client_name: None,
        ts_state_dir: None,
        ts_ephemeral: false,
    }
}

fn base(uri: &Uri, ty: &str) -> ProxyConfig {
    ProxyConfig {
        ty: ty.into(),
        server: uri.host.clone(),
        port: uri.port,
        ..blank()
    }
}

fn with_name(mut c: ProxyConfig, uri: &Uri) -> ProxyConfig {
    c.name = uri.fragment.trim().to_string();
    if c.name.is_empty() {
        // sub-store's URI parsers fall back to `?remarks=` / `?remark=`
        // when the `#fragment` is absent.
        if let Some(r) = uri.q("remarks").or_else(|| uri.q("remark")) {
            c.name = r.trim().to_string();
        }
    }
    c
}

/// Map a share-link `fp` value onto an ant-supported uTLS name.
///
/// Absent → `default_when_tls` (mihomo defaults to `chrome`); `none`/`off`
/// disables uTLS entirely; an unknown name is dropped with a warning.
fn utls_fp(raw: Option<&String>, default_when_tls: bool) -> Option<String> {
    let s = raw.map(|v| v.trim().to_ascii_lowercase()).unwrap_or_default();
    match s.as_str() {
        "" => {
            if default_when_tls {
                Some("chrome".into())
            } else {
                None
            }
        }
        "none" | "off" | "false" => None,
        "randomized" | "randomize" => Some("random".into()),
        "browser360" => Some("360".into()),
        other => {
            if UtlsFingerprint::parse(other).is_some() {
                Some(other.to_string())
            } else {
                tracing::warn!(fp = other, "unsupported uTLS fingerprint ignored");
                None
            }
        }
    }
}

/// TLS knobs that every TLS-capable outbound understands.
///
/// `utls_default`: whether to fall back to `chrome` when `fp` is absent
/// (mihomo does this for vless/vmess/trojan/anytls; not for ss).
fn apply_tls(c: &mut ProxyConfig, uri: &Uri, utls_default: bool) {
    c.sni = uri.q("sni").or_else(|| uri.q("peer")).cloned();
    c.alpn = uri.alpn();
    c.skip_cert_verify = uri.flag(&["allowInsecure", "insecure", "skip-cert-verify"]);
    c.fingerprint = uri.q("pinSHA256").or_else(|| uri.q("pcs")).cloned();
    c.client_fingerprint = utls_fp(uri.q("fp"), utls_default && c.tls);
}

/// `?type=` transport for vless / vmess / trojan / ss.
///
/// Returns false for transports ant cannot dial (`grpc`, `httpupgrade`,
/// `quic`, `kcp`, …).
fn apply_transport(c: &mut ProxyConfig, uri: &Uri) -> bool {
    match uri.transport().as_str() {
        "tcp" | "raw" | "none" | "" => {
            c.network = "tcp".into();
            true
        }
        "ws" => {
            c.network = "ws".into();
            // sub-store accepts both `path` / `wspath` and `host` /
            // `obfsParam` for the WS path and Host header.
            c.ws_path = uri.q("path").or_else(|| uri.q("wspath")).cloned();
            c.ws_host = uri
                .q("host")
                .or_else(|| uri.q("obfsParam"))
                .cloned();
            true
        }
        "xhttp" => {
            c.network = "xhttp".into();
            c.xhttp_path = uri.q("path").or_else(|| uri.q("wspath")).cloned();
            c.xhttp_host = uri
                .q("host")
                .or_else(|| uri.q("obfsParam"))
                .cloned();
            c.xhttp_mode = uri.q("mode").cloned();
            true
        }
        other => {
            tracing::debug!(transport = other, "unsupported transport skipped");
            false
        }
    }
}

// ── per-protocol builders ─────────────────────────────────────────

fn hysteria2(uri: &Uri) -> Option<ProxyConfig> {
    let mut c = base(uri, "hysteria2");
    c.tls = true;
    c.password = uri
        .user
        .clone()
        .or_else(|| uri.q("auth").cloned())
        .or_else(|| uri.q("password").cloned());
    c.sni = uri.q("sni").or_else(|| uri.q("peer")).cloned();
    c.obfs = uri.q("obfs").cloned();
    c.obfs_password = uri.q("obfs-password").cloned();
    c.up = uri.q("up").or_else(|| uri.q("upmbps")).cloned();
    c.down = uri.q("down").or_else(|| uri.q("downmbps")).cloned();
    c.ports = uri
        .q("ports")
        .or_else(|| uri.q("mport"))
        .cloned()
        .or_else(|| uri.port_range.clone());
    c.alpn = uri.alpn();
    c.fingerprint = uri.q("pinSHA256").cloned();
    c.skip_cert_verify = uri.flag(&["insecure", "allowInsecure", "skip-cert-verify"]);
    c.password.as_ref()?;
    Some(with_name(c, uri))
}

fn tuic(uri: &Uri) -> Option<ProxyConfig> {
    // TUIC v5: `uuid:password@host:port`. A bare `token@` (v4) has no outbound.
    let (uuid, password) = {
        let u = uri.user.as_deref()?;
        let (a, b) = u.split_once(':')?;
        (a.to_string(), b.to_string())
    };
    let mut c = base(uri, "tuic");
    c.tls = true;
    c.uuid = Some(uuid);
    c.password = Some(password);
    c.sni = uri.q("sni").or_else(|| uri.q("peer")).cloned();
    c.alpn = uri.alpn();
    c.congestion_control = uri
        .q("congestion_control")
        .or_else(|| uri.q("congestion-controller"))
        .cloned();
    // `disable_sni` turns SNI off, it does NOT disable certificate
    // verification (sub-store maps `disable-sni` to its own field).
    c.skip_cert_verify = uri.flag(&[
        "insecure",
        "allowInsecure",
        "allow-insecure",
        "skip-cert-verify",
    ]);
    c.fingerprint = uri.q("pinSHA256").cloned();
    Some(with_name(c, uri))
}

fn anytls(uri: &Uri) -> Option<ProxyConfig> {
    let mut c = base(uri, "anytls");
    c.tls = true;
    c.password = uri.user.clone().or_else(|| uri.q("password").cloned());
    apply_tls(&mut c, uri, true);
    c.password.as_ref()?;
    Some(with_name(c, uri))
}

fn vless(uri: &Uri) -> Option<ProxyConfig> {
    let uuid = uri.user.clone()?;
    let security = uri.q_lower("security").unwrap_or_else(|| "none".into());
    let mut c = base(uri, "vless");
    c.uuid = Some(uuid);
    // mihomo: `tls` or anything ending in `tls` (`xtls`) or `reality` → TLS on.
    c.tls = security.ends_with("tls") || security == "reality";
    if !apply_transport(&mut c, uri) {
        return None;
    }
    apply_tls(&mut c, uri, true);
    if uri.q("pbk").is_some() || security == "reality" {
        c.reality_public_key = uri.q("pbk").or_else(|| uri.q("publicKey")).cloned();
        c.reality_short_id = uri.q("sid").or_else(|| uri.q("shortId")).cloned();
        // REALITY is a self-implemented handshake; uTLS is ignored there.
        c.client_fingerprint = None;
    }
    // ant supports `xtls-rprx-vision` only; drop anything else.
    if let Some(flow) = uri.q_lower("flow") {
        if flow.contains("vision") {
            c.flow = Some("xtls-rprx-vision".into());
        }
    }
    Some(with_name(c, uri))
}

fn vmess(uri: &Uri, line: &str) -> Option<ProxyConfig> {
    // Two shapes: `vmess://<base64(json)>` (v2rayN) and the Xray VMessAEAD
    // link `vmess://uuid@host:port?...`.
    if let Some(c) = vmess_aead(uri) {
        return Some(c);
    }
    vmess_json(uri, line)
}

fn vmess_json(uri: &Uri, line: &str) -> Option<ProxyConfig> {
    let body = line.split_once("://").map(|(_, r)| r)?.split('#').next()?;
    let json = decode_b64(body)
        .or_else(|| decode_b64(&uri.host))
        .or_else(|| Some(uri.host.clone()))?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
    let server = get("add")?;
    let port = match v.get("port") {
        Some(serde_json::Value::String(s)) => s.trim().parse::<u16>().ok()?,
        Some(n) => n.as_u64().and_then(|n| u16::try_from(n).ok())?,
        None => return None,
    };
    let mut c = base(uri, "vmess");
    c.server = server;
    c.port = port;
    c.uuid = get("id");
    c.alter_id = Some(
        v.get("aid")
            .or_else(|| v.get("alterId"))
            .and_then(json_u32)
            .unwrap_or(0),
    );
    c.cipher = get("scy")
        .or_else(|| get("security"))
        .or_else(|| get("encryption"))
        .filter(|s| !s.is_empty())
        .map(|s| normalize_vmess_cipher(&s));
    // sub-store: `["tls", true, 1, "1"].includes(i.tls)`.
    c.tls = match v.get("tls") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_u64() == Some(1),
        Some(serde_json::Value::String(s)) => {
            s.trim().eq_ignore_ascii_case("tls") || s.trim() == "1"
        }
        _ => false,
    };
    // The v2rayN JSON carries the transport in `net` (and ws host/path in
    // `host` / `path`) — there is no `?type=` query on this shape.
    match get("net")
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "tcp" | "raw" | "" => c.network = "tcp".into(),
        "ws" => {
            c.network = "ws".into();
            c.ws_path = get("path").filter(|s| !s.is_empty());
            c.ws_host = get("host")
                .or_else(|| get("obfsParam"))
                .filter(|s| !s.is_empty())
                .map(|s| json_host_header(&s));
        }
        "xhttp" => {
            c.network = "xhttp".into();
            c.xhttp_path = get("path").filter(|s| !s.is_empty());
            c.xhttp_host = get("host")
                .filter(|s| !s.is_empty())
                .map(|s| json_host_header(&s));
            c.xhttp_mode = get("mode").filter(|s| !s.is_empty());
        }
        // grpc / httpupgrade / kcp: no implementation in ant.
        other => {
            tracing::debug!(net = other, "unsupported vmess transport skipped");
            return None;
        }
    }
    // sub-store: `sni` → `peer` fallback.
    c.sni = get("sni")
        .filter(|s| !s.is_empty())
        .or_else(|| get("peer").filter(|s| !s.is_empty()));
    c.alpn = v.get("alpn").and_then(json_alpn);
    // v2rayN stores the "insecure" flag as `verify_cert: false` or
    // `allowInsecure: true` / `"TRUE"` / `1`.
    c.skip_cert_verify = v
        .get("verify_cert")
        .map(|x| !json_truthy(x))
        .unwrap_or(false)
        || v.get("allowInsecure")
            .or_else(|| v.get("allowinsecure"))
            .map(json_truthy)
            .unwrap_or(false);
    c.fingerprint = get("pcs").filter(|s| !s.is_empty());
    let fp = get("fp").filter(|s| !s.is_empty());
    c.client_fingerprint = utls_fp(fp.as_ref(), c.tls);
    // sub-store: `#fragment` wins, then ps / remarks / remark.
    c.name = if uri.fragment.trim().is_empty() {
        get("ps")
            .or_else(|| get("remarks"))
            .or_else(|| get("remark"))
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        uri.fragment.trim().to_string()
    };
    Some(c)
}

fn json_u32(v: &serde_json::Value) -> Option<u32> {
    match v {
        serde_json::Value::String(s) => s.trim().parse::<u32>().ok(),
        serde_json::Value::Number(n) => n.as_u64().and_then(|x| u32::try_from(x).ok()),
        _ => None,
    }
}

fn json_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        serde_json::Value::String(s) => matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
        _ => false,
    }
}

fn json_alpn(v: &serde_json::Value) -> Option<Vec<String>> {
    let list: Vec<String> = match v {
        serde_json::Value::String(s) => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str())
            .map(|s| s.to_string())
            .collect(),
        _ => return None,
    };
    (!list.is_empty()).then_some(list)
}

/// v2rayN sometimes stores the WS Host as a JSON string (`{"Host":"cdn"}`).
fn json_host_header(s: &str) -> String {
    let t = s.trim();
    if t.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            if let Some(h) = v
                .get("Host")
                .or_else(|| v.get("host"))
                .and_then(|x| x.as_str())
            {
                return h.to_string();
            }
        }
    }
    t.to_string()
}

fn normalize_vmess_cipher(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    // ant's vmess outbound uses the short name (SS uses the long one).
    match s.as_str() {
        "chacha20-ietf-poly1305" => "chacha20-poly1305".into(),
        _ => s,
    }
}

fn vmess_aead(uri: &Uri) -> Option<ProxyConfig> {
    // Needs `uuid@host:port`; a base64 blob has no `@` before the payload.
    let uuid = uri.user.clone()?;
    let mut c = base(uri, "vmess");
    c.uuid = Some(uuid);
    c.alter_id = Some(0);
    // sub-store's common URI parser maps VMessAEAD `encryption` → `cipher`.
    c.cipher = uri
        .q("encryption")
        .map(|s| normalize_vmess_cipher(s));
    let security = uri.q_lower("security").unwrap_or_default();
    c.tls = security.ends_with("tls") || uri.q_lower("tls").as_deref() == Some("tls");
    if !apply_transport(&mut c, uri) {
        return None;
    }
    apply_tls(&mut c, uri, true);
    Some(with_name(c, uri))
}

fn trojan(uri: &Uri) -> Option<ProxyConfig> {
    let mut c = base(uri, "trojan");
    c.tls = true;
    c.password = uri.user.clone();
    if !apply_transport(&mut c, uri) {
        return None;
    }
    apply_tls(&mut c, uri, true);
    c.password.as_ref()?;
    Some(with_name(c, uri))
}

fn shadowsocks(uri: &Uri) -> Option<ProxyConfig> {
    // Two shapes:
    //   ss://BASE64(method:password)@host:port#name          (SIP002)
    //   ss://BASE64(method:password@host:port)#name          (legacy)
    if uri.q("plugin").is_some() {
        tracing::warn!("ss link with `plugin` skipped (obfs/v2ray-plugin unsupported)");
        return None;
    }
    let (userinfo, host, port) = match &uri.user {
        Some(u) => (u.clone(), uri.host.clone(), uri.port),
        None => {
            let blob = decode_b64(&uri.host)?;
            let blob = blob.split('?').next().unwrap_or(&blob).to_string();
            let (hp, hostport) = blob.rsplit_once('@')?;
            let (h, p, _) = split_host_port(hostport);
            (hp.to_string(), h, p.unwrap_or(uri.port))
        }
    };
    // The userinfo is base64 (SIP002 / legacy) or plain `method:password`
    // (AEAD-2022 links, which sub-store emits percent-encoded rather than
    // base64). Prefer the plain form when the prefix is a cipher ant knows —
    // this matches sub-store's `xie()` and avoids mangling a plaintext blob
    // that happens to be valid base64.
    let looks_plain = userinfo
        .split_once(':')
        .map(|(m, _)| normalize_ss_method(m).is_some())
        .unwrap_or(false);
    let userinfo = if looks_plain {
        userinfo
    } else {
        decode_b64(&userinfo).unwrap_or(userinfo)
    };
    let (method, raw_password) = userinfo.split_once(':')?;
    let method = normalize_ss_method(method)?;
    // AEAD-2022 links may carry several PSKs (`psk1:psk2:…`); ant holds a
    // single PSK, so keep the first one (same as sing-box's client behaviour).
    let password = if method.starts_with("2022-") && raw_password.contains(':') {
        tracing::warn!("ss 2022 link carries multiple PSKs; using the first");
        raw_password.split(':').next().unwrap_or(raw_password).to_string()
    } else {
        raw_password.to_string()
    };
    // ant decodes the PSK with the canonical padded STANDARD alphabet, while
    // links usually carry url-safe / unpadded keys — re-encode to be safe.
    let password = if method.starts_with("2022-") {
        normalize_psk(&password)
    } else {
        password
    };
    let mut c = base(uri, "shadowsocks");
    c.server = host;
    c.port = port;
    c.cipher = Some(method);
    c.password = Some(password.to_string());
    if !apply_transport(&mut c, uri) {
        return None;
    }
    apply_tls(&mut c, uri, false);
    // ant gates SS TLS on an explicit SNI / uTLS fingerprint — a bare SS node
    // is raw TCP. sub-store's URI SS Parser also treats `security != none`
    // as an explicit TLS request.
    c.tls = c.sni.is_some() || c.client_fingerprint.is_some();
    if uri
        .q_lower("security")
        .map(|s| s != "none")
        .unwrap_or(false)
    {
        c.tls = true;
    }
    Some(with_name(c, uri))
}

fn normalize_ss_method(m: &str) -> Option<String> {
    let m = m.trim().to_ascii_lowercase();
    let out = match m.as_str() {
        "aes-128-gcm" | "aes-256-gcm" | "2022-blake3-aes-128-gcm"
        | "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => m.clone(),
        "chacha20-ietf-poly1305" | "chacha20-poly1305" => "chacha20-ietf-poly1305".into(),
        "none" | "plain" => "none".into(),
        // Stream ciphers (aes-128-cfb, rc4-md5, …) are not implemented.
        _ => return None,
    };
    Some(out)
}

/// Re-encode an AEAD-2022 PSK into canonical padded STANDARD base64.
/// Returns the input unchanged when it is not decodable (ant will report it).
fn normalize_psk(s: &str) -> String {
    use base64::Engine;
    let t = s.trim();
    for eng in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ] {
        for cand in [t.to_string(), pad(t)] {
            if let Ok(b) = eng.decode(cand.as_bytes()) {
                return base64::engine::general_purpose::STANDARD.encode(b);
            }
        }
    }
    s.to_string()
}

fn socks(uri: &Uri, ty: &str) -> Option<ProxyConfig> {
    let mut c = base(uri, ty);
    c.tls = false;
    if let Some(u) = &uri.user {
        // sub-store (and Shadowrocket) emit `socks://BASE64(user:pass)@host`;
        // plain `user:pass` links must keep working too. A decoded blob is
        // only accepted when it actually contains a `user:pass` pair.
        let user = match decode_b64(u) {
            Some(d) if d.contains(':') => d,
            _ => u.clone(),
        };
        match user.split_once(':') {
            Some((a, b)) => {
                if !a.is_empty() {
                    c.username = Some(a.to_string());
                }
                // SOCKS4/4a has no password auth — keep only the USERID.
                if ty == "socks5" && !b.is_empty() {
                    c.password = Some(b.to_string());
                }
            }
            None => {
                if !user.is_empty() {
                    c.username = Some(user.clone());
                }
            }
        }
    }
    Some(with_name(c, uri))
}

/// `naive://user:pass@host:port?sni=&insecure=` — ant-native (NaiveProxy is
/// always TLS + HTTP/2 CONNECT with Basic auth).
fn naive(uri: &Uri) -> Option<ProxyConfig> {
    let (user, pass) = uri.user.as_deref()?.split_once(':')?;
    let mut c = base(uri, "naive");
    c.tls = true;
    c.username = Some(user.to_string());
    c.password = Some(pass.to_string());
    // naive is a censorship-evasion transport and ant dials it through uTLS,
    // so default to `chrome` like the other uTLS-capable outbounds.
    apply_tls(&mut c, uri, true);
    Some(with_name(c, uri))
}

/// `shadowquic://user:pass@host:port?sni=<required>&...` — ant-native (JLS).
fn shadowquic(uri: &Uri) -> Option<ProxyConfig> {
    let (user, pass) = uri.user.as_deref()?.split_once(':')?;
    let mut c = base(uri, "shadowquic");
    c.username = Some(user.to_string());
    c.password = Some(pass.to_string());
    c.sni = uri.q("sni").or_else(|| uri.q("peer")).cloned();
    // SNI must match the server's jls-upstream domain; without it the node
    // cannot dial at all.
    c.sni.as_ref()?;
    c.alpn = uri.alpn();
    c.skip_cert_verify = uri.flag(&["insecure", "allowInsecure", "skip-cert-verify"]);
    c.zero_rtt = !uri.flag(&["disable-zero-rtt"]);
    c.over_stream = uri.flag(&["over-stream"]);
    c.initial_mtu = uri.q("initial-mtu").and_then(|v| v.parse().ok());
    c.min_mtu = uri.q("min-mtu").and_then(|v| v.parse().ok());
    Some(with_name(c, uri))
}

/// `spectre://user:pass@host:port?sni=<required>&up=&down=` — ant-native
/// (QUIC + JLS 伪装 + Brutal 拥塞控制，见 `outbound/spectre.rs`)。
fn spectre(uri: &Uri) -> Option<ProxyConfig> {
    let (user, pass) = uri.user.as_deref()?.split_once(':')?;
    let mut c = base(uri, "spectre");
    c.username = Some(user.to_string());
    c.password = Some(pass.to_string());
    c.sni = uri.q("sni").or_else(|| uri.q("peer")).cloned();
    // SNI 必须匹配服务端伪装域名；缺失的节点根本无法拨号。
    c.sni.as_ref()?;
    // 速率：up = 客户端上传（tx_bps），down = 客户端下载（rx_bps）。
    // 语法同 spectre 参考实现 parse_rate：`50mbps` / `12500000`（裸数字为
    // 字节/秒，与 hysteria2 出站按 Mbps 解释不同）。
    c.up = uri.q("up").cloned();
    c.down = uri.q("down").cloned();
    Some(with_name(c, uri))
}

/// `wireguard://<base64(json)>` — ant-native; there is no cross-client WG
/// share-link standard, so the JSON keys mirror the ant YAML field names.
fn wireguard(uri: &Uri) -> Option<ProxyConfig> {
    let json = decode_b64(&uri.user.clone().unwrap_or_default())
        .or_else(|| decode_b64(&uri.host))
        .or_else(|| Some(uri.host.clone()))?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    let get = |ks: &[&str]| -> Option<String> {
        ks.iter()
            .find_map(|k| v.get(*k).and_then(|x| x.as_str()).map(|s| s.to_string()))
    };
    let mut c = base(uri, "wireguard");
    if let Some(s) = get(&["server", "add", "endpoint"]) {
        c.server = s;
    }
    if let Some(p) = v
        .get("port")
        .and_then(|x| x.as_u64())
        .and_then(|n| u16::try_from(n).ok())
    {
        c.port = p;
    }
    c.private_key = get(&["private-key", "privateKey", "private_key"]);
    c.peer_public_key = get(&["peer-public-key", "peerPublicKey", "public-key", "peer_public_key"]);
    c.pre_shared_key = get(&["pre-shared-key", "preSharedKey", "pre_shared_key"]);
    if let Some(addr) = v.get("local-address").or_else(|| v.get("local_address")).or_else(|| v.get("address")) {
        match addr {
            serde_json::Value::Array(a) => {
                c.local_address = a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect();
            }
            serde_json::Value::String(s) => {
                c.local_address = s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            _ => {}
        }
    }
    c.wg_mtu = v.get("mtu").and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok());
    c.persistent_keepalive = v
        .get("persistent-keepalive")
        .or_else(|| v.get("persistent_keepalive"))
        .and_then(|x| x.as_u64())
        .and_then(|n| u16::try_from(n).ok());
    c.name = get(&["name", "ps"]).unwrap_or_default().trim().to_string();
    if c.name.is_empty() {
        c.name = uri.fragment.trim().to_string();
    }
    // private-key + peer-public-key + at least one local address are mandatory.
    c.private_key.as_ref()?;
    c.peer_public_key.as_ref()?;
    if c.local_address.is_empty() {
        return None;
    }
    Some(c)
}

/// `ssh://user[:password]@host:22?host-key=...&private-key=...#name`
///
/// 没有跨客户端标准，字段与 YAML 对齐；密码里含 `:` 时用 `?password=` 覆盖。
fn ssh(uri: &Uri) -> Option<ProxyConfig> {
    let mut c = base(uri, "ssh");
    if let Some(user) = uri.user.clone() {
        if !user.is_empty() {
            match user.split_once(':') {
                Some((u, p)) => {
                    c.username = Some(u.to_string());
                    c.password = Some(p.to_string());
                }
                None => c.username = Some(user),
            }
        }
    }
    if let Some(pw) = uri.q("password") {
        c.password = Some(pw.clone());
    }
    if let Some(k) = uri.q("private-key").or_else(|| uri.q("private_key")) {
        c.private_key = Some(k.clone());
    }
    if let Some(p) = uri
        .q("private-key-passphrase")
        .or_else(|| uri.q("private_key_passphrase"))
    {
        c.ssh_private_key_passphrase = Some(p.clone());
    }
    if let Some(keys) = uri.q("host-key").or_else(|| uri.q("host_key")) {
        let list: Vec<String> = keys
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            c.ssh_host_key = Some(list);
        }
    }
    if let Some(algos) = uri
        .q("host-key-algorithms")
        .or_else(|| uri.q("host_key_algorithms"))
    {
        c.ssh_host_key_algorithms = Some(
            algos
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        );
    }
    if let Some(secret) = uri.q("totp") {
        c.ssh_totp = Some(crate::config::SshTotpConfig {
            ty: None,
            secret: secret.clone(),
            step: 30,
            digits: 6,
            algorithm: "sha1".into(),
        });
    }
    c.username.as_ref()?;
    Some(with_name(c, uri))
}

/// `tailscale://<base64(json)>#name` — ant-native；JSON keys 与 YAML 字段一致。
fn tailscale_link(uri: &Uri) -> Option<ProxyConfig> {
    let json = decode_b64(&uri.user.clone().unwrap_or_default())
        .or_else(|| decode_b64(&uri.host))
        .or_else(|| Some(uri.host.clone()))?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    let get = |ks: &[&str]| -> Option<String> {
        ks.iter()
            .find_map(|k| v.get(*k).and_then(|x| x.as_str()).map(|s| s.to_string()))
    };
    let mut c = base(uri, "tailscale");
    // Tailscale 出站没有固定 server/port。
    c.server = String::new();
    c.port = 0;
    c.ts_auth_key = get(&["auth-key", "auth_key", "authkey"]);
    c.ts_control_url = get(&["control-url", "control_url", "controlUrl"]);
    c.ts_hostname = get(&["hostname"]);
    c.ts_client_name = get(&["client-name", "client_name", "clientName"]);
    c.ts_state_dir = get(&["state-dir", "state_dir", "stateDir"]);
    c.ts_ephemeral = v
        .get("ephemeral")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    c.name = get(&["name", "ps"]).unwrap_or_default().trim().to_string();
    if c.name.is_empty() {
        c.name = uri.fragment.trim().to_string();
    }
    Some(c)
}

/// base64 decode with padding / url-safe / whitespace tolerance.
///
/// Subscription blobs are routinely wrapped at 76 columns (or URL-safe and
/// unpadded, like sub-store's `Base64` helper), so inner whitespace is
/// stripped before decoding. Returns `None` when the input is not decodable
/// base64 or does not decode to valid UTF-8.
pub fn decode_b64(s: &str) -> Option<String> {
    use base64::Engine;
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    for eng in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ] {
        // Engines reject both missing *and* surplus padding, so try the raw
        // string plus a padded copy.
        for cand in [compact.clone(), pad(&compact)] {
            if let Ok(bytes) = eng.decode(cand.as_bytes()) {
                if let Ok(t) = String::from_utf8(bytes) {
                    return Some(t);
                }
            }
        }
    }
    None
}

fn pad(s: &str) -> String {
    let mut out = s.to_string();
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hysteria2() {
        let c = from_link("hysteria2://pass@h2.example.com:8443?sni=real.example.com&obfs=salamander&insecure=1&alpn=h3,h3-29&ports=1000-2000&up=100&down=200&pinSHA256=deadbeef#%E9%A6%99%E6%B8%AF").unwrap();
        assert_eq!(c.ty, "hysteria2");
        assert_eq!(c.server, "h2.example.com");
        assert_eq!(c.port, 8443);
        assert_eq!(c.password.as_deref(), Some("pass"));
        assert_eq!(c.sni.as_deref(), Some("real.example.com"));
        assert_eq!(c.obfs.as_deref(), Some("salamander"));
        assert!(c.skip_cert_verify);
        assert_eq!(c.alpn.as_deref(), Some(&vec!["h3".to_string(), "h3-29".to_string()][..]));
        assert_eq!(c.ports.as_deref(), Some("1000-2000"));
        assert_eq!(c.up.as_deref(), Some("100"));
        assert_eq!(c.down.as_deref(), Some("200"));
        assert_eq!(c.fingerprint.as_deref(), Some("deadbeef"));
        assert_eq!(c.name, "香港");
        assert!(c.tls);
    }

    #[test]
    fn parses_links_with_path_separator_before_query() {
        // v2rayN / sing-box generators emit `host:443/?insecure=1&...`
        for link in [
            "hysteria2://pass@h2.example.com:8443/?insecure=1&sni=real.example.com#HK",
            "hysteria2://pass@h2.example.com:8443/?insecure=1&sni=real.example.com",
        ] {
            let c = from_link(link).unwrap();
            assert_eq!(c.server, "h2.example.com");
            assert_eq!(c.port, 8443);
            assert_eq!(c.password.as_deref(), Some("pass"));
            assert!(c.skip_cert_verify);
        }
        // trailing slash without query
        let c = from_link("hysteria2://pass@h2.example.com:8443/#HK").unwrap();
        assert_eq!(c.server, "h2.example.com");
        assert_eq!(c.port, 8443);
        // vless with trailing slash
        let c = from_link("vless://uuid@v.example.com:443/?security=tls&sni=v.example.com&type=ws&path=/ws#V").unwrap();
        assert_eq!(c.server, "v.example.com");
        assert_eq!(c.port, 443);
        assert!(c.tls);
        assert_eq!(c.ws_path.as_deref(), Some("/ws"));
    }

    #[test]
    fn parses_tuic() {
        let c = from_link("tuic://11111111-2222-3333-4444-555555555555:mypass@tuic.example.com:1234?congestion_control=bbr&alpn=h3&sni=t.example.com&pinSHA256=aa#TUIC-1").unwrap();
        assert_eq!(c.ty, "tuic");
        assert_eq!(c.uuid.as_deref(), Some("11111111-2222-3333-4444-555555555555"));
        assert_eq!(c.password.as_deref(), Some("mypass"));
        assert_eq!(c.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(c.fingerprint.as_deref(), Some("aa"));
        assert_eq!(c.name, "TUIC-1");
        // TUIC v4 `token@` has no outbound in ant.
        assert!(from_link("tuic://onlytoken@tuic.example.com:1234#v4").is_none());
    }

    #[test]
    fn parses_anytls_with_utls_default() {
        let c = from_link("anytls://atpass@at.example.com:443?sni=at.com&alpn=h2,http/1.1#AT").unwrap();
        assert_eq!(c.ty, "anytls");
        assert_eq!(c.password.as_deref(), Some("atpass"));
        assert_eq!(c.sni.as_deref(), Some("at.com"));
        // fp absent → mihomo-style default
        assert_eq!(c.client_fingerprint.as_deref(), Some("chrome"));
        let c = from_link("anytls://atpass@at.example.com:443?sni=at.com&fp=firefox#AT").unwrap();
        assert_eq!(c.client_fingerprint.as_deref(), Some("firefox"));
        let c = from_link("anytls://atpass@at.example.com:443?sni=at.com&fp=none#AT").unwrap();
        assert!(c.client_fingerprint.is_none());
    }

    #[test]
    fn parses_vless_reality() {
        let c = from_link("vless://uuid-xxx@1.2.3.4:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&pbk=pubkey&sid=abcd&sni=www.microsoft.com&fp=chrome#VL").unwrap();
        assert_eq!(c.ty, "vless");
        assert!(c.tls);
        assert_eq!(c.reality_public_key.as_deref(), Some("pubkey"));
        assert_eq!(c.reality_short_id.as_deref(), Some("abcd"));
        assert_eq!(c.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(c.network, "tcp");
        // uTLS is ignored under REALITY (self-implemented handshake).
        assert!(c.client_fingerprint.is_none());
    }

    #[test]
    fn parses_vless_ws_and_xhttp_and_skips_grpc() {
        let c = from_link("vless://uuid@a.com:80?type=ws&path=%2Fws&host=a.com&security=none#W").unwrap();
        assert_eq!(c.ws_path.as_deref(), Some("/ws"));
        assert_eq!(c.ws_host.as_deref(), Some("a.com"));
        assert!(!c.tls);
        let c = from_link("vless://uuid@a.com:443?type=xhttp&path=%2Fx&host=a.com&mode=stream-one&security=tls&fp=safari#X").unwrap();
        assert_eq!(c.network, "xhttp");
        assert_eq!(c.xhttp_path.as_deref(), Some("/x"));
        assert_eq!(c.xhttp_mode.as_deref(), Some("stream-one"));
        assert!(c.tls);
        assert_eq!(c.client_fingerprint.as_deref(), Some("safari"));
        // xtls also turns TLS on (mihomo: HasSuffix(security,"tls")).
        assert!(from_link("vless://uuid@a.com:443?security=xtls&type=tcp#T").unwrap().tls);
        assert!(from_link("vless://uuid@a.com:443?type=grpc&serviceName=g#G").is_none());
    }

    #[test]
    fn parses_vmess_base64_json() {
        let json = r#"{"v":"2","ps":"节点","add":"v.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","type":"none","host":"v.example.com","path":"/path","tls":"tls","sni":"v.example.com","scy":"auto"}"#;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let c = from_link(&format!("vmess://{b64}")).unwrap();
        assert_eq!(c.ty, "vmess");
        assert_eq!(c.server, "v.example.com");
        assert_eq!(c.port, 443);
        assert_eq!(c.network, "ws");
        assert_eq!(c.ws_path.as_deref(), Some("/path"));
        assert!(c.tls);
        assert_eq!(c.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(c.name, "节点");
    }

    #[test]
    fn parses_vmess_aead_link() {
        let c = from_link("vmess://11111111-2222-3333-4444-555555555555@v.example.com:443?encryption=auto&security=tls&type=xhttp&path=/x&host=v.example.com&mode=packet-up&sni=v.example.com&fp=ios#AEAD").unwrap();
        assert_eq!(c.ty, "vmess");
        assert_eq!(c.uuid.as_deref(), Some("11111111-2222-3333-4444-555555555555"));
        assert_eq!(c.network, "xhttp");
        assert_eq!(c.xhttp_mode.as_deref(), Some("packet-up"));
        assert_eq!(c.client_fingerprint.as_deref(), Some("ios"));
        assert_eq!(c.name, "AEAD");
    }

    #[test]
    fn parses_trojan_tcp_ws_xhttp() {
        let c = from_link("trojan://pw@t.example.com:443?sni=real.com&allowInsecure=1&pcs=pin&T").unwrap();
        assert_eq!(c.ty, "trojan");
        assert_eq!(c.password.as_deref(), Some("pw"));
        assert_eq!(c.network, "tcp");
        assert_eq!(c.fingerprint.as_deref(), Some("pin"));
        assert_eq!(c.client_fingerprint.as_deref(), Some("chrome"));
        assert!(c.skip_cert_verify);
        assert!(c.tls);
        let c = from_link("trojan://pw@t.example.com:443?type=ws&path=%2Fws&host=h.com&sni=s.com#W").unwrap();
        assert_eq!(c.network, "ws");
        assert_eq!(c.ws_path.as_deref(), Some("/ws"));
        let c = from_link("trojan://pw@t.example.com:443?type=xhttp&path=%2Fx&mode=stream-up&sni=s.com#X").unwrap();
        assert_eq!(c.network, "xhttp");
        assert_eq!(c.xhttp_mode.as_deref(), Some("stream-up"));
        assert!(from_link("trojan://pw@t.example.com:443?type=grpc&serviceName=g#G").is_none());
    }

    #[test]
    fn parses_ss_sip002() {
        use base64::Engine;
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pass");
        let c = from_link(&format!("ss://{ui}@ss.example.com:8388#SS")).unwrap();
        assert_eq!(c.ty, "shadowsocks");
        assert_eq!(c.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(c.password.as_deref(), Some("pass"));
        assert_eq!(c.server, "ss.example.com");
        assert_eq!(c.port, 8388);
        assert_eq!(c.name, "SS");
        // bare SS is raw TCP — no SNI, no uTLS
        assert!(!c.tls);
    }

    #[test]
    fn parses_ss_legacy_and_2022() {
        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD.encode("chacha20-ietf-poly1305:pass@ss.example.com:8388");
        let c = from_link(&format!("ss://{blob}#Legacy")).unwrap();
        assert_eq!(c.cipher.as_deref(), Some("chacha20-ietf-poly1305"));
        assert_eq!(c.server, "ss.example.com");
        assert_eq!(c.port, 8388);
        // 2022 links may list several PSKs (`psk1:psk2`); ant holds a single
        // one, so the first is kept.
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("2022-blake3-aes-128-gcm:pskA:pskB");
        let c = from_link(&format!("ss://{ui}@ss.example.com:8388#S22")).unwrap();
        assert_eq!(c.cipher.as_deref(), Some("2022-blake3-aes-128-gcm"));
        assert_eq!(c.password.as_deref(), Some("pskA"));

        // A url-safe / unpadded PSK is re-encoded to canonical padded STANDARD
        // (ant's 2022 PSK decoder requires canonical padding).
        let raw = (0u8..16).collect::<Vec<u8>>();
        let psk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
        let want = base64::engine::general_purpose::STANDARD.encode(&raw);
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("2022-blake3-aes-128-gcm:{psk}"));
        let c = from_link(&format!("ss://{ui}@ss.example.com:8388#S22")).unwrap();
        assert_eq!(c.password.as_deref(), Some(want.as_str()));
        assert!(want.ends_with("=="), "{want}");
    }

    #[test]
    fn ss_tls_only_with_sni_or_fp() {
        use base64::Engine;
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-128-gcm:pass");
        let c = from_link(&format!("ss://{ui}@ss.example.com:443?type=ws&path=/w&sni=cdn.com&fp=chrome#T")).unwrap();
        assert!(c.tls);
        assert_eq!(c.network, "ws");
        assert_eq!(c.client_fingerprint.as_deref(), Some("chrome"));
        // plugin-based obfs has no implementation
        assert!(from_link(&format!("ss://{ui}@ss.example.com:443?plugin=obfs-local#P")).is_none());
    }

    #[test]
    fn parses_socks_variants() {
        let c = from_link("socks5://u:p@s.example.com:1080#S5").unwrap();
        assert_eq!(c.ty, "socks5");
        assert_eq!(c.username.as_deref(), Some("u"));
        assert_eq!(c.password.as_deref(), Some("p"));
        let c = from_link("socks4a://userid@s.example.com:1080#S4").unwrap();
        assert_eq!(c.ty, "socks4a");
        assert_eq!(c.username.as_deref(), Some("userid"));
        assert!(c.password.is_none());
    }

    #[test]
    fn parses_native_naive_shadowquic_wireguard() {
        let c = from_link("naive://u:p@n.example.com:443?sni=real.com&insecure=1#N").unwrap();
        assert_eq!(c.ty, "naive");
        assert!(c.tls);
        assert_eq!(c.username.as_deref(), Some("u"));
        assert!(c.skip_cert_verify);

        let c = from_link("shadowquic://u:p@q.example.com:443?sni=jls.example.com&alpn=h3&over-stream=1&min-mtu=1200#SQ").unwrap();
        assert_eq!(c.ty, "shadowquic");
        assert_eq!(c.sni.as_deref(), Some("jls.example.com"));
        assert!(c.over_stream);
        assert_eq!(c.min_mtu, Some(1200));
        // shadowquic requires an SNI
        assert!(from_link("shadowquic://u:p@q.example.com:443#SQ").is_none());

        let json = r#"{"server":"wg.example.com","port":51820,"private-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","peer-public-key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","local-address":["10.7.0.2/32"],"mtu":1420,"persistent-keepalive":25,"name":"WG"}"#;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let c = from_link(&format!("wireguard://{b64}")).unwrap();
        assert_eq!(c.ty, "wireguard");
        assert_eq!(c.server, "wg.example.com");
        assert_eq!(c.port, 51820);
        assert_eq!(c.local_address, vec!["10.7.0.2/32".to_string()]);
        assert_eq!(c.wg_mtu, Some(1420));
        assert_eq!(c.persistent_keepalive, Some(25));
        assert_eq!(c.name, "WG");
    }

    #[test]
    fn parses_native_ssh_tailscale() {
        let c = from_link(
            "ssh://alice:secret@ssh.example.com:2222?private-key=%2Fhome%2Falice%2F.ssh%2Fid_ed25519&host-key=ssh-ed25519%20AAAA#SSH",
        )
        .unwrap();
        assert_eq!(c.ty, "ssh");
        assert_eq!(c.server, "ssh.example.com");
        assert_eq!(c.port, 2222);
        assert_eq!(c.username.as_deref(), Some("alice"));
        assert_eq!(c.password.as_deref(), Some("secret"));
        assert_eq!(
            c.private_key.as_deref(),
            Some("/home/alice/.ssh/id_ed25519")
        );
        assert_eq!(
            c.ssh_host_key.as_ref().and_then(|v| v.first()).map(String::as_str),
            Some("ssh-ed25519 AAAA")
        );
        assert_eq!(c.name, "SSH");
        // 没有用户名就构不成可认证的 SSH 节点。
        assert!(from_link("ssh://ssh.example.com:22#S").is_none());

        let json = r#"{"auth-key":"tskey-auth-xxx","control-url":"https://headscale.example.com","hostname":"ant-node","state-dir":"/var/lib/ant/ts","ephemeral":true,"name":"TS"}"#;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let c = from_link(&format!("tailscale://{b64}")).unwrap();
        assert_eq!(c.ty, "tailscale");
        assert!(c.server.is_empty());
        assert_eq!(c.port, 0);
        assert_eq!(c.ts_auth_key.as_deref(), Some("tskey-auth-xxx"));
        assert_eq!(
            c.ts_control_url.as_deref(),
            Some("https://headscale.example.com")
        );
        assert_eq!(c.ts_hostname.as_deref(), Some("ant-node"));
        assert_eq!(c.ts_state_dir.as_deref(), Some("/var/lib/ant/ts"));
        assert!(c.ts_ephemeral);
        assert_eq!(c.name, "TS");
    }

    #[test]
    fn parses_native_spectre() {
        let c = from_link("spectre://u:p@sp.example.com:4433?sni=echo.example.com&up=50mbps&down=200mbps#SP")
            .unwrap();
        assert_eq!(c.ty, "spectre");
        assert_eq!(c.server, "sp.example.com");
        assert_eq!(c.port, 4433);
        assert_eq!(c.username.as_deref(), Some("u"));
        assert_eq!(c.password.as_deref(), Some("p"));
        assert_eq!(c.sni.as_deref(), Some("echo.example.com"));
        assert_eq!(c.up.as_deref(), Some("50mbps"));
        assert_eq!(c.down.as_deref(), Some("200mbps"));
        assert_eq!(c.name, "SP");
        // sni is required (JLS camouflage domain)
        assert!(from_link("spectre://u:p@sp.example.com:4433#SP").is_none());
        // missing user:pass
        assert!(from_link("spectre://sp.example.com:4433?sni=a.com#SP").is_none());
    }

    #[test]
    fn unsupported_schemes_return_none() {
        // No ant outbound exists for these.
        assert!(from_link("ssr://abc").is_none());
        assert!(from_link("hysteria://up=1,down=2@h.com:443#hy1").is_none());
        assert!(from_link("http://a.com:80#H").is_none());
        assert!(from_link("vmess://not-base64-json").is_none());
    }

    #[test]
    fn parses_sub_store_socks_link() {
        // sub-store emits `socks://BASE64(user:pass)@host:port#name`.
        use base64::Engine;
        let ui = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let c = from_link(&format!("socks://{ui}@s.example.com:1080#S5")).unwrap();
        assert_eq!(c.ty, "socks5");
        assert_eq!(c.username.as_deref(), Some("alice"));
        assert_eq!(c.password.as_deref(), Some("secret"));
        // Plain `user:pass` must keep working.
        let c = from_link("socks5://u:p@s.example.com:1080#P").unwrap();
        assert_eq!(c.username.as_deref(), Some("u"));
        assert_eq!(c.password.as_deref(), Some("p"));
    }

    #[test]
    fn decodes_wrapped_and_url_safe_base64() {
        use base64::Engine;
        let raw = "trojan://pw@t.example.com:443#T\n";
        let b = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(
            decode_b64(&format!("{}\n{}", &b[..16], &b[16..])).as_deref(),
            Some(raw)
        );
        let nopad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(decode_b64(&nopad).as_deref(), Some(raw));
    }

    // ── 各协议字段映射回归（对齐 sub-store 的 URI 解析器输出） ──────────

    #[test]
    fn vmess_json_accepts_boolean_tls_and_reads_all_tls_fields() {
        use base64::Engine;
        // sub-store 的 VMess Parser：`["tls",true,1,"1"].includes(i.tls)`，
        // 且把 peer/alpn/allowInsecure/fp 都映射到 TLS 字段。
        let json = r#"{"ps":"V","add":"v.example.com","port":"443","id":"U","aid":"0","net":"ws","host":"{\"Host\":\"cdn.com\"}","path":"/ws","tls":true,"peer":"sni.example.com","alpn":"h2,http/1.1","allowInsecure":true,"fp":"firefox"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let c = from_link(&format!("vmess://{b64}")).unwrap();
        assert!(c.tls, "tls: true must enable TLS");
        assert_eq!(c.sni.as_deref(), Some("sni.example.com"), "peer fallback");
        assert_eq!(c.ws_host.as_deref(), Some("cdn.com"), "JSON host header");
        assert_eq!(
            c.alpn.as_deref(),
            Some(&vec!["h2".to_string(), "http/1.1".to_string()][..])
        );
        assert!(c.skip_cert_verify, "allowInsecure");
        assert_eq!(c.client_fingerprint.as_deref(), Some("firefox"));
    }

    #[test]
    fn vmess_json_name_falls_back_to_remarks() {
        use base64::Engine;
        let json = r#"{"remarks":"RM","add":"v.com","port":443,"id":"U","net":"tcp"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        assert_eq!(from_link(&format!("vmess://{b64}")).unwrap().name, "RM");
    }

    #[test]
    fn vmess_aead_reads_encryption() {
        // sub-store 通用解析器：vmess 的 `encryption` → `cipher`。
        let c = from_link(
            "vmess://U@v.com:443?encryption=chacha20-ietf-poly1305&security=tls&type=tcp#AE",
        )
        .unwrap();
        assert_eq!(c.cipher.as_deref(), Some("chacha20-poly1305"));
        assert!(c.tls);
        let c =
            from_link("vmess://U@v.com:443?encryption=auto&security=none&type=tcp#AE2").unwrap();
        assert_eq!(c.cipher.as_deref(), Some("auto"));
        assert!(!c.tls);
    }

    #[test]
    fn ss_link_security_tls_and_wspath() {
        use base64::Engine;
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        // sub-store URI SS Parser：`security != none` → tls。
        let c = from_link(&format!("ss://{ui}@s.com:443?security=tls#T")).unwrap();
        assert!(c.tls, "security=tls must enable SS TLS");
        // sub-store 同时接受 `wspath`（ws 路径）与 `path`。
        let c = from_link(&format!(
            "ss://{ui}@s.com:443?type=ws&wspath=%2Fws&host=cdn.com#W"
        ))
        .unwrap();
        assert_eq!(c.ws_path.as_deref(), Some("/ws"));
        assert_eq!(c.ws_host.as_deref(), Some("cdn.com"));
    }

    #[test]
    fn tuic_disable_sni_does_not_disable_cert_verify() {
        // `disable_sni` 是关闭 SNI，不是关闭证书校验。
        let c = from_link("tuic://U:P@t.com:443?disable_sni=1&insecure=0#T").unwrap();
        assert!(!c.skip_cert_verify);
        let c = from_link("tuic://U:P@t.com:443?insecure=1#T2").unwrap();
        assert!(c.skip_cert_verify);
    }

    #[test]
    fn hysteria2_port_range_is_not_part_of_host() {
        // sub-store 允许 `host:1000-2000,3000` 端口跳跃范围。
        let c = from_link("hysteria2://pw@h.com:1000-2000?sni=r.com#H").unwrap();
        assert_eq!(c.server, "h.com");
        assert_eq!(c.ports.as_deref(), Some("1000-2000"));
        assert_eq!(c.port, 1000);
    }

    #[test]
    fn link_name_falls_back_to_remarks() {
        let c = from_link("vless://U@v.com:443?remarks=%E8%8A%82%E7%82%B9&security=tls#").unwrap();
        assert_eq!(c.name, "节点");
        let c = from_link("trojan://pw@t.com:443?remark=RM#FRAG").unwrap();
        assert_eq!(c.name, "FRAG");
    }
}
