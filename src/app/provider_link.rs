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
//! | `naive` `shadowquic` `wireguard` | ant-native formats (no cross-client standard exists) |
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
        "wireguard" | "wg" => wireguard(&uri),
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
    let (host, port) = split_host_port(hostport);
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
        query: map,
        fragment: percent_decode(frag),
    })
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "socks" | "socks5" | "socks5h" | "socks4" | "socks4a" => 1080,
        "naive" => 443,
        "shadowquic" | "sq" => 443,
        "wireguard" | "wg" => 51820,
        _ => 443,
    }
}

fn split_host_port(s: &str) -> (String, Option<u16>) {
    if let Some(rest) = s.strip_prefix('[') {
        // [::1]:443
        let (host, tail) = match rest.split_once(']') {
            Some((h, t)) => (h, t),
            None => (rest, ""),
        };
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        return (host.to_string(), port);
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().ok())
        }
        _ => (s.to_string(), None),
    }
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
            c.ws_path = uri.q("path").cloned();
            c.ws_host = uri.q("host").cloned();
            true
        }
        "xhttp" => {
            c.network = "xhttp".into();
            c.xhttp_path = uri.q("path").cloned();
            c.xhttp_host = uri.q("host").cloned();
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
    c.ports = uri.q("ports").or_else(|| uri.q("mport")).cloned();
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
    c.skip_cert_verify = uri.flag(&["insecure", "allowInsecure", "disable_sni"]);
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
        Some(serde_json::Value::String(s)) => s.parse::<u16>().ok()?,
        Some(n) => n.as_u64().and_then(|n| u16::try_from(n).ok())?,
        None => return None,
    };
    let mut c = base(uri, "vmess");
    c.server = server;
    c.port = port;
    c.uuid = get("id");
    c.alter_id = Some(0);
    c.cipher = get("scy")
        .or_else(|| get("security"))
        .filter(|s| !s.is_empty());
    c.tls = get("tls").as_deref() == Some("tls");
    // The v2rayN JSON carries the transport in `net` (and ws host/path in
    // `host` / `path`) — there is no `?type=` query on this shape.
    match get("net").unwrap_or_else(|| "tcp".into()).to_ascii_lowercase().as_str() {
        "tcp" | "raw" | "" => c.network = "tcp".into(),
        "ws" => {
            c.network = "ws".into();
            c.ws_path = get("path").filter(|s| !s.is_empty());
            c.ws_host = get("host").filter(|s| !s.is_empty());
        }
        "xhttp" => {
            c.network = "xhttp".into();
            c.xhttp_path = get("path").filter(|s| !s.is_empty());
            c.xhttp_host = get("host").filter(|s| !s.is_empty());
            c.xhttp_mode = get("mode").filter(|s| !s.is_empty());
        }
        // grpc / httpupgrade / kcp: no implementation in ant.
        other => {
            tracing::debug!(net = other, "unsupported vmess transport skipped");
            return None;
        }
    }
    c.sni = get("sni").filter(|s| !s.is_empty());
    c.fingerprint = get("pcs").filter(|s| !s.is_empty());
    if c.tls {
        c.client_fingerprint = utls_fp(get("fp").as_ref(), true);
    }
    c.name = get("ps").unwrap_or_default().trim().to_string();
    if c.name.is_empty() {
        c.name = uri.fragment.trim().to_string();
    }
    Some(c)
}

fn vmess_aead(uri: &Uri) -> Option<ProxyConfig> {
    // Needs `uuid@host:port`; a base64 blob has no `@` before the payload.
    let uuid = uri.user.clone()?;
    let mut c = base(uri, "vmess");
    c.uuid = Some(uuid);
    c.alter_id = Some(0);
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
            let (h, p) = split_host_port(hostport);
            (hp.to_string(), h, p.unwrap_or(uri.port))
        }
    };
    // The userinfo may itself be base64 (SIP002) or plain `method:password`.
    let userinfo = decode_b64(&userinfo).unwrap_or(userinfo);
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
    // is raw TCP.
    c.tls = c.sni.is_some() || c.client_fingerprint.is_some();
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
        match u.split_once(':') {
            Some((a, b)) => {
                c.username = Some(a.to_string());
                // SOCKS4/4a has no password auth — keep only the USERID.
                if ty == "socks5" {
                    c.password = Some(b.to_string());
                }
            }
            None => c.username = Some(u.clone()),
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

/// base64 decode with padding / url-safe tolerance. Returns `None` when the
/// input is not decodable base64 or does not decode to valid UTF-8.
pub fn decode_b64(s: &str) -> Option<String> {
    use base64::Engine;
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    for eng in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ] {
        // Engines reject both missing *and* surplus padding, so try the raw
        // string plus a padded copy.
        for cand in [s.to_string(), pad(s)] {
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
    fn unsupported_schemes_return_none() {
        // No ant outbound exists for these.
        assert!(from_link("ssr://abc").is_none());
        assert!(from_link("hysteria://up=1,down=2@h.com:443#hy1").is_none());
        assert!(from_link("http://a.com:80#H").is_none());
        assert!(from_link("vmess://not-base64-json").is_none());
    }
}
