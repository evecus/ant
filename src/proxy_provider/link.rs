//! Share-link → [`ProxyConfig`] conversion (mihomo `common/convert` equivalent).
//!
//! Supported schemes (the ones ant can actually dial):
//! `hysteria2` / `hy2`, `tuic`, `anytls`, `vless`, `vmess`, `trojan`,
//! `ss` (SIP002 + legacy), `socks` / `socks5`.
//!
//! Anything else (`ssr`, `hysteria` v1, `http`, `wireguard`, `mieru`, `grpc`
//! transports …) returns `None` and the caller skips the line with a warning —
//! a single unknown link must never abort a whole subscription.

use crate::config::ProxyConfig;
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
    fn flag(&self, keys: &[&str]) -> bool {
        keys.iter().any(|k| match self.query.get(*k) {
            Some(v) => matches!(v.as_str(), "1" | "true" | "True" | "TRUE" | "yes"),
            None => false,
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
        "vmess" => vmess(&uri),
        "trojan" => trojan(&uri),
        "ss" | "shadowsocks" => shadowsocks(&uri),
        "socks" | "socks5" | "socks5h" => socks(&uri),
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
        "socks" | "socks5" | "socks5h" => 1080,
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

// ── per-protocol builders ─────────────────────────────────────────

fn base(uri: &Uri, ty: &str) -> ProxyConfig {
    ProxyConfig {
        ty: ty.into(),
        server: uri.host.clone(),
        port: uri.port,
        ..blank()
    }
}

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

fn with_name(mut c: ProxyConfig, uri: &Uri) -> ProxyConfig {
    c.name = uri.fragment.trim().to_string();
    c
}

fn hysteria2(uri: &Uri) -> Option<ProxyConfig> {
    let mut c = base(uri, "hysteria2");
    c.tls = true;
    c.password = uri
        .user
        .clone()
        .or_else(|| uri.q("auth").cloned())
        .or_else(|| uri.q("password").cloned());
    c.sni = uri.q("sni").cloned();
    c.obfs = uri.q("obfs").cloned();
    c.obfs_password = uri.q("obfs-password").cloned();
    c.up = uri.q("up").cloned().or_else(|| uri.q("upmbps").cloned());
    c.down = uri.q("down").cloned().or_else(|| uri.q("downmbps").cloned());
    c.ports = uri.q("ports").cloned().or_else(|| uri.q("mport").cloned());
    c.alpn = uri.alpn();
    c.fingerprint = uri.q("pinSHA256").cloned();
    c.skip_cert_verify = uri.flag(&["insecure", "allowInsecure", "skip-cert-verify"]);
    c.password.as_ref()?;
    Some(with_name(c, uri))
}

fn tuic(uri: &Uri) -> Option<ProxyConfig> {
    // TUIC v5: `uuid:password@host:port`. A bare `token@` (v4) is not
    // supported by ant's TUIC outbound.
    let (uuid, password) = {
        let u = uri.user.as_deref()?;
        let (a, b) = u.split_once(':')?;
        (a.to_string(), b.to_string())
    };
    let mut c = base(uri, "tuic");
    c.tls = true;
    c.uuid = Some(uuid);
    c.password = Some(password);
    c.sni = uri.q("sni").cloned();
    c.alpn = uri.alpn();
    c.congestion_control = uri
        .q("congestion_control")
        .or_else(|| uri.q("congestion-controller"))
        .cloned();
    c.skip_cert_verify = uri.flag(&["insecure", "allowInsecure", "disable_sni"]);
    Some(with_name(c, uri))
}

fn anytls(uri: &Uri) -> Option<ProxyConfig> {
    let mut c = base(uri, "anytls");
    c.tls = true;
    c.password = uri.user.clone().or_else(|| uri.q("password").cloned());
    c.sni = uri.q("sni").cloned();
    c.alpn = uri.alpn();
    c.skip_cert_verify = uri.flag(&["insecure", "allowInsecure", "skip-cert-verify"]);
    c.client_fingerprint = uri.q("fp").cloned();
    c.password.as_ref()?;
    Some(with_name(c, uri))
}

fn vless(uri: &Uri) -> Option<ProxyConfig> {
    let uuid = uri.user.clone()?;
    let security = uri
        .q("security")
        .cloned()
        .unwrap_or_else(|| "none".to_string())
        .to_ascii_lowercase();
    let transport = uri
        .q("type")
        .cloned()
        .unwrap_or_else(|| "tcp".to_string())
        .to_ascii_lowercase();
    if !matches!(transport.as_str(), "tcp" | "ws" | "xhttp") {
        // grpc / httpupgrade / quic transports are not implemented in ant.
        return None;
    }
    let mut c = base(uri, "vless");
    c.uuid = Some(uuid);
    c.network = transport.clone();
    c.tls = matches!(security.as_str(), "tls" | "reality");
    c.sni = uri.q("sni").cloned();
    c.alpn = uri.alpn();
    c.skip_cert_verify = uri.flag(&["allowInsecure", "insecure", "skip-cert-verify"]);
    if security == "reality" {
        c.reality_public_key = uri.q("pbk").cloned().or_else(|| uri.q("publicKey").cloned());
        c.reality_short_id = uri.q("sid").cloned().or_else(|| uri.q("shortId").cloned());
    } else if security == "tls" {
        // uTLS fingerprint only makes sense on the plain-rustls TLS path;
        // REALITY has its own handshake.
        c.client_fingerprint = uri.q("fp").cloned();
    }
    // ant supports `xtls-rprx-vision` only; drop anything else.
    if let Some(flow) = uri.q("flow") {
        let f = flow.to_ascii_lowercase();
        if f.contains("vision") {
            c.flow = Some("xtls-rprx-vision".into());
        }
    }
    match transport.as_str() {
        "ws" => {
            c.ws_path = uri.q("path").cloned();
            c.ws_host = uri.q("host").cloned();
        }
        "xhttp" => {
            c.xhttp_path = uri.q("path").cloned();
            c.xhttp_host = uri.q("host").cloned();
            c.xhttp_mode = uri.q("mode").cloned();
        }
        _ => {}
    }
    Some(with_name(c, uri))
}

fn vmess(uri: &Uri) -> Option<ProxyConfig> {
    // `vmess://<base64(json)>` (v2rayN) — body already extracted by caller.
    let json = decode_b64(uri.user.as_deref().unwrap_or(""))
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
    let transport = get("net").unwrap_or_else(|| "tcp".into()).to_ascii_lowercase();
    if !matches!(transport.as_str(), "tcp" | "ws" | "xhttp") {
        return None;
    }
    let mut c = ProxyConfig {
        name: String::new(),
        ty: "vmess".into(),
        server,
        port,
        ..base(uri, "vmess")
    };
    c.uuid = get("id");
    c.alter_id = Some(0);
    c.network = transport.clone();
    c.cipher = get("scy")
        .or_else(|| get("security"))
        .filter(|s| !s.is_empty());
    c.tls = get("tls").as_deref() == Some("tls");
    c.sni = get("sni").filter(|s| !s.is_empty());
    c.skip_cert_verify = uri.flag(&["allowInsecure", "insecure"]);
    match transport.as_str() {
        "ws" => {
            c.ws_path = get("path").filter(|s| !s.is_empty());
            c.ws_host = get("host").filter(|s| !s.is_empty());
        }
        "xhttp" => {
            c.xhttp_path = get("path").filter(|s| !s.is_empty());
            c.xhttp_host = get("host").filter(|s| !s.is_empty());
            c.xhttp_mode = get("mode").filter(|s| !s.is_empty());
        }
        _ => {}
    }
    c.name = get("ps").unwrap_or_default().trim().to_string();
    if c.name.is_empty() {
        c.name = uri.fragment.trim().to_string();
    }
    Some(c)
}

fn trojan(uri: &Uri) -> Option<ProxyConfig> {
    let mut c = base(uri, "trojan");
    c.tls = true;
    c.password = uri.user.clone();
    c.sni = uri.q("sni").cloned();
    c.alpn = uri.alpn();
    c.skip_cert_verify = uri.flag(&["allowInsecure", "insecure", "skip-cert-verify"]);
    c.fingerprint = uri.q("pcs").cloned();
    let transport = uri
        .q("type")
        .cloned()
        .unwrap_or_else(|| "tcp".to_string())
        .to_ascii_lowercase();
    match transport.as_str() {
        "ws" => {
            c.network = "ws".into();
            c.ws_path = uri.q("path").cloned();
            c.ws_host = uri.q("host").cloned();
        }
        "tcp" | "" => {}
        _ => return None,
    }
    c.password.as_ref()?;
    Some(with_name(c, uri))
}

fn shadowsocks(uri: &Uri) -> Option<ProxyConfig> {
    // Two shapes:
    //   ss://BASE64(method:password)@host:port#name          (SIP002)
    //   ss://BASE64(method:password@host:port)#name          (legacy)
    // `uri.user` is set for SIP002, unset for the legacy all-in-one blob.
    let (userinfo, host, port) = match &uri.user {
        Some(u) => (u.clone(), uri.host.clone(), uri.port),
        None => {
            let blob = decode_b64(&uri.host)?;
            // strip plugin suffix: method:password@host:port?plugin=...
            let blob = blob.split('?').next().unwrap_or(&blob);
            let (hp, hostport) = blob.rsplit_once('@')?;
            let (h, p) = split_host_port(hostport);
            let port = p.or(Some(uri.port)).unwrap_or(443);
            (hp.to_string(), h, port)
        }
    };
    // The userinfo may itself be base64 (SIP002) or plain `method:password`.
    let userinfo = decode_b64(&userinfo).unwrap_or(userinfo);
    let (method, password) = userinfo.split_once(':')?;
    let method = normalize_ss_method(method)?;
    let mut c = ProxyConfig {
        server: host,
        port,
        ..base(uri, "shadowsocks")
    };
    c.ty = "shadowsocks".into();
    c.cipher = Some(method);
    c.password = Some(password.to_string());
    c.tls = false;
    c.network = "tcp".into();
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

fn socks(uri: &Uri) -> Option<ProxyConfig> {
    let mut c = base(uri, "socks5");
    c.tls = false;
    if let Some(u) = &uri.user {
        match u.split_once(':') {
            Some((a, b)) => {
                c.username = Some(a.to_string());
                c.password = Some(b.to_string());
            }
            None => c.username = Some(u.clone()),
        }
    }
    Some(with_name(c, uri))
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
        let c = from_link("hysteria2://pass@h2.example.com:8443?sni=real.example.com&obfs=salamander&insecure=1&alpn=h3,h3-29#%E9%A6%99%E6%B8%AF").unwrap();
        assert_eq!(c.ty, "hysteria2");
        assert_eq!(c.server, "h2.example.com");
        assert_eq!(c.port, 8443);
        assert_eq!(c.password.as_deref(), Some("pass"));
        assert_eq!(c.sni.as_deref(), Some("real.example.com"));
        assert_eq!(c.obfs.as_deref(), Some("salamander"));
        assert!(c.skip_cert_verify);
        assert_eq!(c.alpn.as_deref(), Some(&vec!["h3".to_string(), "h3-29".to_string()][..]));
        assert_eq!(c.name, "香港");
        assert!(c.tls);
    }

    #[test]
    fn parses_tuic() {
        let c = from_link("tuic://11111111-2222-3333-4444-555555555555:mypass@tuic.example.com:1234?congestion_control=bbr&alpn=h3&sni=t.example.com#TUIC-1").unwrap();
        assert_eq!(c.ty, "tuic");
        assert_eq!(c.uuid.as_deref(), Some("11111111-2222-3333-4444-555555555555"));
        assert_eq!(c.password.as_deref(), Some("mypass"));
        assert_eq!(c.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(c.name, "TUIC-1");
    }

    #[test]
    fn parses_vless_reality() {
        let c = from_link("vless://uuid-xxx@1.2.3.4:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&pbk=pubkey&sid=abcd&sni=www.microsoft.com#VL").unwrap();
        assert_eq!(c.ty, "vless");
        assert!(c.tls);
        assert_eq!(c.reality_public_key.as_deref(), Some("pubkey"));
        assert_eq!(c.reality_short_id.as_deref(), Some("abcd"));
        assert_eq!(c.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(c.network, "tcp");
        assert!(c.client_fingerprint.is_none());
    }

    #[test]
    fn parses_vless_ws_and_skips_grpc() {
        let c = from_link("vless://uuid@a.com:80?type=ws&path=%2Fws&host=a.com&security=none#W").unwrap();
        assert_eq!(c.ws_path.as_deref(), Some("/ws"));
        assert_eq!(c.ws_host.as_deref(), Some("a.com"));
        assert!(!c.tls);
        assert!(from_link("vless://uuid@a.com:443?type=grpc&serviceName=g#G").is_none());
    }

    #[test]
    fn parses_vmess_base64() {
        let json = r#"{"v":"2","ps":"节点","add":"v.example.com","port":"443","id":"uuid-1","aid":"0","net":"ws","type":"none","host":"v.example.com","path":"/path","tls":"tls","sni":"v.example.com","scy":"auto"}"#;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let c = from_link(&format!("vmess://{b64}")).unwrap();
        assert_eq!(c.ty, "vmess");
        assert_eq!(c.server, "v.example.com");
        assert_eq!(c.port, 443);
        assert_eq!(c.uuid.as_deref(), Some("uuid-1"));
        assert_eq!(c.network, "ws");
        assert_eq!(c.ws_path.as_deref(), Some("/path"));
        assert!(c.tls);
        assert_eq!(c.name, "节点");
    }

    #[test]
    fn parses_trojan() {
        let c = from_link("trojan://pw@t.example.com:443?sni=real.com&allowInsecure=1#T").unwrap();
        assert_eq!(c.ty, "trojan");
        assert_eq!(c.password.as_deref(), Some("pw"));
        assert_eq!(c.sni.as_deref(), Some("real.com"));
        assert!(c.skip_cert_verify);
        assert!(c.tls);
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
    }

    #[test]
    fn parses_ss_legacy() {
        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD.encode("chacha20-ietf-poly1305:pass@ss.example.com:8388");
        let c = from_link(&format!("ss://{blob}#Legacy")).unwrap();
        assert_eq!(c.cipher.as_deref(), Some("chacha20-ietf-poly1305"));
        assert_eq!(c.server, "ss.example.com");
        assert_eq!(c.port, 8388);
    }

    #[test]
    fn parses_ss_2022() {
        use base64::Engine;
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("2022-blake3-aes-128-gcm:pskA:pskB");
        let c = from_link(&format!("ss://{ui}@ss.example.com:8388#S22")).unwrap();
        assert_eq!(c.cipher.as_deref(), Some("2022-blake3-aes-128-gcm"));
        assert_eq!(c.password.as_deref(), Some("pskA:pskB"));
    }

    #[test]
    fn unsupported_schemes_return_none() {
        assert!(from_link("ssr://abc").is_none());
        assert!(from_link("http://a.com:80#H").is_none());
        assert!(from_link("vmess://not-base64-json").is_none());
    }
}
