//! Subscription payload → `Vec<ProxyConfig>`.
//!
//! Accepted payload shapes (same set as mihomo):
//! 1. YAML/JSON document with a `proxies:` list (or a bare list of nodes);
//! 2. base64-encoded (1) — the classic `v2rayN` subscription blob;
//! 3. base64-encoded newline-separated share links;
//! 4. plain newline-separated share links.

use super::provider_link;
use crate::config::ProxyConfig;
use anyhow::{bail, Result};
use regex::Regex;

/// Parse a raw provider payload (file content or HTTP response body).
pub fn parse_payload(provider: &str, data: &[u8]) -> Result<Vec<ProxyConfig>> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t.to_string(),
        Err(_) => String::from_utf8_lossy(data).into_owned(),
    };
    parse_text(provider, &text, 0)
}

fn parse_text(provider: &str, text: &str, depth: usize) -> Result<Vec<ProxyConfig>> {
    let t = text.trim();
    if t.is_empty() {
        bail!("proxy-provider `{provider}`: empty payload");
    }
    // 1) YAML / JSON document
    if let Some(list) = yaml_proxies(t) {
        return Ok(list);
    }
    // 2) base64 blob (subscription links or an embedded YAML document)
    if depth < 2 {
        if let Some(decoded) = provider_link::decode_b64(t) {
            if let Ok(list) = parse_text(provider, &decoded, depth + 1) {
                return Ok(list);
            }
        }
    }
    // 3) plain share-link list
    let list = share_links(t);
    if !list.is_empty() {
        return Ok(list);
    }
    bail!(
        "proxy-provider `{provider}`: payload is neither a YAML/JSON `proxies:` list, \
         a base64 blob, nor a share-link list"
    )
}

fn yaml_proxies(text: &str) -> Option<Vec<ProxyConfig>> {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        proxies: Vec<ProxyConfig>,
    }
    if let Ok(w) = serde_yaml::from_str::<Wrapper>(text) {
        if !w.proxies.is_empty() {
            return Some(w.proxies);
        }
    }
    if let Ok(list) = serde_yaml::from_str::<Vec<ProxyConfig>>(text) {
        if !list.is_empty() {
            return Some(list);
        }
    }
    None
}

fn share_links(text: &str) -> Vec<ProxyConfig> {
    let mut out = Vec::new();
    for line in text.split(['\n', '\r']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match provider_link::from_link(line) {
            Some(c) => out.push(c),
            None => {
                tracing::warn!(
                    scheme = provider_link::scheme_of(line),
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
            ..provider_link::blank()
        }
    }
}
