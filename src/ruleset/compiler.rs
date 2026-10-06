//! Compile mihomo rule-provider YAML/text → intermediate `CompiledRuleSet`
//! (used for direct matching and optional `.ars` export).

use super::format::*;
use anyhow::{anyhow, bail, Context, Result};
use fst::SetBuilder;
use serde::Deserialize;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default)]
pub struct CompiledRuleSet {
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ipv4_cidrs: Vec<(Ipv4Addr, u8)>,
    pub ipv6_cidrs: Vec<(Ipv6Addr, u8)>,
}

/// Optional YAML envelope used by mihomo rule-provider files.
#[derive(Deserialize, Default)]
struct MihomoProviderFile {
    #[serde(default)]
    payload: Vec<String>,
    /// Optional hint: domain | ipcidr | classical
    #[serde(default)]
    behavior: Option<String>,
}

/// Behavior of the source rule list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderBehavior {
    Domain,
    Ipcidr,
    Classical,
}

impl ProviderBehavior {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "domain" => Ok(Self::Domain),
            "ipcidr" | "ip" | "ip-cidr" => Ok(Self::Ipcidr),
            "classical" => Ok(Self::Classical),
            other => bail!("unknown behavior `{other}`; use domain, ipcidr, or classical"),
        }
    }
}

/// Compile mihomo rule-provider source (YAML with `payload:` or plain text lines).
///
/// `behavior_hint`: from CLI `--behavior`, or `None` to auto-detect / use YAML `behavior:`.
pub fn compile_mihomo_ruleset(src: &str, behavior_hint: Option<ProviderBehavior>) -> Result<CompiledRuleSet> {
    let (lines, yaml_behavior) = extract_payload_lines(src)?;
    let behavior = behavior_hint
        .or(yaml_behavior)
        .unwrap_or_else(|| detect_behavior(&lines));

    let mut out = CompiledRuleSet::default();
    match behavior {
        ProviderBehavior::Domain => {
            for line in &lines {
                ingest_domain_entry(&mut out, line)?;
            }
        }
        ProviderBehavior::Ipcidr => {
            for line in &lines {
                ingest_ip_entry(&mut out, line)?;
            }
        }
        ProviderBehavior::Classical => {
            for line in &lines {
                ingest_classical_line(&mut out, line)?;
            }
        }
    }
    Ok(out)
}

/// Prefer YAML `payload:`; otherwise treat whole file as text (one rule per line).
fn extract_payload_lines(src: &str) -> Result<(Vec<String>, Option<ProviderBehavior>)> {
    let trimmed = src.trim();
    if trimmed.is_empty() {
        return Ok((vec![], None));
    }

    // Fast path: looks like a YAML mapping with payload
    if trimmed.starts_with('{') || trimmed.contains("payload:") || trimmed.contains("payload :") {
        if let Ok(file) = serde_yaml::from_str::<MihomoProviderFile>(src) {
            if !file.payload.is_empty() || file.behavior.is_some() {
                let beh = file
                    .behavior
                    .as_deref()
                    .map(ProviderBehavior::parse)
                    .transpose()?;
                let lines = file
                    .payload
                    .into_iter()
                    .map(|s| strip_comment(s.trim()).to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                return Ok((lines, beh));
            }
        }
    }

    // Plain text / classical lines
    let lines = src
        .lines()
        .map(|l| strip_comment(l.trim()).to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Ok((lines, None))
}

fn strip_comment(s: &str) -> &str {
    // inline comment after space+#
    if let Some(i) = s.find(" #") {
        return s[..i].trim();
    }
    if s.starts_with('#') || s.starts_with("//") || s.starts_with(';') {
        return "";
    }
    s
}

fn detect_behavior(lines: &[String]) -> ProviderBehavior {
    let mut domainish = 0usize;
    let mut ipish = 0usize;
    let mut classical = 0usize;
    for l in lines.iter().take(32) {
        let up = l.to_ascii_uppercase();
        if up.starts_with("DOMAIN")
            || up.starts_with("IP-CIDR")
            || up.starts_with("IP-CIDR6")
            || up.starts_with("SRC-IP")
            || up.starts_with("GEOIP")
            || up.starts_with("GEOSITE")
        {
            classical += 1;
        } else if l.contains('/') && (l.contains(':') || l.chars().filter(|c| *c == '.').count() >= 1)
        {
            // likely CIDR
            if parse_ipv4_cidr(l).is_ok() || parse_ipv6_cidr(l).is_ok() {
                ipish += 1;
            } else {
                domainish += 1;
            }
        } else {
            domainish += 1;
        }
    }
    if classical > 0 && classical >= domainish && classical >= ipish {
        ProviderBehavior::Classical
    } else if ipish > domainish {
        ProviderBehavior::Ipcidr
    } else {
        ProviderBehavior::Domain
    }
}

/// domain behavior: clash-style wildcards.
/// - `example.com` → exact domain
/// - `+.example.com` / `.example.com` → domain suffix
/// - `*.example.com` → treat as suffix `example.com` (best-effort)
fn ingest_domain_entry(out: &mut CompiledRuleSet, raw: &str) -> Result<()> {
    let s = raw.trim().trim_matches(|c| c == '\'' || c == '"');
    if s.is_empty() {
        return Ok(());
    }
    // classical line accidentally in domain set
    if s.contains(',') {
        return ingest_classical_line(out, s);
    }
    if let Some(rest) = s.strip_prefix("+.") {
        push_suffix(out, rest);
    } else if let Some(rest) = s.strip_prefix('.') {
        push_suffix(out, rest);
    } else if s.contains('*') {
        // map *.foo.com or *.*.foo.com → suffix of trailing labels without *
        let cleaned = s.trim_start_matches("*.").trim_start_matches('*').trim_start_matches('.');
        if cleaned.is_empty() {
            tracing::warn!("skip unsupported domain wildcard: {s}");
        } else {
            push_suffix(out, cleaned);
        }
    } else {
        push_domain(out, s);
    }
    Ok(())
}

fn ingest_ip_entry(out: &mut CompiledRuleSet, raw: &str) -> Result<()> {
    let s = raw.trim().trim_matches(|c| c == '\'' || c == '"');
    if s.is_empty() {
        return Ok(());
    }
    if s.contains(',') {
        return ingest_classical_line(out, s);
    }
    push_cidr(out, s);
    Ok(())
}

/// classical: `TYPE,payload[,extra...]` (outbound column ignored if present)
fn ingest_classical_line(out: &mut CompiledRuleSet, line: &str) -> Result<()> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(());
    }
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return Ok(());
    }
    let kind = parts[0].to_ascii_uppercase();
    let payload = parts.get(1).copied().unwrap_or("");
    match kind.as_str() {
        "DOMAIN" => push_domain(out, payload),
        "DOMAIN-SUFFIX" => push_suffix(out, payload),
        "DOMAIN-KEYWORD" => {
            let v = payload.to_ascii_lowercase();
            if !v.is_empty() {
                out.domain_keywords.push(v);
            }
        }
        "DOMAIN-REGEX" => {
            if !payload.is_empty() {
                regex::Regex::new(payload)
                    .with_context(|| format!("invalid DOMAIN-REGEX: {payload}"))?;
                out.domain_regexes.push(payload.to_string());
            }
        }
        "DOMAIN-WILDCARD" => {
            // best-effort → suffix of last static labels
            let cleaned = payload
                .trim_start_matches("*.")
                .trim_start_matches('*')
                .trim_start_matches('.');
            if cleaned.is_empty() {
                tracing::warn!("skip DOMAIN-WILDCARD: {payload}");
            } else {
                push_suffix(out, cleaned);
            }
        }
        "IP-CIDR" | "IP-CIDR6" => {
            // strip no-resolve / src flags
            push_cidr(out, payload);
        }
        // Unsupported in .ars — skip with warning
        "GEOIP" | "GEOSITE" | "SRC-IP-CIDR" | "SRC-IP-CIDR6" | "DST-PORT" | "SRC-PORT"
        | "PROCESS-NAME" | "PROCESS-PATH" | "RULE-SET" | "MATCH" | "AND" | "OR" | "NOT"
        | "SUB-RULE" | "NETWORK" | "IN-PORT" | "IN-TYPE" | "UID" => {
            tracing::warn!("skip unsupported classical rule type: {kind}");
        }
        _ => {
            // bare domain/cidr line without type prefix
            if payload.is_empty() && !parts[0].is_empty() {
                if parse_ipv4_cidr(parts[0]).is_ok() || parse_ipv6_cidr(parts[0]).is_ok() {
                    push_cidr(out, parts[0]);
                } else if parts[0].contains('.') || parts[0].contains(':') {
                    push_domain(out, parts[0]);
                } else {
                    tracing::warn!("skip unknown classical line: {line}");
                }
            } else {
                tracing::warn!("skip unknown classical rule type: {kind}");
            }
        }
    }
    Ok(())
}

/// sing-box rule-set source format (JSON): `{"version": N, "rules": [...]}`
#[derive(Deserialize)]
struct SingboxSourceFile {
    #[serde(default)]
    rules: Vec<SingboxRule>,
}

/// One entry of sing-box source `rules`. Unknown keys are warn-skipped.
#[derive(Deserialize)]
struct SingboxRule {
    /// logical rule (nested `rules`) — not representable in .ars, skip whole item
    #[serde(default)]
    rules: Option<serde_json::Value>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    domain_suffix: Vec<String>,
    #[serde(default)]
    domain_keyword: Vec<String>,
    #[serde(default)]
    domain_regex: Vec<String>,
    #[serde(default)]
    ip_cidr: Vec<String>,
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Compile a sing-box rule-set source JSON (`version` + `rules`) into `.ars` sections.
///
/// Supported fields: `domain` / `domain_suffix` / `domain_keyword` /
/// `domain_regex` / `ip_cidr`. Logical rules (nested `rules`) and any other
/// field are warn-skipped, same policy as mihomo classical compilation.
pub fn compile_singbox_json(src: &str) -> Result<CompiledRuleSet> {
    let file: SingboxSourceFile =
        serde_json::from_str(src).context("parse sing-box rule-set JSON")?;
    let mut out = CompiledRuleSet::default();
    for rule in &file.rules {
        ingest_singbox_rule(&mut out, rule)?;
    }
    Ok(out)
}

fn ingest_singbox_rule(out: &mut CompiledRuleSet, rule: &SingboxRule) -> Result<()> {
    if rule.rules.is_some() {
        tracing::warn!("skip sing-box logical rule (nested rules not supported in .ars)");
        return Ok(());
    }
    if rule.kind.is_some() {
        tracing::warn!("skip sing-box rule with `type` field");
        return Ok(());
    }
    for k in rule.extra.keys() {
        tracing::warn!("skip unsupported sing-box rule field: {k}");
    }
    for d in &rule.domain {
        push_domain(out, d);
    }
    for d in &rule.domain_suffix {
        // `.example.com` and `example.com` are both suffix matches in sing-box
        push_suffix(out, d.trim_start_matches('.'));
    }
    for k in &rule.domain_keyword {
        let v = k.to_ascii_lowercase();
        if !v.is_empty() {
            out.domain_keywords.push(v);
        }
    }
    for r in &rule.domain_regex {
        regex::Regex::new(r).with_context(|| format!("invalid domain_regex: {r}"))?;
        out.domain_regexes.push(r.to_string());
    }
    for c in &rule.ip_cidr {
        push_cidr(out, c);
    }
    Ok(())
}

fn push_domain(out: &mut CompiledRuleSet, s: &str) {
    let v = s.trim_matches('.').to_ascii_lowercase();
    if !v.is_empty() {
        out.domains.push(v);
    }
}

fn push_suffix(out: &mut CompiledRuleSet, s: &str) {
    let v = s.trim_matches('.').to_ascii_lowercase();
    if !v.is_empty() {
        out.domain_suffixes.push(v);
    }
}

fn push_cidr(out: &mut CompiledRuleSet, cidr: &str) {
    if let Ok((a, p)) = parse_ipv4_cidr(cidr) {
        out.ipv4_cidrs.push((a, p));
    } else if let Ok((a, p)) = parse_ipv6_cidr(cidr) {
        out.ipv6_cidrs.push((a, p));
    } else if let Ok(ip) = cidr.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => out.ipv4_cidrs.push((v4, 32)),
            std::net::IpAddr::V6(v6) => out.ipv6_cidrs.push((v6, 128)),
        }
    } else {
        tracing::warn!("skip invalid ip/cidr: {cidr}");
    }
}

fn parse_ipv4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, pref) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("missing /"))?;
    let a: Ipv4Addr = addr.parse()?;
    let p: u8 = pref.parse()?;
    if p > 32 {
        bail!("ipv4 prefix > 32");
    }
    Ok((a, p))
}

fn parse_ipv6_cidr(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, pref) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("missing /"))?;
    let a: Ipv6Addr = addr.parse()?;
    let p: u8 = pref.parse()?;
    if p > 128 {
        bail!("ipv6 prefix > 128");
    }
    Ok((a, p))
}

/// FST key: labels reversed, joined by 0x00 (same as matcher).
/// Exact-domain FST key: reversed labels joined by `.` (e.g. `com.google`).
pub fn domain_to_fst_key(domain: &str) -> String {
    let mut labels: Vec<&str> = domain.split('.').filter(|s| !s.is_empty()).collect();
    labels.reverse();
    labels.join(".")
}

/// Suffix FST key: reversed labels + trailing `.` (e.g. `com.google.`).
fn suffix_to_fst_key(suffix: &str) -> String {
    let mut key = domain_to_fst_key(suffix);
    if !key.is_empty() {
        key.push('.');
    }
    key
}

pub(crate) fn build_domain_fst(domains: &[String]) -> Result<Vec<u8>> {
    if domains.is_empty() {
        return Ok(vec![]);
    }
    let mut keys: Vec<String> = domains.iter().map(|d| domain_to_fst_key(d)).collect();
    keys.sort_unstable();
    keys.dedup();
    let mut buf = Vec::new();
    {
        let mut builder = SetBuilder::new(&mut buf).map_err(|e| anyhow!("fst builder: {e}"))?;
        for k in &keys {
            builder
                .insert(k.as_bytes())
                .map_err(|e| anyhow!("fst insert: {e}"))?;
        }
        builder.finish().map_err(|e| anyhow!("fst finish: {e}"))?;
    }
    Ok(buf)
}

pub(crate) fn build_suffix_fst(suffixes: &[String]) -> Result<Vec<u8>> {
    if suffixes.is_empty() {
        return Ok(vec![]);
    }
    let mut keys: Vec<String> = suffixes.iter().map(|d| suffix_to_fst_key(d)).collect();
    keys.sort_unstable();
    keys.dedup();
    let mut buf = Vec::new();
    {
        let mut builder = SetBuilder::new(&mut buf).map_err(|e| anyhow!("fst builder: {e}"))?;
        for k in &keys {
            builder
                .insert(k.as_bytes())
                .map_err(|e| anyhow!("fst insert: {e}"))?;
        }
        builder.finish().map_err(|e| anyhow!("fst finish: {e}"))?;
    }
    Ok(buf)
}

fn encode_strings(list: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for s in list {
        let b = s.as_bytes();
        if b.len() > 255 {
            // loader uses a single length byte
            tracing::warn!("string longer than 255 bytes truncated in .ars: {}…", &s[..32]);
            continue;
        }
        buf.push(b.len() as u8);
        buf.extend_from_slice(b);
    }
    buf
}

fn encode_ipv4(list: &[(Ipv4Addr, u8)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(list.len() * IPV4_ENTRY_LEN);
    for (a, p) in list {
        buf.extend_from_slice(&a.octets());
        buf.push(*p);
    }
    buf
}

fn encode_ipv6(list: &[(Ipv6Addr, u8)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(list.len() * IPV6_ENTRY_LEN);
    for (a, p) in list {
        buf.extend_from_slice(&a.octets());
        buf.push(*p);
    }
    buf
}

pub fn write_ars<W: Write>(compiled: &CompiledRuleSet, w: &mut W) -> Result<()> {
    let domain_fst = build_domain_fst(&compiled.domains)?;
    let suffix_fst = build_suffix_fst(&compiled.domain_suffixes)?;
    let keywords = encode_strings(&compiled.domain_keywords);
    let regexes = encode_strings(&compiled.domain_regexes);
    let v4 = encode_ipv4(&compiled.ipv4_cidrs);
    let v6 = encode_ipv6(&compiled.ipv6_cidrs);

    let sections: Vec<(SectionType, usize, Vec<u8>)> = [
        (SectionType::DomainFst, compiled.domains.len(), domain_fst),
        (
            SectionType::DomainSuffixFst,
            compiled.domain_suffixes.len(),
            suffix_fst,
        ),
        (
            SectionType::DomainKeyword,
            compiled.domain_keywords.len(),
            keywords,
        ),
        (
            SectionType::DomainRegex,
            compiled.domain_regexes.len(),
            regexes,
        ),
        (SectionType::IpCidrV4, compiled.ipv4_cidrs.len(), v4),
        (SectionType::IpCidrV6, compiled.ipv6_cidrs.len(), v6),
    ]
    .into_iter()
    .filter(|(_, _, data)| !data.is_empty())
    .collect();

    w.write_all(&MAGIC)?;
    w.write_all(&[VERSION])?;
    w.write_all(&[0x00])?; // flags
    w.write_all(&(sections.len() as u32).to_le_bytes())?;
    w.write_all(&[0u8; 4])?; // reserved

    for (ty, count, data) in &sections {
        w.write_all(&[(*ty) as u8])?;
        w.write_all(&(*count as u32).to_le_bytes())?;
        w.write_all(&(data.len() as u32).to_le_bytes())?;
        w.write_all(data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classical_yaml_payload() {
        let src = r#"
payload:
  - DOMAIN-SUFFIX,google.com
  - DOMAIN-KEYWORD,ads
  - DOMAIN,exact.test
  - IP-CIDR,10.0.0.0/8
"#;
        let c = compile_mihomo_ruleset(src, Some(ProviderBehavior::Classical)).unwrap();
        assert!(c.domain_suffixes.contains(&"google.com".into()));
        assert!(c.domain_keywords.contains(&"ads".into()));
        assert!(c.domains.contains(&"exact.test".into()));
        assert!(!c.ipv4_cidrs.is_empty());
    }

    #[test]
    fn domain_behavior_plus_prefix() {
        let src = r#"
payload:
  - "+.example.com"
  - "foo.com"
  - ".bar.com"
"#;
        let c = compile_mihomo_ruleset(src, Some(ProviderBehavior::Domain)).unwrap();
        assert!(c.domain_suffixes.contains(&"example.com".into()));
        assert!(c.domain_suffixes.contains(&"bar.com".into()));
        assert!(c.domains.contains(&"foo.com".into()));
    }

    #[test]
    fn text_ipcidr() {
        let src = "1.1.1.0/24\n2001:db8::/32\n";
        let c = compile_mihomo_ruleset(src, Some(ProviderBehavior::Ipcidr)).unwrap();
        assert_eq!(c.ipv4_cidrs.len(), 1);
        assert_eq!(c.ipv6_cidrs.len(), 1);
    }

    #[test]
    fn singbox_json_ruleset() {
        let src = r#"{
  "version": 3,
  "rules": [
    {
      "domain": ["exact.test"],
      "domain_suffix": [".example.com", "plain.com"],
      "domain_keyword": ["ADS"],
      "domain_regex": ["^regex\\d+\\.test$"],
      "ip_cidr": ["10.0.0.0/8", "2001:db8::/32", "1.2.3.4"]
    },
    {
      "type": "logical",
      "mode": "and",
      "rules": [{ "domain_suffix": ["inner.com"] }]
    },
    {
      "source_ip_cidr": ["192.168.0.0/16"],
      "domain": ["still.parsed.test"]
    }
  ]
}"#;
        let c = compile_singbox_json(src).unwrap();
        assert!(c.domains.contains(&"exact.test".into()));
        assert!(c.domains.contains(&"still.parsed.test".into()));
        assert!(c.domain_suffixes.contains(&"example.com".into()));
        assert!(c.domain_suffixes.contains(&"plain.com".into()));
        assert!(c.domain_keywords.contains(&"ads".into()));
        assert_eq!(c.domain_regexes.len(), 1);
        assert_eq!(c.ipv4_cidrs.len(), 2);
        assert_eq!(c.ipv6_cidrs.len(), 1);
    }

    #[test]
    fn singbox_json_invalid_regex_fails() {
        let src = r#"{"version":3,"rules":[{"domain_regex":["(["}]}"#;
        assert!(compile_singbox_json(src).is_err());
    }
}
