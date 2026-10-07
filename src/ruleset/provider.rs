//! Load rule-providers from local files, redb cache, or remote HTTP URLs.

use super::{compile_mihomo_ruleset, compile_singbox_json, ProviderBehavior, RuleSet};
use crate::cache::AppCache;
use crate::config::{RulesetConfig, RulesetStorage};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use tracing::{info, warn};

/// Load every rule-provider into matchers.
///
/// - `type: file` — read from path or redb
/// - `type: http` — download from `url`, then save to path / redb / default `rules/<name>.ars`
pub async fn load_all(
    list: &[RulesetConfig],
    cache: Option<&AppCache>,
) -> Result<HashMap<String, RuleSet>> {
    let mut out = HashMap::new();
    for rs in list {
        let behavior = behavior_of(rs);
        let loaded = load_one(rs, behavior, cache).await?;
        out.insert(rs.name.clone(), loaded);
    }
    Ok(out)
}

fn behavior_of(rs: &RulesetConfig) -> Option<ProviderBehavior> {
    match rs.ty.as_str() {
        "domain" => Some(ProviderBehavior::Domain),
        "ip" => Some(ProviderBehavior::Ipcidr),
        "classical" => Some(ProviderBehavior::Classical),
        _ => None,
    }
}

/// Force re-download a remote (`type: http`) ruleset and write to storage.
/// Returns the freshly parsed matcher.
pub async fn refresh_remote(
    rs: &RulesetConfig,
    cache: Option<&AppCache>,
) -> Result<RuleSet> {
    if !rs.provider_type.eq_ignore_ascii_case("http") {
        bail!("refresh_remote only applies to type: http providers");
    }
    let url = rs
        .url
        .as_deref()
        .filter(|u| !u.trim().is_empty())
        .with_context(|| format!("rule-provider `{}`: missing url", rs.name))?;
    info!(name = %rs.name, %url, "updating remote ruleset");
    let data = crate::app::http::http_get(url)
        .await
        .with_context(|| format!("download ruleset `{}` from {url}", rs.name))?;
    write_storage(rs, &data, cache)?;
    info!(
        name = %rs.name,
        bytes = data.len(),
        dest = storage_label(&rs.storage),
        "ruleset updated and stored"
    );
    parse_bytes(&rs.name, &data, behavior_of(rs), rs.format.as_deref())
}

async fn load_one(
    rs: &RulesetConfig,
    behavior: Option<ProviderBehavior>,
    cache: Option<&AppCache>,
) -> Result<RuleSet> {
    let is_http = rs.provider_type.eq_ignore_ascii_case("http");

    // 1) Prefer existing local storage when not forcing a refresh.
    if let Some(data) = read_storage(rs, cache)? {
        info!(
            name = %rs.name,
            source = storage_label(&rs.storage),
            bytes = data.len(),
            "loaded ruleset from storage"
        );
        return parse_bytes(&rs.name, &data, behavior, rs.format.as_deref());
    }

    // 2) HTTP download when type is http (or file missing and url present).
    if is_http {
        let url = rs
            .url
            .as_deref()
            .filter(|u| !u.trim().is_empty())
            .with_context(|| format!("rule-provider `{}`: missing url", rs.name))?;
        info!(name = %rs.name, %url, "downloading ruleset");
        let data = crate::app::http::http_get(url)
            .await
            .with_context(|| format!("download ruleset `{}` from {url}", rs.name))?;
        write_storage(rs, &data, cache)?;
        info!(
            name = %rs.name,
            bytes = data.len(),
            dest = storage_label(&rs.storage),
            "ruleset downloaded and stored"
        );
        return parse_bytes(&rs.name, &data, behavior, rs.format.as_deref());
    }

    // 3) type:file with no data
    match &rs.storage {
        RulesetStorage::File(path) => bail!(
            "rule-provider `{}`: file not found at {} \
             (set path, enable cache, or use type: http with url)",
            rs.name,
            path.display()
        ),
        RulesetStorage::Db => bail!(
            "rule-provider `{}`: not in cache and no url to download \
             (use type: http with url, or seed the cache)",
            rs.name
        ),
    }
}

fn read_storage(rs: &RulesetConfig, cache: Option<&AppCache>) -> Result<Option<Vec<u8>>> {
    match &rs.storage {
        RulesetStorage::File(path) => {
            if path.is_file() {
                let data = std::fs::read(path)
                    .with_context(|| format!("read ruleset `{}` from {}", rs.name, path.display()))?;
                Ok(Some(data))
            } else {
                Ok(None)
            }
        }
        RulesetStorage::Db => {
            let Some(c) = cache else {
                warn!(
                    name = %rs.name,
                    "ruleset storage is Db but no cache opened; treat as miss"
                );
                return Ok(None);
            };
            Ok(c.get_ruleset(&rs.name))
        }
    }
}

fn write_storage(rs: &RulesetConfig, data: &[u8], cache: Option<&AppCache>) -> Result<()> {
    match &rs.storage {
        RulesetStorage::File(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create dir {}", parent.display()))?;
                }
            }
            std::fs::write(path, data)
                .with_context(|| format!("write ruleset `{}` to {}", rs.name, path.display()))?;
            Ok(())
        }
        RulesetStorage::Db => {
            let Some(c) = cache else {
                bail!(
                    "rule-provider `{}`: cache storage requested but redb is not open \
                     (enable profile.store-selected or set path)",
                    rs.name
                );
            };
            let meta = rs.url.as_deref();
            c.put_ruleset(&rs.name, data, meta)?;
            Ok(())
        }
    }
}

fn storage_label(s: &RulesetStorage) -> String {
    match s {
        RulesetStorage::File(p) => p.display().to_string(),
        RulesetStorage::Db => "redb".into(),
    }
}

/// Parse raw bytes into a RuleSet.
/// Detects binary `.ars` by magic; otherwise treats as text/yaml/json.
fn parse_bytes(
    name: &str,
    data: &[u8],
    behavior: Option<ProviderBehavior>,
    format_hint: Option<&str>,
) -> Result<RuleSet> {
    // Binary ARS magic "ARST"
    if data.len() >= 4 && &data[0..4] == b"ARST" {
        return RuleSet::from_bytes(name, data).with_context(|| format!("parse .ars `{name}`"));
    }

    let text = std::str::from_utf8(data)
        .with_context(|| format!("ruleset `{name}` is not UTF-8 text and not .ars binary"))?;

    let fmt = format_hint
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| detect_text_format(text));

    let compiled = if fmt == "json" {
        compile_singbox_json(text)?
    } else {
        compile_mihomo_ruleset(text, behavior)?
    };

    info!(
        "parsed plaintext ruleset `{name}` (domains={} suffixes={} keywords={} regex={} v4={} v6={})",
        compiled.domains.len(),
        compiled.domain_suffixes.len(),
        compiled.domain_keywords.len(),
        compiled.domain_regexes.len(),
        compiled.ipv4_cidrs.len(),
        compiled.ipv6_cidrs.len(),
    );
    RuleSet::from_compiled(name, compiled)
}

fn detect_text_format(text: &str) -> String {
    let t = text.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        "json".into()
    } else {
        "yaml".into()
    }
}
