//! Ruleset loading: binary `.ars` **or** plaintext (mihomo YAML / text / sing-box JSON).
//!
//! Plaintext providers are parsed into an in-memory matcher directly — there is
//! **no** intermediate `.ars` compilation step at runtime. The `ruleset-convert`
//! CLI remains available if you still want to pre-build binary files offline.

mod format;
mod compiler;
mod loader;
mod matcher;

pub use compiler::{
    compile_mihomo_ruleset, compile_singbox_json, write_ars, CompiledRuleSet, ProviderBehavior,
};
pub use matcher::RuleSet;

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Load a ruleset from disk into a matchable `RuleSet`.
///
/// - `.ars` → binary parse
/// - `.json` → sing-box rule-set JSON → direct matcher
/// - `.yaml` / `.yml` / text / list → mihomo provider → direct matcher
///
/// `behavior` applies to mihomo sources when the file does not declare one.
/// `format_hint` overrides extension detection (`text` / `yaml` / `json` / `ars`).
pub fn load_ruleset(
    name: &str,
    path: &Path,
    behavior: Option<ProviderBehavior>,
    format_hint: Option<&str>,
) -> Result<RuleSet> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let fmt = format_hint
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| ext.clone());

    if fmt == "ars" || ext == "ars" {
        let data =
            std::fs::read(path).with_context(|| format!("read ruleset `{name}` from {path:?}"))?;
        return RuleSet::from_bytes(name, &data)
            .with_context(|| format!("parse .ars ruleset `{name}`"));
    }

    // Plaintext / JSON → parse into CompiledRuleSet → build matcher directly.
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read ruleset `{name}` from {path:?}"))?;

    let compiled = if fmt == "json" || ext == "json" {
        compile_singbox_json(&raw)?
    } else {
        compile_mihomo_ruleset(&raw, behavior)?
    };

    tracing::info!(
        "loaded plaintext ruleset `{name}` from {path:?} \
         (domains={} suffixes={} keywords={} regex={} v4={} v6={})",
        compiled.domains.len(),
        compiled.domain_suffixes.len(),
        compiled.domain_keywords.len(),
        compiled.domain_regexes.len(),
        compiled.ipv4_cidrs.len(),
        compiled.ipv6_cidrs.len(),
    );

    RuleSet::from_compiled(name, compiled).with_context(|| format!("build ruleset `{name}`"))
}

/// Backward-compatible entry: load any supported format (binary or plaintext).
pub fn load_ars(name: &str, path: &Path) -> Result<RuleSet> {
    load_ruleset(name, path, None, None)
}

/// Convert a ruleset source file → `.ars` (offline helper; not used at runtime).
pub fn convert_to_ars(input: &Path, output: &Path, behavior: Option<ProviderBehavior>) -> Result<()> {
    let raw = std::fs::read_to_string(input)
        .with_context(|| format!("read {input:?}"))?;
    let ext = input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let compiled = if ext == "json" {
        if behavior.is_some() {
            bail!("--behavior applies to mihomo YAML/text sources only; sing-box JSON is self-describing");
        }
        compile_singbox_json(&raw)?
    } else {
        compile_mihomo_ruleset(&raw, behavior)?
    };
    let mut out = std::fs::File::create(output)
        .with_context(|| format!("create {output:?}"))?;
    write_ars(&compiled, &mut out)?;
    tracing::info!(
        "wrote .ars {output:?} (domains={} suffixes={} keywords={} regex={} v4={} v6={})",
        compiled.domains.len(),
        compiled.domain_suffixes.len(),
        compiled.domain_keywords.len(),
        compiled.domain_regexes.len(),
        compiled.ipv4_cidrs.len(),
        compiled.ipv6_cidrs.len(),
    );
    Ok(())
}
