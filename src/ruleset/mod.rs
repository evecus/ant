//! Binary ruleset `.ars` (Ant Rule Set).
//! Layout inspired by reflex `.rrs`: header + typed sections, domain FST + IP ranges.
//! Source format: mihomo rule-provider YAML (`payload:`) or plain text lines.

mod format;
mod compiler;
mod loader;
mod matcher;

pub use compiler::{compile_mihomo_ruleset, write_ars, ProviderBehavior};
pub use matcher::RuleSet;

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Load a `.ars` binary ruleset from disk.
pub fn load_ars(name: &str, path: &Path) -> Result<RuleSet> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if !ext.eq_ignore_ascii_case("ars") {
        bail!(
            "ruleset `{}` path must be a .ars file (got {:?}); convert YAML with: ant ruleset-convert -i in.yaml -o out.ars",
            name,
            path
        );
    }
    let data = std::fs::read(path).with_context(|| format!("read ruleset {} from {:?}", name, path))?;
    RuleSet::from_bytes(name, &data).with_context(|| format!("parse .ars ruleset {}", name))
}

/// Convert mihomo rule-provider YAML/text → `.ars`.
pub fn convert_to_ars(input: &Path, output: &Path, behavior: Option<ProviderBehavior>) -> Result<()> {
    let raw = std::fs::read_to_string(input)
        .with_context(|| format!("read {:?}", input))?;
    let compiled = compile_mihomo_ruleset(&raw, behavior)?;
    let mut out = std::fs::File::create(output)
        .with_context(|| format!("create {:?}", output))?;
    write_ars(&compiled, &mut out)?;
    tracing::info!(
        "wrote .ars {:?} (domains={} suffixes={} keywords={} regex={} v4={} v6={})",
        output,
        compiled.domains.len(),
        compiled.domain_suffixes.len(),
        compiled.domain_keywords.len(),
        compiled.domain_regexes.len(),
        compiled.ipv4_cidrs.len(),
        compiled.ipv6_cidrs.len(),
    );
    Ok(())
}
