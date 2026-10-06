//! Ruleset loading: binary `.ars` **or** plaintext (mihomo YAML / text / sing-box JSON).
//!
//! Plaintext providers are parsed into an in-memory matcher directly — there is
//! **no** intermediate `.ars` compilation step at runtime. The `ruleset-convert`
//! CLI remains available if you still want to pre-build binary files offline.

mod format;
mod compiler;
mod loader;
mod matcher;
mod provider;

pub use compiler::{
    compile_mihomo_ruleset, compile_singbox_json, write_ars, ProviderBehavior,
};
pub use matcher::RuleSet;
pub use provider::load_all as load_all_providers;

use anyhow::{bail, Context, Result};
use std::path::Path;

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
