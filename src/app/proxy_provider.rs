//! Proxy providers (`proxy-providers:` in the YAML config).
//!
//! Mirrors mihomo's `adapter/provider` package, minus the parts ant has no
//! equivalent for (health-check scheduler, `override`, `age` encryption):
//!
//! * `type: file` — read a local YAML/JSON/link-list file;
//! * `type: http` — download a subscription, cache it to `path`, and refresh on
//!   `interval-time` (hours) or on demand via the API (`PUT /providers/proxies/{name}`).
//!
//! Nodes loaded here are merged into the outbound table and can be pulled into
//! proxy-groups with `use: [provider-name]` / `include-all-providers: true`.

use super::provider_parse as parse;
use crate::config::{ProxyConfig, ProxyProviderConfig};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// `subscription-userinfo` response header, parsed like mihomo's
/// `adapter/provider.SubscriptionInfo` (all values in bytes).
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct SubscriptionInfo {
    pub upload: i64,
    pub download: i64,
    pub total: i64,
    pub expire: i64,
}

impl SubscriptionInfo {
    /// Parse `upload=1; download=2; total=3; expire=4` (any order, any subset).
    fn from_header(v: &str) -> Option<Self> {
        let mut s = Self::default();
        let mut any = false;
        for part in v.split([';', ',']) {
            let (k, val) = part.split_once('=')?;
            let n: i64 = val.trim().parse().ok()?;
            match k.trim().to_ascii_lowercase().as_str() {
                "upload" => s.upload = n,
                "download" => s.download = n,
                "total" => s.total = n,
                "expire" => s.expire = n,
                _ => continue,
            }
            any = true;
        }
        if any {
            Some(s)
        } else {
            None
        }
    }
}

/// How `fetch` obtains a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchMode {
    /// Startup: use the cache file when present, otherwise download.
    PreferCache,
    /// `ant check`: cache only, never hit the network.
    Offline,
    /// Manual / scheduled refresh: always download (file: re-read).
    ForceNetwork,
}

/// Runtime state of one provider.
#[derive(Debug, Clone)]
pub struct ProviderState {
    pub name: String,
    /// `file` | `http` (lower-cased).
    pub ty: String,
    pub url: Option<String>,
    pub path: Option<PathBuf>,
    /// Refresh interval in hours; 0 = manual only.
    pub interval_time: u64,
    pub proxies: Vec<ProxyConfig>,
    /// Unix milliseconds of the last successful load/update.
    pub updated_at_ms: Option<i64>,
    pub subscription_info: Option<SubscriptionInfo>,
    /// Error message of the last failed refresh (cleared on success).
    pub last_error: Option<String>,
}

impl ProviderState {
    pub fn node_names(&self) -> Vec<String> {
        self.proxies.iter().map(|p| p.name.clone()).collect()
    }
}

/// The live set of proxy-providers.
pub struct ProxyProviderStore {
    /// Immutable configuration (keys = provider names).
    cfg: HashMap<String, ProxyProviderConfig>,
    state: RwLock<HashMap<String, ProviderState>>,
    /// Serializes refreshes so a UI button storm cannot stampede the network.
    update_lock: tokio::sync::Mutex<()>,
}

impl ProxyProviderStore {
    /// Load every provider.
    ///
    /// `base` is the run directory (`-d/--dir` or cwd) used to derive the
    /// default cache path `providers/<name>.yaml` for http providers without an
    /// explicit `path`.
    ///
    /// `offline` (used by `ant check`) skips the startup download of an http
    /// provider that has no cache file yet, instead of failing.
    pub async fn load_all(
        cfgs: &HashMap<String, ProxyProviderConfig>,
        base: Option<&Path>,
        offline: bool,
    ) -> Result<Arc<Self>> {
        let mut cfg: HashMap<String, ProxyProviderConfig> = HashMap::new();
        for (name, pp) in cfgs {
            let mut pp = pp.clone();
            if pp.path.is_none() && pp.ty.eq_ignore_ascii_case("http") {
                let p = match base {
                    Some(b) => b.join(crate::config::Config::default_proxy_provider_path(name)),
                    None => crate::config::Config::default_proxy_provider_path(name),
                };
                pp.path = Some(p);
            }
            cfg.insert(name.clone(), pp);
        }

        let mut state = HashMap::new();
        for (name, pp) in &cfg {
            state.insert(
                name.clone(),
                ProviderState {
                    name: name.clone(),
                    ty: pp.ty.to_ascii_lowercase(),
                    url: pp.url.clone(),
                    path: pp.path.clone(),
                    interval_time: pp.interval_time,
                    proxies: Vec::new(),
                    updated_at_ms: None,
                    subscription_info: None,
                    last_error: None,
                },
            );
        }
        let store = Arc::new(Self {
            cfg,
            state: RwLock::new(state),
            update_lock: tokio::sync::Mutex::new(()),
        });

        let mode = if offline {
            FetchMode::Offline
        } else {
            FetchMode::PreferCache
        };
        for name in store.cfg.keys() {
            match store.fetch(name, mode).await {
                Ok((proxies, sub, at)) => {
                    store.commit(name, proxies, sub, at, None);
                    tracing::info!(
                        provider = %name,
                        nodes = store.state.read().unwrap()[name].proxies.len(),
                        "proxy-provider loaded"
                    );
                }
                Err(e) => {
                    if offline && store.cfg[name].ty.eq_ignore_ascii_case("http") {
                        tracing::warn!(
                            provider = %name,
                            error = %e,
                            "proxy-provider not downloaded (offline check); \
                             nodes will be empty until the subscription is fetched"
                        );
                        store.commit(name, Vec::new(), None, None, Some(e.to_string()));
                        continue;
                    }
                    store.commit(name, Vec::new(), None, None, Some(e.to_string()));
                    return Err(e).with_context(|| format!("proxy-provider `{name}`"));
                }
            }
        }
        Ok(store)
    }

    /// Force-refresh one provider: re-download (`http`) or re-read (`file`),
    /// persist the cache file, and swap in the new node list.
    ///
    /// Returns the new node count.
    pub async fn update(&self, name: &str) -> Result<usize> {
        if !self.cfg.contains_key(name) {
            bail!("unknown proxy-provider `{name}`");
        }
        let _guard = self.update_lock.lock().await;
        match self.fetch(name, FetchMode::ForceNetwork).await {
            Ok((proxies, sub, at)) => {
                let n = proxies.len();
                self.commit(name, proxies, sub, at, None);
                Ok(n)
            }
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!(provider = %name, error = %msg, "proxy-provider update failed");
                self.set_error(name, &msg);
                Err(e)
            }
        }
    }

    /// Fetch + parse without touching state.
    async fn fetch(
        &self,
        name: &str,
        mode: FetchMode,
    ) -> Result<(Vec<ProxyConfig>, Option<SubscriptionInfo>, Option<i64>)> {
        let pp = &self.cfg[name];
        let ty = pp.ty.to_ascii_lowercase();
        match ty.as_str() {
            "file" => {
                let path = pp
                    .path
                    .as_ref()
                    .context("proxy-provider `file` requires `path`")?;
                let data = std::fs::read(path)
                    .with_context(|| format!("read proxy-provider {}", path.display()))?;
                let at = mtime_ms(path);
                let proxies = self.parse(name, &data)?;
                Ok((proxies, None, at))
            }
            "http" => {
                let path = pp.path.clone();
                // 1) Initial load: reuse the cache file so startup stays fast
                //    (and `ant check` stays offline). `update()` uses
                //    `ForceNetwork` and skips this branch.
                if mode != FetchMode::ForceNetwork {
                    if let Some(p) = path.as_deref().filter(|p| p.is_file()) {
                        if let Some(data) = std::fs::read(p).ok().filter(|d| !d.is_empty()) {
                            let at = mtime_ms(p);
                            let proxies = self.parse(name, &data)?;
                            tracing::debug!(
                                provider = %name,
                                path = %p.display(),
                                "proxy-provider loaded from cache file"
                            );
                            return Ok((proxies, None, at));
                        }
                    }
                }
                if mode == FetchMode::Offline {
                    bail!(
                        "no cache file at {} and downloads are disabled",
                        path.as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<none>".into())
                    );
                }
                // 2) Download.
                let url = pp
                    .url
                    .as_deref()
                    .filter(|u| !u.trim().is_empty())
                    .with_context(|| format!("proxy-provider `{name}` requires `url`"))?;
                tracing::info!(provider = %name, %url, "fetching subscription");
                let headers = pp.header.clone().unwrap_or_default();
                let resp = crate::app::http::http_get_ex(url, &headers)
                    .await
                    .with_context(|| format!("download subscription `{name}` from {url}"))?;
                if !resp.is_success() {
                    bail!("HTTP {} fetching {url}", resp.status);
                }
                let sub = resp.header("subscription-userinfo").and_then(SubscriptionInfo::from_header);
                if let Some(p) = path.as_deref() {
                    if let Err(e) = write_cache(p, &resp.body) {
                        tracing::warn!(
                            provider = %name,
                            path = %p.display(),
                            error = %e,
                            "failed to write subscription cache"
                        );
                    }
                }
                let proxies = self.parse(name, &resp.body)?;
                Ok((proxies, sub, Some(now_ms())))
            }
            other => bail!("proxy-provider `{name}`: unsupported type `{other}`"),
        }
    }

    fn parse(&self, name: &str, data: &[u8]) -> Result<Vec<ProxyConfig>> {
        let pp = &self.cfg[name];
        let list = parse::parse_payload(name, data)?;
        parse::finalize(
            name,
            list,
            pp.filter.as_deref(),
            pp.exclude_filter.as_deref(),
        )
    }

    fn commit(
        &self,
        name: &str,
        proxies: Vec<ProxyConfig>,
        sub: Option<SubscriptionInfo>,
        at: Option<i64>,
        err: Option<String>,
    ) {
        if let Ok(mut g) = self.state.write() {
            if let Some(s) = g.get_mut(name) {
                s.proxies = proxies;
                s.subscription_info = sub.or(s.subscription_info);
                if at.is_some() {
                    s.updated_at_ms = at;
                }
                s.last_error = err;
            }
        }
    }

    fn set_error(&self, name: &str, msg: &str) {
        if let Ok(mut g) = self.state.write() {
            if let Some(s) = g.get_mut(name) {
                s.last_error = Some(msg.to_string());
            }
        }
    }

    /// provider name → node names (feeds proxy-group `use:` resolution).
    pub fn index(&self) -> HashMap<String, Vec<String>> {
        let g = self.state.read().unwrap();
        g.iter()
            .map(|(k, v)| (k.clone(), v.node_names()))
            .collect()
    }

    /// Every node of every provider, tagged with its provider name.
    pub fn nodes(&self) -> Vec<(String, ProxyConfig)> {
        let g = self.state.read().unwrap();
        let mut out = Vec::new();
        let mut names: Vec<&String> = g.keys().collect();
        names.sort();
        for name in names {
            for p in &g[name].proxies {
                out.push((name.clone(), p.clone()));
            }
        }
        out
    }

    /// Unix ms of the last successful load/update (None = never loaded).
    pub fn last_updated_ms(&self, name: &str) -> Option<i64> {
        self.state
            .read()
            .unwrap()
            .get(name)
            .and_then(|s| s.updated_at_ms)
    }

    /// Interval (hours) for a provider; 0 = manual only.
    pub fn interval_time(&self, name: &str) -> u64 {
        self.cfg.get(name).map(|c| c.interval_time).unwrap_or(0)
    }

    /// Providers that have an `interval-time` > 0 (auto refresh candidates).
    pub fn auto_update_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .cfg
            .iter()
            .filter(|(_, c)| c.interval_time > 0 && c.ty.eq_ignore_ascii_case("http"))
            .map(|(k, _)| k.clone())
            .collect();
        v.sort();
        v
    }

    /// JSON snapshot for the API / dashboard (mihomo `providerForApi` shape,
    /// plus ant's `interval-time` and `error`).
    pub fn snapshot(&self) -> Vec<serde_json::Value> {
        let g = self.state.read().unwrap();
        let mut names: Vec<&String> = g.keys().collect();
        names.sort();
        names
            .into_iter()
            .map(|n| {
                let s = &g[n];
                let vehicle = if s.ty == "http" { "HTTP" } else { "File" };
                let proxies: Vec<serde_json::Value> = s
                    .proxies
                    .iter()
                    .map(|p| serde_json::json!({ "name": p.name, "type": p.ty }))
                    .collect();
                serde_json::json!({
                    "name": s.name,
                    "type": "Proxy",
                    "vehicleType": vehicle,
                    "providerType": s.ty,
                    "url": s.url,
                    "path": s.path.as_ref().map(|p| p.display().to_string()),
                    "interval-time": s.interval_time,
                    "count": s.proxies.len(),
                    "proxies": proxies,
                    "updatedAt": s.updated_at_ms,
                    "subscriptionInfo": s.subscription_info,
                    "error": s.last_error,
                })
            })
            .collect()
    }
}

fn write_cache(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
    }
    std::fs::write(path, data).with_context(|| format!("write {}", path.display()))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn mtime_ms(path: &Path) -> Option<i64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subscription_userinfo() {
        let s = SubscriptionInfo::from_header("upload=1; download=2; total=3; expire=4").unwrap();
        assert_eq!((s.upload, s.download, s.total, s.expire), (1, 2, 3, 4));
        assert!(SubscriptionInfo::from_header("garbage").is_none());
    }

    #[tokio::test]
    async fn loads_file_provider() {
        let dir = std::env::temp_dir().join(format!("ant-pp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("sub.yaml");
        std::fs::write(
            &f,
            "proxies:\n  - name: n1\n    type: socks5\n    server: 1.1.1.1\n    port: 1080\n",
        )
        .unwrap();
        let mut cfgs = HashMap::new();
        cfgs.insert(
            "p".into(),
            ProxyProviderConfig {
                ty: "file".into(),
                path: Some(f.clone()),
                url: None,
                interval_time: 0,
                filter: None,
                exclude_filter: None,
                header: None,
            },
        );
        let store = ProxyProviderStore::load_all(&cfgs, Some(&dir), false)
            .await
            .unwrap();
        assert_eq!(store.index()["p"], vec!["n1".to_string()]);
        let snap = store.snapshot();
        assert_eq!(snap[0]["vehicleType"], "File");
        assert_eq!(snap[0]["count"], 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
