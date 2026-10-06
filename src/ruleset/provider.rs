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
        let behavior = match rs.ty.as_str() {
            "domain" => Some(ProviderBehavior::Domain),
            "ip" => Some(ProviderBehavior::Ipcidr),
            "classical" => Some(ProviderBehavior::Classical),
            _ => None,
        };
        let loaded = load_one(rs, behavior, cache).await?;
        out.insert(rs.name.clone(), loaded);
    }
    Ok(out)
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
        let data = http_get(url)
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

/// Minimal HTTP GET using hyper (already in tree).
async fn http_get(url: &str) -> Result<Vec<u8>> {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use std::time::Duration;

    let uri: hyper::Uri = url.parse().with_context(|| format!("invalid url {url}"))?;
    let scheme = uri.scheme_str().unwrap_or("http");

    if scheme == "https" {
        return http_get_https(url).await;
    }

    let connector = HttpConnector::new();
    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(connector);
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri)
        .header(hyper::header::USER_AGENT, "ant/0.1")
        .body(Empty::<Bytes>::new())
        .context("build request")?;

    let resp = tokio::time::timeout(Duration::from_secs(30), client.request(req))
        .await
        .context("download timed out")?
        .context("http request failed")?;

    let status = resp.status();
    if !status.is_success() {
        bail!("HTTP {status} fetching {url}");
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .context("read body")?
        .to_bytes();
    Ok(body.to_vec())
}

async fn http_get_https(url: &str) -> Result<Vec<u8>> {
    https_get_rustls(url).await
}

async fn https_get_rustls(url: &str) -> Result<Vec<u8>> {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::ServerName;
    use std::sync::Arc as StdArc;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let uri: hyper::Uri = url.parse().with_context(|| format!("invalid url {url}"))?;
    let host = uri.host().context("url missing host")?.to_string();
    let port = uri.port_u16().unwrap_or(443);
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(StdArc::new(tls_cfg));
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name {host}"))?;

    let tcp = tokio::time::timeout(
        Duration::from_secs(15),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .context("tcp connect timeout")?
    .with_context(|| format!("tcp connect {host}:{port}"))?;

    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("tls handshake")?;
    let io = TokioIo::new(tls);

    let (mut sender, conn) = http1::handshake(io).await.context("http1 handshake")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(path)
        .header(hyper::header::HOST, host)
        .header(hyper::header::USER_AGENT, "ant/0.1")
        .body(Empty::<Bytes>::new())
        .context("build https request")?;

    let resp = tokio::time::timeout(Duration::from_secs(30), sender.send_request(req))
        .await
        .context("https request timeout")?
        .context("https request failed")?;

    let status = resp.status();
    if !status.is_success() {
        bail!("HTTPS {status} fetching {url}");
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .context("read https body")?
        .to_bytes();
    Ok(body.to_vec())
}
