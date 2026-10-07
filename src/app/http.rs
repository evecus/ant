//! Minimal HTTP/HTTPS GET client (hyper + rustls), shared by rule-providers
//! and proxy-providers.
//!
//! Deliberately tiny: no connection pooling, no proxy support — these fetches
//! are rare (startup / periodic refresh) and must not pull extra dependencies
//! into the binary.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::time::Duration;

/// Default `User-Agent` sent when the caller does not override it.
pub const DEFAULT_UA: &str = "ant/0.1";

/// Whole-request deadline (connect + TLS + headers + body).
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// TCP connect deadline.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum number of 3xx hops followed before giving up.
const MAX_REDIRECTS: usize = 5;

/// Full response of a GET: status, lower-cased headers, body.
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308)
    }
    /// Lower-cased header value (empty string when absent).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }
}

/// GET `url`, following redirects; returns the body. Errors on non-2xx.
pub async fn http_get(url: &str) -> Result<Vec<u8>> {
    let resp = http_get_ex(url, &HashMap::new()).await?;
    if !resp.is_success() {
        bail!("HTTP {} fetching {url}", resp.status);
    }
    Ok(resp.body)
}

/// GET `url` with extra request headers, following redirects.
///
/// Extra headers override the defaults (`host` / `user-agent`); a header value
/// of `""` is still sent as-is.
pub async fn http_get_ex(url: &str, extra: &HashMap<String, String>) -> Result<HttpResponse> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let resp = one_hop(&current, extra).await?;
        if !resp.is_redirect() {
            return Ok(resp);
        }
        let Some(location) = resp.header("location").map(|s| s.trim().to_string()) else {
            return Ok(resp);
        };
        let next = resolve_redirect(&current, &location);
        tracing::debug!(from = %current, to = %next, status = resp.status, "following redirect");
        current = next;
    }
    bail!("too many redirects fetching {url}")
}

/// Resolve a possibly-relative `Location` against the request URL.
fn resolve_redirect(base: &str, location: &str) -> String {
    if location.contains("://") {
        return location.to_string();
    }
    let origin = match base.split("://").nth(1) {
        Some(rest) => match rest.find('/') {
            Some(i) => &base[..base.len() - rest.len() + i],
            None => base,
        },
        None => return location.to_string(),
    };
    if let Some(rest) = location.strip_prefix('/') {
        format!("{origin}/{rest}")
    } else {
        format!("{origin}/{location}")
    }
}

async fn one_hop(url: &str, extra: &HashMap<String, String>) -> Result<HttpResponse> {
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let uri: hyper::Uri = url.parse().with_context(|| format!("invalid url {url}"))?;
    let scheme = uri.scheme_str().unwrap_or("http").to_ascii_lowercase();
    if scheme == "https" {
        return https_one_hop(url, extra).await;
    }

    let connector = HttpConnector::new();
    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(connector);
    let req = build_request(url, extra)?;

    let resp = tokio::time::timeout(TOTAL_TIMEOUT, client.request(req))
        .await
        .context("download timed out")?
        .context("http request failed")?;
    collect(url, resp).await
}

fn build_request(
    url: &str,
    extra: &HashMap<String, String>,
) -> Result<hyper::Request<http_body_util::Empty<hyper::body::Bytes>>> {
    use http_body_util::Empty;
    use hyper::body::Bytes;

    let mut b = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(url)
        .header(hyper::header::USER_AGENT, DEFAULT_UA)
        .header(hyper::header::ACCEPT, "*/*");
    for (k, v) in extra {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(Empty::<Bytes>::new()).context("build request")
}

/// Shared response → `HttpResponse` conversion (works for both h1 client and
/// the hand-rolled https sender).
async fn collect(url: &str, resp: hyper::Response<hyper::body::Incoming>) -> Result<HttpResponse> {
    use http_body_util::BodyExt;

    let status = resp.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in resp.headers().iter() {
        if let Ok(val) = v.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), val.to_string());
        }
    }
    let body = tokio::time::timeout(TOTAL_TIMEOUT, resp.into_body().collect())
        .await
        .with_context(|| format!("read body of {url} timed out"))?
        .context("read body")?
        .to_bytes();
    Ok(HttpResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

/// HTTPS via a hand-rolled rustls connector (no connector crate needed because
/// hyper-util's legacy client cannot be built on a custom TLS connector
/// without pulling `hyper-rustls`).
async fn https_one_hop(url: &str, extra: &HashMap<String, String>) -> Result<HttpResponse> {
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::ServerName;
    use std::sync::Arc as StdArc;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let uri: hyper::Uri = url.parse().with_context(|| format!("invalid url {url}"))?;
    let host = uri.host().context("url missing host")?.to_string();
    let port = uri.port_u16().unwrap_or(443);
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(StdArc::new(tls_cfg));
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name {host}"))?;

    let tcp = tokio::time::timeout(
        CONNECT_TIMEOUT,
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

    let mut b = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(path)
        .header(hyper::header::HOST, host.clone())
        .header(hyper::header::USER_AGENT, DEFAULT_UA)
        .header(hyper::header::ACCEPT, "*/*");
    for (k, v) in extra {
        b = b.header(k.as_str(), v.as_str());
    }
    let req = b.body(Empty::<Bytes>::new()).context("build https request")?;

    let resp = tokio::time::timeout(TOTAL_TIMEOUT, sender.send_request(req))
        .await
        .context("https request timeout")?
        .context("https request failed")?;
    collect(url, resp).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_absolute_and_relative() {
        assert_eq!(
            resolve_redirect("http://a.com/x/y", "http://b.com/z"),
            "http://b.com/z"
        );
        assert_eq!(
            resolve_redirect("https://a.com/x/y", "/z"),
            "https://a.com/z"
        );
        assert_eq!(resolve_redirect("https://a.com", "/z"), "https://a.com/z");
        assert_eq!(resolve_redirect("https://a.com/x", "z"), "https://a.com/z");
    }
}
