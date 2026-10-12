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
    let uri: hyper::Uri = url.parse().with_context(|| format!("invalid url {url}"))?;
    let scheme = uri.scheme_str().unwrap_or("http").to_ascii_lowercase();
    if scheme == "https" {
        https_one_hop(url, extra).await
    } else {
        http_one_hop(url, extra).await
    }
}

/// Dial `host:port`.
///
/// With the Android `VpnService.protect()` bridge active (`ANT_PROTECT_SOCK`),
/// go through `sockopt::connect_tcp` (bootstrap DNS + protected socket) so the
/// fetch bypasses our own VPN. Everywhere else: plain `TcpStream::connect`,
/// exactly as before.
async fn dial(host: &str, port: u16) -> Result<tokio::net::TcpStream> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if crate::app::protect::enabled() {
        return tokio::time::timeout(CONNECT_TIMEOUT, async {
            let addr = crate::dns::resolve_host_via_bootstrap(host, port).await?;
            crate::app::sockopt::connect_tcp(addr).await
        })
        .await
        .context("tcp connect timeout")?
        .with_context(|| format!("tcp connect {host}:{port}"));
    }
    tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((host, port)))
        .await
        .context("tcp connect timeout")?
        .with_context(|| format!("tcp connect {host}:{port}"))
}

/// `Host` header value: bare host for the scheme's default port, else `host:port`.
fn host_header(host: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Plain HTTP over a socket from [`dial`].
async fn http_one_hop(url: &str, extra: &HashMap<String, String>) -> Result<HttpResponse> {
    let uri: hyper::Uri = url.parse().with_context(|| format!("invalid url {url}"))?;
    let host = uri.host().context("url missing host")?.to_string();
    let port = uri.port_u16().unwrap_or(80);
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let tcp = dial(&host, port).await?;
    send_h1(url, tcp, &host_header(&host, port, 80), path, extra).await
}

/// Send one GET over an established stream (plain TCP or TLS).
async fn send_h1<T>(
    url: &str,
    io: T,
    host_header: &str,
    path: &str,
    extra: &HashMap<String, String>,
) -> Result<HttpResponse>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;

    let (mut sender, conn) = http1::handshake(TokioIo::new(io))
        .await
        .context("http1 handshake")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut b = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(path)
        .header(hyper::header::HOST, host_header)
        .header(hyper::header::USER_AGENT, DEFAULT_UA)
        .header(hyper::header::ACCEPT, "*/*");
    for (k, v) in extra {
        b = b.header(k.as_str(), v.as_str());
    }
    let req = b.body(Empty::<Bytes>::new()).context("build request")?;

    let resp = tokio::time::timeout(TOTAL_TIMEOUT, sender.send_request(req))
        .await
        .context("http request timeout")?
        .context("http request failed")?;
    collect(url, resp).await
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
    use rustls::pki_types::ServerName;
    use std::sync::Arc as StdArc;
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

    let tcp = dial(&host, port).await?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("tls handshake")?;
    send_h1(url, tls, &host_header(&host, port, 443), path, extra).await
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

    #[test]
    fn host_header_includes_non_default_port() {
        assert_eq!(host_header("a.com", 80, 80), "a.com");
        assert_eq!(host_header("a.com", 8080, 80), "a.com:8080");
        assert_eq!(host_header("a.com", 443, 443), "a.com");
    }

    #[tokio::test]
    async fn plain_http_get_over_connect_tcp() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = c.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            req
        });
        let resp = http_one_hop(&format!("http://127.0.0.1:{port}/x?y=1"), &HashMap::new())
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
        let req = srv.await.unwrap();
        assert!(req.starts_with("GET /x?y=1 HTTP/1.1"), "{req}");
        assert!(req.to_ascii_lowercase().contains(&format!("host: 127.0.0.1:{port}")), "{req}");
    }
}
