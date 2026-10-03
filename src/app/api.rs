//! Clash-style local API: connection list + embedded UI panel.
//!
//! Opening `/ui` (or polling `/connections`) arms the connection tracker for a
//! short TTL. Closing the browser stops registration and frees the map.

use crate::app::stats;
use crate::app::ui::UI_HTML;
use anyhow::{Context, Result};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn run_api(listen: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("api bind {listen}"))?;
    tracing::info!("api panel http://{listen}/ui (tracking only while UI is open)");
    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, peer));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("api conn {peer}: {e}");
            }
        });
    }
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    _peer: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    match (req.method(), path) {
        (&Method::GET, "/") | (&Method::GET, "/ui") | (&Method::GET, "/ui/") => {
            // Arm tracker: subsequent inbound connections will be recorded.
            stats::global().touch();
            Ok(html_static(StatusCode::OK, UI_HTML))
        }
        (&Method::GET, "/connections") | (&Method::GET, "/api/connections") => {
            // list() itself touches; keeps TTL alive while the browser polls.
            let list = stats::global().list();
            let body = serde_json::to_vec(&list).unwrap_or_else(|_| b"[]".to_vec());
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json; charset=utf-8")
                .header("cache-control", "no-store")
                .body(Full::new(Bytes::from(body)))
                .unwrap())
        }
        _ => Ok(html_static(
            StatusCode::NOT_FOUND,
            "<!doctype html><title>404</title><p>not found. try <a href=\"/ui\">/ui</a>",
        )),
    }
}

fn html_static(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

pub fn parse_listen(s: &str) -> Result<SocketAddr> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty api listen");
    }
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        let port: u16 = p.parse().context("api port")?;
        let ip: std::net::IpAddr = h.parse().context("api host")?;
        return Ok(SocketAddr::new(ip, port));
    }
    anyhow::bail!("invalid api address: {s}")
}
