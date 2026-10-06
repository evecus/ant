//! Clash-style local API: dashboard UI + JSON endpoints.
//!
//! Connection tracking is controlled by the top-level config key
//! `api-connection-record` (default true = always record live sessions).
//! When set to false, opening `/ui` (or polling `/connections`) arms the
//! tracker for a short TTL; closing the browser stops registration and frees
//! the map.

use crate::app::stats;
use crate::app::ui::{LOGIN_HTML, UI_HTML};
use crate::config::Config;
use crate::outbound::OutboundManager;
use anyhow::{Context, Result};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{COOKIE, SET_COOKIE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;

static OUTBOUNDS: RwLock<Option<Arc<OutboundManager>>> = RwLock::new(None);
static CONFIG: RwLock<Option<Arc<Config>>> = RwLock::new(None);
/// api-secret 鉴权状态：None = 未启用（无 api-secret 字段）。
static AUTH: RwLock<Option<AuthState>> = RwLock::new(None);

/// 鉴权 Cookie 名。登录成功后下发，Max-Age 一年，浏览器持久保存。
const AUTH_COOKIE: &str = "ant_auth";

struct AuthState {
    secret: String,
    /// 登录成功后下发的随机 token（进程内有效）。
    token: String,
}

pub fn set_outbounds(m: Arc<OutboundManager>) {
    *OUTBOUNDS.write().unwrap() = Some(m);
}

pub fn set_config(c: Arc<Config>) {
    *CONFIG.write().unwrap() = Some(c.clone());
    // Wire connection-recording mode into the stats tracker.
    stats::set_always_record(c.global.api_connection_record);
    if c.global.api_connection_record {
        tracing::info!("api connection record: always-on (api-connection-record: true)");
    } else {
        tracing::info!("api connection record: opt-in while UI open (api-connection-record: false)");
    }
    let secret = c.global.api_secret.clone();
    if secret.is_empty() {
        *AUTH.write().unwrap() = None;
    } else {
        // token 每次启动随机生成：改密码 / 重启即全部失效。
        let token = hex::encode(rand::random::<[u8; 32]>());
        *AUTH.write().unwrap() = Some(AuthState { secret, token });
        tracing::info!("api auth enabled (api-secret set); login required for /ui");
    }
}

fn outbounds() -> Option<Arc<OutboundManager>> {
    OUTBOUNDS.read().unwrap().clone()
}

fn config() -> Option<Arc<Config>> {
    CONFIG.read().unwrap().clone()
}

pub async fn run_api(listen: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("api bind {listen}"))?;
    tracing::info!("api panel http://{listen}/ui");
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
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    // ── api-secret 鉴权门 ────────────────────────────────────────
    // 未携带有效凭证时：POST /login 处理登录；页面路径回登录页；
    // JSON 接口回 401（前端 fetch 包装器收到 401 自动跳回登录）。
    if !authorized(&req) {
        if req.method() == Method::POST && (path == "/login" || path == "/api/login") {
            return Ok(handle_login(req).await);
        }
        if path == "/" || path == "/ui" || path == "/ui/" {
            return Ok(html_static(StatusCode::OK, LOGIN_HTML));
        }
        return Ok(json_msg(StatusCode::UNAUTHORIZED, "unauthorized: login required"));
    }

    match (req.method(), path.as_str()) {
        (&Method::GET, "/") | (&Method::GET, "/ui") | (&Method::GET, "/ui/") => {
            stats::global().touch();
            Ok(html_static(StatusCode::OK, UI_HTML))
        }
        (&Method::GET, "/connections") | (&Method::GET, "/api/connections") => {
            let list = stats::global().list();
            Ok(json_body(StatusCode::OK, &list))
        }
        (&Method::GET, "/proxies") | (&Method::GET, "/api/proxies") => {
            let body = match outbounds() {
                Some(m) => m.group_status(),
                None => Vec::new(),
            };
            Ok(json_body(StatusCode::OK, &body))
        }
        (&Method::GET, "/configs") | (&Method::GET, "/api/configs") => {
            Ok(json_body(StatusCode::OK, &build_info()))
        }
        // PUT /proxies/{group}
        (&Method::PUT, p)
            if p.starts_with("/proxies/") || p.starts_with("/api/proxies/") =>
        {
            let rest = p
                .trim_start_matches("/api")
                .trim_start_matches("/proxies/")
                .trim_matches('/');
            // delay endpoint is GET only; if path ends with /delay, 405
            if rest.ends_with("/delay") {
                return Ok(json_msg(StatusCode::METHOD_NOT_ALLOWED, "use GET for delay"));
            }
            let group = rest;
            let body = match read_body(req).await {
                Ok(b) => b,
                Err(e) => return Ok(json_msg(StatusCode::BAD_REQUEST, &format!("body: {e}"))),
            };
            let name = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()));
            let Some(member) = name else {
                return Ok(json_msg(
                    StatusCode::BAD_REQUEST,
                    "JSON body must include {\"name\":\"member\"}",
                ));
            };
            let Some(m) = outbounds() else {
                return Ok(json_msg(StatusCode::SERVICE_UNAVAILABLE, "outbounds not ready"));
            };
            match m.set_group(group, &member) {
                Ok(()) => Ok(json_msg(StatusCode::OK, "ok")),
                Err(e) => Ok(json_msg(StatusCode::BAD_REQUEST, &format!("{e:#}"))),
            }
        }
        // GET /proxies/{name}/delay?url=&timeout=
        (&Method::GET, p)
            if (p.starts_with("/proxies/") || p.starts_with("/api/proxies/"))
                && p.ends_with("/delay") =>
        {
            let rest = p
                .trim_start_matches("/api")
                .trim_start_matches("/proxies/")
                .trim_end_matches("/delay")
                .trim_matches('/');
            let name = percent_decode(rest);
            let mut url = "http://www.gstatic.com/generate_204".to_string();
            let mut timeout_ms: u64 = 5000;
            for pair in query.split('&') {
                let mut it = pair.splitn(2, '=');
                let k = it.next().unwrap_or("");
                let v = it.next().unwrap_or("");
                if k == "url" {
                    url = percent_decode(v);
                } else if k == "timeout" {
                    timeout_ms = v.parse().unwrap_or(5000);
                }
            }
            let Some(m) = outbounds() else {
                return Ok(json_msg(StatusCode::SERVICE_UNAVAILABLE, "outbounds not ready"));
            };
            let name2 = name.clone();
            let url2 = url.clone();
            let fut = m.delay(&name2, &url2);
            let delay = match tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms.max(500)),
                fut,
            )
            .await
            {
                Ok(Some(ms)) => ms as i64,
                _ => -1,
            };
            Ok(json_body(
                StatusCode::OK,
                &serde_json::json!({ "delay": delay, "name": name, "url": url }),
            ))
        }
        _ => Ok(html_static(
            StatusCode::NOT_FOUND,
            "<!doctype html><title>404</title><p>not found. try <a href=\"/ui\">/ui</a>",
        )),
    }
}

// ── api-secret 鉴权 ─────────────────────────────────────────────

/// 请求是否已授权：未配置 api-secret 一律放行；否则校验 Cookie
/// `ant_auth=<token>` 或 `Authorization: Bearer <token>`。
fn authorized(req: &Request<hyper::body::Incoming>) -> bool {
    let guard = AUTH.read().unwrap();
    let Some(auth) = guard.as_ref() else {
        return true;
    };
    let cookie_ok = req
        .headers()
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(';').any(|pair| {
                let pair = pair.trim();
                match pair.strip_prefix(AUTH_COOKIE) {
                    Some(rest) => rest.strip_prefix('=') == Some(auth.token.as_str()),
                    None => false,
                }
            })
        });
    if cookie_ok {
        return true;
    }
    req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| ct_eq(t, &auth.token))
        .unwrap_or(false)
}

/// POST /login：body `{"password": "..."}`。成功 → 下发凭证 Cookie（一年有效）。
async fn handle_login(req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return json_msg(StatusCode::BAD_REQUEST, &format!("body: {e}")),
    };
    let password = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("password").and_then(|p| p.as_str()).map(|s| s.to_string()));
    let Some(password) = password else {
        return json_msg(StatusCode::BAD_REQUEST, "JSON body must include {\"password\":\"...\"}");
    };
    let guard = AUTH.read().unwrap();
    let Some(auth) = guard.as_ref() else {
        return json_msg(StatusCode::BAD_REQUEST, "api-secret is not configured");
    };
    if !ct_eq(&password, &auth.secret) {
        return json_msg(StatusCode::UNAUTHORIZED, "wrong password");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(
            SET_COOKIE,
            format!("{AUTH_COOKIE}={}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax", auth.token),
        )
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from_static(b"{\"message\":\"ok\"}")))
        .unwrap()
}

/// 常数时间字符串比较（避免时序侧信道泄漏密码/前缀匹配）。
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn build_info() -> serde_json::Value {
    let Some(c) = config() else {
        return serde_json::json!({});
    };
    let rule_providers: Vec<serde_json::Value> = c
        .rule_providers
        .iter()
        .map(|(name, p)| {
            serde_json::json!({
                "name": name,
                "type": p.ty,
                "behavior": p.behavior,
                "path": p.path.as_ref().map(|x| x.display().to_string()).unwrap_or_default(),
                "url": p.url,
            })
        })
        .collect();
    let proxies: Vec<String> = outbounds()
        .map(|m| m.node_names().to_vec())
        .unwrap_or_else(|| c.proxies.iter().map(|p| p.name.clone()).collect());
    serde_json::json!({
        "mixed_port": c.global.mixed_port.unwrap_or(0),
        "tproxy_port": c.global.tproxy_port.unwrap_or(0),
        "redir_port": c.global.redir_port.unwrap_or(0),
        "api": c.global.api,
        "bind_address": c.global.bind_address,
        "log_level": c.global.log_level,
        "sniff": c.global.sniff,
        "auth": !c.global.api_secret.is_empty(),
        "api_connection_record": c.global.api_connection_record,
        "dns_enable": c.dns.enable,
        "dns_port": if c.dns.enable { serde_json::json!(c.dns.listen_port()) } else { serde_json::Value::Null },
        "dns_mode": c.dns.mode,
        "dns_rule_follow_route": c.dns.rule_follow_route,
        "dns_default_nameserver": c.dns.default_nameserver,
        "dns_direct_nameserver": c.dns.direct_nameserver,
        "dns_proxy_nameserver": c.dns.proxy_nameserver,
        "fakeip_range": c.dns.fakeip_range,
        "fakeip6_range": c.dns.fakeip6_range,
        "dns_ipv6": c.dns.ipv6,
        "tun_enable": c.tun.enable,
        "tun_stack": "system",
        "tun_device": c.tun.device,
        "tun_auto_route": c.tun.auto_route,
        "tun_strict_route": c.tun.strict_route,
        "tun_auto_detect_interface": c.tun.auto_detect_interface,
        "tun_dns_hijack": c.tun.dns_hijack,
        "rule_providers": rule_providers,
        "route": c.route,
        "proxies": proxies,
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = hex(bytes[i + 1]);
                let l = hex(bytes[i + 2]);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn html_static(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

fn json_body<T: serde::Serialize>(status: StatusCode, val: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn read_body(req: Request<hyper::body::Incoming>) -> Result<Vec<u8>, String> {
    use http_body_util::BodyExt;
    let collected = req
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?;
    Ok(collected.to_bytes().to_vec())
}

fn json_msg(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "message": msg }).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Parse `host:port` or `:port` or `port` into a listen address (default host 127.0.0.1).
pub fn parse_listen(s: &str) -> Result<SocketAddr> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    if let Some(rest) = s.strip_prefix(':') {
        let port: u16 = rest.parse().context("api port")?;
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    // host:port without brackets
    if let Some((h, p)) = s.rsplit_once(':') {
        let port: u16 = p.parse().context("api port")?;
        let ip: std::net::IpAddr = h.parse().context("api host")?;
        return Ok(SocketAddr::new(ip, port));
    }
    anyhow::bail!("invalid api listen address: {s}")
}
