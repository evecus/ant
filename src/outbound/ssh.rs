//! SSH 出站（feature `ssh`）。
//!
//! 参考 reflex `src/outbound/ssh.rs`，按 ant 的 `OutboundDialer` 接口重写：
//! 每个 `dial_tcp` 建立一条到 SSH server 的会话，认证后用 `direct-tcpip`
//! channel 转发到目标（域名优先用 `host_hint`，让远端解析，避免本地 DNS 污染）。
//!
//! 认证顺序（与 reflex / clash-rs 一致）：公钥 → 密码 → 键盘交互（含 TOTP 2FA）。
//! SSH 没有 UDP 转发，`dial_udp` 直接报错。

use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::{ProxyConfig, SshTotpConfig};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use russh::{
    client::{self, Handle, KeyboardInteractiveAuthResponse, Msg},
    keys::ssh_key,
};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

const DEFAULT_SSH_PORT: u16 = 22;
const PASSWORD_PROMPT: &str = "Password: ";
const VERIFICATION_CODE_PROMPT: &str = "Verification code: ";
const KEYBOARD_ROUNDS: usize = 5;

// ── russh client::Handler ───────────────────────────────────────────────────

/// 校验服务端公钥：未配置 `host-key` 时接受任何公钥（仅调试用），
/// 配置了时要求精确匹配，否则返回 `UnknownKey`。
struct SshClientHandler {
    expected_keys: Vec<ssh_key::PublicKey>,
}

impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let matches = self.expected_keys.is_empty()
            || self.expected_keys.iter().any(|k| k == server_public_key);
        async move {
            if matches {
                Ok(true)
            } else {
                Err(russh::Error::UnknownKey)
            }
        }
    }
}

// ── SshOutbound ─────────────────────────────────────────────────────────────

pub struct SshOutbound {
    tag: String,
    server: String,
    port: u16,
    username: String,
    password: Option<String>,
    /// 在 `new()` 里一次性加载（PEM 内容或文件路径），fail-fast。
    private_key: Option<russh::keys::PrivateKey>,
    host_keys: Vec<ssh_key::PublicKey>,
    totp: Option<totp_rs::TOTP>,
}

impl SshOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        let tag = cfg.name.clone();
        let server = cfg.server.trim().to_string();
        if server.is_empty() {
            bail!("ssh: server is required");
        }
        let port = if cfg.port == 0 { DEFAULT_SSH_PORT } else { cfg.port };
        let username = cfg
            .username
            .clone()
            .filter(|s| !s.trim().is_empty())
            .context("ssh: username is required")?;

        // 期望的服务端公钥：解析失败的条目跳过并告警（与 reflex 一致）。
        let mut host_keys = Vec::new();
        if let Some(list) = &cfg.ssh_host_key {
            for s in list {
                match ssh_key::PublicKey::from_openssh(s) {
                    Ok(k) => host_keys.push(k),
                    Err(e) => warn!(tag = %tag, err = %e, "ssh: host-key parse failed, skipping"),
                }
            }
        }
        if cfg.ssh_host_key_algorithms.is_some() {
            debug!(
                tag = %tag,
                "ssh: host-key-algorithms is parsed but negotiated by russh defaults"
            );
        }

        let private_key = load_private_key(cfg.private_key.as_deref(), cfg.ssh_private_key_passphrase.as_deref())
            .with_context(|| format!("ssh node `{tag}`"))?;
        let totp = build_totp(cfg.ssh_totp.as_ref()).with_context(|| format!("ssh node `{tag}`"))?;

        tracing::info!("proxy node `{tag}` (ssh) ready (server={server}, port={port})");
        Ok(Self {
            tag,
            server,
            port,
            username,
            password: cfg.password.clone(),
            private_key,
            host_keys,
            totp,
        })
    }

    /// 建立并认证一条 SSH 会话。
    async fn connect_session(&self) -> Result<Handle<SshClientHandler>> {
        // 复用其他出站的解析路径：IP 直用，域名走 bootstrap DNS，
        // 避免 TUN auto-route 下解析请求环回进 ant 自己的 DNS。
        let addr = super::anytls::resolve_server(&self.server, self.port)
            .await
            .with_context(|| format!("ssh: resolve {}:{}", self.server, self.port))?;

        // 走 sockopt::connect_tcp 设 SO_MARK / 绑定物理网卡，防止 SSH 自身的
        // TCP 流量被 TUN 截获形成回环。
        let stream = crate::app::sockopt::connect_tcp(addr)
            .await
            .with_context(|| format!("ssh: tcp connect to {}:{}", self.server, self.port))?;

        let config = Arc::new(client::Config::default());
        let handler = SshClientHandler {
            expected_keys: self.host_keys.clone(),
        };
        debug!(tag = %self.tag, "ssh: connecting");
        let mut session = client::connect_stream(config, stream, handler)
            .await
            .map_err(|e| anyhow!("ssh: handshake with {}:{} failed: {e}", self.server, self.port))?;
        self.authenticate(&mut session).await?;
        Ok(session)
    }

    /// 公钥 → 密码 → 键盘交互（含 TOTP）。
    async fn authenticate(&self, session: &mut Handle<SshClientHandler>) -> Result<()> {
        if let Some(private_key) = &self.private_key {
            // best_supported_rsa_hash: Result<Option<Option<HashAlg>>, Error>
            let hash = session
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            let key_with_hash =
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(private_key.clone()), hash);
            match session
                .authenticate_publickey(&self.username, key_with_hash)
                .await
            {
                Ok(res) if res.success() => {
                    debug!(tag = %self.tag, "ssh: publickey auth succeeded");
                    return Ok(());
                }
                Ok(_) => debug!(tag = %self.tag, "ssh: publickey auth rejected, trying next"),
                Err(e) => warn!(tag = %self.tag, err = %e, "ssh: publickey auth error, trying next"),
            }
        }

        if let Some(password) = &self.password {
            match session.authenticate_password(&self.username, password).await {
                Ok(res) if res.success() => {
                    debug!(tag = %self.tag, "ssh: password auth succeeded");
                    return Ok(());
                }
                Ok(_) => debug!(tag = %self.tag, "ssh: password auth rejected, trying keyboard-interactive"),
                Err(e) => warn!(tag = %self.tag, err = %e, "ssh: password auth error, trying keyboard-interactive"),
            }
        }

        self.keyboard_interactive(session).await
    }

    /// 键盘交互：按 prompt 回填 password / TOTP 验证码。
    async fn keyboard_interactive(&self, session: &mut Handle<SshClientHandler>) -> Result<()> {
        let mut resp = session
            .authenticate_keyboard_interactive_start(&self.username, None)
            .await
            .map_err(|e| anyhow!("ssh: keyboard-interactive start failed: {e}"))?;

        for _ in 0..KEYBOARD_ROUNDS {
            match resp {
                KeyboardInteractiveAuthResponse::Success => {
                    debug!(tag = %self.tag, "ssh: keyboard-interactive auth succeeded");
                    return Ok(());
                }
                KeyboardInteractiveAuthResponse::Failure { .. } => {
                    bail!("ssh: keyboard-interactive auth rejected by server");
                }
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let answers: Vec<String> = prompts
                        .iter()
                        .map(|p| {
                            if p.prompt.contains(PASSWORD_PROMPT) {
                                self.password.clone().unwrap_or_default()
                            } else if p.prompt.contains(VERIFICATION_CODE_PROMPT) {
                                self.totp
                                    .as_ref()
                                    .and_then(|t| t.generate_current().ok())
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            }
                        })
                        .collect();
                    resp = session
                        .authenticate_keyboard_interactive_respond(answers)
                        .await
                        .map_err(|e| anyhow!("ssh: keyboard-interactive respond failed: {e}"))?;
                }
            }
        }
        bail!("ssh: keyboard-interactive auth exceeded retry limit")
    }

    /// 打开 direct-tcpip channel，返回可当字节流用的 channel。
    async fn open_channel(&self, host: String, port: u16) -> Result<SshChannelStream> {
        let session = self.connect_session().await?;
        debug!(tag = %self.tag, host = %host, port = port, "ssh: opening direct-tcpip channel");
        let channel = session
            .channel_open_direct_tcpip(host.clone(), port as u32, "0.0.0.0".to_string(), 0)
            .await
            .map_err(|e| anyhow!("ssh: open direct-tcpip to {host}:{port} failed: {e}"))?;
        Ok(SshChannelStream::new(channel, session))
    }
}

#[async_trait]
impl OutboundDialer for SshOutbound {
    async fn dial_tcp(&self, addr: std::net::SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        // 域名交给 SSH server 解析；没有域名提示时用已解析的 IP。
        let host = host_hint
            .filter(|h| !h.is_empty())
            .map(|h| h.to_string())
            .unwrap_or_else(|| addr.ip().to_string());
        let port = if addr.port() == 0 { 443 } else { addr.port() };
        let channel = self.open_channel(host, port).await?;
        Ok(Box::new(channel))
    }

    async fn dial_udp(&self, _local_hint: Option<std::net::SocketAddr>) -> Result<Box<dyn UdpSession>> {
        bail!("ssh outbound `{}` does not support UDP forwarding", self.tag)
    }
}

// ── Channel 字节流包装 ──────────────────────────────────────────────────────

/// russh 0.51 的 `ChannelStream<Msg>` 是字节流；同时持有 `Handle` 守卫，
/// 避免 channel 还在使用时会话被提前释放。
type ClientChannelStream = russh::ChannelStream<Msg>;

pub struct SshChannelStream {
    stream: ClientChannelStream,
    _session: Handle<SshClientHandler>,
}

impl SshChannelStream {
    fn new(channel: russh::Channel<Msg>, session: Handle<SshClientHandler>) -> Self {
        Self {
            stream: channel.into_stream(),
            _session: session,
        }
    }
}

impl AsyncRead for SshChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshChannelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

// ── 密钥 / TOTP 辅助 ────────────────────────────────────────────────────────

/// `private_key` 含 `"PRIVATE KEY"` 视为内联 PEM，否则视为文件路径（`~` 展开）。
fn load_private_key(
    raw: Option<&str>,
    passphrase: Option<&str>,
) -> Result<Option<russh::keys::PrivateKey>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if raw.contains("PRIVATE KEY") {
        let key = russh::keys::decode_secret_key(raw, passphrase)
            .map_err(|e| anyhow!("failed to decode inline private key: {e}"))?;
        return Ok(Some(key));
    }
    let path = expand_tilde(raw);
    let key = russh::keys::load_secret_key(&path, passphrase)
        .map_err(|e| anyhow!("failed to load private key from '{path}': {e}"))?;
    Ok(Some(key))
}

fn build_totp(opt: Option<&SshTotpConfig>) -> Result<Option<totp_rs::TOTP>> {
    let Some(opt) = opt else {
        return Ok(None);
    };
    let is_otpauth = opt
        .ty
        .as_deref()
        .map(|t| t.eq_ignore_ascii_case("otpauth"))
        .unwrap_or(false);
    if is_otpauth {
        // 与 reflex 一致：otpauth 模式用 RFC6238 默认参数解析 Base32 密钥。
        let secret = totp_rs::Secret::Encoded(opt.secret.clone())
            .to_bytes()
            .map_err(|e| anyhow!("ssh totp: invalid otpauth secret: {e:?}"))?;
        let rfc = totp_rs::Rfc6238::with_defaults(secret)
            .map_err(|e| anyhow!("ssh totp: invalid rfc6238: {e}"))?;
        let totp = totp_rs::TOTP::from_rfc6238(rfc)
            .map_err(|e| anyhow!("ssh totp: invalid otpauth: {e}"))?;
        return Ok(Some(totp));
    }
    let algorithm = match opt.algorithm.to_ascii_lowercase().as_str() {
        "sha1" => totp_rs::Algorithm::SHA1,
        "sha256" => totp_rs::Algorithm::SHA256,
        "sha512" => totp_rs::Algorithm::SHA512,
        other => bail!("ssh totp: unsupported algorithm '{other}'"),
    };
    let secret = totp_rs::Secret::Encoded(opt.secret.clone())
        .to_bytes()
        .map_err(|e| anyhow!("ssh totp: invalid secret: {e:?}"))?;
    let totp = totp_rs::TOTP::new(algorithm, opt.digits, 1, opt.step, secret)
        .map_err(|e| anyhow!("ssh totp: invalid config: {e}"))?;
    Ok(Some(totp))
}

fn expand_tilde(path: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    let Some(home) = dirs::home_dir().map(|p| p.to_string_lossy().to_string()) else {
        return path.to_string();
    };
    if path == "~" {
        home
    } else if let Some(rest) = path.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        // `~user/...` 不支持，原样返回。
        path.to_string()
    }
}
