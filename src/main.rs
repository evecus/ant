use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

mod app;
mod cache;
mod config;
mod dns;
mod inbound;
#[cfg(all(
    feature = "tun",
    any(target_os = "linux", target_os = "android", target_os = "windows", target_os = "macos")
))]
mod tun;
mod outbound;
mod ruleset;

use app::router::Router;
use config::Config;
use outbound::OutboundManager;

#[derive(Parser, Debug)]
#[command(name = "ant", about = "Minimal proxy (Hysteria2 + .ars rulesets; Linux/macOS/Windows)")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Commands>,

    /// Path to YAML config (when running proxy)
    #[arg(
        short = 'c',
        long = "config",
        default_value = "config.yaml",
        global = true,
        conflicts_with = "dir"
    )]
    config: String,

    /// Directory mode: use <dir>/config.yaml, or the single *.yaml file in
    /// <dir> when config.yaml is absent; relative rule-provider paths in the
    /// config resolve against <dir>
    #[arg(short = 'd', long = "dir", global = true, value_name = "DIR")]
    dir: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Convert sing-box JSON / mihomo YAML-text rule-set → binary `.ars` (by input extension)
    #[command(name = "ruleset-convert")]
    RulesetConvert {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// mihomo sources only: domain | ipcidr | classical (default: auto-detect / YAML `behavior:`)
        #[arg(short = 'b', long = "behavior")]
        behavior: Option<String>,
    },
    /// Validate a YAML config, then exit (no proxy is started)
    Check {
        /// Config file to check (defaults to the -c/--config value)
        #[arg(value_name = "CONFIG")]
        path: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    match cli.cmd {
        Some(Commands::RulesetConvert { input, output, behavior }) => {
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_env_filter(EnvFilter::new("info"))
                .init();
            let beh = behavior
                .as_deref()
                .map(ruleset::ProviderBehavior::parse)
                .transpose()?;
            ruleset::convert_to_ars(&input, &output, beh)?;
            return Ok(());
        }
        Some(Commands::Check { path }) => {
            // Runtime logs to stderr so stdout stays a clean check report.
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(std::io::stderr)
                .with_env_filter(EnvFilter::new("info"))
                .init();
            let (path, base_dir) = match (&path, &cli.dir) {
                (Some(p), _) => (p.clone(), None),
                (None, Some(d)) => {
                    let dir = std::path::PathBuf::from(d);
                    (resolve_config_in_dir(&dir)?.display().to_string(), Some(dir))
                }
                (None, None) => (cli.config.clone(), None),
            };
            return cmd_check(&path, base_dir.as_deref()).await;
        }
        None => {}
    }

    let (config_path, base_dir) = match &cli.dir {
        Some(d) => {
            let dir = std::path::PathBuf::from(d);
            (resolve_config_in_dir(&dir)?.display().to_string(), Some(dir))
        }
        None => (cli.config.clone(), None),
    };
    let mut cfg_val = Config::load(&config_path)?;
    if let Some(base) = &base_dir {
        cfg_val.resolve_ruleset_paths(base);
    }
    let cfg = std::sync::Arc::new(cfg_val);
    // 注册 bootstrap 上游（default-nameserver，纯 IP）。这里只做内存注册，
    // 不发起任何网络请求：所有域名解析都推迟到实际使用点（DNS 查询 / 拨号），
    // 失败仅影响当次操作并自然重试，绝不阻塞或终止启动。
    // DNS 模块关闭（无 dns: 块或 enable=false）时不注册 bootstrap：
    // resolve_host_via_bootstrap 直接走系统 resolver（tokio lookup_host）。
    if cfg.dns.enable {
        let ns = cfg
            .dns
            .default_nameserver
            .as_deref()
            .context("dns.enable=true requires dns.default-nameserver")?;
        crate::dns::set_bootstrap(crate::dns::parse_nameserver(ns).context("invalid default-nameserver")?);
        tracing::info!("default-nameserver {}", ns);
    } else {
        tracing::info!("dns module disabled; internal resolution uses the system resolver");
    }
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.global.log_level));
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(std::io::stderr),
        )
        .with(app::log_buffer::BufferLayer)
        .init();

    tracing::info!("ant starting, config={}", config_path);

    // Resolve SO_MARK (Linux) / route mark bookkeeping. On macOS SO_MARK is a
    // no-op but the value is still stored for logging consistency.
    #[cfg(all(
        feature = "tun",
        any(target_os = "linux", target_os = "android", target_os = "windows", target_os = "macos")
    ))]
    let mark = if cfg.tun.enable {
        let m = tun::marks_resolve(
            cfg.global.mark,
            cfg.tun.auto_route,
            cfg.tun.auto_redirect,
            cfg.tun.auto_detect_interface,
        );
        if m != 0 && cfg.global.mark == 0 {
            tracing::info!(mark = format!("0x{m:x}"), "TUN auto mark (user mark was 0)");
        }
        m
    } else {
        cfg.global.mark
    };
    #[cfg(not(all(
        feature = "tun",
        any(target_os = "linux", target_os = "android", target_os = "windows", target_os = "macos")
    )))]
    let mark = cfg.global.mark;
    app::sockopt::set_fwmark(mark);
    let bind = cfg.global.bind_address.clone();
    let ipv6 = cfg.global.ipv6;
    tracing::info!("bind-address={bind} ipv6={ipv6}");
    let cache = if cfg.global.cache {
        let path = cfg.cache_db_path(base_dir.as_deref());
        match crate::cache::AppCache::open(&path) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "cache=true but redb open failed");
                None
            }
        }
    } else {
        tracing::debug!("cache=false; DNS/FakeIP/select memory-only, rulesets use files");
        None
    };
    let router = Router::from_config(&cfg, base_dir.as_deref(), cache.clone()).await?;
    if let Ok(list) = cfg.ruleset_list(base_dir.as_deref()) {
        router.spawn_ruleset_updater(list, cache.clone());
    }
    // DNS 模块关闭时整个 dns 配置对下游（ECH upstream 等）不可见。
    let dns_ref = if cfg.dns.enable { Some(&cfg.dns) } else { None };
    let select_cache = cache.clone();
    let outbounds = OutboundManager::new(
        &cfg.proxies,
        &cfg.proxy_groups,
        &cfg.proxy_providers,
        dns_ref,
        select_cache,
    )
    .await?;
    crate::app::api::set_outbounds(outbounds.clone());
    crate::app::api::set_router(router.clone());
    crate::app::api::set_config(cfg.clone());

    let mut handles = Vec::new();

    if cfg.global.mixed_port.unwrap_or(0) > 0 {
        let r = router.clone();
        let o = outbounds.clone();
        let port = cfg.global.mixed_port.unwrap();
        let bind = bind.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::run_mixed(port, bind, ipv6, r, o).await {
                tracing::error!("mixed inbound exited: {e:#}");
            }
        }));
    }

    if cfg.global.http_port.unwrap_or(0) > 0 {
        let r = router.clone();
        let o = outbounds.clone();
        let port = cfg.global.http_port.unwrap();
        let bind = bind.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::run_http(port, bind, ipv6, r, o).await {
                tracing::error!("http inbound exited: {e:#}");
            }
        }));
    }

    if cfg.global.socks_port.unwrap_or(0) > 0 {
        let r = router.clone();
        let o = outbounds.clone();
        let port = cfg.global.socks_port.unwrap();
        let bind = bind.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::run_socks(port, bind, ipv6, r, o).await {
                tracing::error!("socks inbound exited: {e:#}");
            }
        }));
    }

    // TPROXY / REDIRECT inbounds are Linux/Android-only (netfilter sockopts);
    // excluded from Windows builds at compile time.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if cfg.global.tproxy_port.unwrap_or(0) > 0 {
        let r = router.clone();
        let o = outbounds.clone();
        let port = cfg.global.tproxy_port.unwrap();
        let bind = bind.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::run_tproxy(port, bind, ipv6, r, o).await {
                tracing::error!("tproxy inbound exited: {e:#}");
            }
        }));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if cfg.global.redir_port.unwrap_or(0) > 0 {
        let r = router.clone();
        let o = outbounds.clone();
        let port = cfg.global.redir_port.unwrap();
        let bind = bind.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::run_redir(port, bind, ipv6, r, o).await {
                tracing::error!("redir inbound exited: {e:#}");
            }
        }));
    }

    // TUN: Linux / Android / Windows / macOS (system stack + optional OS integration).
    #[cfg(all(
        feature = "tun",
        any(target_os = "linux", target_os = "android", target_os = "windows", target_os = "macos")
    ))]
    if cfg.tun.enable {
        let r = router.clone();
        let o = outbounds.clone();
        let c = cfg.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = tun::run_tun(c, r, o).await {
                tracing::error!("tun inbound exited: {e:#}");
            }
        }));
    }

    // tproxy/redir are Linux-only; warn if configured on other platforms.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        if cfg.global.tproxy_port.unwrap_or(0) > 0 {
            tracing::warn!("tproxy-port is Linux/Android-only; ignored on this platform");
        }
        if cfg.global.redir_port.unwrap_or(0) > 0 {
            tracing::warn!("redir-port is Linux/Android-only; ignored on this platform");
        }
    }

    if !cfg.global.api.trim().is_empty() {
        match app::api::parse_listen(&cfg.global.api) {
            Ok(addr) => {
                handles.push(tokio::spawn(async move {
                    if let Err(e) = app::api::run_api(addr).await {
                        tracing::error!("api exited: {e:#}");
                    }
                }));
            }
            Err(e) => tracing::error!("invalid api={}: {e:#}", cfg.global.api),
        }
    }

    // DNS 模块启用且配置了 port 时才监听；省略 port = 仅劫持应答（无监听）。
    if cfg.dns.enable && cfg.dns.listen_port() > 0 {
        let c = cfg.clone();
        let r = router.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = dns::run_dns_server(c, r).await {
                tracing::error!("dns server exited: {e:#}");
            }
        }));
    }

    if handles.is_empty() {
        anyhow::bail!(
            "no inbound enabled (set mixed-port / http-port / socks-port / tproxy-port / redir-port / tun.enable / api / dns.port)"
        );
    }

    tracing::info!("ant ready");
    // Graceful shutdown: abort tasks so TUN RouteGuard/RedirectGuard Drop runs
    // and cleans ip rule / nftables (same responsibility as sing-tun Close).
    let aborts: Vec<_> = handles.iter().map(|h| h.abort_handle()).collect();
    tokio::select! {
        _ = futures::future::join_all(handles) => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("signal: shutting down, cleaning TUN routes/redirect...");
            for a in aborts {
                a.abort();
            }
            // Allow Drop to run inside aborted tasks
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        }
    }
    tracing::info!("ant stopped");
    Ok(())
}

/// Resolve the config file inside a `-d/--dir` directory:
/// 1. `<dir>/config.yaml` if it exists (other-named yaml files may coexist);
/// 2. otherwise the single other `*.yaml`/`*.yml` file in `<dir>` — if there
///    are none, or more than one, fail fast.
fn resolve_config_in_dir(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    if !dir.is_dir() {
        anyhow::bail!("-d/--dir `{}` is not an existing directory", dir.display());
    }
    let config_yaml = dir.join("config.yaml");
    if config_yaml.is_file() {
        return Ok(config_yaml);
    }
    let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
        })
        .collect();
    candidates.sort();
    match candidates.len() {
        0 => anyhow::bail!(
            "no `config.yaml` and no *.yaml file found in `{}`",
            dir.display()
        ),
        1 => Ok(candidates.remove(0)),
        n => anyhow::bail!(
            "no `config.yaml` in `{}` and {n} yaml files found; keep exactly one of: {}",
            dir.display(),
            candidates
                .iter()
                .map(|p| p.file_name().unwrap_or_default().to_string_lossy())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `ant check <config.yaml>` — walk the full startup path except dialing:
/// YAML parse + validate, bootstrap DNS resolution, .ars ruleset loading,
/// and outbound (dialer) construction. Exits non-zero on the first failure.
///
/// `base_dir` (from `-d/--dir`) resolves relative rule-provider paths.
async fn cmd_check(path: &str, base_dir: Option<&std::path::Path>) -> Result<()> {
    println!("checking config: {path}");

    let mut cfg = Config::load(path).context("config invalid")?;
    if let Some(base) = base_dir {
        cfg.resolve_ruleset_paths(base);
    }
    println!(
        "  ok    YAML parse + validate ({} proxy node(s), {} route rule(s))",
        cfg.proxies.len(),
        cfg.route.len()
    );

    anyhow::ensure!(
        cfg.global.mixed_port.unwrap_or(0) > 0
            || cfg.global.http_port.unwrap_or(0) > 0
            || cfg.global.socks_port.unwrap_or(0) > 0
            || cfg.global.tproxy_port.unwrap_or(0) > 0
            || cfg.global.redir_port.unwrap_or(0) > 0
            || cfg.tun.enable
            || !cfg.global.api.trim().is_empty()
            || (cfg.dns.enable && cfg.dns.listen_port() > 0),
        "no inbound enabled (set mixed-port / http-port / socks-port / tproxy-port / redir-port / tun.enable / api / dns.port)"
    );

    if cfg.dns.enable {
        let ns = cfg
            .dns
            .default_nameserver
            .as_deref()
            .context("dns.enable=true requires dns.default-nameserver")?;
        crate::dns::set_bootstrap(
            crate::dns::parse_nameserver(ns).context("invalid default-nameserver")?,
        );
        println!("  ok    bootstrap dns: default={}", ns);
    } else {
        println!("  ok    dns module disabled (system resolver)");
    }

    Router::from_config(&cfg, None, None).await.context("router build failed")?;
    println!(
        "  ok    router: {} ruleset(s) loaded from .ars files",
        cfg.rule_providers.len()
    );

    let dns_ref = if cfg.dns.enable { Some(&cfg.dns) } else { None };
    OutboundManager::new(
        &cfg.proxies,
        &cfg.proxy_groups,
        &cfg.proxy_providers,
        dns_ref,
        None,
    )
        .await
        .context("outbound build failed (no dial attempted)")?;
    println!("  ok    outbounds built ({} node(s), no dial)", cfg.proxies.len());

    print_summary(&cfg);
    println!("config ok: {path}");
    Ok(())
}

/// Short human-readable digest of the validated config.
fn print_summary(cfg: &Config) {
    for p in &cfg.proxies {
        let mut tags = Vec::new();
        let net = p.network.to_ascii_lowercase();
        if net != "tcp" {
            tags.push(net);
        }
        if p.reality_public_key.as_ref().is_some_and(|s| !s.is_empty()) {
            tags.push("reality".into());
        }
        if p.tls {
            tags.push("tls".into());
        }
        let tag = if tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", tags.join("+"))
        };
        println!("  node   {} {} {}:{}{}", p.name, p.ty, p.server, p.port, tag);
    }
    if let Ok(list) = cfg.ruleset_list(None) {
        for rs in &list {
            let src = match &rs.storage {
                crate::config::RulesetStorage::File(p) => p.display().to_string(),
                crate::config::RulesetStorage::Db => "redb".into(),
            };
            let extra = rs.url.as_ref().map(|u| format!(" url={u}")).unwrap_or_default();
            println!("  rules  {} ({}) <- {}{}", rs.name, rs.ty, src, extra);
        }
    }
    for line in &cfg.route {
        println!("  route  {line}");
    }
    if !cfg.dns.enable {
        println!("  dns    disabled (no dns block / enable=false; system resolver)");
    } else {
        let dns_mode = if cfg.dns.mode == "fakeip" {
            format!(
                "fakeip/{} ({} fakeip-filter rule(s))",
                cfg.dns.fakeip_filter_mode,
                cfg.dns.fakeip_filter.len()
            )
        } else {
            "redir-host".to_string()
        };
        let port_disp = if cfg.dns.listen_port() > 0 {
            cfg.dns.listen_port().to_string()
        } else {
            "-".into()
        };
        if cfg.dns.rule_follow_route {
            println!(
                "  dns    mode={dns_mode} rule-follow-route=true port={} direct={} proxy={} default={}",
                port_disp,
                cfg.dns.direct_nameserver.as_deref().unwrap_or("-"),
                cfg.dns.proxy_nameserver.as_deref().unwrap_or("-"),
                cfg.dns.default_nameserver.as_deref().unwrap_or("-")
            );
        } else {
            println!(
                "  dns    mode={dns_mode} rule-follow-route=false port={} rules={} nameserver={} default={}",
                port_disp,
                cfg.dns.rules.len(),
                cfg.dns.nameserver.as_deref().unwrap_or("-"),
                cfg.dns.default_nameserver.as_deref().unwrap_or("-")
            );
            for line in &cfg.dns.rules {
                println!("  dns    rule  {line}");
            }
        }
    }
    println!(
        "  listen mixed-port={} http-port={} socks-port={} tproxy-port={} redir-port={} api={} sniff={} auth={}",
        cfg.global.mixed_port.unwrap_or(0),
        cfg.global.http_port.unwrap_or(0),
        cfg.global.socks_port.unwrap_or(0),
        cfg.global.tproxy_port.unwrap_or(0),
        cfg.global.redir_port.unwrap_or(0),
        if cfg.global.api.is_empty() {
            "-"
        } else {
            cfg.global.api.as_str()
        },
        if cfg.global.sniff { "on" } else { "off" },
        if cfg.global.api_secret.is_empty() { "off" } else { "on" }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ant-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn dir_resolution_prefers_config_yaml() {
        let dir = make_tmp_dir("prefers");
        std::fs::write(dir.join("config.yaml"), "placeholder").unwrap();
        std::fs::write(dir.join("my-proxy.yaml"), "placeholder").unwrap();
        let p = resolve_config_in_dir(&dir).unwrap();
        assert_eq!(p, dir.join("config.yaml"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dir_resolution_single_other_yaml() {
        let dir = make_tmp_dir("single");
        std::fs::write(dir.join("my-proxy.yaml"), "placeholder").unwrap();
        let p = resolve_config_in_dir(&dir).unwrap();
        assert_eq!(p, dir.join("my-proxy.yaml"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dir_resolution_rejects_multiple_yaml() {
        let dir = make_tmp_dir("multi");
        std::fs::write(dir.join("a.yaml"), "placeholder").unwrap();
        std::fs::write(dir.join("b.yml"), "placeholder").unwrap();
        let err = resolve_config_in_dir(&dir).unwrap_err().to_string();
        assert!(err.contains("keep exactly one"), "got: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dir_resolution_rejects_empty_dir() {
        let dir = make_tmp_dir("empty");
        let err = resolve_config_in_dir(&dir).unwrap_err().to_string();
        assert!(err.contains("no `config.yaml`"), "got: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dir_resolution_rejects_missing_dir() {
        assert!(resolve_config_in_dir(std::path::Path::new("/no/such/dir-xyz")).is_err());
    }
}
