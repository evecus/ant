use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod app;
mod config;
mod dns;
mod inbound;
mod outbound;
mod ruleset;

use app::router::Router;
use config::Config;
use outbound::OutboundManager;

#[derive(Parser, Debug)]
#[command(name = "ant", about = "Minimal Linux proxy (Hysteria2 + .ars rulesets)")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Commands>,

    /// Path to YAML config (when running proxy)
    #[arg(short = 'c', long = "config", default_value = "config.yaml", global = true)]
    config: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Convert mihomo rule-provider YAML/text → binary `.ars`
    #[command(name = "ruleset-convert")]
    RulesetConvert {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// domain | ipcidr | classical (default: auto-detect / YAML `behavior:`)
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
            let path = path.unwrap_or(cli.config);
            return cmd_check(&path).await;
        }
        None => {}
    }

    let mut cfg = Config::load(&cli.config)?;
    crate::dns::apply_bootstrap(&mut cfg).await?;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.global.log_level));
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(filter)
        .init();

    tracing::info!("ant starting, config={}", cli.config);

    app::sockopt::set_fwmark(cfg.global.mark);
    let bind = cfg.global.bind_address.clone();
    tracing::info!("bind-address={bind}");
    let router = Router::from_config(&cfg)?;
    let outbounds = OutboundManager::new(&cfg.proxies, Some(&cfg.dns)).await?;

    let mut handles = Vec::new();

    if cfg.global.mixed_port > 0 {
        let r = router.clone();
        let o = outbounds.clone();
        let port = cfg.global.mixed_port;
        let bind = bind.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::run_mixed(port, bind, r, o).await {
                tracing::error!("mixed inbound exited: {e:#}");
            }
        }));
    }

    // TPROXY / REDIRECT inbounds are Linux/Android-only (netfilter sockopts);
    // excluded from Windows builds at compile time.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if cfg.global.tproxy_port > 0 {
        let r = router.clone();
        let o = outbounds.clone();
        let port = cfg.global.tproxy_port;
        let bind = bind.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::run_tproxy(port, bind, r, o).await {
                tracing::error!("tproxy inbound exited: {e:#}");
            }
        }));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if cfg.global.redir_port > 0 {
        let r = router.clone();
        let o = outbounds.clone();
        let port = cfg.global.redir_port;
        let bind = bind.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::run_redir(port, bind, r, o).await {
                tracing::error!("redir inbound exited: {e:#}");
            }
        }));
    }

    if cfg.dns.port > 0 {
        let c = Arc::new(cfg.clone());
        let r = router.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = dns::run_dns_server(c, r).await {
                tracing::error!("dns server exited: {e:#}");
            }
        }));
    }

    if handles.is_empty() {
        anyhow::bail!("no inbound enabled (set mixed-port / tproxy-port / redir-port / port)");
    }

    tracing::info!("ant ready");
    futures::future::join_all(handles).await;
    Ok(())
}

/// `ant check <config.yaml>` — walk the full startup path except dialing:
/// YAML parse + validate, bootstrap DNS resolution, .ars ruleset loading,
/// and outbound (dialer) construction. Exits non-zero on the first failure.
async fn cmd_check(path: &str) -> Result<()> {
    println!("checking config: {path}");

    let mut cfg = Config::load(path).context("config invalid")?;
    println!(
        "  ok    YAML parse + validate ({} proxy node(s), {} rule(s))",
        cfg.proxies.len(),
        cfg.rules.len()
    );

    anyhow::ensure!(
        cfg.global.mixed_port > 0
            || cfg.global.tproxy_port > 0
            || cfg.global.redir_port > 0
            || cfg.dns.port > 0,
        "no inbound enabled (set mixed-port / tproxy-port / redir-port / port)"
    );

    crate::dns::apply_bootstrap(&mut cfg)
        .await
        .context("bootstrap DNS via default-nameserver failed")?;
    println!(
        "  ok    bootstrap dns: direct={} proxy={}",
        cfg.dns.direct_nameserver, cfg.dns.proxy_nameserver
    );

    Router::from_config(&cfg).context("router build failed")?;
    println!(
        "  ok    router: {} ruleset(s) loaded from .ars files",
        cfg.rule_providers.len()
    );

    OutboundManager::new(&cfg.proxies, Some(&cfg.dns))
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
    if let Ok(list) = cfg.ruleset_list() {
        for rs in &list {
            println!("  rules  {} ({}) <- {}", rs.name, rs.ty, rs.path.display());
        }
    }
    for line in &cfg.rules {
        println!("  route  {line}");
    }
    let dns_mode = if cfg.dns.mode == "fakeip" {
        format!(
            "fakeip/{} ({} fakeip-filter rule(s))",
            cfg.dns.fakeip_filter_mode,
            cfg.dns.fakeip_filter.len()
        )
    } else {
        "redir-host".to_string()
    };
    println!(
        "  dns    mode={dns_mode} port={} direct={} proxy={} default={}",
        cfg.dns.port,
        cfg.dns.direct_nameserver,
        cfg.dns.proxy_nameserver,
        cfg.dns.default_nameserver
    );
    println!(
        "  listen mixed-port={} tproxy-port={} redir-port={} sniff={}",
        cfg.global.mixed_port,
        cfg.global.tproxy_port,
        cfg.global.redir_port,
        if cfg.global.sniff { "on" } else { "off" }
    );
}
