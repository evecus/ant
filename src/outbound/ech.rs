//! ECH (Encrypted Client Hello, RFC 9849) 配置解析与获取。
//!
//! 与 reflex / sing-box `OutboundECHOptions` 语义对齐：
//! 1. `ech-config`（PEM `ECH CONFIGS` 块）或 `ech-config-path` 显式提供；
//! 2. 都没有时通过 DNS HTTPS RR（type 65）的 `ech` SVCB 参数获取。
//!
//! 解析出的 ECHConfigList 原始字节交给 rustls 的 `EchConfig::new`（rustls
//! 0.23.28+ 原生支持客户端 ECH，本模块只负责配置面，不参与握手）。
//!
//! 隐私注意：DNS 查询会以明文暴露 inner SNI（除非 upstream 本身是 DoH/DoT）。
//! 查询顺序为 proxy-nameserver（通常是加密上游）→ nameserver（rule 模式回退）
//! → default-nameserver（bootstrap）。

use anyhow::{bail, Context, Result};
use base64::Engine;

use crate::config::ProxyConfig;
use crate::dns::{exchange, DnsUpstream};

/// HTTPS RR 的 RR type（RFC 9460）。
const RR_TYPE_HTTPS: u16 = 65;
/// SVCB/HTTPS 参数 `ech` 的 key（RFC 9460 §7.1）。
const SVCB_KEY_ECH: u16 = 5;

// ── PEM 解析 ────────────────────────────────────────────────────────────────

/// 解析 PEM 格式的 ECH 配置（块类型 `ECH CONFIGS`）。
///
/// 与 sing-box `parseECHClientConfig`（`pem.Decode` + 校验 block type）一致：
/// 要求恰好包含一个 `ECH CONFIGS` 块。返回 ECHConfigList 原始字节。
pub fn parse_ech_config_pem(pem_text: &str) -> Result<Vec<u8>> {
    let begin = "-----BEGIN ECH CONFIGS-----";
    let end = "-----END ECH CONFIGS-----";

    let start = pem_text
        .find(begin)
        .ok_or_else(|| anyhow::anyhow!("PEM ECH CONFIGS block not found"))?;
    let body_start = start + begin.len();
    let end_pos = pem_text[body_start..]
        .find(end)
        .ok_or_else(|| anyhow::anyhow!("PEM ECH CONFIGS block not terminated"))?;
    let b64_body = &pem_text[body_start..body_start + end_pos];

    // PEM 每 64 字符一个换行；STANDARD 引擎不容忍空白，先全部去除再解码。
    let b64_clean: String = b64_body
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&b64_clean)
        .map_err(|e| anyhow::anyhow!("decode ECH CONFIGS base64: {e}"))?;

    // 与 sing-box 一致：要求恰好一个 PEM 块。
    if pem_text[body_start + end_pos + end.len()..].contains("-----BEGIN ECH CONFIGS-----") {
        bail!("multiple ECH CONFIGS PEM blocks found, expected exactly one");
    }
    if decoded.is_empty() {
        bail!("ECH CONFIGS block decodes to empty bytes");
    }
    Ok(decoded)
}

// ── 配置解析入口 ─────────────────────────────────────────────────────────────

/// 解析 VLESS 节点的 ECHConfigList 原始字节。
///
/// 优先级（对齐 sing-box）：
/// 1. `ech-config`（PEM 字符串）
/// 2. `ech-config-path`（PEM 文件）
/// 3. DNS HTTPS RR（查询名 = `ech-query-server-name` 或 sni；非 443 端口按
///    RFC 9460 §9.1 使用 `_<port>._https.<name>` 端口前缀命名），
///    依次尝试 `ech_dns` 中的每个 upstream。
///
/// 三个来源全部不可用时返回明确错误（fail-fast，不静默降级为非 ECH 连接）。
pub async fn resolve_ech_config_list(
    cfg: &ProxyConfig,
    sni: &str,
    ech_dns: Option<&[DnsUpstream]>,
) -> Result<Vec<u8>> {
    if let Some(pem) = cfg.ech_config.as_ref().filter(|s| !s.trim().is_empty()) {
        let bytes = parse_ech_config_pem(pem)?;
        tracing::debug!(
            node = %cfg.name,
            bytes = bytes.len(),
            "ech: loaded ECHConfigList from inline ech-config"
        );
        return Ok(bytes);
    }
    if let Some(path) = &cfg.ech_config_path {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("read ech-config-path '{}'", path.display()))?;
        let bytes = parse_ech_config_pem(&content)?;
        tracing::debug!(
            node = %cfg.name,
            path = %path.display(),
            bytes = bytes.len(),
            "ech: loaded ECHConfigList from ech-config-path"
        );
        return Ok(bytes);
    }

    let upstreams = ech_dns.unwrap_or(&[]);
    if upstreams.is_empty() {
        bail!(
            "vless `{}`: ech is enabled but no ech-config / ech-config-path is set \
             and no DNS upstream is available for the HTTPS RR lookup",
            cfg.name
        );
    }
    let base = cfg
        .ech_query_server_name
        .as_ref()
        .map(|s| s.trim().trim_end_matches('.'))
        .filter(|s| !s.is_empty())
        .unwrap_or(sni.trim_end_matches('.'));
    let query_name = https_rr_query_name(base, cfg.port);
    fetch_ech_config_from_dns(upstreams, &query_name)
        .await
        .with_context(|| format!("vless `{}`: fetch ECH config via DNS HTTPS RR", cfg.name))
}

/// HTTPS RR 查询名：443 端口直接用域名；其它端口按 RFC 9460 §9.1 加端口前缀。
fn https_rr_query_name(name: &str, port: u16) -> String {
    match port {
        443 => name.to_string(),
        port => format!("_{port}._https.{name}"),
    }
}

// ── DNS HTTPS RR 查询 ────────────────────────────────────────────────────────

/// 构造 type-65（HTTPS）DNS 查询报文（递归期望位关闭，RD=0 与上游语义无关）。
fn build_https_query(name: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0);
    q.extend_from_slice(&RR_TYPE_HTTPS.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

/// 依次尝试每个 upstream 查询 HTTPS RR 并提取 `ech` 参数，base64 解码为
/// ECHConfigList 原始字节。全部失败时返回最后一个错误。
async fn fetch_ech_config_from_dns(upstreams: &[DnsUpstream], query_name: &str) -> Result<Vec<u8>> {
    let query = build_https_query(query_name);
    let mut last_err: Option<anyhow::Error> = None;
    for up in upstreams {
        match exchange(up, &query).await {
            Ok(resp) => match extract_ech_param(&resp) {
                Some(b64) => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(b64.trim())
                        .map_err(|e| {
                            anyhow::anyhow!("decode DNS 'ech' param base64 via {up}: {e}")
                        })?;
                    if bytes.is_empty() {
                        last_err = Some(anyhow::anyhow!("DNS 'ech' param empty via {up}"));
                        continue;
                    }
                    tracing::debug!(
                        query_name = %query_name,
                        upstream = %up,
                        bytes = bytes.len(),
                        "ech: fetched ECHConfigList from DNS HTTPS RR"
                    );
                    return Ok(bytes);
                }
                None => {
                    last_err = Some(anyhow::anyhow!(
                        "no 'ech' param in DNS HTTPS RR for {query_name} via {up}"
                    ));
                }
            },
            Err(e) => {
                tracing::debug!(
                    query_name = %query_name,
                    upstream = %up,
                    "ech: HTTPS RR query failed: {e:#}"
                );
                last_err = Some(e.context(format!("query via {up}")));
            }
        }
    }
    bail!(
        "no ECH config found for {query_name} (tried {} upstream(s)): {}",
        upstreams.len(),
        last_err
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no upstream".into())
    )
}

/// 从 DNS 应答报文中提取 HTTPS RR 的 `ech` SVCB 参数（base64 字符串）。
///
/// HTTPS RR RDATA（RFC 9460 §2.2）：
/// ```text
/// SvcPriority (2B) | TargetName (domain, 可能压缩) | SvcParams...
/// 每个 SvcParam: [key (2B)][len (2B)][value ...]
/// ```
fn extract_ech_param(resp: &[u8]) -> Option<String> {
    if resp.len() < 12 {
        return None;
    }
    // 仅接受成功应答（RCODE=0），NXDOMAIN/ ServFail 不视为"无 ECH"。
    if resp[3] & 0x0F != 0 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12usize;
    // 跳过 Question 段。
    for _ in 0..u16::from_be_bytes([resp[4], resp[5]]) {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4)?; // qtype(2) + qclass(2)
    }
    // 遍历 Answer 段。
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlength > resp.len() {
            return None;
        }
        if rr_type == RR_TYPE_HTTPS {
            if let Some(v) = parse_svcb_ech_param(&resp[rdata..rdata + rdlength]) {
                return Some(v);
            }
        }
        pos = rdata + rdlength;
    }
    None
}

/// 解析 HTTPS RR RDATA 的 SvcParams，找到 `ech`（key=5）参数值。
fn parse_svcb_ech_param(rdata: &[u8]) -> Option<String> {
    if rdata.len() < 2 {
        return None;
    }
    let mut pos = 2usize; // 跳过 SvcPriority
    pos = skip_name_in(rdata, pos)?; // TargetName（可能含压缩指针）
    while pos + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            return None;
        }
        if key == SVCB_KEY_ECH {
            return std::str::from_utf8(&rdata[pos..pos + len])
                .ok()
                .map(|s| s.to_string());
        }
        pos += len;
    }
    None
}

/// 跳过 DNS 报文中的域名（支持压缩指针），返回下一字段位置。
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return pos.checked_add(2);
        }
        pos = pos.checked_add(1 + len as usize)?;
    }
}

/// 跳过 SVCB RDATA 内的域名；压缩指针在 RDATA 内表现为 2 字节跳过。
fn skip_name_in(rdata: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *rdata.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return pos.checked_add(2);
        }
        pos = pos.checked_add(1 + len as usize)?;
    }
}

// ── 测试 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 编码一个最小合法 ECHConfigList 的 base64（供 DNS 应答测试用）。
    fn test_ech_config_b64() -> String {
        // ECHConfigContents: config_id(1) + kem_id(2) + pk_len(2) + pk(32)
        //   + suites_len(2) + suites(4) + max_name_len(1) + pn_len(1) + pn + ext(2)
        let pk = vec![0x42u8; 32];
        let mut contents = Vec::new();
        contents.push(0x01); // config_id
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // kem
        contents.extend_from_slice(&(pk.len() as u16).to_be_bytes());
        contents.extend_from_slice(&pk);
        let suite = [0x0001u16.to_be_bytes(), 0x0001u16.to_be_bytes()].concat();
        contents.extend_from_slice(&(suite.len() as u16).to_be_bytes());
        contents.extend_from_slice(&suite);
        contents.push(0); // maximum_name_length
        let pn = b"cloudflare-ech.com";
        contents.push(pn.len() as u8);
        contents.extend_from_slice(pn);
        contents.extend_from_slice(&0u16.to_be_bytes()); // extensions

        let mut ech_config = 0xfe0du16.to_be_bytes().to_vec();
        ech_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        ech_config.extend_from_slice(&contents);

        let mut list = (ech_config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&ech_config);
        base64::engine::general_purpose::STANDARD.encode(&list)
    }

    /// 构造一条 HTTPS RR 应答（Question + 1 条 Answer，TargetName 内嵌压缩指针）。
    fn build_https_resp(ech_b64: &str) -> Vec<u8> {
        let name = b"\x07example\x03com\x00";
        let mut m = Vec::new();
        // header: id, flags(RCODE=0), qd=1, an=1, ns=0, ar=0
        m.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        // question
        m.extend_from_slice(name);
        m.extend_from_slice(&65u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        // answer: name 指针指向 offset 12
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(&65u16.to_be_bytes()); // type HTTPS
        m.extend_from_slice(&1u16.to_be_bytes()); // class IN
        m.extend_from_slice(&[0, 0, 0, 60]); // ttl
        // rdata: priority(2) + target(压缩指针 -> offset 12) + svparam ech
        let val = ech_b64.as_bytes();
        let rdlen = 2 + 2 + 4 + val.len();
        m.extend_from_slice(&(rdlen as u16).to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // priority
        m.extend_from_slice(&[0xC0, 0x0C]); // target 压缩指针
        m.extend_from_slice(&5u16.to_be_bytes()); // key ech
        m.extend_from_slice(&(val.len() as u16).to_be_bytes());
        m.extend_from_slice(val);
        m
    }

    #[test]
    fn extract_ech_param_from_response() {
        let b64 = test_ech_config_b64();
        let resp = build_https_resp(&b64);
        assert_eq!(extract_ech_param(&resp).as_deref(), Some(b64.as_str()));
    }

    #[test]
    fn extract_ech_param_none_on_rcode_error() {
        let b64 = test_ech_config_b64();
        let mut resp = build_https_resp(&b64);
        resp[3] |= 0x03; // NXDOMAIN
        assert!(extract_ech_param(&resp).is_none());
    }

    #[test]
    fn extract_ech_param_none_on_empty_answer() {
        let resp = vec![0u8; 12];
        assert!(extract_ech_param(&resp).is_none());
    }

    #[test]
    fn https_rr_query_name_port_prefix() {
        assert_eq!(https_rr_query_name("example.com", 443), "example.com");
        assert_eq!(
            https_rr_query_name("example.com", 8443),
            "_8443._https.example.com"
        );
    }

    #[test]
    fn parse_ech_config_pem_roundtrip() {
        let b64 = test_ech_config_b64();
        let pem = format!("-----BEGIN ECH CONFIGS-----\n{b64}\n-----END ECH CONFIGS-----\n");
        let decoded = parse_ech_config_pem(&pem).expect("parse");
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&decoded),
            b64
        );
    }

    #[test]
    fn parse_ech_config_pem_rejects_wrong_type() {
        let pem = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----";
        assert!(parse_ech_config_pem(pem).is_err());
    }

    #[test]
    fn parse_ech_config_pem_rejects_missing_end() {
        assert!(parse_ech_config_pem("-----BEGIN ECH CONFIGS-----\nZm9v\n").is_err());
    }

    #[test]
    fn parse_ech_config_pem_rejects_multiple_blocks() {
        let b64 = test_ech_config_b64();
        let block = format!(
            "-----BEGIN ECH CONFIGS-----\n{b64}\n-----END ECH CONFIGS-----\n"
        );
        assert!(parse_ech_config_pem(&format!("{block}{block}")).is_err());
    }

    #[test]
    fn parse_ech_config_pem_tolerates_whitespace() {
        let b64 = test_ech_config_b64();
        // 手动按 16 字符折行，模拟 PEM 多行 + \r\n。
        let folded: Vec<&str> = b64.as_bytes()
            .chunks(16)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let pem = format!(
            "-----BEGIN ECH CONFIGS-----\r\n{}\r\n-----END ECH CONFIGS-----\n",
            folded.join("\r\n")
        );
        let decoded = parse_ech_config_pem(&pem).expect("parse");
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&decoded),
            b64
        );
    }
}

// 死代码防抖：exchange 导入用于 fetch；AsyncReadExt/AsyncWriteExt 仅为对齐
// upstream.rs 的写法（exchange 内部处理 IO），此处并不直接使用。
// 实际上它们未使用 —— 见下。
