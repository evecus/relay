//! 共用工具：地址/SNI 解析、TLS 配置构建、DNS-over-TCP 帧收发、ECS 注入。

use anyhow::Result;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 解析地址字符串为 SocketAddr，缺省端口用 default_port 补齐。
///
/// 支持的形式：
///   - `1.2.3.4`         → `1.2.3.4:default_port`
///   - `1.2.3.4:53`      → `1.2.3.4:53`
///   - `[::1]`           → `[::1]:default_port`
///   - `[::1]:53`        → `[::1]:53`
///
/// 不支持域名形式（域名应在更高层用 tokio::net::lookup_host 解析）。
pub fn parse_addr(s: &str, default_port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    anyhow::bail!("Cannot parse address: {}", s)
}

/// 解析 host:port 字符串，返回 (host, port)。
///
/// 用于 DoT/DoQ：`tls://dns.google` / `tls://8.8.8.8` / `tls://[::1]:853`。
///
/// 不解析域名为 IP —— 域名在运行时由 HostResolver 解析（lazy + 缓存），
/// 避免启动时阻塞解析 + resolv.conf 循环依赖问题。
///
/// 修复 Bug 2：旧实现 `host_part.split(':').next()` 对 `[::1]:853` 会
/// 取到 `"["`，导致 SNI 无效。现严格区分 IPv6 与 IPv4/域名。
pub fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    // 切掉路径部分（如 /dns-query，虽然 DoT/DoQ 不应有路径）
    let host_part = s.split('/').next().unwrap_or(s);

    // IPv6 字面量：[::1] 或 [::1]:port
    if host_part.starts_with('[') {
        let end = host_part
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("malformed IPv6 host: missing ']' in {}", s))?;
        let host = &host_part[1..end]; // 不含括号
        let after = &host_part[end + 1..];
        let port = if let Some(port_str) = after.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("invalid port in {}", s))?
        } else if after.is_empty() {
            default_port
        } else {
            anyhow::bail!("malformed host: {}", s);
        };
        // 校验 IPv6 地址合法性
        let _: std::net::Ipv6Addr = host
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IPv6 address: {}", host))?;
        // host 保留 IP 字符串形式（不带括号），用于 SNI
        return Ok((host.to_string(), port));
    }

    // IPv4 / 域名 + 可选端口
    // 注意：IPv6 不会到这里（已 bracket 处理），所以 rfind(':') 安全
    let (host, port) = if let Some(pos) = host_part.rfind(':') {
        let port: u16 = host_part[pos + 1..]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid port in {}", s))?;
        (host_part[..pos].to_string(), port)
    } else {
        (host_part.to_string(), default_port)
    };

    if host.is_empty() {
        anyhow::bail!("empty host in: {}", s);
    }

    Ok((host, port))
}

/// 解析 EDNS Client Subnet 配置字符串，如 "1.2.3.0/24" 或 "2001:db8::/32"。
///
/// 返回 (IpAddr, prefix_len)。解析失败返回 None 并打印 warning，
/// 让上游仍可工作（只是不注入 EDNS0_SUBNET）。
pub fn parse_client_subnet(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr_str, prefix_str) = s.split_once('/')?;
    let addr: std::net::IpAddr = addr_str.parse().ok()?;
    let prefix_len: u8 = prefix_str.parse().ok()?;
    let max = match addr {
        std::net::IpAddr::V4(_) => 32u8,
        std::net::IpAddr::V6(_) => 128u8,
    };
    if prefix_len > max {
        tracing::warn!(client_subnet = %s, "prefix_len exceeds address family max, ignoring");
        return None;
    }
    Some((addr, prefix_len))
}

/// 注入 EDNS Client Subnet (RFC 7871) OPT 选项到 DNS 请求。
///
/// 对齐 sing-box client.go:123-129：查询前注入 EDNS0_SUBNET。
/// 若请求已有 OPT 记录则附加，否则新增 OPT。
///
/// 实现方式：在 wire 字节层面操作，不依赖 hickory_proto Edns 高级 API
/// （hickory_proto 0.24 的 EdnsOption 对 ECS 支持有限）。
pub fn inject_client_subnet(
    request: &Message,
    (subnet, prefix_len): (std::net::IpAddr, u8),
) -> Result<Message> {
    let bytes = request.to_vec()?;

    // RFC 7871 §6 EDNS0_SUBNET 选项数据格式：
    //   FAMILY (2 bytes, 1=IPv4, 2=IPv6)
    //   SOURCE PREFIX-LENGTH (1 byte)
    //   SCOPE PREFIX-LENGTH (1 byte, client→server 时为 0)
    //   ADDRESS (变量长度，按 prefix_len 向上取整到字节)
    let (family, addr_bytes): (u16, Vec<u8>) = match subnet {
        std::net::IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        std::net::IpAddr::V6(v6) => (2, v6.octets().to_vec()),
    };
    let addr_byte_len = (prefix_len as usize).div_ceil(8).max(1).min(addr_bytes.len());

    let new_bytes = wire_inject_ecs(&bytes, family, prefix_len, &addr_bytes[..addr_byte_len])?;
    let new_msg = Message::from_bytes(&new_bytes)?;
    Ok(new_msg)
}

/// 在 wire 字节层面注入 EDNS0_SUBNET option。
///
/// 流程：
/// 1. 解析 DNS header（12 字节）获取 ARCOUNT
/// 2. 如已有 OPT 记录（Additional 段第一个为 TYPE=41），追加 ECS option 到其 RDATA
/// 3. 如无 OPT 记录，新增一个 OPT RR
/// 4. 更新 ARCOUNT（如新增 OPT）和 RDLENGTH（如修改 OPT）
fn wire_inject_ecs(
    msg: &[u8],
    family: u16,
    prefix_len: u8,
    addr_bytes: &[u8],
) -> Result<Vec<u8>> {
    if msg.len() < 12 {
        anyhow::bail!("dns message too short");
    }

    // 构建 ECS option 数据（TLV 格式）
    // option-code (2) + option-len (2) + option-data
    let option_data = {
        let mut data = Vec::with_capacity(4 + 4 + addr_bytes.len());
        data.extend_from_slice(&8u16.to_be_bytes()); // option-code = 8 (EDNS0_SUBNET)
        let opt_data_len = 4 + addr_bytes.len(); // family(2) + src_prefix(1) + scope_prefix(1) + addr
        data.extend_from_slice(&(opt_data_len as u16).to_be_bytes());
        data.extend_from_slice(&family.to_be_bytes());
        data.push(prefix_len);
        data.push(0); // scope prefix length = 0
        data.extend_from_slice(addr_bytes);
        data
    };

    // 解析 header
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let nscount = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let arcount = u16::from_be_bytes([msg[10], msg[11]]) as usize;

    // 跳过 Question 段
    let mut pos = 12usize;
    for _ in 0..qdcount {
        skip_qname(msg, &mut pos)?;
        pos += 4; // QTYPE + QCLASS
    }
    // 跳过 Answer + Authority
    for _ in 0..(ancount + nscount) {
        skip_rr(msg, &mut pos)?;
    }

    // 扫描 Additional 段找 OPT (TYPE=41)
    let mut opt_pos: Option<usize> = None; // OPT RR 起始位置（NAME 字段开始处）
    let mut opt_rdlength_pos: Option<usize> = None;
    let mut opt_rdata_pos: Option<usize> = None;
    let mut opt_rdata_len: usize = 0;
    let mut additional_end = pos;
    for _ in 0..arcount {
        let rr_start = pos;
        skip_qname(msg, &mut pos)?;
        if pos + 10 > msg.len() {
            anyhow::bail!("additional RR header truncated");
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata_pos = pos + 10;
        if rtype == 41 {
            opt_pos = Some(rr_start);
            opt_rdlength_pos = Some(pos + 8);
            opt_rdata_pos = Some(rdata_pos);
            opt_rdata_len = rdlength;
        }
        pos = rdata_pos + rdlength;
        additional_end = pos;
    }

    let mut out = Vec::with_capacity(msg.len() + option_data.len() + 11);
    out.extend_from_slice(&msg[..additional_end]);

    if let (Some(_), Some(rdlength_pos), Some(rdata_pos)) =
        (opt_pos, opt_rdlength_pos, opt_rdata_pos)
    {
        // 已有 OPT：把 ECS option 追加到 RDATA 末尾
        // 先复制 OPT 之前的所有字节（含 header、Question、Answer、Authority、之前的 Additional RRs）
        // out 已包含 msg[..additional_end]
        // 但我们需要修改 RDLENGTH，所以先重置 out 到 OPT RDLENGTH 之前
        out.truncate(rdlength_pos);

        // 新的 RDATA = 原 RDATA + option_data
        let new_rdlength = (opt_rdata_len + option_data.len()) as u16;
        out.extend_from_slice(&new_rdlength.to_be_bytes());
        // 复制原 RDATA
        out.extend_from_slice(&msg[rdata_pos..rdata_pos + opt_rdata_len]);
        // 追加 ECS option
        out.extend_from_slice(&option_data);

        // 复制 additional_end 之后的字节（如果有，理论上 Additional 段已遍历完，应为空）
        // 但 additional_end == msg.len() 时无后续
        if additional_end < msg.len() {
            out.extend_from_slice(&msg[additional_end..]);
        }

        // ARCOUNT 不变
        Ok(out)
    } else {
        // 无 OPT：在 Additional 段末尾追加新 OPT RR
        // 新 OPT RR: NAME(1, root) + TYPE(2, 41) + CLASS(2, UDPSize=1232) + TTL(4, 0) + RDLENGTH(2) + RDATA(option)
        let opt_rr = {
            let mut rr = Vec::with_capacity(11 + option_data.len());
            rr.push(0u8); // NAME = root
            rr.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
            rr.extend_from_slice(&1232u16.to_be_bytes()); // CLASS = UDP payload size
            rr.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0
            rr.extend_from_slice(&(option_data.len() as u16).to_be_bytes()); // RDLENGTH
            rr.extend_from_slice(&option_data); // RDATA
            rr
        };
        out.extend_from_slice(&opt_rr);

        // 复制 additional_end 之后的字节
        if additional_end < msg.len() {
            out.extend_from_slice(&msg[additional_end..]);
        }

        // 更新 ARCOUNT +1
        let new_arcount = (arcount + 1) as u16;
        out[10] = (new_arcount >> 8) as u8;
        out[11] = (new_arcount & 0xff) as u8;

        Ok(out)
    }
}

fn skip_qname(msg: &[u8], pos: &mut usize) -> Result<()> {
    loop {
        if *pos >= msg.len() {
            anyhow::bail!("qname truncated");
        }
        let len = msg[*pos];
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        if (len & 0xC0) == 0xC0 {
            *pos += 2;
            return Ok(());
        }
        *pos += 1 + len as usize;
    }
}

fn skip_rr(msg: &[u8], pos: &mut usize) -> Result<()> {
    skip_qname(msg, pos)?;
    if *pos + 10 > msg.len() {
        anyhow::bail!("rr header truncated");
    }
    let rdlength = u16::from_be_bytes([msg[*pos + 8], msg[*pos + 9]]) as usize;
    *pos += 10 + rdlength;
    Ok(())
}

/// 构建 rustls ClientConfig。
/// insecure=true 时使用 NoVerifier 跳过证书验证。
pub fn build_rustls_client_config(insecure: bool) -> Result<Arc<rustls::ClientConfig>> {
    use std::sync::Arc as StdArc;

    if insecure {
        // insecure 模式：用 NoVerifier 跳过证书验证
        let cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(StdArc::new(NoVerifier))
            .with_no_client_auth();
        return Ok(StdArc::new(cfg));
    }

    let mut root_store = rustls::RootCertStore::empty();
    // 优先加载 webpki-roots（内置，无系统依赖）
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // 再尝试加载系统根证书（用于自部署 CA 签发的证书）
    // rustls-native-certs 0.7: load_native_certs() -> io::Result<Vec<CertificateDer>>
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                let _ = root_store.add(cert);
            }
        }
        Err(e) => {
            tracing::warn!("Failed to load native certs: {}", e);
        }
    }

    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(StdArc::new(cfg))
}

/// 跳过证书验证的 Verifier（insecure 模式）。
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
            ED448,
        ]
    }
}

/// DNS-over-TCP 帧收发：2 字节大端长度前缀。
///
/// 整个 exchange 由调用方包在 timeout 内，避免读前缀时永久阻塞。
pub async fn tcp_framed_exchange<S>(stream: &mut S, msg: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
{
    let len = msg.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await?;

    let resp_len = stream.read_u16().await? as usize;
    if resp_len < 12 {
        anyhow::bail!("dns tcp response too short: {}", resp_len);
    }
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}
