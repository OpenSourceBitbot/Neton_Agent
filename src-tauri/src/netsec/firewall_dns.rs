// yxpil · NETON
//! 防火墙规则测试与 DNS 安全模块
//!
//! 提供防火墙出站/入站端口测试、防火墙绕过检测、IDS/IPS 检测、
//! 防火墙规则审计，以及 DNS 服务器检测、DNS 泄露测试、DNS 投毒检测、
//! DNSSEC 验证、邮件安全检查（SPF/DKIM/DMARC）、DNS 隧道检测、
//! 反向 DNS 查询等功能。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant};
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::rdata::TXT;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::Resolver;

// ============================================================================
// 第一部分：防火墙结构体
// ============================================================================

/// 端口状态
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortStatus {
    /// 开放
    Open,
    /// 关闭
    Closed,
    /// 过滤（防火墙拦截）
    Filtered,
    /// 开放|过滤（无法确定）
    OpenFiltered,
}

/// 防火墙测试配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallTestConfig {
    /// 目标主机
    pub target: String,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
    /// 并发数（保留字段）
    pub concurrency: usize,
    /// 是否启用分片绕过测试
    pub enable_fragment: bool,
    /// 源端口欺骗列表
    pub spoof_source_ports: Vec<u16>,
}

impl Default for FirewallTestConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".to_string(),
            timeout_ms: 2000,
            concurrency: 50,
            enable_fragment: false,
            spoof_source_ports: vec![53, 80, 443],
        }
    }
}

/// 端口测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortTestResult {
    /// 端口号
    pub port: u16,
    /// 状态
    pub status: PortStatus,
    /// 服务名称
    pub service: String,
    /// 响应时间（毫秒）
    pub response_time_ms: u64,
}

/// 防火墙绕过测试类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassTestType {
    /// FIN 扫描
    FinScan,
    /// NULL 扫描（无标志位）
    NullScan,
    /// XMAS 扫描（FIN+PSH+URG）
    XmasScan,
    /// ACK 扫描
    AckScan,
    /// 分片绕过
    FragmentBypass,
    /// 源端口欺骗
    SourcePortSpoof,
    /// 时间戳规避
    TimestampEvasion,
}

/// 防火墙绕过测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallBypassResult {
    /// 目标主机
    pub target: String,
    /// 测试端口
    pub port: u16,
    /// 测试类型
    pub test_type: BypassTestType,
    /// 是否可能绕过
    pub possible_bypass: bool,
    /// 测试详情
    pub details: String,
    /// 响应时间（毫秒）
    pub response_time_ms: u64,
    /// 是否支持（底层能力限制）
    pub supported: bool,
}

/// IDS/IPS 检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsIpsDetectionResult {
    /// 目标主机
    pub target: String,
    /// 是否疑似存在 IDS/IPS
    pub suspected_ids_ips: bool,
    /// 置信度 (0-100)
    pub confidence: u8,
    /// 检测指标
    pub indicators: Vec<String>,
    /// WAF 检测结果
    pub waf_detected: bool,
    /// WAF 名称（如果检测到）
    pub waf_name: Option<String>,
}

/// 危险端口信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousPortInfo {
    /// 端口号
    pub port: u16,
    /// 服务名称
    pub service: String,
    /// 风险等级
    pub risk_level: String,
    /// 风险描述
    pub description: String,
    /// 是否开放
    pub is_open: bool,
}

/// 防火墙审计结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallAuditResult {
    /// 目标主机
    pub target: String,
    /// 危险端口检查结果
    pub dangerous_ports: Vec<DangerousPortInfo>,
    /// 开放的危险端口数量
    pub open_dangerous_count: usize,
    /// 建议关闭的端口列表
    pub recommended_close: Vec<u16>,
    /// 安全基线评分 (0-100)
    pub security_score: u8,
    /// 审计建议
    pub recommendations: Vec<String>,
}

/// 防火墙综合报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallReport {
    /// 目标主机
    pub target: String,
    /// 出站端口测试结果
    pub outbound_tests: Vec<PortTestResult>,
    /// 入站端口测试结果（如果有）
    pub inbound_tests: Vec<PortTestResult>,
    /// 绕过测试结果
    pub bypass_tests: Vec<FirewallBypassResult>,
    /// IDS/IPS 检测结果
    pub ids_ips_detection: Option<IdsIpsDetectionResult>,
    /// 审计结果
    pub audit: Option<FirewallAuditResult>,
    /// 总耗时（毫秒）
    pub total_duration_ms: u64,
}

// ============================================================================
// 第二部分：DNS 安全结构体
// ============================================================================

/// DNS 服务器信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerInfo {
    /// 服务器地址
    pub address: String,
    /// 服务器名称（如果可识别）
    pub name: Option<String>,
    /// 是否支持 DNSSEC
    pub supports_dnssec: Option<bool>,
    /// 平均响应时间（毫秒）
    pub avg_response_time_ms: u64,
    /// 是否为系统默认 DNS
    pub is_system_default: bool,
}

/// DNS 速度测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSpeedTestResult {
    /// DNS 服务器地址
    pub dns_server: String,
    /// 测试的域名列表
    pub domains: Vec<String>,
    /// 每个域名的解析时间（毫秒）
    pub domain_times: HashMap<String, u64>,
    /// 平均响应时间（毫秒）
    pub avg_time_ms: u64,
    /// 最快响应时间（毫秒）
    pub min_time_ms: u64,
    /// 最慢响应时间（毫秒）
    pub max_time_ms: u64,
    /// 成功率
    pub success_rate: f32,
}

/// DNS 泄露检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLeakResult {
    /// 是否存在泄露
    pub has_leak: bool,
    /// 检测到的 DNS 服务器列表
    pub detected_servers: Vec<String>,
    /// 配置的 DNS 服务器
    pub configured_servers: Vec<String>,
    /// WebRTC 泄露提示
    pub webrtc_leak_hint: String,
    /// 可能的泄露通道
    pub leak_channels: Vec<String>,
    /// 详细说明
    pub details: String,
}

/// DNS 投毒检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPoisonResult {
    /// 测试域名
    pub domain: String,
    /// 是否疑似投毒
    pub suspected_poisoning: bool,
    /// 置信度 (0-100)
    pub confidence: u8,
    /// 各公共 DNS 解析结果对比
    pub dns_results: HashMap<String, Vec<String>>,
    /// 异常解析标记
    pub anomalies: Vec<String>,
    /// 是否解析到内网 IP
    pub has_private_ip: bool,
    /// 内网 IP 列表
    pub private_ips: Vec<String>,
}

/// DNSSEC 验证结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecResult {
    /// 域名
    pub domain: String,
    /// 是否启用 DNSSEC
    pub dnssec_enabled: bool,
    /// 签名是否有效
    pub signature_valid: Option<bool>,
    /// DNSKEY 记录数量
    pub dnskey_count: usize,
    /// RRSIG 记录数量
    pub rrsig_count: usize,
    /// DS 记录是否存在
    pub ds_record_present: bool,
    /// 验证详情
    pub details: String,
    /// 是否支持验证（框架级）
    pub validation_supported: bool,
}

/// 邮件安全检查结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSecurityResult {
    /// 域名
    pub domain: String,
    /// SPF 记录
    pub spf_record: Option<String>,
    /// SPF 是否存在
    pub spf_exists: bool,
    /// SPF 策略评估
    pub spf_evaluation: String,
    /// SPF 允许的 IP 数量
    pub spf_allowed_ip_count: usize,
    /// DMARC 记录
    pub dmarc_record: Option<String>,
    /// DMARC 是否存在
    pub dmarc_exists: bool,
    /// DMARC 策略
    pub dmarc_policy: Option<String>,
    /// DMARC 策略评估
    pub dmarc_evaluation: String,
    /// DKIM 测试结果（常见选择器）
    pub dkim_selectors_tested: Vec<DkimSelectorResult>,
    /// 整体安全评级
    pub overall_rating: String,
    /// 建议
    pub recommendations: Vec<String>,
}

/// DKIM 选择器测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimSelectorResult {
    /// 选择器名称
    pub selector: String,
    /// 是否存在
    pub exists: bool,
    /// 公钥（如果存在）
    pub public_key: Option<String>,
}

/// PTR 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtrRecord {
    /// IP 地址
    pub ip: String,
    /// 反向解析的域名
    pub hostnames: Vec<String>,
    /// 是否解析成功
    pub success: bool,
    /// 错误信息（如果失败）
    pub error: Option<String>,
}

/// DNS 隧道检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTunnelDetectResult {
    /// 测试域名
    pub domain: String,
    /// 是否疑似 DNS 隧道
    pub suspected_tunnel: bool,
    /// 置信度 (0-100)
    pub confidence: u8,
    /// 子域名长度异常
    pub subdomain_length_anomaly: bool,
    /// 最长子域名长度
    pub max_subdomain_length: usize,
    /// 子域名熵值
    pub subdomain_entropy: f64,
    /// 高熵子域名检测
    pub high_entropy_detected: bool,
    /// 检测指标详情
    pub indicators: Vec<String>,
}

/// DNS 安全综合报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSecurityReport {
    /// DNS 服务器信息
    pub dns_servers: Vec<DnsServerInfo>,
    /// 速度测试结果
    pub speed_test: Option<DnsSpeedTestResult>,
    /// 泄露测试结果
    pub leak_test: Option<DnsLeakResult>,
    /// 投毒检测结果
    pub poison_test: Option<DnsPoisonResult>,
    /// DNSSEC 结果
    pub dnssec: Option<DnssecResult>,
    /// 邮件安全结果
    pub email_security: Option<EmailSecurityResult>,
    /// 反向 DNS 结果
    pub reverse_dns: Option<PtrRecord>,
    /// DNS 隧道检测结果
    pub tunnel_detect: Option<DnsTunnelDetectResult>,
}

// ============================================================================
// 辅助函数：常见端口与服务映射
// ============================================================================

/// 常见端口服务映射
fn common_port_services() -> HashMap<u16, &'static str> {
    let mut map = HashMap::new();
    map.insert(21, "FTP");
    map.insert(22, "SSH");
    map.insert(23, "Telnet");
    map.insert(25, "SMTP");
    map.insert(53, "DNS");
    map.insert(80, "HTTP");
    map.insert(110, "POP3");
    map.insert(119, "NNTP");
    map.insert(135, "MS-RPC");
    map.insert(139, "NetBIOS");
    map.insert(143, "IMAP");
    map.insert(389, "LDAP");
    map.insert(443, "HTTPS");
    map.insert(445, "SMB");
    map.insert(465, "SMTPS");
    map.insert(587, "SMTP-Submission");
    map.insert(993, "IMAPS");
    map.insert(995, "POP3S");
    map.insert(1433, "MSSQL");
    map.insert(1521, "Oracle");
    map.insert(3306, "MySQL");
    map.insert(3389, "RDP");
    map.insert(5432, "PostgreSQL");
    map.insert(5900, "VNC");
    map.insert(6379, "Redis");
    map.insert(8080, "HTTP-Proxy");
    map.insert(8443, "HTTPS-Alt");
    map.insert(27017, "MongoDB");
    map
}

/// 获取常见端口列表
fn get_common_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 119, 135, 139, 143, 389, 443, 445,
        465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
        8080, 8443, 27017,
    ]
}

/// 危险端口列表（需要重点审计）
fn dangerous_ports() -> Vec<(u16, &'static str, &'static str, &'static str)> {
    vec![
        (21, "FTP", "高", "FTP 明文传输，易被嗅探密码，建议禁用或改用 SFTP"),
        (22, "SSH", "中", "SSH 远程管理，建议限制来源 IP 并使用密钥认证"),
        (23, "Telnet", "高", "Telnet 明文传输，极度不安全，建议立即关闭"),
        (135, "MS-RPC", "高", "Windows RPC 服务，常被蠕虫利用，建议限制"),
        (139, "NetBIOS", "高", "NetBIOS 服务，SMB 漏洞利用入口，建议禁用"),
        (445, "SMB", "高", "SMB 文件共享，永恒之蓝等漏洞利用入口，建议禁用"),
        (1433, "MSSQL", "高", "MSSQL 数据库，建议禁止公网访问"),
        (3306, "MySQL", "高", "MySQL 数据库，建议禁止公网访问"),
        (3389, "RDP", "高", "远程桌面，蓝洞漏洞风险，建议限制来源 IP"),
        (5432, "PostgreSQL", "中", "PostgreSQL 数据库，建议禁止公网访问"),
        (5900, "VNC", "中", "VNC 远程桌面，建议禁用或使用加密隧道"),
        (6379, "Redis", "高", "Redis 默认无认证，建议禁止公网访问"),
        (27017, "MongoDB", "高", "MongoDB 默认无认证，建议禁止公网访问"),
    ]
}

/// 解析端口字符串（支持逗号分隔，如 "22,80,443"）
fn parse_ports_str(ports_str: &str) -> Vec<u16> {
    ports_str
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect()
}

/// 执行单个 TCP 端口连接测试
fn test_tcp_port(target: &str, port: u16, timeout_ms: u64) -> (PortStatus, u64) {
    let addr = format!("{}:{}", target, port);
    let start = Instant::now();

    match TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
        Duration::from_millis(timeout_ms),
    ) {
        Ok(_) => {
            let elapsed = start.elapsed().as_millis() as u64;
            (PortStatus::Open, elapsed)
        }
        Err(e) => {
            let elapsed = start.elapsed().as_millis() as u64;
            // 根据错误类型判断是关闭还是过滤
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                (PortStatus::Closed, elapsed)
            } else if e.kind() == std::io::ErrorKind::TimedOut {
                (PortStatus::Filtered, elapsed)
            } else {
                // 其他错误也视为过滤
                (PortStatus::Filtered, elapsed)
            }
        }
    }
}

/// 获取服务名称
fn get_service_name(port: u16) -> String {
    common_port_services()
        .get(&port)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

// ============================================================================
// 防火墙测试 - 公共函数
// ============================================================================

/// 出站端口测试
///
/// 测试目标主机的指定端口是否可达（TCP 连接测试）。
/// ports 参数为逗号分隔的端口号，如 "22,80,443"。
pub fn test_outbound_ports(target: String, ports: String) -> Result<String, String> {
    let start_time = Instant::now();
    let port_list = parse_ports_str(&ports);

    if port_list.is_empty() {
        return Err("无效的端口列表".to_string());
    }

    let timeout_ms = 2000;
    let mut results: Vec<PortTestResult> = Vec::new();

    for port in &port_list {
        let (status, response_time) = test_tcp_port(&target, *port, timeout_ms);
        results.push(PortTestResult {
            port: *port,
            status,
            service: get_service_name(*port),
            response_time_ms: response_time,
        });
    }

    // 按端口号排序
    results.sort_by_key(|r| r.port);

    let report = FirewallReport {
        target: target.clone(),
        outbound_tests: results,
        inbound_tests: vec![],
        bypass_tests: vec![],
        ids_ips_detection: None,
        audit: None,
        total_duration_ms: start_time.elapsed().as_millis() as u64,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(report, "出站端口测试完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 端口范围测试
///
/// 测试目标主机指定范围内的所有端口。
pub fn test_port_range(target: String, start: u16, end: u16) -> Result<String, String> {
    let start_time = Instant::now();

    if start > end {
        return Err("起始端口不能大于结束端口".to_string());
    }

    let timeout_ms = 1500;
    let mut results: Vec<PortTestResult> = Vec::new();

    // 限制最大测试端口数，避免超时
    let max_ports = 1024;
    let actual_end = if end - start + 1 > max_ports {
        start + max_ports - 1
    } else {
        end
    };

    for port in start..=actual_end {
        let (status, response_time) = test_tcp_port(&target, port, timeout_ms);
        // 只记录开放或过滤的端口，关闭的端口太多
        if status == PortStatus::Open || status == PortStatus::Filtered {
            results.push(PortTestResult {
                port,
                status,
                service: get_service_name(port),
                response_time_ms: response_time,
            });
        }
    }

    results.sort_by_key(|r| r.port);

    let report = FirewallReport {
        target: target.clone(),
        outbound_tests: results,
        inbound_tests: vec![],
        bypass_tests: vec![],
        ids_ips_detection: None,
        audit: None,
        total_duration_ms: start_time.elapsed().as_millis() as u64,
    };

    let message = if actual_end < end {
        format!(
            "端口范围测试完成（已限制最多 {} 个端口，实际测试 {}-{}）",
            max_ports, start, actual_end
        )
    } else {
        "端口范围测试完成".to_string()
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(report, &message))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 防火墙绕过测试
///
/// 执行多种防火墙绕过检测，包括 FIN、NULL、XMAS、ACK 扫描等。
/// 注意：没有 pnet 库时，部分测试提供理论框架和配置选项。
pub fn firewall_bypass_test(target: String, port: u16) -> Result<String, String> {
    let start_time = Instant::now();
    let mut results: Vec<FirewallBypassResult> = Vec::new();

    // 1. 基础 TCP 连接测试（作为基准）
    let (base_status, base_time) = test_tcp_port(&target, port, 2000);
    let base_is_open = base_status == PortStatus::Open;

    // 2. FIN 扫描（理论框架 - 无原始套接字权限时不可用）
    results.push(FirewallBypassResult {
        target: target.clone(),
        port,
        test_type: BypassTestType::FinScan,
        possible_bypass: false,
        details: "FIN 扫描：发送 FIN 包探测端口状态。\
                  无状态防火墙可能允许 FIN 包通过。\
                  当前环境使用标准套接字，无法发送自定义 TCP 标志位，\
                  此测试为理论框架。建议使用原始套接字库（如 pnet）实现。"
            .to_string(),
        response_time_ms: 0,
        supported: false,
    });

    // 3. NULL 扫描（理论框架）
    results.push(FirewallBypassResult {
        target: target.clone(),
        port,
        test_type: BypassTestType::NullScan,
        possible_bypass: false,
        details: "NULL 扫描：发送无任何标志位的 TCP 包。\
                  某些防火墙规则未匹配无标志位数据包。\
                  当前环境使用标准套接字，无法实现，此测试为理论框架。"
            .to_string(),
        response_time_ms: 0,
        supported: false,
    });

    // 4. XMAS 扫描（理论框架）
    results.push(FirewallBypassResult {
        target: target.clone(),
        port,
        test_type: BypassTestType::XmasScan,
        possible_bypass: false,
        details: "XMAS 扫描：发送 FIN+PSH+URG 标志位组合的数据包。\
                  某些防火墙规则集可能遗漏此类非常规组合。\
                  当前环境使用标准套接字，无法实现，此测试为理论框架。"
            .to_string(),
        response_time_ms: 0,
        supported: false,
    });

    // 5. ACK 扫描（理论框架）
    results.push(FirewallBypassResult {
        target: target.clone(),
        port,
        test_type: BypassTestType::AckScan,
        possible_bypass: false,
        details: "ACK 扫描：发送 ACK 包探测防火墙规则。\
                  用于判断防火墙是有状态还是无状态。\
                  当前环境使用标准套接字，无法实现，此测试为理论框架。"
            .to_string(),
        response_time_ms: 0,
        supported: false,
    });

    // 6. 分片绕过测试（理论框架）
    results.push(FirewallBypassResult {
        target: target.clone(),
        port,
        test_type: BypassTestType::FragmentBypass,
        possible_bypass: false,
        details: "分片绕过：将 TCP 头分片到多个 IP 分片中。\
                  某些防火墙不重组分片包，导致过滤规则失效。\
                  当前环境无法控制 IP 分片，此测试为理论框架。"
            .to_string(),
        response_time_ms: 0,
        supported: false,
    });

    // 7. 源端口欺骗测试（基于常见源端口的行为差异检测）
    // 使用 TTL 和响应时间差异来推断是否有基于源端口的规则
    let mut spoof_details = String::from(
        "源端口欺骗：使用常见源端口（53/DNS、80/HTTP、443/HTTPS）测试\
         是否存在基于源端口的防火墙规则差异。\n",
    );

    // 标准连接测试作为参照
    spoof_details.push_str(&format!(
        "基准测试（随机源端口）：端口{} {:?}，响应时间 {}ms\n",
        port, base_status, base_time
    ));

    // 注意：标准 TCP 套接字无法指定源端口进行欺骗，
    // 这里提供配置框架和检测思路
    spoof_details.push_str(
        "提示：标准 TCP 套接字无法主动指定源端口进行欺骗测试。\
         如需完整的源端口欺骗测试，需要使用原始套接字库（如 pnet）。\n\
         常见可用于绕过的源端口：53(DNS)、80(HTTP)、443(HTTPS)、123(NTP)",
    );

    results.push(FirewallBypassResult {
        target: target.clone(),
        port,
        test_type: BypassTestType::SourcePortSpoof,
        possible_bypass: false,
        details: spoof_details,
        response_time_ms: base_time,
        supported: false,
    });

    // 8. 时间戳规避检测
    // 基于多次测试的响应时间变化检测
    let mut timestamp_details = String::from("时间戳规避：检测防火墙是否基于时间戳进行速率限制。\n");
    let mut times = Vec::new();
    for i in 0..5 {
        let (_, t) = test_tcp_port(&target, port, 2000);
        times.push(t);
        timestamp_details.push_str(&format!("第{}次测试响应时间: {}ms\n", i + 1, t));
    }

    let avg_time = if !times.is_empty() {
        times.iter().sum::<u64>() / times.len() as u64
    } else {
        0
    };

    // 检查是否有明显的延迟递增（可能是速率限制）
    let has_rate_limit = times.windows(2).filter(|w| w[1] > w[0] * 2).count() >= 2;

    timestamp_details.push_str(&format!(
        "平均响应时间: {}ms\n是否疑似速率限制: {}\n\
         建议：如怀疑速率限制，可降低测试频率或使用时间戳规避技术。",
        avg_time, has_rate_limit
    ));

    results.push(FirewallBypassResult {
        target: target.clone(),
        port,
        test_type: BypassTestType::TimestampEvasion,
        possible_bypass: has_rate_limit,
        details: timestamp_details,
        response_time_ms: avg_time,
        supported: true,
    });

    let report = FirewallReport {
        target: target.clone(),
        outbound_tests: vec![PortTestResult {
            port,
            status: base_status,
            service: get_service_name(port),
            response_time_ms: base_time,
        }],
        inbound_tests: vec![],
        bypass_tests: results,
        ids_ips_detection: None,
        audit: None,
        total_duration_ms: start_time.elapsed().as_millis() as u64,
    };

    let message = if base_is_open {
        format!("防火墙绕过测试完成（基准：端口 {} 开放）", port)
    } else {
        format!("防火墙绕过测试完成（基准：端口 {} {:?}）", port, base_status)
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(report, &message))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 防火墙规则审计
///
/// 检查目标主机的常见危险端口，评估安全基线。
pub fn firewall_audit(target: String) -> Result<String, String> {
    let start_time = Instant::now();
    let timeout_ms = 1500;
    let mut dangerous_results: Vec<DangerousPortInfo> = Vec::new();
    let mut open_dangerous_count = 0;
    let mut recommended_close: Vec<u16> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();

    for (port, service, risk_level, description) in dangerous_ports() {
        let (status, _) = test_tcp_port(&target, port, timeout_ms);
        let is_open = status == PortStatus::Open;

        if is_open {
            open_dangerous_count += 1;
            recommended_close.push(port);
        }

        dangerous_results.push(DangerousPortInfo {
            port,
            service: service.to_string(),
            risk_level: risk_level.to_string(),
            description: description.to_string(),
            is_open,
        });
    }

    // 计算安全评分
    let _total_dangerous = dangerous_ports().len() as u8;
    let security_score = if open_dangerous_count == 0 {
        95
    } else {
        let penalty = (open_dangerous_count as u8) * 8;
        if penalty > 80 { 15 } else { 95 - penalty }
    };

    // 生成建议
    if open_dangerous_count > 0 {
        recommendations.push(format!(
            "发现 {} 个危险端口处于开放状态，建议立即评估并关闭不必要的端口。",
            open_dangerous_count
        ));

        if recommended_close.contains(&23) {
            recommendations.push("Telnet(23) 极度不安全，建议立即关闭，改用 SSH。".to_string());
        }
        if recommended_close.contains(&445) {
            recommendations.push("SMB(445) 存在永恒之蓝等高危漏洞风险，如非必要请禁用。".to_string());
        }
        if recommended_close.contains(&3389) {
            recommendations.push("RDP(3389) 建议限制来源 IP，启用网络级别身份验证 (NLA)。".to_string());
        }
        if recommended_close.contains(&6379) || recommended_close.contains(&27017) {
            recommendations.push("数据库端口（Redis/MongoDB）默认无认证，禁止公网暴露。".to_string());
        }
    } else {
        recommendations.push("常见危险端口均处于关闭或过滤状态，安全状况良好。".to_string());
    }

    recommendations.push("建议定期进行端口审计，及时发现异常开放的端口。".to_string());
    recommendations.push("建议实施最小开放原则，只开放必要的服务端口。".to_string());
    recommendations.push("建议部署 IDS/IPS 系统，监控异常流量和端口扫描行为。".to_string());

    let audit_result = FirewallAuditResult {
        target: target.clone(),
        dangerous_ports: dangerous_results,
        open_dangerous_count,
        recommended_close,
        security_score,
        recommendations,
    };

    let report = FirewallReport {
        target: target.clone(),
        outbound_tests: vec![],
        inbound_tests: vec![],
        bypass_tests: vec![],
        ids_ips_detection: None,
        audit: Some(audit_result),
        total_duration_ms: start_time.elapsed().as_millis() as u64,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(report, "防火墙规则审计完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

// ============================================================================
// DNS 安全 - 辅助函数
// ============================================================================

/// 创建系统默认 DNS 解析器
fn create_system_resolver() -> Result<Resolver, String> {
    Resolver::from_system_conf().map_err(|e| format!("创建 DNS 解析器失败: {}", e))
}

/// 创建指定 DNS 服务器的解析器
fn create_custom_resolver(dns_server: &str) -> Result<Resolver, String> {
    let mut config = ResolverConfig::new();
    let socket_addr = format!("{}:53", dns_server)
        .parse()
        .map_err(|e| format!("DNS 地址解析失败: {}", e))?;
    config.add_name_server(NameServerConfig {
        socket_addr,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 2;

    Resolver::new(config, opts).map_err(|e| format!("创建 DNS 解析器失败: {}", e))
}

/// 检查 IP 是否为内网地址
fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unicast_link_local(),
        Err(_) => false,
    }
}

/// 计算字符串熵值（用于 DNS 隧道检测）
fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0;
    for count in freq.values() {
        let p = *count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// 公共 DNS 服务器列表
fn public_dns_servers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("8.8.8.8", "Google DNS"),
        ("8.8.4.4", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("1.0.0.1", "Cloudflare DNS"),
        ("114.114.114.114", "114 DNS"),
        ("223.5.5.5", "AliDNS"),
        ("223.6.6.6", "AliDNS"),
        ("180.76.76.76", "Baidu DNS"),
    ]
}

// ============================================================================
// DNS 安全 - 公共函数
// ============================================================================

/// 获取当前系统 DNS 服务器
pub fn get_dns_servers() -> Result<String, String> {
    let mut servers: Vec<DnsServerInfo> = Vec::new();

    // 尝试从系统配置读取 DNS
    match Resolver::from_system_conf() {
        Ok(resolver) => {
            // 获取名称服务器配置信息
            // 由于 Resolver 不直接暴露配置，我们通过解析方式探测
            // 先尝试解析一个知名域名来验证 DNS 工作
            let test_domain = "www.baidu.com";
            let start = Instant::now();
            let avg_time = match resolver.lookup_ip(test_domain) {
                Ok(_) => start.elapsed().as_millis() as u64,
                Err(_) => 0,
            };

            // 尝试读取系统 DNS 配置（Windows 通过注册表，Linux 通过 /etc/resolv.conf）
            // 这里使用信任 DNS 库的系统配置加载
            // 由于 API 限制，我们提供通用的 DNS 服务器检测
            servers.push(DnsServerInfo {
                address: "system-default".to_string(),
                name: Some("系统默认 DNS".to_string()),
                supports_dnssec: None,
                avg_response_time_ms: avg_time,
                is_system_default: true,
            });

            // 额外提示：可以通过网络接口获取 DNS 服务器地址
            // 在 Windows 上可通过 ipconfig /all 获取
            // 这里提供概念性的系统 DNS 检测
        }
        Err(e) => {
            return Err(format!("获取系统 DNS 配置失败: {}", e));
        }
    }

    serde_json::to_string(&crate::netsec::ToolResult::ok(
        servers,
        "DNS 服务器信息获取完成（使用系统默认 DNS 配置）",
    ))
    .map_err(|e| format!("序列化失败: {}", e))
}

/// DNS 速度测试
///
/// 测试多个域名的解析速度，评估 DNS 服务器性能。
/// domains 参数为逗号分隔的域名列表。
pub fn dns_speed_test(domains: String) -> Result<String, String> {
    let domain_list: Vec<String> = domains
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if domain_list.is_empty() {
        return Err("域名列表不能为空".to_string());
    }

    let resolver = create_system_resolver()?;
    let mut domain_times: HashMap<String, u64> = HashMap::new();
    let mut success_count = 0;
    let mut min_time = u64::MAX;
    let mut max_time = 0u64;
    let mut total_time = 0u64;

    for domain in &domain_list {
        let start = Instant::now();
        match resolver.lookup_ip(domain) {
            Ok(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                domain_times.insert(domain.clone(), elapsed);
                success_count += 1;
                total_time += elapsed;
                if elapsed < min_time {
                    min_time = elapsed;
                }
                if elapsed > max_time {
                    max_time = elapsed;
                }
            }
            Err(_) => {
                domain_times.insert(domain.clone(), u64::MAX);
            }
        }
    }

    let avg_time = if success_count > 0 {
        total_time / success_count as u64
    } else {
        0
    };

    let success_rate = if !domain_list.is_empty() {
        success_count as f32 / domain_list.len() as f32
    } else {
        0.0
    };

    if min_time == u64::MAX {
        min_time = 0;
    }

    let result = DnsSpeedTestResult {
        dns_server: "system-default".to_string(),
        domains: domain_list,
        domain_times,
        avg_time_ms: avg_time,
        min_time_ms: min_time,
        max_time_ms: max_time,
        success_rate,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "DNS 速度测试完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// DNS 泄露测试
///
/// 检测是否真实使用配置的 DNS，以及是否存在 DNS 泄露通道。
pub fn dns_leak_test() -> Result<String, String> {
    let mut configured_servers: Vec<String> = Vec::new();
    let mut detected_servers: Vec<String> = Vec::new();

    // 获取系统配置的 DNS
    match Resolver::from_system_conf() {
        Ok(_resolver) => {
            configured_servers.push("system-default".to_string());

            // 通过解析已知的泄露测试域名来检测实际使用的 DNS
            // 注意：完整的 DNS 泄露测试需要专用的泄露测试服务
            // 这里使用多个公共 DNS 对比的方式进行提示性检测

            // 解析一个域名，然后对比不同 DNS 的结果
            let test_domain = "www.baidu.com";

            // 系统 DNS 解析结果
            let system_ips: Vec<String> = match _resolver.lookup_ip(test_domain) {
                Ok(ips) => ips.iter().map(|ip| ip.to_string()).collect(),
                Err(_) => vec![],
            };

            if !system_ips.is_empty() {
                detected_servers.push("system-default (active)".to_string());
            }

            // 检测是否可能使用了其他 DNS（通过对比结果差异）
            for (dns_addr, dns_name) in public_dns_servers().iter().take(3) {
                if let Ok(custom_resolver) = create_custom_resolver(dns_addr) {
                    if let Ok(custom_ips) = custom_resolver.lookup_ip(test_domain) {
                        let custom_ip_vec: Vec<String> =
                            custom_ips.iter().map(|ip| ip.to_string()).collect();
                        // 如果结果差异大，可能使用了不同的 DNS
                        let overlap = system_ips
                            .iter()
                            .filter(|ip| custom_ip_vec.contains(ip))
                            .count();
                        if overlap == 0 && !system_ips.is_empty() {
                            detected_servers
                                .push(format!("{} ({}) - 结果不同，可能存在多 DNS", dns_addr, dns_name));
                        }
                    }
                }
            }
        }
        Err(e) => {
            return Err(format!("DNS 解析器初始化失败: {}", e));
        }
    }

    let has_leak = detected_servers.len() > 1;

    let leak_channels = vec![
        "系统默认 DNS 解析器",
        "浏览器 DoH/DoT 配置（如 Firefox TRR）",
        "VPN 客户端 DNS 配置",
        "代理服务器 DNS 解析",
        "WebRTC ICE 候选地址（可能绕过 VPN）",
        "路由器/网关 DNS 重定向",
        "ISP 透明 DNS 代理",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect();

    let result = DnsLeakResult {
        has_leak,
        detected_servers,
        configured_servers,
        webrtc_leak_hint: "WebRTC 可能绕过 VPN/DNS 配置泄露真实 IP 和 DNS。\
                           建议在浏览器中禁用 WebRTC 或使用 WebRTC 屏蔽扩展。"
            .to_string(),
        leak_channels,
        details: "DNS 泄露测试为提示性检测。完整的 DNS 泄露测试需要连接专用的泄露测试服务（如 dnsleaktest.com）。\
                  当前检测基于多 DNS 解析结果对比，结果仅供参考。"
            .to_string(),
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "DNS 泄露测试完成（提示性检测）"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// DNS 投毒检测
///
/// 对比多个公共 DNS 的解析结果，检测异常解析。
pub fn dns_poison_detect(domain: String) -> Result<String, String> {
    let mut dns_results: HashMap<String, Vec<String>> = HashMap::new();
    let mut anomalies: Vec<String> = Vec::new();
    let mut all_ips: Vec<String> = Vec::new();
    let mut private_ips: Vec<String> = Vec::new();

    // 使用系统 DNS 解析
    if let Ok(resolver) = create_system_resolver() {
        if let Ok(ips) = resolver.lookup_ip(&domain) {
            let ip_list: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
            dns_results.insert("system-default".to_string(), ip_list.clone());
            all_ips.extend(ip_list);
        }
    }

    // 使用多个公共 DNS 解析并对比
    for (dns_addr, dns_name) in public_dns_servers().iter().take(5) {
        if let Ok(resolver) = create_custom_resolver(dns_addr) {
            if let Ok(ips) = resolver.lookup_ip(&domain) {
                let ip_list: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                dns_results.insert(format!("{} ({})", dns_addr, dns_name), ip_list.clone());
                all_ips.extend(ip_list);
            }
        }
    }

    // 检查内网 IP
    for ip in &all_ips {
        if is_private_ip(ip) {
            private_ips.push(ip.clone());
            anomalies.push(format!("解析到内网/特殊 IP: {}", ip));
        }
    }

    // 对比不同 DNS 的结果差异
    let dns_keys: Vec<String> = dns_results.keys().cloned().collect();
    if dns_keys.len() >= 2 {
        let first_key = &dns_keys[0];
        let first_ips = dns_results.get(first_key).unwrap();

        for key in &dns_keys[1..] {
            let other_ips = dns_results.get(key).unwrap();
            let overlap: Vec<&String> = first_ips.iter().filter(|ip| other_ips.contains(ip)).collect();

            if overlap.is_empty() && !first_ips.is_empty() && !other_ips.is_empty() {
                anomalies.push(format!(
                    "DNS 结果差异：{} 与 {} 解析结果完全不同",
                    first_key, key
                ));
            }
        }
    }

    // 统计唯一 IP 数量
    let unique_ips: std::collections::HashSet<&String> = all_ips.iter().collect();
    if unique_ips.len() > 10 {
        anomalies.push(format!("解析到过多 IP 地址 ({})，可能存在轮询或 CDN", unique_ips.len()));
    }

    let has_private_ip = !private_ips.is_empty();
    let suspected_poisoning = !anomalies.is_empty();
    let confidence = if has_private_ip {
        85u8
    } else if anomalies.len() >= 2 {
        60u8
    } else if anomalies.len() == 1 {
        30u8
    } else {
        0u8
    };

    let result = DnsPoisonResult {
        domain: domain.clone(),
        suspected_poisoning,
        confidence,
        dns_results,
        anomalies,
        has_private_ip,
        private_ips,
    };

    let message = if suspected_poisoning {
        format!("DNS 投毒检测完成（疑似异常，置信度 {}%）", confidence)
    } else {
        "DNS 投毒检测完成（未发现明显异常）".to_string()
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, &message))
        .map_err(|e| format!("序列化失败: {}", e))
}

// ============================================================
// 兼容层：commands_netsec.rs 中使用的函数名别名
// ============================================================

pub fn test_ports(target: String, ports: String) -> Result<String, String> {
    test_outbound_ports(target, ports)
}

pub fn bypass_test(target: String, port: u16) -> Result<String, String> {
    firewall_bypass_test(target, port)
}

pub fn audit(target: String) -> Result<String, String> {
    firewall_audit(target)
}

pub fn get_servers() -> Result<String, String> {
    get_dns_servers()
}

pub fn speed_test(domains: String) -> Result<String, String> {
    dns_speed_test(domains)
}

pub fn leak_test() -> Result<String, String> {
    dns_leak_test()
}

pub fn poison_detect(domain: String) -> Result<String, String> {
    dns_poison_detect(domain)
}

pub fn email_security(domain: String) -> Result<String, String> {
    email_security_check(domain)
}

pub fn reverse(ip: String) -> Result<String, String> {
    reverse_dns(ip)
}

pub fn tunnel_detect(domain: String) -> Result<String, String> {
    dns_tunnel_detect(domain)
}

/// DNSSEC 检查
///
/// 检查域名是否启用 DNSSEC，验证签名有效性（框架级）。
pub fn dnssec_check(domain: String) -> Result<String, String> {
    let mut details = String::new();
    let mut dnssec_enabled = false;
    let mut dnskey_count = 0;
    let mut rrsig_count = 0;
    let mut ds_record_present = false;

    // 使用系统 DNS 解析器
    let resolver = match create_system_resolver() {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("DNS 解析器创建失败: {}", e));
        }
    };

    // 查询 DNSKEY 记录
    match resolver.lookup(&domain, RecordType::DNSKEY) {
        Ok(records) => {
            dnskey_count = records.iter().count();
            if dnskey_count > 0 {
                dnssec_enabled = true;
                details.push_str(&format!("找到 {} 条 DNSKEY 记录\n", dnskey_count));
            }
        }
        Err(e) => {
            details.push_str(&format!("DNSKEY 查询结果: {}\n", e));
        }
    }

    // 查询 RRSIG 记录（A 记录的签名）
    match resolver.lookup(&domain, RecordType::RRSIG) {
        Ok(records) => {
            rrsig_count = records.iter().count();
            details.push_str(&format!("找到 {} 条 RRSIG 记录\n", rrsig_count));
        }
        Err(e) => {
            details.push_str(&format!("RRSIG 查询结果: {}\n", e));
        }
    }

    // 查询 DS 记录（需要查询父域）
    // DS 记录通常在顶级域名服务器上
    let parent_domain = domain
        .splitn(2, '.')
        .nth(1)
        .unwrap_or(&domain)
        .to_string();

    let ds_query = format!("{}.", domain);
    match resolver.lookup(&ds_query, RecordType::DS) {
        Ok(records) => {
            ds_record_present = records.iter().count() > 0;
            if ds_record_present {
                details.push_str(&format!("找到 DS 记录（存在于 {}）\n", parent_domain));
            }
        }
        Err(e) => {
            details.push_str(&format!("DS 查询结果: {}\n", e));
        }
    }

    // 如果没有直接查到 DNSKEY，也可能是因为解析器不支持或域名未启用
    if dnskey_count == 0 && rrsig_count == 0 {
        dnssec_enabled = false;
        details.push_str("未检测到 DNSSEC 相关记录，域名可能未启用 DNSSEC\n");
        details.push_str("提示：部分 DNS 解析器可能过滤 DNSSEC 相关记录，建议使用支持 DNSSEC 的解析器重试\n");
    }

    let result = DnssecResult {
        domain: domain.clone(),
        dnssec_enabled,
        signature_valid: if dnssec_enabled { None } else { Some(false) },
        dnskey_count,
        rrsig_count,
        ds_record_present,
        details,
        validation_supported: false, // 框架级，完整验证需要额外的加密库
    };

    let message = if dnssec_enabled {
        format!("DNSSEC 检查完成（域名已启用 DNSSEC，{} 条 DNSKEY）", dnskey_count)
    } else {
        "DNSSEC 检查完成（域名未启用 DNSSEC 或查询受限）".to_string()
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, &message))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 邮件安全检查
///
/// 检查域名的 SPF、DKIM、DMARC 记录。
pub fn email_security_check(domain: String) -> Result<String, String> {
    let resolver = create_system_resolver()?;
    let mut spf_record: Option<String> = None;
    let mut spf_exists = false;
    let mut spf_evaluation = String::new();
    let mut spf_allowed_ip_count = 0;

    let mut dmarc_record: Option<String> = None;
    let mut dmarc_exists = false;
    let mut dmarc_policy: Option<String> = None;
    let mut dmarc_evaluation = String::new();

    let mut dkim_selectors_tested: Vec<DkimSelectorResult> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();

    // 查询 SPF 记录（TXT 记录中以 v=spf1 开头）
    match resolver.txt_lookup(&domain) {
        Ok(txt_records) => {
            for txt in txt_records.iter() {
                let txt_str = txt_to_string(txt);
                if txt_str.starts_with("v=spf1") {
                    spf_exists = true;
                    spf_record = Some(txt_str.clone());

                    // 解析 SPF 记录
                    // 统计允许的 IP/机制数量
                    spf_allowed_ip_count = txt_str
                        .split_whitespace()
                        .filter(|part| {
                            part.starts_with("ip4:")
                                || part.starts_with("ip6:")
                                || part.starts_with("a:")
                                || part.starts_with("mx:")
                                || part.starts_with("include:")
                                || part.starts_with("ptr:")
                                || part.starts_with("exists:")
                        })
                        .count();

                    // 评估 SPF 策略
                    if txt_str.contains("-all") {
                        spf_evaluation = "严格模式 (-all)：未授权的服务器将被拒绝。最佳实践。".to_string();
                    } else if txt_str.contains("~all") {
                        spf_evaluation = "软失败模式 (~all)：未授权的服务器标记为可疑但不拒绝。建议逐步迁移到 -all。".to_string();
                        recommendations.push("SPF 当前为软失败模式 (~all)，建议迁移到严格模式 (-all)。".to_string());
                    } else if txt_str.contains("?all") {
                        spf_evaluation = "中立模式 (?all)：不做任何判断。安全性较低。".to_string();
                        recommendations.push("SPF 当前为中立模式 (?all)，建议至少使用软失败 (~all)。".to_string());
                    } else if txt_str.contains("+all") {
                        spf_evaluation = "允许所有 (+all)：所有服务器都被允许。极度不安全！".to_string();
                        recommendations.push("SPF 使用了 +all，这会允许任何服务器发送邮件！请立即修改。".to_string());
                    } else {
                        spf_evaluation = "无法识别 SPF 结束策略。".to_string();
                    }

                    break;
                }
            }
        }
        Err(_) => {}
    }

    if !spf_exists {
        spf_evaluation = "未找到 SPF 记录。".to_string();
        recommendations.push("未配置 SPF 记录，建议添加 SPF 记录以防止邮件伪造。".to_string());
    }

    // 查询 DMARC 记录（_dmarc.子域名的 TXT 记录）
    let dmarc_domain = format!("_dmarc.{}", domain);
    match resolver.txt_lookup(&dmarc_domain) {
        Ok(txt_records) => {
            for txt in txt_records.iter() {
                let txt_str = txt_to_string(txt);
                if txt_str.starts_with("v=DMARC1") {
                    dmarc_exists = true;
                    dmarc_record = Some(txt_str.clone());

                    // 解析 DMARC 策略
                    for part in txt_str.split(';') {
                        let part = part.trim();
                        if part.starts_with("p=") {
                            let policy = part[2..].trim().to_string();
                            dmarc_policy = Some(policy.clone());

                            match policy.as_str() {
                                "reject" => {
                                    dmarc_evaluation = "拒绝模式 (p=reject)：未通过验证的邮件将被拒绝。最高安全级别。".to_string();
                                }
                                "quarantine" => {
                                    dmarc_evaluation = "隔离模式 (p=quarantine)：未通过验证的邮件将被标记为垃圾邮件。".to_string();
                                    recommendations.push("DMARC 当前为隔离模式，建议在确认无误后升级为拒绝模式 (reject)。".to_string());
                                }
                                "none" => {
                                    dmarc_evaluation = "监控模式 (p=none)：仅收集报告，不采取行动。".to_string();
                                    recommendations.push("DMARC 当前为监控模式 (none)，建议逐步升级到 quarantine 再到 reject。".to_string());
                                }
                                _ => {
                                    dmarc_evaluation = format!("未知策略: {}", policy);
                                }
                            }
                            break;
                        }
                    }

                    break;
                }
            }
        }
        Err(_) => {}
    }

    if !dmarc_exists {
        dmarc_evaluation = "未找到 DMARC 记录。".to_string();
        recommendations.push("未配置 DMARC 记录，建议添加 DMARC 记录以增强邮件安全。".to_string());
    }

    // 测试常见 DKIM 选择器
    let common_selectors = vec![
        "google", "default", "selector1", "selector2", "mail", "smtp",
        "k1", "k2", "s1", "s2", "mandrill", "sendgrid", "mailchimp",
    ];

    for selector in common_selectors {
        let dkim_domain = format!("{}._domainkey.{}", selector, domain);
        let exists = match resolver.txt_lookup(&dkim_domain) {
            Ok(txt_records) => {
                let mut found = false;
                let mut pub_key = None;
                for txt in txt_records.iter() {
                    let txt_str = txt_to_string(txt);
                    if txt_str.contains("k=rsa") || txt_str.contains("p=") {
                        found = true;
                        // 提取公钥
                        for part in txt_str.split(';') {
                            let part = part.trim();
                            if part.starts_with("p=") {
                                pub_key = Some(part[2..].to_string());
                                break;
                            }
                        }
                        break;
                    }
                }
                dkim_selectors_tested.push(DkimSelectorResult {
                    selector: selector.to_string(),
                    exists: found,
                    public_key: pub_key,
                });
                found
            }
            Err(_) => {
                dkim_selectors_tested.push(DkimSelectorResult {
                    selector: selector.to_string(),
                    exists: false,
                    public_key: None,
                });
                false
            }
        };

        if exists {
            // 找到一个就停止，避免过多查询
            break;
        }
    }

    let dkim_found = dkim_selectors_tested.iter().any(|s| s.exists);
    if !dkim_found {
        recommendations.push("未检测到常见 DKIM 选择器，可能未配置 DKIM 或使用了非标准选择器名称。".to_string());
    }

    // 整体安全评级
    let overall_rating = if spf_exists && dmarc_exists && dkim_found {
        match dmarc_policy.as_deref() {
            Some("reject") => "优秀 (A)".to_string(),
            Some("quarantine") => "良好 (B)".to_string(),
            _ => "一般 (C)".to_string(),
        }
    } else if spf_exists && dmarc_exists {
        "一般 (C)".to_string()
    } else if spf_exists || dmarc_exists {
        "较差 (D)".to_string()
    } else {
        "危险 (F)".to_string()
    };

    let result = EmailSecurityResult {
        domain: domain.clone(),
        spf_record,
        spf_exists,
        spf_evaluation,
        spf_allowed_ip_count,
        dmarc_record,
        dmarc_exists,
        dmarc_policy,
        dmarc_evaluation,
        dkim_selectors_tested,
        overall_rating,
        recommendations,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "邮件安全检查完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 将 TXT 记录转换为字符串
fn txt_to_string(txt: &TXT) -> String {
    txt.iter()
        .map(|bytes| String::from_utf8_lossy(bytes))
        .collect::<Vec<_>>()
        .join("")
}

/// 反向 DNS 查询
///
/// 查询 IP 地址的 PTR 记录（反向解析）。
pub fn reverse_dns(ip: String) -> Result<String, String> {
    let resolver = create_system_resolver()?;

    // 验证 IP 地址格式
    let ip_addr: IpAddr = ip.parse().map_err(|e| format!("无效的 IP 地址: {}", e))?;

    match resolver.reverse_lookup(ip_addr) {
        Ok(names) => {
            let hostnames: Vec<String> = names
                .iter()
                .map(|name| name.to_string().trim_end_matches('.').to_string())
                .collect();

            let result = PtrRecord {
                ip: ip.clone(),
                hostnames: hostnames.clone(),
                success: !hostnames.is_empty(),
                error: if hostnames.is_empty() {
                    Some("未找到 PTR 记录".to_string())
                } else {
                    None
                },
            };

            let message = if hostnames.is_empty() {
                format!("反向 DNS 查询完成（{} 无 PTR 记录）", ip)
            } else {
                format!("反向 DNS 查询完成（{} -> {}）", ip, hostnames.join(", "))
            };

            serde_json::to_string(&crate::netsec::ToolResult::ok(result, &message))
                .map_err(|e| format!("序列化失败: {}", e))
        }
        Err(e) => {
            let result = PtrRecord {
                ip: ip.clone(),
                hostnames: vec![],
                success: false,
                error: Some(e.to_string()),
            };

            serde_json::to_string(&crate::netsec::ToolResult::ok(result, "反向 DNS 查询失败"))
                .map_err(|e| format!("序列化失败: {}", e))
        }
    }
}

/// DNS 隧道检测
///
/// 检测异常长域名和高熵子域名，判断是否疑似 DNS 隧道。
pub fn dns_tunnel_detect(domain: String) -> Result<String, String> {
    let mut indicators: Vec<String> = Vec::new();
    let mut subdomain_length_anomaly = false;
    let max_subdomain_length: usize;
    let mut high_entropy_detected = false;
    let subdomain_entropy: f64;

    // 分析域名结构
    let parts: Vec<&str> = domain.split('.').collect();
    let subdomain_parts: Vec<&str> = if parts.len() > 2 {
        // 去掉最后两部分（主域名+TLD），剩余为子域名部分
        parts[..parts.len() - 2].to_vec()
    } else {
        vec![]
    };

    let full_subdomain = subdomain_parts.join(".");
    max_subdomain_length = full_subdomain.len();

    // 检查子域名长度异常
    // DNS 标签最大长度 63，总长度 253
    // 隧道工具通常使用很长的子域名
    if max_subdomain_length > 100 {
        subdomain_length_anomaly = true;
        indicators.push(format!(
            "子域名长度异常：{} 字符（正常通常 < 50）",
            max_subdomain_length
        ));
    }

    // 检查单个标签长度
    for part in &subdomain_parts {
        if part.len() > 50 {
            indicators.push(format!("标签长度异常：\"{}\" 有 {} 字符", part, part.len()));
        }
    }

    // 计算子域名熵值
    subdomain_entropy = calculate_entropy(&full_subdomain);

    // 高熵检测（正常人类可读的域名熵值通常 < 4，
    // Base32/Base64 编码的数据熵值通常 > 4.5）
    if subdomain_entropy > 4.2 && !full_subdomain.is_empty() {
        high_entropy_detected = true;
        indicators.push(format!(
            "子域名高熵值：{:.2}（正常域名通常 < 4.0，编码数据通常 > 4.5）",
            subdomain_entropy
        ));
    }

    // 检查字符分布（DNS 隧道常用十六进制或 base32 字符集）
    let hex_chars = full_subdomain
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .count();
    if !full_subdomain.is_empty() && hex_chars as f64 / full_subdomain.len() as f64 > 0.8 {
        indicators.push("子域名字符以十六进制为主，疑似编码数据".to_string());
    }

    // 检查是否包含异常多的数字
    let digit_count = full_subdomain.chars().filter(|c| c.is_ascii_digit()).count();
    if !full_subdomain.is_empty() && digit_count as f64 / full_subdomain.len() as f64 > 0.5 {
        indicators.push("子域名中数字比例异常高".to_string());
    }

    // 检查子域名层级数
    if subdomain_parts.len() > 5 {
        indicators.push(format!(
            "子域名层级过多：{} 层（正常通常 < 3）",
            subdomain_parts.len()
        ));
    }

    // 计算置信度
    let mut confidence = 0u8;
    if subdomain_length_anomaly {
        confidence += 30;
    }
    if high_entropy_detected {
        confidence += 35;
    }
    if subdomain_parts.len() > 5 {
        confidence += 15;
    }
    if indicators.len() >= 3 {
        confidence += 20;
    }
    if confidence > 100 {
        confidence = 100;
    }

    let suspected_tunnel = confidence >= 50;

    // 添加通用提示
    indicators.push("提示：DNS 隧道检测为启发式分析，可能存在误报。".to_string());
    indicators.push("常见 DNS 隧道工具：iodine、dns2tcp、dnscat2、Heyoka".to_string());

    let result = DnsTunnelDetectResult {
        domain: domain.clone(),
        suspected_tunnel,
        confidence,
        subdomain_length_anomaly,
        max_subdomain_length,
        subdomain_entropy,
        high_entropy_detected,
        indicators,
    };

    let message = if suspected_tunnel {
        format!(
            "DNS 隧道检测完成（疑似 DNS 隧道，置信度 {}%）",
            confidence
        )
    } else {
        "DNS 隧道检测完成（未发现明显隧道特征）".to_string()
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, &message))
        .map_err(|e| format!("序列化失败: {}", e))
}
