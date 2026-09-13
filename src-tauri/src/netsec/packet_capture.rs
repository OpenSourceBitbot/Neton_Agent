// yxpil · NETON
//! 数据包捕获分析模块
//! 提供网络接口列表、数据包捕获、协议解析、流量统计、DNS监控、
//! HTTP分析、ARP监控、数据导出等功能。
//!
//! 注意：由于未引入 pcap 依赖，本模块提供框架级实现。
//! 如需真实抓包，请安装 WinPcap/Npcap (Windows) 或 libpcap (Linux)，
//! 并引入 pnet 或 pcap 相关 crate。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ============================================================
// 全局捕获状态
// ============================================================

lazy_static::lazy_static! {
    /// 全局捕获状态
    static ref CAPTURE_STATE: Mutex<CaptureState> = Mutex::new(CaptureState::new());
}

/// 全局捕获状态结构
struct CaptureState {
    /// 是否正在捕获
    pub is_running: bool,
    /// 捕获的数据包列表
    pub packets: Vec<PacketInfo>,
    /// 捕获统计
    pub stats: CaptureStats,
    /// DNS 查询记录
    pub dns_queries: Vec<DnsQuery>,
    /// HTTP 请求记录
    pub http_requests: Vec<HttpRequestInfo>,
    /// ARP 表
    pub arp_table: Vec<ArpEntry>,
    /// 捕获开始时间
    pub start_time: Option<Instant>,
    /// 捕获配置
    pub config: Option<CaptureConfig>,
}

impl CaptureState {
    fn new() -> Self {
        Self {
            is_running: false,
            packets: Vec::new(),
            stats: CaptureStats::default(),
            dns_queries: Vec::new(),
            http_requests: Vec::new(),
            arp_table: Vec::new(),
            start_time: None,
            config: None,
        }
    }

    fn reset(&mut self) {
        self.is_running = false;
        self.packets.clear();
        self.stats = CaptureStats::default();
        self.dns_queries.clear();
        self.http_requests.clear();
        self.arp_table.clear();
        self.start_time = None;
        self.config = None;
    }
}

// ============================================================
// 数据结构定义
// ============================================================

/// 网络接口信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// 接口名称
    pub name: String,
    /// 接口描述（Windows）
    pub description: Option<String>,
    /// IP 地址列表
    pub ip_addresses: Vec<String>,
    /// MAC 地址
    pub mac_address: Option<String>,
    /// 状态：up/down
    pub status: String,
    /// 接口类型
    pub interface_type: String,
    /// MTU
    pub mtu: Option<u32>,
}

/// 捕获配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// 接口名称
    pub interface: String,
    /// BPF 过滤表达式
    pub filter: String,
    /// 捕获数量限制（0 表示无限制）
    pub count_limit: u32,
    /// 捕获时间限制（秒，0 表示无限制）
    pub duration_sec: u32,
    /// 混杂模式
    pub promiscuous: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            filter: String::new(),
            count_limit: 0,
            duration_sec: 0,
            promiscuous: true,
        }
    }
}

/// 数据包信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    /// 时间戳（秒）
    pub timestamp: f64,
    /// 数据包大小（字节）
    pub size: u32,
    /// 以太网帧
    pub ethernet: Option<EthernetFrame>,
    /// IP 包
    pub ip: Option<IpPacket>,
    /// TCP 包
    pub tcp: Option<TcpPacket>,
    /// UDP 包
    pub udp: Option<UdpPacket>,
    /// ICMP 包
    pub icmp: Option<IcmpPacket>,
    /// ARP 包
    pub arp: Option<ArpPacket>,
    /// DNS 查询
    pub dns: Option<DnsQuery>,
    /// HTTP 请求/响应
    pub http: Option<HttpInfo>,
    /// 原始数据摘要（前64字节十六进制）
    pub payload_hex: Option<String>,
}

/// 以太网帧
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetFrame {
    /// 源 MAC 地址
    pub src_mac: String,
    /// 目的 MAC 地址
    pub dst_mac: String,
    /// 协议类型（0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6）
    pub ether_type: u16,
    /// 协议类型名称
    pub ether_type_name: String,
}

/// IP 包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpPacket {
    /// IP 版本（4 或 6）
    pub version: u8,
    /// 源 IP 地址
    pub src_ip: String,
    /// 目的 IP 地址
    pub dst_ip: String,
    /// 协议号（6=TCP, 17=UDP, 1=ICMP）
    pub protocol: u8,
    /// 协议名称
    pub protocol_name: String,
    /// TTL / Hop Limit
    pub ttl: u8,
    /// 总长度
    pub total_length: u16,
    /// 标识
    pub identification: u16,
    /// 标志位
    pub flags: u8,
    /// 片偏移
    pub fragment_offset: u16,
}

/// TCP 包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPacket {
    /// 源端口
    pub src_port: u16,
    /// 目的端口
    pub dst_port: u16,
    /// 序列号
    pub sequence: u32,
    /// 确认号
    pub acknowledgment: u32,
    /// 数据偏移
    pub data_offset: u8,
    /// 标志位
    pub flags: TcpFlags,
    /// 窗口大小
    pub window_size: u16,
    /// 校验和
    pub checksum: u16,
    /// 紧急指针
    pub urgent_pointer: u16,
}

/// TCP 标志位
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlags {
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    pub fn from_u8(flags: u8) -> Self {
        Self {
            urg: (flags & 0x20) != 0,
            ack: (flags & 0x10) != 0,
            psh: (flags & 0x08) != 0,
            rst: (flags & 0x04) != 0,
            syn: (flags & 0x02) != 0,
            fin: (flags & 0x01) != 0,
        }
    }

    pub fn to_string(&self) -> String {
        let mut s = String::new();
        if self.urg { s.push('U'); }
        if self.ack { s.push('A'); }
        if self.psh { s.push('P'); }
        if self.rst { s.push('R'); }
        if self.syn { s.push('S'); }
        if self.fin { s.push('F'); }
        if s.is_empty() { s.push('-'); }
        s
    }
}

/// UDP 包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpPacket {
    /// 源端口
    pub src_port: u16,
    /// 目的端口
    pub dst_port: u16,
    /// 长度
    pub length: u16,
    /// 校验和
    pub checksum: u16,
}

/// ICMP 包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpPacket {
    /// 类型
    pub icmp_type: u8,
    /// 代码
    pub code: u8,
    /// 校验和
    pub checksum: u16,
    /// 标识符（Echo）
    pub identifier: Option<u16>,
    /// 序列号（Echo）
    pub sequence: Option<u16>,
    /// 类型名称
    pub type_name: String,
}

/// ARP 包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpPacket {
    /// 硬件类型
    pub hardware_type: u16,
    /// 协议类型
    pub protocol_type: u16,
    /// 硬件地址长度
    pub hw_addr_len: u8,
    /// 协议地址长度
    pub proto_addr_len: u8,
    /// 操作码（1=请求, 2=响应）
    pub operation: u16,
    /// 操作名称
    pub operation_name: String,
    /// 发送方 MAC
    pub sender_mac: String,
    /// 发送方 IP
    pub sender_ip: String,
    /// 目标 MAC
    pub target_mac: String,
    /// 目标 IP
    pub target_ip: String,
}

/// DNS 查询
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    /// 事务 ID
    pub transaction_id: u16,
    /// 查询/响应
    pub is_response: bool,
    /// 操作码
    pub opcode: u8,
    /// 响应码
    pub response_code: u8,
    /// 查询域名
    pub query_name: String,
    /// 查询类型
    pub query_type: String,
    /// 查询类
    pub query_class: String,
    /// 回答记录
    pub answers: Vec<DnsRecord>,
    /// 权威记录
    pub authorities: Vec<DnsRecord>,
    /// 附加记录
    pub additionals: Vec<DnsRecord>,
    /// 响应时间（毫秒，仅查询时）
    pub response_time_ms: Option<u64>,
    /// 时间戳
    pub timestamp: f64,
    /// 源 IP
    pub src_ip: String,
    /// 目的 IP
    pub dst_ip: String,
}

/// DNS 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// 名称
    pub name: String,
    /// 类型
    pub record_type: String,
    /// 类
    pub class: String,
    /// TTL
    pub ttl: u32,
    /// 数据
    pub data: String,
}

/// HTTP 信息（请求或响应）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    /// 是否为请求
    pub is_request: bool,
    /// 请求方法（请求时）
    pub method: Option<String>,
    /// URL（请求时）
    pub url: Option<String>,
    /// HTTP 版本
    pub version: String,
    /// 状态码（响应时）
    pub status_code: Option<u16>,
    /// 状态描述（响应时）
    pub status_text: Option<String>,
    /// Host
    pub host: Option<String>,
    /// User-Agent
    pub user_agent: Option<String>,
    /// Content-Type
    pub content_type: Option<String>,
    /// Content-Length
    pub content_length: Option<u32>,
    /// Cookie
    pub cookie: Option<String>,
    /// Authorization
    pub authorization: Option<String>,
    /// 检测到的敏感信息类型
    pub sensitive_info: Vec<String>,
    /// 时间戳
    pub timestamp: f64,
}

/// HTTP 请求信息（简化版，用于列表展示）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestInfo {
    pub timestamp: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub user_agent: Option<String>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub sensitive_info: Vec<String>,
}

/// ARP 条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub interface: String,
    pub is_static: bool,
    pub last_seen: f64,
}

/// 捕获统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStats {
    /// 捕获数据包总数
    pub total_packets: u64,
    /// 总字节数
    pub total_bytes: u64,
    /// 捕获持续时间（秒）
    pub duration_sec: f64,
    /// 每秒数据包数
    pub packets_per_second: f64,
    /// 每秒字节数
    pub bytes_per_second: f64,
    /// 协议分布
    pub protocol_stats: ProtocolStats,
    /// Top 会话
    pub top_talkers: Vec<TopTalker>,
    /// Top 端口
    pub top_ports: Vec<PortStat>,
    /// 异常检测结果
    pub anomalies: Vec<AnomalyInfo>,
}

impl Default for CaptureStats {
    fn default() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            duration_sec: 0.0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            protocol_stats: ProtocolStats::default(),
            top_talkers: Vec::new(),
            top_ports: Vec::new(),
            anomalies: Vec::new(),
        }
    }
}

/// 协议统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStats {
    pub tcp_count: u64,
    pub udp_count: u64,
    pub icmp_count: u64,
    pub arp_count: u64,
    pub other_count: u64,
    pub tcp_percent: f64,
    pub udp_percent: f64,
    pub icmp_percent: f64,
    pub arp_percent: f64,
    pub other_percent: f64,
}

impl Default for ProtocolStats {
    fn default() -> Self {
        Self {
            tcp_count: 0,
            udp_count: 0,
            icmp_count: 0,
            arp_count: 0,
            other_count: 0,
            tcp_percent: 0.0,
            udp_percent: 0.0,
            icmp_percent: 0.0,
            arp_percent: 0.0,
            other_percent: 0.0,
        }
    }
}

/// Top 会话（IP 对流量）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTalker {
    pub src_ip: String,
    pub dst_ip: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub protocol: String,
}

/// 端口统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStat {
    pub port: u16,
    pub packet_count: u64,
    pub byte_count: u64,
    pub protocol: String,
    pub service: String,
}

/// 异常信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyInfo {
    pub type_: String,
    pub description: String,
    pub severity: String,
    pub source_ip: Option<String>,
    pub target_ip: Option<String>,
    pub packet_count: u64,
    pub timestamp: f64,
}

/// 捕获结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketCaptureResult {
    pub interface: String,
    pub filter: String,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub duration_sec: f64,
    pub packets: Vec<PacketInfo>,
    pub stats: CaptureStats,
}

// ============================================================
// 工具函数
// ============================================================

/// 获取当前时间戳（秒，浮点）
fn current_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 将结果序列化为 JSON
fn to_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|e| format!("序列化失败: {}", e))
}

/// 构建成功响应
fn success_response<T: Serialize>(data: T, message: &str) -> Result<String, String> {
    let result = super::ToolResult::ok(data, message);
    super::result_to_json(&result)
}

/// 构建错误响应
fn error_response(message: &str) -> Result<String, String> {
    let result: super::ToolResult<()> = super::ToolResult::error(message);
    super::result_to_json(&result)
}

// ============================================================
// 1. 网络接口列表
// ============================================================

/// 获取本机所有网络接口
/// 通过系统命令获取（Windows: ipconfig /all，Linux: ip addr）
pub fn list_interfaces() -> Result<String, String> {
    let interfaces = get_network_interfaces()?;
    let count = interfaces.len();
    success_response(interfaces, &format!("成功获取 {} 个网络接口", count))
}

/// 获取网络接口列表（内部实现）
fn get_network_interfaces() -> Result<Vec<NetworkInterface>, String> {
    #[cfg(target_os = "windows")]
    {
        get_interfaces_windows()
    }
    #[cfg(target_os = "linux")]
    {
        get_interfaces_linux()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err("不支持的操作系统".to_string())
    }
}

#[cfg(target_os = "windows")]
fn get_interfaces_windows() -> Result<Vec<NetworkInterface>, String> {
    let output = Command::new("ipconfig")
        .arg("/all")
        .output()
        .map_err(|e| format!("执行 ipconfig 失败: {}", e))?;

    if !output.status.success() {
        return Err(format!("ipconfig 执行失败: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    parse_ipconfig_all(&output_str)
}

#[cfg(target_os = "windows")]
fn parse_ipconfig_all(output: &str) -> Result<Vec<NetworkInterface>, String> {
    let mut interfaces: Vec<NetworkInterface> = Vec::new();
    let mut current: Option<NetworkInterface> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        // 检测新的接口段（以 "   。。。" 结尾的行是接口名称）
        if !line.starts_with(' ') && !trimmed.is_empty() && trimmed.contains("适配器") {
            // 保存之前的接口
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = trimmed.trim_end_matches(':').trim().to_string();
            current = Some(NetworkInterface {
                name: name.clone(),
                description: None,
                ip_addresses: Vec::new(),
                mac_address: None,
                status: "unknown".to_string(),
                interface_type: "unknown".to_string(),
                mtu: None,
            });
        } else if let Some(ref mut iface) = current {
            if trimmed.starts_with("描述") {
                if let Some(val) = trimmed.split(':').nth(1) {
                    iface.description = Some(val.trim().to_string());
                }
            } else if trimmed.starts_with("物理地址") || trimmed.starts_with("DHCP") {
                if trimmed.starts_with("物理地址") {
                    if let Some(val) = trimmed.split(':').nth(1) {
                        let mac = val.trim().replace('-', ":").to_uppercase();
                        if mac.len() == 17 {
                            iface.mac_address = Some(mac);
                        }
                    }
                }
            } else if trimmed.starts_with("IPv4 地址") {
                if let Some(val) = trimmed.split(':').nth(1) {
                    let ip = val.trim().to_string();
                    // 去掉可能的 (首选) 标记
                    let ip = ip.split("(首选)").next().unwrap_or(&ip).trim().to_string();
                    if !ip.is_empty() {
                        iface.ip_addresses.push(ip);
                    }
                }
            } else if trimmed.contains("已启用") && trimmed.contains("媒体状态") {
                iface.status = if trimmed.contains("已断开连接") {
                    "down".to_string()
                } else {
                    "up".to_string()
                };
            } else if trimmed.contains("媒体状态") && trimmed.contains("媒体已断开") {
                iface.status = "down".to_string();
            }
        }
    }

    // 保存最后一个接口
    if let Some(iface) = current.take() {
        interfaces.push(iface);
    }

    // 如果状态没解析出来，根据是否有 IP 推断
    for iface in &mut interfaces {
        if iface.status == "unknown" {
            iface.status = if iface.ip_addresses.is_empty() { "down".to_string() } else { "up".to_string() };
        }
    }

    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn get_interfaces_linux() -> Result<Vec<NetworkInterface>, String> {
    let output = Command::new("ip")
        .args(["addr", "show"])
        .output()
        .map_err(|e| format!("执行 ip addr 失败: {}", e))?;

    if !output.status.success() {
        return Err(format!("ip addr 执行失败: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    parse_ip_addr(&output_str)
}

#[cfg(target_os = "linux")]
fn parse_ip_addr(output: &str) -> Result<Vec<NetworkInterface>, String> {
    let mut interfaces: Vec<NetworkInterface> = Vec::new();
    let mut current: Option<NetworkInterface> = None;

    for line in output.lines() {
        // 接口行: 数字: 名称: <标志> ...
        if !line.starts_with(' ') && line.contains(':') && line.chars().next().map_or(false, |c| c.is_ascii_digit()) {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }

            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() >= 2 {
                let name = parts[1].trim().to_string();
                let flags = line
                    .find('<')
                    .and_then(|start| line.find('>').map(|end| &line[start + 1..end]))
                    .unwrap_or("");

                let status = if flags.contains("UP") || flags.contains("LOWER_UP") {
                    "up".to_string()
                } else {
                    "down".to_string()
                };

                let iface_type = if name.starts_with("lo") {
                    "loopback".to_string()
                } else if name.starts_with("eth") || name.starts_with("en") {
                    "ethernet".to_string()
                } else if name.starts_with("wlan") || name.starts_with("wl") {
                    "wireless".to_string()
                } else if name.starts_with("docker") || name.starts_with("veth") {
                    "virtual".to_string()
                } else if name.starts_with("tun") || name.starts_with("tap") {
                    "tunnel".to_string()
                } else {
                    "unknown".to_string()
                };

                current = Some(NetworkInterface {
                    name,
                    description: None,
                    ip_addresses: Vec::new(),
                    mac_address: None,
                    status,
                    interface_type: iface_type,
                    mtu: None,
                });
            }
        } else if let Some(ref mut iface) = current {
            let trimmed = line.trim();
            if trimmed.starts_with("link/ether") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    iface.mac_address = Some(parts[1].to_uppercase().to_string());
                }
            } else if trimmed.starts_with("inet ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let addr = parts[1].split('/').next().unwrap_or(parts[1]).to_string();
                    iface.ip_addresses.push(addr);
                }
            } else if trimmed.starts_with("inet6 ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let addr = parts[1].split('/').next().unwrap_or(parts[1]).to_string();
                    iface.ip_addresses.push(addr);
                }
            } else if trimmed.contains("mtu") {
                if let Some(mtu_str) = trimmed
                    .find("mtu")
                    .and_then(|i| trimmed[i..].split_whitespace().nth(1))
                {
                    if let Ok(mtu) = mtu_str.parse::<u32>() {
                        iface.mtu = Some(mtu);
                    }
                }
            }
        }
    }

    if let Some(iface) = current.take() {
        interfaces.push(iface);
    }

    Ok(interfaces)
}

// ============================================================
// 2. 数据包捕获（框架级实现）
// ============================================================

/// 开始数据包捕获
/// 注意：由于未引入 pcap 依赖，此函数提供框架级模拟实现
pub fn start_capture(interface: String, filter: String, count: u32, duration_sec: u32) -> Result<String, String> {
    let mut state = CAPTURE_STATE.lock().map_err(|e| format!("获取锁失败: {}", e))?;

    if state.is_running {
        return error_response("捕获已在运行中，请先停止当前捕获");
    }

    state.reset();
    state.is_running = true;
    state.start_time = Some(Instant::now());
    state.config = Some(CaptureConfig {
        interface: interface.clone(),
        filter: filter.clone(),
        count_limit: count,
        duration_sec,
        promiscuous: true,
    });

    // 生成一些模拟数据包用于演示统计功能
    generate_mock_packets(&mut state, count, duration_sec);

    state.is_running = false;

    let result = PacketCaptureResult {
        interface,
        filter,
        total_packets: state.stats.total_packets,
        total_bytes: state.stats.total_bytes,
        duration_sec: state.stats.duration_sec,
        packets: state.packets.clone(),
        stats: state.stats.clone(),
    };

    success_response(result, "数据包捕获完成（模拟模式）。如需真实抓包，请安装 WinPcap/Npcap 或 libpcap 并引入 pnet/pcap 依赖。")
}

/// 生成模拟数据包（演示用）
fn generate_mock_packets(state: &mut CaptureState, count: u32, duration_sec: u32) {
    let packet_count = if count > 0 { count as usize } else { 100 };
    let duration = if duration_sec > 0 { duration_sec as f64 } else { 10.0 };

    let src_ips = vec!["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.5"];
    let dst_ips = vec!["8.8.8.8", "1.1.1.1", "192.168.1.1", "142.250.80.46"];
    let tcp_ports = vec![80u16, 443, 8080, 22, 3389];
    let udp_ports = vec![53u16, 123, 5060];
    let mac_addrs = vec![
        "00:1A:2B:3C:4D:5E",
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66",
        "FE:FF:FF:FF:FF:FF",
    ];

    let mut rng_state = 42u32;
    let mut rand = || {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        (rng_state >> 16) & 0x7fff
    };

    let start_ts = current_timestamp() - duration;

    for i in 0..packet_count {
        let ts = start_ts + (i as f64) * duration / (packet_count as f64);
        let size = 64 + (rand() % 1400) as u32;

        // 随机协议分布：50% TCP, 30% UDP, 10% ICMP, 10% ARP
        let proto_choice = rand() % 100;

        let mut packet = PacketInfo {
            timestamp: ts,
            size,
            ethernet: None,
            ip: None,
            tcp: None,
            udp: None,
            icmp: None,
            arp: None,
            dns: None,
            http: None,
            payload_hex: None,
        };

        let src_mac = mac_addrs[(rand() as usize) % mac_addrs.len()].to_string();
        let dst_mac = mac_addrs[(rand() as usize) % mac_addrs.len()].to_string();

        if proto_choice < 50 {
            // TCP
            let src_ip = src_ips[(rand() as usize) % src_ips.len()].to_string();
            let dst_ip = dst_ips[(rand() as usize) % dst_ips.len()].to_string();
            let src_port = 1024 + (rand() % 64000) as u16;
            let dst_port = tcp_ports[(rand() as usize) % tcp_ports.len()];

            packet.ethernet = Some(EthernetFrame {
                src_mac: src_mac.clone(),
                dst_mac: dst_mac.clone(),
                ether_type: 0x0800,
                ether_type_name: "IPv4".to_string(),
            });

            packet.ip = Some(IpPacket {
                version: 4,
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                protocol: 6,
                protocol_name: "TCP".to_string(),
                ttl: (64 + (rand() % 64) as u8),
                total_length: size as u16,
                identification: rand() as u16,
                flags: 0,
                fragment_offset: 0,
            });

            let flag_choice = rand() % 10;
            let flags_val = match flag_choice {
                0..=4 => 0x10,  // ACK
                5..=6 => 0x02,  // SYN
                7 => 0x12,      // SYN-ACK
                8 => 0x11,      // FIN-ACK
                _ => 0x18,      // PSH-ACK
            };

            packet.tcp = Some(TcpPacket {
                src_port,
                dst_port,
                sequence: rand() as u32,
                acknowledgment: rand() as u32,
                data_offset: 5,
                flags: TcpFlags::from_u8(flags_val),
                window_size: 65535,
                checksum: 0,
                urgent_pointer: 0,
            });

            // HTTP 模拟（端口 80 或 8080）
            if dst_port == 80 || dst_port == 8080 {
                let methods = vec!["GET", "POST", "HEAD", "PUT"];
                let paths = vec!["/", "/index.html", "/api/data", "/login", "/search"];
                let hosts = vec!["example.com", "test.org", "api.service.io"];
                let agents = vec!["Mozilla/5.0", "curl/7.68.0", "Python-urllib/3.8"];

                let is_req = rand() % 2 == 0;
                let method = methods[(rand() as usize) % methods.len()].to_string();
                let path = paths[(rand() as usize) % paths.len()].to_string();
                let host = hosts[(rand() as usize) % hosts.len()].to_string();
                let user_agent = agents[(rand() as usize) % agents.len()].to_string();

                let mut sensitive_info = Vec::new();
                if path.contains("login") && method == "POST" {
                    sensitive_info.push("疑似登录请求".to_string());
                }
                if rand() % 20 == 0 {
                    sensitive_info.push("疑似 Cookie 泄露".to_string());
                }

                let http_info = HttpInfo {
                    is_request: is_req,
                    method: if is_req { Some(method.clone()) } else { None },
                    url: if is_req { Some(path.clone()) } else { None },
                    version: "HTTP/1.1".to_string(),
                    status_code: if !is_req { Some(200) } else { None },
                    status_text: if !is_req { Some("OK".to_string()) } else { None },
                    host: Some(host.clone()),
                    user_agent: Some(user_agent.clone()),
                    content_type: Some("text/html".to_string()),
                    content_length: Some(size as u32 - 40),
                    cookie: if rand() % 5 == 0 { Some("session=abc123".to_string()) } else { None },
                    authorization: None,
                    sensitive_info,
                    timestamp: ts,
                };

                packet.http = Some(http_info.clone());

                // 记录到 HTTP 请求列表
                state.http_requests.push(HttpRequestInfo {
                    timestamp: ts,
                    src_ip,
                    dst_ip,
                    method,
                    url: path,
                    host,
                    user_agent: Some(user_agent),
                    status_code: if rand() % 2 == 0 { Some(200) } else { None },
                    content_type: Some("text/html".to_string()),
                    sensitive_info: http_info.sensitive_info,
                });
            }

            state.stats.protocol_stats.tcp_count += 1;
        } else if proto_choice < 80 {
            // UDP
            let src_ip = src_ips[(rand() as usize) % src_ips.len()].to_string();
            let dst_ip = dst_ips[(rand() as usize) % dst_ips.len()].to_string();
            let src_port = 1024 + (rand() % 64000) as u16;
            let dst_port = udp_ports[(rand() as usize) % udp_ports.len()];

            packet.ethernet = Some(EthernetFrame {
                src_mac: src_mac.clone(),
                dst_mac: dst_mac.clone(),
                ether_type: 0x0800,
                ether_type_name: "IPv4".to_string(),
            });

            packet.ip = Some(IpPacket {
                version: 4,
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                protocol: 17,
                protocol_name: "UDP".to_string(),
                ttl: 64,
                total_length: size as u16,
                identification: rand() as u16,
                flags: 0,
                fragment_offset: 0,
            });

            packet.udp = Some(UdpPacket {
                src_port,
                dst_port,
                length: size as u16,
                checksum: 0,
            });

            // DNS 模拟（端口 53）
            if dst_port == 53 {
                let domains = vec![
                    "www.google.com", "github.com", "api.twitter.com",
                    "cdn.cloudflare.com", "mail.example.com", "averylongsubdomain.example.co.uk",
                ];
                let qtypes = vec!["A", "AAAA", "CNAME", "MX", "TXT"];
                let query_name = domains[(rand() as usize) % domains.len()].to_string();
                let qtype = qtypes[(rand() as usize) % qtypes.len()].to_string();
                let is_response = rand() % 2 == 0;

                let mut answers = Vec::new();
                if is_response {
                    answers.push(DnsRecord {
                        name: query_name.clone(),
                        record_type: "A".to_string(),
                        class: "IN".to_string(),
                        ttl: 300,
                        data: format!("{}.{}.{}.{}",
                            rand() % 255, rand() % 255, rand() % 255, rand() % 255),
                    });
                }

                let dns = DnsQuery {
                    transaction_id: rand() as u16,
                    is_response,
                    opcode: 0,
                    response_code: if is_response { 0 } else { 0 },
                    query_name: query_name.clone(),
                    query_type: qtype,
                    query_class: "IN".to_string(),
                    answers,
                    authorities: Vec::new(),
                    additionals: Vec::new(),
                    response_time_ms: if is_response { Some((rand() % 100) as u64) } else { None },
                    timestamp: ts,
                    src_ip,
                    dst_ip,
                };

                packet.dns = Some(dns.clone());
                state.dns_queries.push(dns);
            }

            state.stats.protocol_stats.udp_count += 1;
        } else if proto_choice < 90 {
            // ICMP
            let src_ip = src_ips[(rand() as usize) % src_ips.len()].to_string();
            let dst_ip = dst_ips[(rand() as usize) % dst_ips.len()].to_string();

            packet.ethernet = Some(EthernetFrame {
                src_mac: src_mac.clone(),
                dst_mac: dst_mac.clone(),
                ether_type: 0x0800,
                ether_type_name: "IPv4".to_string(),
            });

            packet.ip = Some(IpPacket {
                version: 4,
                src_ip,
                dst_ip,
                protocol: 1,
                protocol_name: "ICMP".to_string(),
                ttl: 64,
                total_length: size as u16,
                identification: rand() as u16,
                flags: 0,
                fragment_offset: 0,
            });

            let icmp_type = if rand() % 2 == 0 { 8 } else { 0 }; // Echo Request / Reply
            packet.icmp = Some(IcmpPacket {
                icmp_type,
                code: 0,
                checksum: 0,
                identifier: Some(rand() as u16),
                sequence: Some(rand() as u16),
                type_name: if icmp_type == 8 { "Echo Request".to_string() } else { "Echo Reply".to_string() },
            });

            state.stats.protocol_stats.icmp_count += 1;
        } else {
            // ARP
            let sender_ip = src_ips[(rand() as usize) % src_ips.len()].to_string();
            let target_ip = src_ips[(rand() as usize) % src_ips.len()].to_string();
            let sender_mac = mac_addrs[(rand() as usize) % mac_addrs.len()].to_string();
            let target_mac = if rand() % 2 == 0 {
                mac_addrs[(rand() as usize) % mac_addrs.len()].to_string()
            } else {
                "00:00:00:00:00:00".to_string()
            };

            let is_request = rand() % 2 == 0;

            packet.ethernet = Some(EthernetFrame {
                src_mac: sender_mac.clone(),
                dst_mac: if is_request { "FF:FF:FF:FF:FF:FF".to_string() } else { target_mac.clone() },
                ether_type: 0x0806,
                ether_type_name: "ARP".to_string(),
            });

            packet.arp = Some(ArpPacket {
                hardware_type: 1,
                protocol_type: 0x0800,
                hw_addr_len: 6,
                proto_addr_len: 4,
                operation: if is_request { 1 } else { 2 },
                operation_name: if is_request { "Request".to_string() } else { "Reply".to_string() },
                sender_mac: sender_mac.clone(),
                sender_ip: sender_ip.clone(),
                target_mac: target_mac.clone(),
                target_ip: target_ip.clone(),
            });

            // 更新 ARP 表
            if !is_request {
                let entry = ArpEntry {
                    ip: sender_ip.clone(),
                    mac: sender_mac.clone(),
                    interface: state.config.as_ref().map(|c| c.interface.clone()).unwrap_or_default(),
                    is_static: false,
                    last_seen: ts,
                };
                if !state.arp_table.iter().any(|e| e.ip == sender_ip && e.mac == sender_mac) {
                    state.arp_table.push(entry);
                }
            }

            state.stats.protocol_stats.arp_count += 1;
        }

        state.packets.push(packet);
        state.stats.total_packets += 1;
        state.stats.total_bytes += size as u64;
    }

    state.stats.duration_sec = duration;
    if duration > 0.0 {
        state.stats.packets_per_second = state.stats.total_packets as f64 / duration;
        state.stats.bytes_per_second = state.stats.total_bytes as f64 / duration;
    }

    // 计算协议百分比
    let total = state.stats.total_packets as f64;
    if total > 0.0 {
        let ps = &mut state.stats.protocol_stats;
        ps.tcp_percent = (ps.tcp_count as f64 / total) * 100.0;
        ps.udp_percent = (ps.udp_count as f64 / total) * 100.0;
        ps.icmp_percent = (ps.icmp_count as f64 / total) * 100.0;
        ps.arp_percent = (ps.arp_count as f64 / total) * 100.0;
        ps.other_percent = (ps.other_count as f64 / total) * 100.0;
    }

    // 计算 Top 会话
    calculate_top_talkers(&mut state.stats, &state.packets);

    // 计算 Top 端口
    calculate_top_ports(&mut state.stats, &state.packets);

    // 异常检测
    detect_anomalies(&mut state.stats, &state.packets);
}

/// 计算 Top 会话
fn calculate_top_talkers(stats: &mut CaptureStats, packets: &[PacketInfo]) {
    let mut talker_map: HashMap<(String, String, String), (u64, u64)> = HashMap::new();

    for pkt in packets {
        if let Some(ref ip) = pkt.ip {
            let proto = ip.protocol_name.clone();
            let key = (ip.src_ip.clone(), ip.dst_ip.clone(), proto);
            let entry = talker_map.entry(key).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += pkt.size as u64;
        }
    }

    let mut talkers: Vec<TopTalker> = talker_map
        .into_iter()
        .map(|((src, dst, proto), (count, bytes))| TopTalker {
            src_ip: src,
            dst_ip: dst,
            packet_count: count,
            byte_count: bytes,
            protocol: proto,
        })
        .collect();

    talkers.sort_by(|a, b| b.byte_count.cmp(&a.byte_count));
    stats.top_talkers = talkers.into_iter().take(10).collect();
}

/// 计算 Top 端口
fn calculate_top_ports(stats: &mut CaptureStats, packets: &[PacketInfo]) {
    let mut port_map: HashMap<(u16, String), (u64, u64)> = HashMap::new();

    for pkt in packets {
        if let Some(ref tcp) = pkt.tcp {
            let key = (tcp.dst_port, "TCP".to_string());
            let entry = port_map.entry(key).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += pkt.size as u64;
        }
        if let Some(ref udp) = pkt.udp {
            let key = (udp.dst_port, "UDP".to_string());
            let entry = port_map.entry(key).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += pkt.size as u64;
        }
    }

    let mut ports: Vec<PortStat> = port_map
        .into_iter()
        .map(|((port, proto), (count, bytes))| PortStat {
            port,
            packet_count: count,
            byte_count: bytes,
            protocol: proto.clone(),
            service: port_service_name(port, &proto),
        })
        .collect();

    ports.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    stats.top_ports = ports.into_iter().take(10).collect();
}

/// 端口服务名称
fn port_service_name(port: u16, protocol: &str) -> String {
    let services: &[((u16, &str), &str)] = &[
        ((20, "TCP"), "FTP-DATA"),
        ((21, "TCP"), "FTP"),
        ((22, "TCP"), "SSH"),
        ((23, "TCP"), "Telnet"),
        ((25, "TCP"), "SMTP"),
        ((53, "TCP"), "DNS"),
        ((53, "UDP"), "DNS"),
        ((67, "UDP"), "DHCP"),
        ((68, "UDP"), "DHCP"),
        ((80, "TCP"), "HTTP"),
        ((110, "TCP"), "POP3"),
        ((123, "UDP"), "NTP"),
        ((143, "TCP"), "IMAP"),
        ((443, "TCP"), "HTTPS"),
        ((445, "TCP"), "SMB"),
        ((993, "TCP"), "IMAPS"),
        ((995, "TCP"), "POP3S"),
        ((3306, "TCP"), "MySQL"),
        ((3389, "TCP"), "RDP"),
        ((5432, "TCP"), "PostgreSQL"),
        ((8080, "TCP"), "HTTP-Proxy"),
        ((8443, "TCP"), "HTTPS-Alt"),
    ];

    services
        .iter()
        .find(|((p, proto), _)| *p == port && *proto == protocol)
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

/// 异常流量检测
fn detect_anomalies(stats: &mut CaptureStats, packets: &[PacketInfo]) {
    // SYN 洪水检测：同一源 IP 发送大量 SYN 包
    let mut syn_count: HashMap<String, u64> = HashMap::new();
    for pkt in packets {
        if let Some(ref tcp) = pkt.tcp {
            if tcp.flags.syn && !tcp.flags.ack {
                if let Some(ref ip) = pkt.ip {
                    *syn_count.entry(ip.src_ip.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    for (src_ip, count) in syn_count.iter() {
        if *count > 50 {
            stats.anomalies.push(AnomalyInfo {
                type_: "SYN_FLOOD".to_string(),
                description: format!("检测到疑似 SYN 洪水攻击，源 IP {} 发送了 {} 个 SYN 包", src_ip, count),
                severity: "high".to_string(),
                source_ip: Some(src_ip.clone()),
                target_ip: None,
                packet_count: *count,
                timestamp: current_timestamp(),
            });
        }
    }

    // 端口扫描检测：同一源 IP 访问大量不同端口
    let mut port_scan: HashMap<String, HashMap<u16, bool>> = HashMap::new();
    for pkt in packets {
        if let Some(ref tcp) = pkt.tcp {
            if tcp.flags.syn && !tcp.flags.ack {
                if let Some(ref ip) = pkt.ip {
                    port_scan
                        .entry(ip.src_ip.clone())
                        .or_insert_with(HashMap::new)
                        .insert(tcp.dst_port, true);
                }
            }
        }
        if let Some(ref udp) = pkt.udp {
            if let Some(ref ip) = pkt.ip {
                port_scan
                    .entry(ip.src_ip.clone())
                    .or_insert_with(HashMap::new)
                    .insert(udp.dst_port, true);
            }
        }
    }

    for (src_ip, ports) in port_scan.iter() {
        if ports.len() > 20 {
            stats.anomalies.push(AnomalyInfo {
                type_: "PORT_SCAN".to_string(),
                description: format!("检测到疑似端口扫描，源 IP {} 扫描了 {} 个不同端口", src_ip, ports.len()),
                severity: "medium".to_string(),
                source_ip: Some(src_ip.clone()),
                target_ip: None,
                packet_count: ports.len() as u64,
                timestamp: current_timestamp(),
            });
        }
    }
}

// ============================================================
// 3. 数据包统计
// ============================================================

/// 获取捕获统计信息
pub fn get_capture_stats() -> Result<String, String> {
    let state = CAPTURE_STATE.lock().map_err(|e| format!("获取锁失败: {}", e))?;

    if state.stats.total_packets == 0 && !state.is_running {
        return success_response(state.stats.clone(), "暂无捕获数据，请先开始捕获");
    }

    let status_msg = if state.is_running {
        "捕获进行中"
    } else {
        "捕获已完成"
    };

    success_response(state.stats.clone(), status_msg)
}

/// 停止数据包捕获
pub fn stop_capture() -> Result<String, String> {
    let mut state = CAPTURE_STATE.lock().map_err(|e| format!("获取锁失败: {}", e))?;

    if !state.is_running {
        return error_response("当前没有正在运行的捕获任务");
    }

    state.is_running = false;

    success_response(
        serde_json::json!({
            "stopped": true,
            "total_packets": state.stats.total_packets,
            "total_bytes": state.stats.total_bytes,
            "duration_sec": state.stats.duration_sec,
        }),
        "捕获已停止",
    )
}

// ============================================================
// 4. DNS 监控
// ============================================================

/// 获取 DNS 查询记录
pub fn get_dns_queries() -> Result<String, String> {
    let state = CAPTURE_STATE.lock().map_err(|e| format!("获取锁失败: {}", e))?;

    let queries = &state.dns_queries;

    // 可疑域名检测
    let mut suspicious_domains: Vec<HashMap<String, String>> = Vec::new();
    for q in queries {
        let domain = &q.query_name;
        let mut reasons: Vec<String> = Vec::new();

        // 异常长域名（> 50 字符）
        if domain.len() > 50 {
            reasons.push("异常长域名".to_string());
        }

        // DGA 特征：高熵值、随机字符组合
        if has_dga_characteristics(domain) {
            reasons.push("疑似 DGA 域名特征".to_string());
        }

        // 包含大量数字
        let digit_count = domain.chars().filter(|c| c.is_ascii_digit()).count();
        if domain.len() > 10 && digit_count as f64 / domain.len() as f64 > 0.4 {
            reasons.push("数字比例过高".to_string());
        }

        if !reasons.is_empty() {
            let mut info = HashMap::new();
            info.insert("domain".to_string(), domain.clone());
            info.insert("reasons".to_string(), reasons.join(", "));
            info.insert("src_ip".to_string(), q.src_ip.clone());
            suspicious_domains.push(info);
        }
    }

    let result = serde_json::json!({
        "total_queries": queries.len(),
        "queries": queries,
        "suspicious_domains": suspicious_domains,
        "suspicious_count": suspicious_domains.len(),
    });

    success_response(result, &format!("共 {} 条 DNS 记录", queries.len()))
}

/// 检测 DGA 域名特征
fn has_dga_characteristics(domain: &str) -> bool {
    let name = domain.split('.').next().unwrap_or(domain);
    if name.len() < 8 {
        return false;
    }

    // 计算元音比例
    let vowels = ['a', 'e', 'i', 'o', 'u'];
    let vowel_count = name.chars().filter(|c| vowels.contains(&c.to_ascii_lowercase())).count();
    let consonant_count = name.chars().filter(|c| c.is_ascii_alphabetic() && !vowels.contains(&c.to_ascii_lowercase())).count();
    let total_letters = vowel_count + consonant_count;

    if total_letters > 0 {
        let ratio = consonant_count as f64 / total_letters as f64;
        // 辅音比例过高可能是 DGA
        if ratio > 0.8 && name.len() > 10 {
            return true;
        }
    }

    false
}

// ============================================================
// 5. HTTP 流量分析
// ============================================================

/// 获取 HTTP 请求记录
pub fn get_http_requests() -> Result<String, String> {
    let state = CAPTURE_STATE.lock().map_err(|e| format!("获取锁失败: {}", e))?;

    let requests = &state.http_requests;

    // 敏感信息统计
    let sensitive_count = requests
        .iter()
        .filter(|r| !r.sensitive_info.is_empty())
        .count();

    let result = serde_json::json!({
        "total_requests": requests.len(),
        "requests": requests,
        "sensitive_info_count": sensitive_count,
        "methods": count_by_field(requests, |r| r.method.clone()),
        "status_codes": count_status_codes(requests),
    });

    success_response(result, &format!("共 {} 条 HTTP 记录", requests.len()))
}

/// 按字段计数
fn count_by_field<T, F>(items: &[T], f: F) -> HashMap<String, u64>
where
    F: Fn(&T) -> String,
{
    let mut counts = HashMap::new();
    for item in items {
        let key = f(item);
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

/// 统计状态码
fn count_status_codes(requests: &[HttpRequestInfo]) -> HashMap<String, u64> {
    let mut counts = HashMap::new();
    for req in requests {
        if let Some(code) = req.status_code {
            let key = code.to_string();
            *counts.entry(key).or_insert(0) += 1;
        }
    }
    counts
}

// ============================================================
// 6. ARP 监控
// ============================================================

/// 获取 ARP 表
pub fn get_arp_table() -> Result<String, String> {
    let state = CAPTURE_STATE.lock().map_err(|e| format!("获取锁失败: {}", e))?;

    let arp_entries = &state.arp_table;

    // 同时尝试从系统获取 ARP 表
    let system_arp = match get_system_arp_table() {
        Ok(entries) => entries,
        Err(_) => Vec::new(),
    };

    let result = serde_json::json!({
        "capture_arp": arp_entries,
        "system_arp": system_arp,
        "capture_count": arp_entries.len(),
        "system_count": system_arp.len(),
    });

    success_response(result, &format!("捕获中 {} 条，系统 ARP 表 {} 条", arp_entries.len(), system_arp.len()))
}

/// 从系统获取 ARP 表
fn get_system_arp_table() -> Result<Vec<ArpEntry>, String> {
    #[cfg(target_os = "windows")]
    {
        get_system_arp_windows()
    }
    #[cfg(target_os = "linux")]
    {
        get_system_arp_linux()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err("不支持的操作系统".to_string())
    }
}

#[cfg(target_os = "windows")]
fn get_system_arp_windows() -> Result<Vec<ArpEntry>, String> {
    let output = Command::new("arp")
        .arg("-a")
        .output()
        .map_err(|e| format!("执行 arp -a 失败: {}", e))?;

    if !output.status.success() {
        return Err(format!("arp 命令执行失败: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();
    let mut current_interface = String::new();

    for line in output_str.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("接口:") {
            if let Some(iface) = trimmed.split(':').nth(1) {
                current_interface = iface.trim().split_whitespace().next().unwrap_or("").to_string();
            }
            continue;
        }

        // 跳过表头和空行
        if trimmed.is_empty() || trimmed.starts_with("Internet 地址") {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            let ip = parts[0].to_string();
            let mac = parts[1].replace('-', ":").to_uppercase();
            if mac.len() == 17 {
                let is_static = if parts.len() >= 3 {
                    parts[2].contains("静态") || parts[2].contains("static")
                } else {
                    false
                };

                entries.push(ArpEntry {
                    ip,
                    mac,
                    interface: current_interface.clone(),
                    is_static,
                    last_seen: current_timestamp(),
                });
            }
        }
    }

    Ok(entries)
}

#[cfg(target_os = "linux")]
fn get_system_arp_linux() -> Result<Vec<ArpEntry>, String> {
    let output = Command::new("arp")
        .arg("-n")
        .output()
        .map_err(|e| format!("执行 arp -n 失败: {}", e))?;

    if !output.status.success() {
        return Err(format!("arp 命令执行失败: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();

    for (i, line) in output_str.lines().enumerate() {
        if i == 0 {
            continue; // 跳过表头
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let ip = parts[0].to_string();
            let mac = parts[2].to_uppercase();
            let iface = parts[4].to_string();
            let is_static = parts[3] == "CM";

            if mac.len() == 17 {
                entries.push(ArpEntry {
                    ip,
                    mac,
                    interface: iface,
                    is_static,
                    last_seen: current_timestamp(),
                });
            }
        }
    }

    Ok(entries)
}

/// ARP 欺骗检测
pub fn detect_arp_spoofing() -> Result<String, String> {
    let state = CAPTURE_STATE.lock().map_err(|e| format!("获取锁失败: {}", e))?;

    let mut findings: Vec<HashMap<String, String>> = Vec::new();

    // 检查同一 IP 对应多个 MAC
    let mut ip_to_macs: HashMap<&str, Vec<&str>> = HashMap::new();
    for entry in &state.arp_table {
        ip_to_macs
            .entry(&entry.ip)
            .or_default()
            .push(&entry.mac);
    }

    for (ip, macs) in ip_to_macs.iter() {
        let unique_macs: std::collections::HashSet<&str> = macs.iter().copied().collect();
        if unique_macs.len() > 1 {
            let mut info = HashMap::new();
            info.insert("type".to_string(), "IP_MULTIPLE_MAC".to_string());
            info.insert("ip".to_string(), ip.to_string());
            info.insert("macs".to_string(), unique_macs.into_iter().collect::<Vec<_>>().join(", "));
            info.insert("description".to_string(), format!("IP 地址 {} 对应了 {} 个不同的 MAC 地址", ip, macs.len()));
            findings.push(info);
        }
    }

    // 检查同一 MAC 对应多个 IP（可能是正常的路由器，但也可能是 ARP 欺骗）
    let mut mac_to_ips: HashMap<&str, Vec<&str>> = HashMap::new();
    for entry in &state.arp_table {
        mac_to_ips
            .entry(&entry.mac)
            .or_default()
            .push(&entry.ip);
    }

    for (mac, ips) in mac_to_ips.iter() {
        if ips.len() > 2 {
            let mut info = HashMap::new();
            info.insert("type".to_string(), "MAC_MULTIPLE_IP".to_string());
            info.insert("mac".to_string(), mac.to_string());
            info.insert("ips".to_string(), ips.join(", "));
            info.insert("description".to_string(), format!("MAC 地址 {} 对应了 {} 个 IP 地址", mac, ips.len()));
            findings.push(info);
        }
    }

    // 检查是否有 MAC 声称是网关 IP（常见 ARP 欺骗手法）
    // （需要知道网关 IP，这里简化处理）

    let result = serde_json::json!({
        "findings": findings,
        "findings_count": findings.len(),
        "arp_table_size": state.arp_table.len(),
    });

    if findings.is_empty() {
        success_response(result, "未检测到 ARP 欺骗异常")
    } else {
        success_response(result, &format!("检测到 {} 个 ARP 异常", findings.len()))
    }
}

// ============================================================
// 7. 导出功能
// ============================================================

/// 导出数据包
/// format: "pcap", "json", "csv"
pub fn export_packets(format: String, path: String) -> Result<String, String> {
    let state = CAPTURE_STATE.lock().map_err(|e| format!("获取锁失败: {}", e))?;

    if state.packets.is_empty() {
        return error_response("没有可导出的数据包");
    }

    match format.to_lowercase().as_str() {
        "json" => export_json(&state.packets, &path),
        "csv" => export_csv(&state.packets, &path),
        "pcap" => export_pcap(&state.packets, &path),
        _ => Err(format!("不支持的导出格式: {}", format)),
    }
}

/// 导出为 JSON 格式
fn export_json(packets: &[PacketInfo], path: &str) -> Result<String, String> {
    let json = serde_json::to_string_pretty(packets).map_err(|e| format!("序列化失败: {}", e))?;

    std::fs::write(path, json).map_err(|e| format!("写入文件失败: {}", e))?;

    success_response(
        serde_json::json!({
            "format": "json",
            "path": path,
            "packet_count": packets.len(),
        }),
        &format!("成功导出 {} 个数据包到 {}", packets.len(), path),
    )
}

/// 导出为 CSV 格式
fn export_csv(packets: &[PacketInfo], path: &str) -> Result<String, String> {
    let mut csv = String::new();

    // 表头
    csv.push_str("timestamp,size,src_mac,dst_mac,ether_type,src_ip,dst_ip,protocol,src_port,dst_port,tcp_flags,info\n");

    for pkt in packets {
        let ts = pkt.timestamp;
        let size = pkt.size;

        let (src_mac, dst_mac, ether_type) = match &pkt.ethernet {
            Some(e) => (e.src_mac.clone(), e.dst_mac.clone(), e.ether_type_name.clone()),
            None => (String::new(), String::new(), String::new()),
        };

        let (src_ip, dst_ip, protocol) = match &pkt.ip {
            Some(ip) => (ip.src_ip.clone(), ip.dst_ip.clone(), ip.protocol_name.clone()),
            None => (String::new(), String::new(), String::new()),
        };

        let (src_port, dst_port, tcp_flags) = if let Some(ref tcp) = pkt.tcp {
            (tcp.src_port.to_string(), tcp.dst_port.to_string(), tcp.flags.to_string())
        } else if let Some(ref udp) = pkt.udp {
            (udp.src_port.to_string(), udp.dst_port.to_string(), String::from("-"))
        } else {
            (String::new(), String::new(), String::new())
        };

        let info = if let Some(ref dns) = pkt.dns {
            format!("DNS {} {}", if dns.is_response { "Response" } else { "Query" }, dns.query_name)
        } else if let Some(ref http) = pkt.http {
            if http.is_request {
                format!("HTTP {} {}", http.method.as_deref().unwrap_or(""), http.url.as_deref().unwrap_or(""))
            } else {
                format!("HTTP {} {}", http.status_code.unwrap_or(0), http.status_text.as_deref().unwrap_or(""))
            }
        } else if let Some(ref icmp) = pkt.icmp {
            format!("ICMP {}", icmp.type_name)
        } else if let Some(ref arp) = pkt.arp {
            format!("ARP {} {} -> {}", arp.operation_name, arp.sender_ip, arp.target_ip)
        } else {
            String::new()
        };

        csv.push_str(&format!(
            "{:.6},{},{},{},{},{},{},{},{},{},{},\"{}\"\n",
            ts, size, src_mac, dst_mac, ether_type,
            src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags, info
        ));
    }

    std::fs::write(path, csv).map_err(|e| format!("写入文件失败: {}", e))?;

    success_response(
        serde_json::json!({
            "format": "csv",
            "path": path,
            "packet_count": packets.len(),
        }),
        &format!("成功导出 {} 个数据包到 {}", packets.len(), path),
    )
}

/// 导出为 PCAP 格式（简化版，使用 PCAP Global Header + Packet Headers）
fn export_pcap(packets: &[PacketInfo], path: &str) -> Result<String, String> {
    // PCAP 文件格式：
    // - Global Header (24 bytes)
    // - Packet Header (16 bytes) + Packet Data (variable)
    // - ...

    use std::io::Write;

    let file = std::fs::File::create(path).map_err(|e| format!("创建文件失败: {}", e))?;
    let mut writer = std::io::BufWriter::new(file);

    // Global Header
    let magic_number: u32 = 0xa1b2c3d4; // 标准 PCAP 魔数
    let version_major: u16 = 2;
    let version_minor: u16 = 4;
    let thiszone: i32 = 0;
    let sigfigs: u32 = 0;
    let snaplen: u32 = 65535;
    let network: u32 = 1; // LINKTYPE_ETHERNET

    writer.write_all(&magic_number.to_le_bytes()).unwrap();
    writer.write_all(&version_major.to_le_bytes()).unwrap();
    writer.write_all(&version_minor.to_le_bytes()).unwrap();
    writer.write_all(&thiszone.to_le_bytes()).unwrap();
    writer.write_all(&sigfigs.to_le_bytes()).unwrap();
    writer.write_all(&snaplen.to_le_bytes()).unwrap();
    writer.write_all(&network.to_le_bytes()).unwrap();

    // 模拟包数据（因为我们没有真实的原始数据包，这里写入最小的以太网帧）
    for pkt in packets {
        let ts_sec = pkt.timestamp as u32;
        let ts_usec = ((pkt.timestamp - ts_sec as f64) * 1_000_000.0) as u32;
        let incl_len = pkt.size.min(65535);
        let orig_len = pkt.size;

        // Packet Header
        writer.write_all(&ts_sec.to_le_bytes()).unwrap();
        writer.write_all(&ts_usec.to_le_bytes()).unwrap();
        writer.write_all(&incl_len.to_le_bytes()).unwrap();
        writer.write_all(&orig_len.to_le_bytes()).unwrap();

        // Packet Data - 写入简化的包数据（填充）
        // 实际应用中应该写入原始字节，这里我们构造一个最小帧
        let mut data = vec![0u8; pkt.size as usize];

        // 填充以太网头部
        if let Some(ref eth) = pkt.ethernet {
            // 目的 MAC
            if let Ok(dst_bytes) = mac_to_bytes(&eth.dst_mac) {
                data[0..6].copy_from_slice(&dst_bytes);
            }
            // 源 MAC
            if let Ok(src_bytes) = mac_to_bytes(&eth.src_mac) {
                data[6..12].copy_from_slice(&src_bytes);
            }
            // EtherType
            data[12] = (eth.ether_type >> 8) as u8;
            data[13] = (eth.ether_type & 0xFF) as u8;
        }

        writer.write_all(&data).unwrap();
    }

    writer.flush().map_err(|e| format!("写入文件失败: {}", e))?;

    success_response(
        serde_json::json!({
            "format": "pcap",
            "path": path,
            "packet_count": packets.len(),
            "note": "简化版 PCAP 格式，包数据为构造的模拟数据",
        }),
        &format!("成功导出 {} 个数据包到 {}", packets.len(), path),
    )
}

/// MAC 地址字符串转字节
fn mac_to_bytes(mac: &str) -> Result<[u8; 6], ()> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err(());
    }
    let mut bytes = [0u8; 6];
    for i in 0..6 {
        bytes[i] = u8::from_str_radix(parts[i], 16).map_err(|_| ())?;
    }
    Ok(bytes)
}

// ============================================================
// 兼容层：commands_netsec.rs 中使用的函数名别名
// ============================================================

pub fn get_stats() -> Result<String, String> {
    get_capture_stats()
}

pub fn get_dns() -> Result<String, String> {
    get_dns_queries()
}

pub fn get_http() -> Result<String, String> {
    get_http_requests()
}

pub fn detect_arp_spoof() -> Result<String, String> {
    detect_arp_spoofing()
}

pub fn export(format: String, path: String) -> Result<String, String> {
    export_packets(format, path)
}
