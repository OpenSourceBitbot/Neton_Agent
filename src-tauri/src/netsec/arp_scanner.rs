// yxpil · NETON
//! ARP 设备扫描工具
//! 局域网设备发现，MAC 地址解析

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// ARP 扫描配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpScanConfig {
    /// 目标网段 CIDR（如 192.168.1.0/24）
    pub network: String,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
    /// 并发数
    pub concurrency: usize,
}

impl Default for ArpScanConfig {
    fn default() -> Self {
        Self {
            network: "192.168.1.0/24".to_string(),
            timeout_ms: 2000,
            concurrency: 50,
        }
    }
}

/// 网络设备信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub ip: String,
    pub mac: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub is_alive: bool,
    pub response_time_ms: u64,
}

/// ARP 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpScanResult {
    pub network: String,
    pub total_hosts: u32,
    pub alive_hosts: Vec<NetworkDevice>,
    pub duration_ms: u64,
}

/// 常见 MAC 地址厂商前缀映射
fn mac_vendor_lookup(mac_prefix: &str) -> Option<&'static str> {
    let mut vendors = HashMap::new();
    vendors.insert("00:1A:2B", "Intel Corp");
    vendors.insert("00:1C:42", "Apple Inc");
    vendors.insert("00:1E:C2", "Apple Inc");
    vendors.insert("00:21:E9", "Apple Inc");
    vendors.insert("00:23:12", "Apple Inc");
    vendors.insert("00:25:00", "Apple Inc");
    vendors.insert("00:26:08", "Apple Inc");
    vendors.insert("00:26:B0", "Apple Inc");
    vendors.insert("00:50:56", "VMware Inc");
    vendors.insert("00:0C:29", "VMware Inc");
    vendors.insert("00:05:69", "VMware Inc");
    vendors.insert("08:00:27", "Oracle VirtualBox");
    vendors.insert("52:54:00", "QEMU Virtual NIC");
    vendors.insert("FE:FF:FF", "Virtual Machine");
    vendors.insert("00:15:5D", "Microsoft Corporation");
    vendors.insert("00:03:FF", "Microsoft Corporation");
    vendors.insert("00:0D:B9", "Cisco Systems");
    vendors.insert("00:12:00", "Cisco Systems");
    vendors.insert("00:1A:6B", "Cisco Systems");
    vendors.insert("00:1F:CA", "Cisco Systems");
    vendors.insert("1C:1D:86", "Cisco Systems");
    vendors.insert("FC:FB:FB", "Cisco Systems");
    vendors.insert("00:1B:21", "Hewlett Packard");
    vendors.insert("00:18:FE", "Hewlett Packard");
    vendors.insert("00:10:DC", "Hewlett Packard");
    vendors.insert("00:24:81", "Huawei Technologies");
    vendors.insert("00:1E:10", "Huawei Technologies");
    vendors.insert("54:89:98", "Huawei Technologies");
    vendors.insert("38:AD:8E", "Xiaomi Communications");
    vendors.insert("AC:CF:23", "Xiaomi Communications");
    vendors.insert("F0:B4:29", "Xiaomi Communications");
    vendors.insert("BC:D1:1F", "TP-Link Technologies");
    vendors.insert("C8:3A:35", "TP-Link Technologies");
    vendors.insert("E8:94:F6", "TP-Link Technologies");
    vendors.insert("74:DA:38", "TP-Link Technologies");
    vendors.insert("E0:CB:4D", "Tenda Technology");
    vendors.insert("C8:0E:14", "Netcore Technology");
    vendors.insert("04:95:E6", "Mercury Communications");
    vendors.insert("D8:FE:E3", "Samsung Electronics");
    vendors.insert("04:18:D6", "ASUSTek Computer");
    vendors.insert("1C:87:2C", "ASUSTek Computer");
    vendors.insert("60:45:CB", "Raspberry Pi Foundation");
    vendors.insert("B8:27:EB", "Raspberry Pi Foundation");
    vendors.insert("DC:A6:32", "Raspberry Pi Foundation");

    let prefix_upper = mac_prefix.to_uppercase();
    vendors.get(prefix_upper.as_str()).copied()
}

/// 解析 CIDR 网络地址，返回 IP 列表
fn parse_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("无效的 CIDR 格式".to_string());
    }

    let ip: Ipv4Addr = parts[0].parse().map_err(|e| format!("无效的 IP 地址: {}", e))?;
    let prefix_len: u8 = parts[1].parse().map_err(|e| format!("无效的前缀长度: {}", e))?;

    if prefix_len > 32 {
        return Err("前缀长度必须在 0-32 之间".to_string());
    }

    let mask = if prefix_len == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_len)
    };

    let ip_u32 = u32::from(ip);
    let network_addr = ip_u32 & mask;
    let broadcast_addr = network_addr | !mask;

    // 跳过网络地址和广播地址
    let mut ips = Vec::new();
    for addr in (network_addr + 1)..broadcast_addr {
        ips.push(Ipv4Addr::from(addr));
    }

    Ok(ips)
}

/// 获取本机 ARP 表（概念性实现，实际需要 pnet 或系统命令）
fn get_system_arp_table() -> HashMap<String, String> {
    let mut arp_table = HashMap::new();
    // 实际实现中应读取系统 ARP 表
    // Windows: arp -a
    // Linux: cat /proc/net/arp
    // macOS: arp -a
    arp_table
}

/// 执行 ARP 扫描
pub async fn scan_arp(config: ArpScanConfig) -> Result<String, String> {
    let start_time = std::time::Instant::now();

    let ips = parse_cidr(&config.network)?;
    let total_hosts = ips.len() as u32;

    // 概念性实现：模拟 ARP 扫描
    // 实际实现需要使用 pnet 库发送 ARP 请求并监听响应
    let mut alive_hosts = Vec::new();

    // 获取本机 ARP 表作为补充信息
    let system_arp = get_system_arp_table();

    // 模拟扫描结果（实际应通过 ARP 请求获取）
    // 这里使用 ICMP ping 作为替代方案的概念演示
    let semaphore = tokio::sync::Semaphore::new(config.concurrency);
    let mut handles = Vec::new();

    for ip in ips {
        let permit = semaphore
            .acquire()
            .await
            .map_err(|e| e.to_string())?;
        let ip_str = ip.to_string();
        let timeout = config.timeout_ms;
        let system_arp_clone = system_arp.clone();

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let start = std::time::Instant::now();

            // 尝试 TCP 连接到常见端口作为存活检测（概念性）
            let is_alive = tokio::time::timeout(
                std::time::Duration::from_millis(timeout),
                tokio::net::TcpStream::connect(format!("{}:80", ip_str)),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);

            // 或者检查系统 ARP 表
            let mac_from_arp = system_arp_clone.get(&ip_str).cloned();

            if is_alive || mac_from_arp.is_some() {
                let mac = mac_from_arp.unwrap_or_else(|| "00:00:00:00:00:00".to_string());
                let vendor = if mac.len() >= 8 {
                    mac_vendor_lookup(&mac[..8])
                } else {
                    None
                };

                Some(NetworkDevice {
                    ip: ip_str,
                    mac,
                    vendor: vendor.map(|v| v.to_string()),
                    hostname: None,
                    is_alive,
                    response_time_ms: start.elapsed().as_millis() as u64,
                })
            } else {
                None
            }
        }));
    }

    for handle in handles {
        if let Ok(Some(device)) = handle.await {
            alive_hosts.push(device);
        }
    }

    // 按 IP 排序
    alive_hosts.sort_by(|a, b| {
        let a_ip: Ipv4Addr = a.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let b_ip: Ipv4Addr = b.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        a_ip.cmp(&b_ip)
    });

    let result = ArpScanResult {
        network: config.network,
        total_hosts,
        alive_hosts,
        duration_ms: start_time.elapsed().as_millis() as u64,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "ARP 扫描完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 获取本机网络接口信息
pub fn get_local_interfaces() -> Result<String, String> {
    use if_addrs::get_if_addrs;

    let interfaces = get_if_addrs().map_err(|e| format!("获取网络接口失败: {}", e))?;

    let result: Vec<serde_json::Value> = interfaces
        .iter()
        .map(|iface| {
            serde_json::json!({
                "name": iface.name,
                "ip": iface.ip().to_string(),
                "netmask": iface.netmask().to_string(),
                "is_loopback": iface.is_loopback(),
            })
        })
        .collect();

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "获取网络接口成功"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// MAC 地址厂商查询
pub fn lookup_mac_vendor(mac: String) -> Result<String, String> {
    let normalized = mac.replace('-', ":").to_uppercase();
    if normalized.len() < 8 {
        return Err("MAC 地址格式无效".to_string());
    }

    let prefix = &normalized[..8];
    let vendor = mac_vendor_lookup(prefix).unwrap_or("未知厂商");

    let result = serde_json::json!({
        "mac": mac,
        "vendor": vendor,
        "prefix": prefix,
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "MAC 厂商查询完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}
