// yxpil · NETON
//! 端口扫描工具
//! 支持 TCP 全连接扫描、常见端口服务识别

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use std::sync::Arc;

/// 端口扫描模式
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    /// TCP 全连接扫描
    TcpConnect,
    /// 快速扫描（仅常见端口）
    Quick,
}

/// 端口扫描配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanConfig {
    /// 目标主机（IP 或域名）
    pub target: String,
    /// 起始端口
    pub start_port: u16,
    /// 结束端口
    pub end_port: u16,
    /// 扫描模式
    pub mode: ScanMode,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
    /// 并发数
    pub concurrency: usize,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".to_string(),
            start_port: 1,
            end_port: 1024,
            mode: ScanMode::Quick,
            timeout_ms: 1000,
            concurrency: 100,
        }
    }
}

/// 开放端口信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub port: u16,
    pub service: String,
    pub protocol: String,
    pub banner: Option<String>,
}

/// 端口扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub target: String,
    pub total_ports: u32,
    pub open_ports: Vec<OpenPort>,
    pub closed_ports: u32,
    pub filtered_ports: u32,
    pub duration_ms: u64,
}

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
pub fn get_common_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 119, 135, 139, 143, 389, 443, 445,
        465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
        8080, 8443, 27017,
    ]
}

/// 执行 TCP 全连接端口扫描
pub async fn scan_ports(config: PortScanConfig) -> Result<String, String> {
    let start_time = std::time::Instant::now();
    let services = common_port_services();

    // 确定要扫描的端口列表
    let ports: Vec<u16> = match config.mode {
        ScanMode::Quick => get_common_ports(),
        ScanMode::TcpConnect => (config.start_port..=config.end_port).collect(),
    };

    let total_ports = ports.len() as u32;
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut open_ports: Vec<OpenPort> = Vec::new();
    let mut closed_count = 0u32;
    let mut filtered_count = 0u32;

    let mut handles = Vec::new();

    for port in ports {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        let target = config.target.clone();
        let timeout = Duration::from_millis(config.timeout_ms);
        let service_name = services
            .get(&port)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let addr: SocketAddr = format!("{}:{}", target, port)
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?;

            match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => Ok(OpenPort {
                    port,
                    service: service_name,
                    protocol: "TCP".to_string(),
                    banner: None,
                }),
                Ok(Err(_)) => Err("closed".to_string()),
                Err(_) => Err("filtered".to_string()),
            }
        }));
    }

    for handle in handles {
        match handle.await {
            Ok(Ok(port_info)) => open_ports.push(port_info),
            Ok(Err(e)) if e == "closed" => closed_count += 1,
            Ok(Err(_)) => filtered_count += 1,
            Err(e) => return Err(format!("扫描任务异常: {}", e)),
        }
    }

    // 按端口号排序
    open_ports.sort_by_key(|p| p.port);

    let result = PortScanResult {
        target: config.target.clone(),
        total_ports,
        open_ports,
        closed_ports: closed_count,
        filtered_ports: filtered_count,
        duration_ms: start_time.elapsed().as_millis() as u64,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "端口扫描完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 单端口探测
pub async fn probe_port(target: String, port: u16, timeout_ms: u64) -> Result<String, String> {
    let services = common_port_services();
    let addr: SocketAddr = format!("{}:{}", target, port)
        .parse()
        .map_err(|e| format!("地址解析失败: {}", e))?;

    let result = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_)) => {
            let service = services
                .get(&port)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            OpenPort {
                port,
                service,
                protocol: "TCP".to_string(),
                banner: None,
            }
        }
        Ok(Err(e)) => return Err(format!("端口关闭: {}", e)),
        Err(_) => return Err("连接超时，端口可能被过滤".to_string()),
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "端口探测完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}
