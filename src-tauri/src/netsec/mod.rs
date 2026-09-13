// yxpil · NETON
//! 网络安全工具模块
//! 提供端口扫描、密码爆破、弱口令分析、ARP扫描、SQL注入测试、
//! Web漏洞扫描（XSS/CSRF/LFI/RFI/命令注入/XXE/SSRF/开放重定向/点击劫持）、
//! CVE搜索、验证码识别、域名分析、网络拓扑、NAT分析、病毒扫描、虚拟浏览器、
//! 网页分析、网络爬虫、设备接入接口测试、数据包捕获分析等功能。

pub mod device_api;
pub mod port_scanner;
pub mod password_cracker;
pub mod weak_password;
pub mod arp_scanner;
pub mod sql_injection;
pub mod cve_search;
pub mod captcha;
pub mod domain_analysis;
pub mod topology;
pub mod nat_analysis;
pub mod virus_scan;
pub mod virtual_browser;
pub mod web_analyzer;
pub mod web_crawler;
pub mod site_info;
pub mod vuln_scanner;
pub mod packet_capture;
pub mod firewall_dns;
pub mod hash_crypto;

use serde::{Deserialize, Serialize};

/// 通用扫描结果状态
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// 通用工具执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult<T: Serialize> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
    pub timestamp: i64,
}

impl<T: Serialize> ToolResult<T> {
    pub fn ok(data: T, message: &str) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            data: Some(data),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            message: message.to_string(),
            data: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}

/// 将 ToolResult 序列化为 JSON 字符串
pub fn result_to_json<T: Serialize>(result: &ToolResult<T>) -> Result<String, String> {
    serde_json::to_string(result).map_err(|e| format!("序列化失败: {}", e))
}
