// yxpil · NETON
//! 域名分析工具
//! WHOIS 查询、DNS 解析、子域名枚举

use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::collections::HashSet;

/// DNS 记录类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    TXT,
    SOA,
    PTR,
    SRV,
    CAA,
}

impl DnsRecordType {
    pub fn to_str(&self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::CNAME => "CNAME",
            DnsRecordType::MX => "MX",
            DnsRecordType::NS => "NS",
            DnsRecordType::TXT => "TXT",
            DnsRecordType::SOA => "SOA",
            DnsRecordType::PTR => "PTR",
            DnsRecordType::SRV => "SRV",
            DnsRecordType::CAA => "CAA",
        }
    }
}

/// DNS 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub priority: Option<u16>,
}

/// WHOIS 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrant: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub raw: String,
}

/// 子域名枚举配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainConfig {
    pub domain: String,
    pub wordlist: Vec<String>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub record_types: Vec<DnsRecordType>,
}

impl Default for SubdomainConfig {
    fn default() -> Self {
        Self {
            domain: "example.com".to_string(),
            wordlist: vec![],
            concurrency: 20,
            timeout_ms: 3000,
            record_types: vec![DnsRecordType::A, DnsRecordType::CNAME],
        }
    }
}

/// 子域名信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainInfo {
    pub subdomain: String,
    pub records: Vec<DnsRecord>,
    pub ip_addresses: Vec<String>,
    pub is_alive: bool,
}

/// 域名分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAnalysisResult {
    pub domain: String,
    pub dns_records: Vec<DnsRecord>,
    pub whois: Option<WhoisInfo>,
    pub subdomains: Vec<SubdomainInfo>,
    pub duration_ms: u64,
}

/// DNS 解析（使用系统 DNS）
pub async fn dns_lookup(domain: String, record_type: DnsRecordType) -> Result<String, String> {
    let start_time = std::time::Instant::now();
    let mut records = Vec::new();

    match record_type {
        DnsRecordType::A => {
            // 使用 tokio 的 DNS 解析
            match tokio::net::lookup_host(format!("{}:0", domain)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if addr.is_ipv4() {
                            records.push(DnsRecord {
                                record_type: "A".to_string(),
                                value: addr.ip().to_string(),
                                ttl: 0,
                                priority: None,
                            });
                        }
                    }
                }
                Err(e) => return Err(format!("DNS 解析失败: {}", e)),
            }
        }
        DnsRecordType::AAAA => {
            match tokio::net::lookup_host(format!("{}:0", domain)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if addr.is_ipv6() {
                            records.push(DnsRecord {
                                record_type: "AAAA".to_string(),
                                value: addr.ip().to_string(),
                                ttl: 0,
                                priority: None,
                            });
                        }
                    }
                }
                Err(e) => return Err(format!("DNS 解析失败: {}", e)),
            }
        }
        _ => {
            // 其他记录类型需要专门的 DNS 库
            // 概念性实现，返回空结果
            records.push(DnsRecord {
                record_type: record_type.to_str().to_string(),
                value: "需要专业 DNS 库支持（概念性实现）".to_string(),
                ttl: 0,
                priority: None,
            });
        }
    }

    let result = serde_json::json!({
        "domain": domain,
        "record_type": record_type.to_str(),
        "records": records,
        "duration_ms": start_time.elapsed().as_millis() as u64,
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "DNS 解析完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 完整 DNS 解析（多种记录类型）
pub async fn dns_full_lookup(domain: String) -> Result<String, String> {
    let start_time = std::time::Instant::now();
    let mut all_records = Vec::new();

    // A 记录
    if let Ok(result_str) = dns_lookup(domain.clone(), DnsRecordType::A).await {
        if let Ok(result) = serde_json::from_str::<crate::netsec::ToolResult<serde_json::Value>>(&result_str) {
            if let Some(data) = result.data {
                if let Some(recs) = data.get("records").and_then(|r| r.as_array()) {
                    for rec in recs {
                        if let Ok(r) = serde_json::from_value::<DnsRecord>(rec.clone()) {
                            all_records.push(r);
                        }
                    }
                }
            }
        }
    }

    // AAAA 记录
    if let Ok(result_str) = dns_lookup(domain.clone(), DnsRecordType::AAAA).await {
        if let Ok(result) = serde_json::from_str::<crate::netsec::ToolResult<serde_json::Value>>(&result_str) {
            if let Some(data) = result.data {
                if let Some(recs) = data.get("records").and_then(|r| r.as_array()) {
                    for rec in recs {
                        if let Ok(r) = serde_json::from_value::<DnsRecord>(rec.clone()) {
                            all_records.push(r);
                        }
                    }
                }
            }
        }
    }

    let result = serde_json::json!({
        "domain": domain,
        "records": all_records,
        "total_records": all_records.len(),
        "duration_ms": start_time.elapsed().as_millis() as u64,
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "DNS 完整解析完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// WHOIS 查询（概念性实现）
pub async fn whois_query(domain: String) -> Result<String, String> {
    let start_time = std::time::Instant::now();

    // 实际实现需要连接 WHOIS 服务器（端口 43）
    // 这里提供概念性实现框架

    // 提取顶级域名
    let tld = domain
        .rsplit('.')
        .next()
        .unwrap_or("com")
        .to_lowercase();

    // WHOIS 服务器映射
    let whois_server = match tld.as_str() {
        "com" | "net" => "whois.verisign-grs.com",
        "org" => "whois.pir.org",
        "info" => "whois.afilias.net",
        "cn" => "whois.cnnic.cn",
        "io" => "whois.nic.io",
        "app" => "whois.nic.google",
        "dev" => "whois.nic.google",
        _ => "whois.iana.org",
    };

    // 概念性：模拟 WHOIS 查询
    // 实际实现应使用 TCP 连接到端口 43
    let mock_raw = format!(
        "Domain Name: {}\n\
         Registrar: Example Registrar, Inc.\n\
         Registrant: Example Corp\n\
         Creation Date: 2020-01-15T00:00:00Z\n\
         Expiration Date: 2026-01-15T23:59:59Z\n\
         Updated Date: 2024-06-20T10:30:00Z\n\
         Name Server: ns1.example.com\n\
         Name Server: ns2.example.com\n\
         Status: clientTransferProhibited\n\
         Status: clientUpdateProhibited",
        domain
    );

    let whois_info = WhoisInfo {
        domain: domain.clone(),
        registrar: Some("Example Registrar, Inc.".to_string()),
        registrant: Some("Example Corp".to_string()),
        creation_date: Some("2020-01-15T00:00:00Z".to_string()),
        expiration_date: Some("2026-01-15T23:59:59Z".to_string()),
        updated_date: Some("2024-06-20T10:30:00Z".to_string()),
        nameservers: vec![
            "ns1.example.com".to_string(),
            "ns2.example.com".to_string(),
        ],
        status: vec![
            "clientTransferProhibited".to_string(),
            "clientUpdateProhibited".to_string(),
        ],
        raw: mock_raw,
    };

    let result = serde_json::json!({
        "whois_server": whois_server,
        "info": whois_info,
        "duration_ms": start_time.elapsed().as_millis() as u64,
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(
        result,
        "WHOIS 查询完成（概念性实现，数据为示例）",
    ))
    .map_err(|e| format!("序列化失败: {}", e))
}

/// 获取常见子域名字典
pub fn get_common_subdomain_wordlist() -> Vec<String> {
    vec![
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "admin", "test", "blog", "dev", "api", "cdn", "static", "images", "img",
        "css", "js", "app", "apps", "portal", "crm", "erp", "shop", "store",
        "forum", "wiki", "news", "m", "mobile", "wap", "beta", "staging", "dev1",
        "dev2", "test1", "test2", "prod", "production", "stage", "demo", "docs",
        "api1", "api2", "api3", "gw", "gateway", "proxy", "vpn", "remote",
        "owa", "exchange", "autodiscover", "activesync", "cpanel", "whm",
        "webmin", "phpmyadmin", "wp-admin", "admin", "administrator", "root",
        "backup", "bak", "old", "new", "test", "staging", "uat", "qa",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

/// 子域名枚举
pub async fn enumerate_subdomains(config: SubdomainConfig) -> Result<String, String> {
    let start_time = std::time::Instant::now();
    let mut subdomains: Vec<SubdomainInfo> = Vec::new();

    let wordlist = if config.wordlist.is_empty() {
        get_common_subdomain_wordlist()
    } else {
        config.wordlist.clone()
    };

    let semaphore = tokio::sync::Semaphore::new(config.concurrency);
    let mut handles = Vec::new();

    for word in &wordlist {
        let permit = semaphore
            .acquire()
            .await
            .map_err(|e| e.to_string())?;

        let subdomain = format!("{}.{}", word, config.domain);
        let timeout = config.timeout_ms;

        handles.push(tokio::spawn(async move {
            let _permit = permit;

            // 尝试 DNS 解析
            let result = tokio::time::timeout(
                Duration::from_millis(timeout),
                tokio::net::lookup_host(format!("{}:0", subdomain)),
            )
            .await;

            match result {
                Ok(Ok(addrs)) => {
                    let addrs_vec: Vec<std::net::SocketAddr> = addrs.collect();
                    if !addrs_vec.is_empty() {
                        let ip_addresses: Vec<String> = addrs_vec
                            .iter()
                            .map(|a| a.ip().to_string())
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .collect();

                        let records = ip_addresses
                            .iter()
                            .map(|ip| DnsRecord {
                                record_type: if ip.contains(':') { "AAAA" } else { "A" }.to_string(),
                                value: ip.clone(),
                                ttl: 0,
                                priority: None,
                            })
                            .collect();

                        Some(SubdomainInfo {
                            subdomain: subdomain.clone(),
                            records,
                            ip_addresses,
                            is_alive: true,
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }));
    }

    for handle in handles {
        if let Ok(Some(subdomain)) = handle.await {
            subdomains.push(subdomain);
        }
    }

    // 按子域名排序
    subdomains.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

    let result = serde_json::json!({
        "domain": config.domain,
        "total_tested": wordlist.len(),
        "found": subdomains.len(),
        "subdomains": subdomains,
        "duration_ms": start_time.elapsed().as_millis() as u64,
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "子域名枚举完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 综合域名分析
pub async fn analyze_domain(domain: String) -> Result<String, String> {
    let start_time = std::time::Instant::now();

    // DNS 解析
    let dns_result = dns_full_lookup(domain.clone()).await?;
    let dns_data: Vec<DnsRecord> = {
        let tool_result: crate::netsec::ToolResult<serde_json::Value> =
            serde_json::from_str(&dns_result).map_err(|e| e.to_string())?;
        tool_result
            .data
            .and_then(|d| d.get("records").cloned())
            .and_then(|r| serde_json::from_value(r).ok())
            .unwrap_or_default()
    };

    // WHOIS 查询
    let whois_result = whois_query(domain.clone()).await?;
    let whois_data: Option<WhoisInfo> = {
        let tool_result: crate::netsec::ToolResult<serde_json::Value> =
            serde_json::from_str(&whois_result).map_err(|e| e.to_string())?;
        tool_result
            .data
            .and_then(|d| d.get("info").cloned())
            .and_then(|w| serde_json::from_value(w).ok())
    };

    // 子域名枚举（使用少量常用子域名）
    let sub_config = SubdomainConfig {
        domain: domain.clone(),
        wordlist: vec![
            "www".to_string(),
            "mail".to_string(),
            "ftp".to_string(),
            "api".to_string(),
            "dev".to_string(),
            "test".to_string(),
            "admin".to_string(),
            "blog".to_string(),
        ],
        concurrency: 10,
        timeout_ms: 3000,
        record_types: vec![DnsRecordType::A],
    };

    let sub_result = enumerate_subdomains(sub_config).await?;
    let subdomains: Vec<SubdomainInfo> = {
        let tool_result: crate::netsec::ToolResult<serde_json::Value> =
            serde_json::from_str(&sub_result).map_err(|e| e.to_string())?;
        tool_result
            .data
            .and_then(|d| d.get("subdomains").cloned())
            .and_then(|s| serde_json::from_value(s).ok())
            .unwrap_or_default()
    };

    let result = DomainAnalysisResult {
        domain,
        dns_records: dns_data,
        whois: whois_data,
        subdomains,
        duration_ms: start_time.elapsed().as_millis() as u64,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "域名分析完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}
