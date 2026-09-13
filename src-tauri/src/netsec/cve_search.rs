// yxpil · NETON
//! CVE 漏洞搜索工具
//! 集成 NVD API，本地漏洞库查询

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// CVE 搜索配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveSearchConfig {
    /// 搜索关键词
    pub keyword: String,
    /// CVE 编号（如 CVE-2024-1234）
    pub cve_id: Option<String>,
    /// 软件产品名
    pub product: Option<String>,
    /// 供应商
    pub vendor: Option<String>,
    /// CVSS 最低分数
    pub min_cvss: Option<f32>,
    /// 结果数量限制
    pub limit: u32,
    /// 仅返回 2020 年后的漏洞
    pub recent_only: bool,
}

impl Default for CveSearchConfig {
    fn default() -> Self {
        Self {
            keyword: String::new(),
            cve_id: None,
            product: None,
            vendor: None,
            min_cvss: None,
            limit: 20,
            recent_only: false,
        }
    }
}

/// CVE 漏洞严重程度
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CveSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl CveSeverity {
    pub fn from_cvss(score: f32) -> Self {
        match score {
            0.0 => CveSeverity::None,
            0.1..=3.9 => CveSeverity::Low,
            4.0..=6.9 => CveSeverity::Medium,
            7.0..=8.9 => CveSeverity::High,
            9.0..=10.0 => CveSeverity::Critical,
            _ => CveSeverity::None,
        }
    }

    pub fn to_label(&self) -> &'static str {
        match self {
            CveSeverity::None => "无",
            CveSeverity::Low => "低危",
            CveSeverity::Medium => "中危",
            CveSeverity::High => "高危",
            CveSeverity::Critical => "严重",
        }
    }
}

/// CVE 漏洞信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub description: String,
    pub cvss_score: f32,
    pub severity: CveSeverity,
    pub published_date: String,
    pub last_modified_date: String,
    pub affected_products: Vec<String>,
    pub references: Vec<String>,
    pub cwe_ids: Vec<String>,
}

/// CVE 搜索结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveSearchResult {
    pub query: String,
    pub total_results: u32,
    pub returned_results: u32,
    pub vulnerabilities: Vec<CveEntry>,
    pub source: String,
}

/// 本地常见漏洞库（概念性）
fn get_local_cve_database() -> Vec<CveEntry> {
    vec![
        CveEntry {
            id: "CVE-2024-21762".to_string(),
            description: "FortiOS SSL VPN 远程代码执行漏洞，攻击者可无需认证通过构造恶意请求执行任意代码。".to_string(),
            cvss_score: 9.8,
            severity: CveSeverity::Critical,
            published_date: "2024-02-08".to_string(),
            last_modified_date: "2024-03-15".to_string(),
            affected_products: vec!["FortiOS".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21762".to_string(),
            ],
            cwe_ids: vec!["CWE-122".to_string()],
        },
        CveEntry {
            id: "CVE-2024-3400".to_string(),
            description: "PAN-OS GlobalProtect 命令注入漏洞，攻击者可通过构造特殊请求在系统上执行任意命令。".to_string(),
            cvss_score: 10.0,
            severity: CveSeverity::Critical,
            published_date: "2024-04-12".to_string(),
            last_modified_date: "2024-05-20".to_string(),
            affected_products: vec!["PAN-OS".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3400".to_string(),
            ],
            cwe_ids: vec!["CWE-77".to_string()],
        },
        CveEntry {
            id: "CVE-2024-6387".to_string(),
            description: "OpenSSH regreSSHion 远程代码执行漏洞，存在于 glibc 系统上的 sshd 服务中。".to_string(),
            cvss_score: 8.1,
            severity: CveSeverity::High,
            published_date: "2024-07-01".to_string(),
            last_modified_date: "2024-07-10".to_string(),
            affected_products: vec!["OpenSSH".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-6387".to_string(),
            ],
            cwe_ids: vec!["CWE-362".to_string()],
        },
        CveEntry {
            id: "CVE-2024-3094".to_string(),
            description: "XZ Utils 后门漏洞，恶意代码注入导致 SSH 认证绕过风险。".to_string(),
            cvss_score: 10.0,
            severity: CveSeverity::Critical,
            published_date: "2024-03-29".to_string(),
            last_modified_date: "2024-04-05".to_string(),
            affected_products: vec!["XZ Utils".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3094".to_string(),
            ],
            cwe_ids: vec!["CWE-506".to_string()],
        },
        CveEntry {
            id: "CVE-2023-46805".to_string(),
            description: "Ivanti Connect Secure 认证绕过漏洞，攻击者可绕过认证访问管理界面。".to_string(),
            cvss_score: 9.1,
            severity: CveSeverity::Critical,
            published_date: "2024-01-10".to_string(),
            last_modified_date: "2024-02-20".to_string(),
            affected_products: vec!["Ivanti Connect Secure".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2023-46805".to_string(),
            ],
            cwe_ids: vec!["CWE-288".to_string()],
        },
        CveEntry {
            id: "CVE-2024-21762".to_string(),
            description: "Citrix NetScaler 远程代码执行漏洞，未授权攻击者可通过构造特殊请求执行代码。".to_string(),
            cvss_score: 9.8,
            severity: CveSeverity::Critical,
            published_date: "2023-10-10".to_string(),
            last_modified_date: "2024-01-15".to_string(),
            affected_products: vec!["Citrix NetScaler".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2023-4966".to_string(),
            ],
            cwe_ids: vec!["CWE-200".to_string()],
        },
        CveEntry {
            id: "CVE-2024-27198".to_string(),
            description: "JetBrains TeamCity 认证绕过漏洞，攻击者可绕过认证并执行管理操作。".to_string(),
            cvss_score: 9.8,
            severity: CveSeverity::Critical,
            published_date: "2024-03-04".to_string(),
            last_modified_date: "2024-03-20".to_string(),
            affected_products: vec!["JetBrains TeamCity".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-27198".to_string(),
            ],
            cwe_ids: vec!["CWE-288".to_string()],
        },
        CveEntry {
            id: "CVE-2024-23897".to_string(),
            description: "Jenkins CLI 任意文件读取漏洞，未认证攻击者可读取 Jenkins 服务器上的任意文件。".to_string(),
            cvss_score: 9.8,
            severity: CveSeverity::Critical,
            published_date: "2024-01-24".to_string(),
            last_modified_date: "2024-02-10".to_string(),
            affected_products: vec!["Jenkins".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-23897".to_string(),
            ],
            cwe_ids: vec!["CWE-22".to_string()],
        },
        CveEntry {
            id: "CVE-2024-20359".to_string(),
            description: "Cisco ASA 和 FTD 设备拒绝服务漏洞，可导致设备重启。".to_string(),
            cvss_score: 7.5,
            severity: CveSeverity::High,
            published_date: "2024-05-22".to_string(),
            last_modified_date: "2024-06-01".to_string(),
            affected_products: vec!["Cisco ASA".to_string(), "Cisco FTD".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-20359".to_string(),
            ],
            cwe_ids: vec!["CWE-400".to_string()],
        },
        CveEntry {
            id: "CVE-2024-38821".to_string(),
            description: "Microsoft Exchange Server 远程代码执行漏洞，需要认证。".to_string(),
            cvss_score: 8.8,
            severity: CveSeverity::High,
            published_date: "2024-06-11".to_string(),
            last_modified_date: "2024-06-20".to_string(),
            affected_products: vec!["Microsoft Exchange Server".to_string()],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-38821".to_string(),
            ],
            cwe_ids: vec!["CWE-94".to_string()],
        },
    ]
}

/// 搜索 CVE 漏洞
pub async fn search_cve(config: CveSearchConfig) -> Result<String, String> {
    let mut all_cves = get_local_cve_database();
    let query = if !config.keyword.is_empty() {
        config.keyword.clone()
    } else if let Some(cve_id) = &config.cve_id {
        cve_id.clone()
    } else if let Some(product) = &config.product {
        product.clone()
    } else {
        "all".to_string()
    };

    // 按 CVE ID 过滤
    if let Some(cve_id) = &config.cve_id {
        all_cves.retain(|c| c.id.to_lowercase().contains(&cve_id.to_lowercase()));
    }

    // 按关键词过滤
    if !config.keyword.is_empty() {
        let keyword = config.keyword.to_lowercase();
        all_cves.retain(|c| {
            c.id.to_lowercase().contains(&keyword)
                || c.description.to_lowercase().contains(&keyword)
                || c.affected_products
                    .iter()
                    .any(|p| p.to_lowercase().contains(&keyword))
        });
    }

    // 按产品过滤
    if let Some(product) = &config.product {
        let product_lower = product.to_lowercase();
        all_cves.retain(|c| {
            c.affected_products
                .iter()
                .any(|p| p.to_lowercase().contains(&product_lower))
        });
    }

    // 按供应商过滤
    if let Some(vendor) = &config.vendor {
        let vendor_lower = vendor.to_lowercase();
        all_cves.retain(|c| {
            c.affected_products
                .iter()
                .any(|p| p.to_lowercase().contains(&vendor_lower))
                || c.description.to_lowercase().contains(&vendor_lower)
        });
    }

    // 按 CVSS 分数过滤
    if let Some(min_cvss) = config.min_cvss {
        all_cves.retain(|c| c.cvss_score >= min_cvss);
    }

    // 仅显示近期漏洞
    if config.recent_only {
        all_cves.retain(|c| c.published_date.as_str() >= "2023-01-01");
    }

    let total = all_cves.len() as u32;

    // 按严重程度排序
    all_cves.sort_by(|a, b| b.cvss_score.partial_cmp(&a.cvss_score).unwrap_or(std::cmp::Ordering::Equal));

    // 限制结果数量
    all_cves.truncate(config.limit as usize);

    let result = CveSearchResult {
        query,
        total_results: total,
        returned_results: all_cves.len() as u32,
        vulnerabilities: all_cves,
        source: "本地漏洞库".to_string(),
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "CVE 搜索完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 从 NVD API 搜索 CVE（概念性实现）
pub async fn search_cve_nvd(keyword: String, limit: u32) -> Result<String, String> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage={}",
        urlencoding::encode(&keyword),
        limit
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    match client.get(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let text = response.text().await.map_err(|e| e.to_string())?;
                let json: serde_json::Value =
                    serde_json::from_str(&text).map_err(|e| e.to_string())?;

                let total_results = json
                    .get("totalResults")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;

                let mut vulnerabilities = Vec::new();

                if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
                    for vuln in vulns {
                        if let Some(cve) = vuln.get("cve") {
                            let id = cve
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let description = cve
                                .get("descriptions")
                                .and_then(|d| d.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|d| d.get("value"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let cvss_score = cve
                                .get("metrics")
                                .and_then(|m| m.get("cvssMetricV31"))
                                .and_then(|m| m.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|v| v.get("cvssData"))
                                .and_then(|d| d.get("baseScore"))
                                .and_then(|s| s.as_f64())
                                .unwrap_or(0.0) as f32;
                            let published = cve
                                .get("published")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            vulnerabilities.push(CveEntry {
                                id,
                                description,
                                cvss_score,
                                severity: CveSeverity::from_cvss(cvss_score),
                                published_date: published,
                                last_modified_date: String::new(),
                                affected_products: vec![],
                                references: vec![],
                                cwe_ids: vec![],
                            });
                        }
                    }
                }

                let result = CveSearchResult {
                    query: keyword,
                    total_results,
                    returned_results: vulnerabilities.len() as u32,
                    vulnerabilities,
                    source: "NVD API".to_string(),
                };

                serde_json::to_string(&crate::netsec::ToolResult::ok(result, "NVD 搜索完成"))
                    .map_err(|e| format!("序列化失败: {}", e))
            } else {
                Err(format!("NVD API 请求失败: {}", response.status()))
            }
        }
        Err(e) => Err(format!("NVD API 连接失败: {}", e)),
    }
}

/// 获取高危漏洞统计
pub fn get_cve_statistics() -> Result<String, String> {
    let cves = get_local_cve_database();

    let critical = cves
        .iter()
        .filter(|c| matches!(c.severity, CveSeverity::Critical))
        .count() as u32;
    let high = cves
        .iter()
        .filter(|c| matches!(c.severity, CveSeverity::High))
        .count() as u32;
    let medium = cves
        .iter()
        .filter(|c| matches!(c.severity, CveSeverity::Medium))
        .count() as u32;
    let low = cves
        .iter()
        .filter(|c| matches!(c.severity, CveSeverity::Low))
        .count() as u32;

    let stats = serde_json::json!({
        "total": cves.len(),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "avg_cvss": cves.iter().map(|c| c.cvss_score).sum::<f32>() / cves.len() as f32,
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(stats, "统计完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}
