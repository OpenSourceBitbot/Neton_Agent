// yxpil · NETON
//! 网络安全工具 Tauri 命令
//! 提供端口扫描、密码爆破、弱口令分析、ARP扫描、SQL注入测试、
//! CVE搜索、验证码识别、域名分析、网络拓扑、NAT分析、病毒扫描、虚拟浏览器等功能的 Tauri 命令封装。

use crate::netsec::arp_scanner::{ArpScanConfig, self};
use crate::netsec::captcha::{CaptchaConfig, CaptchaType, self};
use crate::netsec::cve_search::{CveSearchConfig, self};
use crate::netsec::domain_analysis::{DnsRecordType, SubdomainConfig, self};
use crate::netsec::nat_analysis::{NatDetectionConfig, self};
use crate::netsec::password_cracker::{CrackProtocol, PasswordCrackConfig, self};
use crate::netsec::port_scanner::{PortScanConfig, ScanMode, self};
use crate::netsec::sql_injection::{InjectionType, SqlInjectionConfig, self};
use crate::netsec::topology::{TracerouteConfig, self};
use crate::netsec::virtual_browser::{ScreenshotConfig, VirtualBrowserConfig, BrowserEngine, self};
use crate::netsec::virus_scan::{ScanType, VirusScanConfig, self};
use crate::netsec::weak_password::{self};
use crate::netsec::web_analyzer::{self};
use crate::netsec::web_crawler::{self};
use crate::netsec::site_info::{self};
use crate::netsec::device_api::{self};
use crate::netsec::vuln_scanner::{self};
use crate::netsec::packet_capture::{self};
use crate::netsec::hash_crypto::{self};
use crate::netsec::firewall_dns::{self};

// ---------- 端口扫描 ----------

/// 端口扫描
#[tauri::command]
pub async fn port_scan(
    target: String,
    ports: String,
    scan_type: String,
    timeout: u64,
    concurrency: u32,
) -> Result<String, String> {
    let mode = match scan_type.to_lowercase().as_str() {
        "quick" => ScanMode::Quick,
        "tcp_connect" | "tcpconnect" | "full" => ScanMode::TcpConnect,
        _ => ScanMode::Quick,
    };

    let (start_port, end_port) = if mode == ScanMode::Quick {
        (1u16, 1024u16)
    } else if ports.contains('-') {
        let parts: Vec<&str> = ports.split('-').collect();
        let start: u16 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(1);
        let end: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(65535);
        (start, end)
    } else {
        let p: u16 = ports.parse().unwrap_or(1024);
        (1, p)
    };

    let config = PortScanConfig {
        target,
        start_port,
        end_port,
        mode,
        timeout_ms: timeout,
        concurrency: concurrency as usize,
    };

    port_scanner::scan_ports(config).await
}

// ---------- 密码爆破 ----------

/// 密码爆破
#[tauri::command]
pub async fn password_crack(
    target: String,
    port: u16,
    protocol: String,
    username: String,
    wordlist: String,
    concurrency: u32,
) -> Result<String, String> {
    let protocol_enum = match protocol.to_lowercase().as_str() {
        "ssh" => CrackProtocol::Ssh,
        "ftp" => CrackProtocol::Ftp,
        "http_basic" | "httpbasic" | "basic" => CrackProtocol::HttpBasic,
        "http_form" | "httpform" | "form" => CrackProtocol::HttpForm,
        _ => CrackProtocol::HttpBasic,
    };

    // 解析密码字典：支持 JSON 数组或逗号/换行分隔
    let passwords: Vec<String> = if wordlist.starts_with('[') {
        serde_json::from_str(&wordlist).unwrap_or_default()
    } else {
        wordlist
            .split(|c: char| c == ',' || c == '\n' || c == ';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    let usernames: Vec<String> = if username.contains(',') {
        username.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        vec![username]
    };

    let config = PasswordCrackConfig {
        target,
        port,
        protocol: protocol_enum,
        usernames,
        passwords,
        concurrency: concurrency as usize,
        timeout_ms: 5000,
        stop_on_first: true,
    };

    password_cracker::crack_passwords(config).await
}

// ---------- 弱口令分析 ----------

/// 弱口令分析
#[tauri::command]
pub fn weak_password_analyze(password: String) -> Result<String, String> {
    weak_password::analyze_password(password)
}

/// 弱口令批量检测
#[tauri::command]
pub fn weak_password_batch(passwords: String) -> Result<String, String> {
    // 解析密码列表：支持 JSON 数组或逗号/换行分隔
    let pw_list: Vec<String> = if passwords.starts_with('[') {
        serde_json::from_str(&passwords).map_err(|e| format!("密码列表格式错误: {}", e))?
    } else {
        passwords
            .split(|c: char| c == ',' || c == '\n' || c == ';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    weak_password::check_weak_passwords(pw_list)
}

// ---------- ARP 扫描 ----------

/// ARP 扫描
#[tauri::command]
pub async fn arp_scan(network: String) -> Result<String, String> {
    let config = ArpScanConfig {
        network,
        timeout_ms: 2000,
        concurrency: 50,
    };

    arp_scanner::scan_arp(config).await
}

/// 获取本地网卡
#[tauri::command]
pub fn get_local_interfaces() -> Result<String, String> {
    arp_scanner::get_local_interfaces()
}

// ---------- SQL 注入测试 ----------

/// SQL 注入测试
#[tauri::command]
pub async fn sql_injection_test(
    url: String,
    param: String,
    method: String,
    scan_type: String,
) -> Result<String, String> {
    let injection_type = match scan_type.to_lowercase().as_str() {
        "basic_error" | "basic" | "error" => InjectionType::BasicError,
        "union" | "union_based" => InjectionType::UnionBased,
        "boolean" | "boolean_blind" => InjectionType::BooleanBlind,
        "time" | "time_based" | "time_blind" => InjectionType::TimeBasedBlind,
        "full" | "all" | "complete" => InjectionType::FullScan,
        _ => InjectionType::BasicError,
    };

    let config = SqlInjectionConfig {
        url,
        param,
        method,
        injection_type,
        timeout_ms: 5000,
        cookies: None,
        headers: None,
    };

    sql_injection::test_sql_injection(config).await
}

// ---------- CVE 搜索 ----------

/// CVE 搜索
#[tauri::command]
pub async fn cve_search(keyword: String, limit: u32) -> Result<String, String> {
    let config = CveSearchConfig {
        keyword,
        cve_id: None,
        product: None,
        vendor: None,
        min_cvss: None,
        limit,
        recent_only: false,
    };

    cve_search::search_cve(config).await
}

/// CVE 统计
#[tauri::command]
pub fn cve_statistics() -> Result<String, String> {
    cve_search::get_cve_statistics()
}

// ---------- 验证码识别 ----------

/// 验证码识别
#[tauri::command]
pub async fn captcha_recognize(image_data: String, captcha_type: String) -> Result<String, String> {
    let captcha_type_enum = match captcha_type.to_lowercase().as_str() {
        "numeric" | "number" => CaptchaType::Numeric,
        "alphabetic" | "alpha" | "letter" => CaptchaType::Alphabetic,
        "alphanumeric" | "mixed" => CaptchaType::Alphanumeric,
        "arithmetic" | "math" => CaptchaType::Arithmetic,
        "slider" | "slide" => CaptchaType::Slider,
        "click" | "point" => CaptchaType::Click,
        _ => CaptchaType::Alphanumeric,
    };

    let config = CaptchaConfig {
        captcha_type: captcha_type_enum,
        length: 4,
        case_sensitive: false,
        preprocess: Default::default(),
    };

    // 如果是 base64 数据，先保存为临时文件
    let image_path = if image_data.starts_with("data:") {
        let rest = image_data.split(',').next_back().unwrap_or_default();
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(rest)
            .map_err(|e| format!("图片解码失败: {}", e))?;
        let temp_path = format!(
            "{}/captcha_{}.png",
            std::env::temp_dir().to_string_lossy(),
            uuid::Uuid::new_v4()
        );
        std::fs::write(&temp_path, bytes).map_err(|e| e.to_string())?;
        temp_path
    } else {
        image_data
    };

    captcha::recognize_captcha(image_path, config).await
}

/// 验证码难度评估
#[tauri::command]
pub fn captcha_difficulty(image_data: String) -> Result<String, String> {
    // 如果是 base64 数据，先保存为临时文件
    let image_path = if image_data.starts_with("data:") {
        let rest = image_data.split(',').next_back().unwrap_or_default();
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(rest)
            .map_err(|e| format!("图片解码失败: {}", e))?;
        let temp_path = format!(
            "{}/captcha_diff_{}.png",
            std::env::temp_dir().to_string_lossy(),
            uuid::Uuid::new_v4()
        );
        std::fs::write(&temp_path, bytes).map_err(|e| e.to_string())?;
        temp_path
    } else {
        image_data
    };

    captcha::evaluate_captcha_difficulty(image_path)
}

// ---------- 域名分析 ----------

/// 域名 DNS 查询
#[tauri::command]
pub async fn domain_dns_lookup(domain: String, record_type: String) -> Result<String, String> {
    let record_type_enum = match record_type.to_uppercase().as_str() {
        "A" => DnsRecordType::A,
        "AAAA" => DnsRecordType::AAAA,
        "CNAME" => DnsRecordType::CNAME,
        "MX" => DnsRecordType::MX,
        "NS" => DnsRecordType::NS,
        "TXT" => DnsRecordType::TXT,
        "SOA" => DnsRecordType::SOA,
        "PTR" => DnsRecordType::PTR,
        "SRV" => DnsRecordType::SRV,
        "CAA" => DnsRecordType::CAA,
        _ => DnsRecordType::A,
    };

    domain_analysis::dns_lookup(domain, record_type_enum).await
}

/// 域名 WHOIS
#[tauri::command]
pub async fn domain_whois(domain: String) -> Result<String, String> {
    domain_analysis::whois_query(domain).await
}

/// 子域名枚举
#[tauri::command]
pub async fn domain_subdomain_enum(domain: String, wordlist: String) -> Result<String, String> {
    // 解析子域名字典：支持 JSON 数组或逗号/换行分隔
    let words: Vec<String> = if wordlist.starts_with('[') {
        serde_json::from_str(&wordlist).unwrap_or_default()
    } else if !wordlist.is_empty() {
        wordlist
            .split(|c: char| c == ',' || c == '\n' || c == ';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![]
    };

    let config = SubdomainConfig {
        domain,
        wordlist: words,
        concurrency: 20,
        timeout_ms: 3000,
        record_types: vec![DnsRecordType::A, DnsRecordType::CNAME],
    };

    domain_analysis::enumerate_subdomains(config).await
}

/// 域名综合分析
#[tauri::command]
pub async fn domain_analyze(domain: String) -> Result<String, String> {
    domain_analysis::analyze_domain(domain).await
}

// ---------- 网络拓扑 ----------

/// 路由追踪
#[tauri::command]
pub async fn topology_traceroute(target: String, max_hops: u32) -> Result<String, String> {
    let config = TracerouteConfig {
        target,
        max_hops: max_hops.min(255) as u8,
        timeout_ms: 2000,
        probes_per_hop: 3,
        start_ttl: 1,
    };

    topology::traceroute(config).await
}

/// 本地拓扑
#[tauri::command]
pub async fn topology_local() -> Result<String, String> {
    topology::get_local_topology().await
}

/// Ping 测试
#[tauri::command]
pub async fn topology_ping(target: String, count: u32) -> Result<String, String> {
    topology::ping(target, count, 2000).await
}

// ---------- NAT 分析 ----------

/// NAT 类型检测
#[tauri::command]
pub async fn nat_detect() -> Result<String, String> {
    nat_analysis::quick_nat_detection().await
}

/// NAT 类型信息
#[tauri::command]
pub fn nat_info(nat_type: String) -> Result<String, String> {
    // nat_type 参数用于过滤或直接返回全部类型信息
    let result = nat_analysis::get_nat_type_info()?;

    if nat_type.is_empty() || nat_type == "all" {
        return Ok(result);
    }

    // 解析返回的 JSON 并按类型过滤
    let tool_result: crate::netsec::ToolResult<serde_json::Value> =
        serde_json::from_str(&result).map_err(|e| e.to_string())?;

    if let Some(data) = tool_result.data {
        if let Some(arr) = data.as_array() {
            let filtered: Vec<&serde_json::Value> = arr
                .iter()
                .filter(|item| {
                    item.get("type")
                        .and_then(|v| v.as_str())
                        .map(|t| t == nat_type.to_lowercase())
                        .unwrap_or(false)
                })
                .collect();

            return serde_json::to_string(&crate::netsec::ToolResult::ok(
                filtered,
                "NAT 类型信息",
            ))
            .map_err(|e| format!("序列化失败: {}", e));
        }
    }

    Ok(result)
}

// ---------- 病毒扫描 ----------

/// 文件病毒扫描
#[tauri::command]
pub fn virus_scan_file(file_path: String, scan_mode: String) -> Result<String, String> {
    let scan_type = match scan_mode.to_lowercase().as_str() {
        "hash" | "hash_only" => ScanType::HashOnly,
        "signature" | "sig" => ScanType::Signature,
        "heuristic" | "heur" => ScanType::Heuristic,
        "full" | "all" | "complete" => ScanType::Full,
        _ => ScanType::Full,
    };

    let config = VirusScanConfig {
        file_path,
        scan_type,
        multi_hash: true,
        max_file_size_mb: 100,
    };

    virus_scan::scan_file(config)
}

/// 目录病毒扫描
#[tauri::command]
pub fn virus_scan_directory(dir_path: String, scan_mode: String) -> Result<String, String> {
    let recursive = match scan_mode.to_lowercase().as_str() {
        "recursive" | "deep" | "full" => true,
        _ => false,
    };

    virus_scan::scan_directory(dir_path, recursive)
}

/// 文件哈希计算
#[tauri::command]
pub fn virus_compute_hashes(file_path: String) -> Result<String, String> {
    let hashes = virus_scan::compute_file_hashes(&file_path, true)?;

    serde_json::to_string(&crate::netsec::ToolResult::ok(hashes, "哈希计算完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

// ---------- 虚拟浏览器 ----------

/// 启动虚拟浏览器
#[tauri::command]
pub async fn vbrowser_launch(engine: String, headless: bool) -> Result<String, String> {
    let engine_enum = match engine.to_lowercase().as_str() {
        "chromium" | "chrome" | "edge" => BrowserEngine::Chromium,
        "firefox" | "ff" => BrowserEngine::Firefox,
        "webkit" | "safari" => BrowserEngine::Webkit,
        _ => BrowserEngine::Chromium,
    };

    let config = VirtualBrowserConfig {
        engine: engine_enum,
        headless,
        ..Default::default()
    };

    virtual_browser::launch_browser(config).await
}

/// 关闭虚拟浏览器
#[tauri::command]
pub async fn vbrowser_close(id: String) -> Result<String, String> {
    virtual_browser::close_browser(id).await
}

/// 虚拟浏览器列表
#[tauri::command]
pub fn vbrowser_list() -> Result<String, String> {
    virtual_browser::list_browsers()
}

/// 页面导航
#[tauri::command]
pub async fn vbrowser_navigate(id: String, url: String) -> Result<String, String> {
    virtual_browser::navigate_to(id, url).await
}

/// 页面截图
#[tauri::command]
pub async fn vbrowser_screenshot(id: String, full_page: bool) -> Result<String, String> {
    let config = ScreenshotConfig {
        full_page,
        ..Default::default()
    };

    virtual_browser::take_screenshot(id, config).await
}

/// 执行 JS
#[tauri::command]
pub async fn vbrowser_execute_js(id: String, script: String) -> Result<String, String> {
    virtual_browser::evaluate_javascript(id, script).await
}

/// 获取页面源码
#[tauri::command]
pub async fn vbrowser_page_source(id: String) -> Result<String, String> {
    // 先尝试从浏览器列表中查找实例并获取当前 URL
    let list_result = virtual_browser::list_browsers()?;
    let tool_result: crate::netsec::ToolResult<serde_json::Value> =
        serde_json::from_str(&list_result).map_err(|e| e.to_string())?;

    let current_url = tool_result
        .data
        .as_ref()
        .and_then(|d| d.get("instances"))
        .and_then(|insts| insts.as_array())
        .and_then(|arr| {
            arr.iter().find(|inst| {
                inst.get("id")
                    .and_then(|v| v.as_str())
                    .map(|i| i == id)
                    .unwrap_or(false)
            })
        })
        .and_then(|inst| inst.get("current_url"))
        .and_then(|u| u.as_str())
        .map(|s| s.to_string());

    match current_url {
        Some(url) => virtual_browser::get_page_source(url).await,
        None => {
            // 如果没有找到实例或当前 URL，尝试用 id 作为 URL（兼容性处理）
            if id.starts_with("http://") || id.starts_with("https://") {
                virtual_browser::get_page_source(id).await
            } else {
                Err(format!("浏览器实例不存在或未加载页面: {}", id))
            }
        }
    }
}

// ---------- 网页分析 ----------

/// 网页综合分析
#[tauri::command]
pub async fn web_analyze(url: String, deep: bool) -> Result<String, String> {
    web_analyzer::analyze_webpage(url, deep).await
}

/// 快速提取页面所有链接
#[tauri::command]
pub async fn web_extract_links(url: String) -> Result<String, String> {
    web_analyzer::extract_links(url).await
}

/// 提取页面所有表单
#[tauri::command]
pub async fn web_extract_forms(url: String) -> Result<String, String> {
    web_analyzer::extract_forms(url).await
}

/// 安全头检测
#[tauri::command]
pub async fn web_check_security_headers(url: String) -> Result<String, String> {
    web_analyzer::check_security_headers(url).await
}

/// 技术栈指纹识别
#[tauri::command]
pub async fn web_detect_tech(url: String) -> Result<String, String> {
    web_analyzer::detect_tech(url).await
}

/// 敏感信息检测
#[tauri::command]
pub async fn web_find_sensitive(url: String) -> Result<String, String> {
    web_analyzer::find_sensitive(url).await
}

// ---------- 爬虫工具 ----------

/// 启动网站爬虫
#[tauri::command]
pub async fn crawl_start(
    start_url: String,
    max_pages: u32,
    max_depth: u32,
    mode: String,
    delay_ms: u64,
    respect_robots: bool,
) -> Result<String, String> {
    web_crawler::crawl_start(start_url, max_pages, max_depth, mode, delay_ms, respect_robots).await
}

/// 单页面链接提取
#[tauri::command]
pub async fn crawl_extract_links(url: String, base_url: String) -> Result<String, String> {
    web_crawler::crawl_extract_links(url, base_url).await
}

/// 死链接检测
#[tauri::command]
pub async fn crawl_check_dead_links(url: String, max_pages: u32) -> Result<String, String> {
    web_crawler::crawl_check_dead_links(url, max_pages).await
}

/// 生成网站结构地图
#[tauri::command]
pub async fn crawl_get_sitemap(url: String, max_pages: u32) -> Result<String, String> {
    web_crawler::crawl_get_sitemap(url, max_pages).await
}

// ---------- 站点信息分析 ----------

/// 综合站点分析
#[tauri::command]
pub async fn site_analyze(url: String, deep: bool) -> Result<String, String> {
    site_info::site_analyze(url, deep).await
}

/// CMS 识别
#[tauri::command]
pub async fn site_detect_cms(url: String) -> Result<String, String> {
    site_info::site_detect_cms(url).await
}

/// 服务器/中间件指纹识别
#[tauri::command]
pub async fn site_detect_server(url: String) -> Result<String, String> {
    site_info::site_detect_server(url).await
}

/// 技术栈检测
#[tauri::command]
pub async fn site_detect_tech_stack(url: String) -> Result<String, String> {
    site_info::site_detect_tech_stack(url).await
}

/// CDN 检测
#[tauri::command]
pub async fn site_detect_cdn(url: String) -> Result<String, String> {
    site_info::site_detect_cdn(url).await
}

/// SSL/TLS 证书信息
#[tauri::command]
pub async fn site_ssl_info(url: String) -> Result<String, String> {
    site_info::site_ssl_info(url).await
}

/// 子域名发现
#[tauri::command]
pub async fn site_subdomain_scan(domain: String, count: u32) -> Result<String, String> {
    site_info::site_subdomain_scan(domain, count).await
}

/// 目录/敏感路径探测
#[tauri::command]
pub async fn site_dir_scan(url: String, count: u32) -> Result<String, String> {
    site_info::site_dir_scan(url, count).await
}

/// 站点安全评分
#[tauri::command]
pub async fn site_security_score(url: String) -> Result<String, String> {
    site_info::site_security_score(url).await
}

// ---------- 设备接入接口 ----------

/// 设备 HTTP 请求
#[tauri::command]
pub async fn device_http_request(
    method: String,
    url: String,
    headers: String,
    body: String,
    body_type: String,
    params: String,
    timeout_ms: u32,
) -> Result<String, String> {
    device_api::http_request(method, url, headers, body, body_type, params, timeout_ms).await
}

/// Modbus 读取操作
#[tauri::command]
pub async fn device_modbus_read(
    host: String,
    port: u16,
    slave_id: u8,
    function: u8,
    address: u16,
    count: u16,
) -> Result<String, String> {
    device_api::modbus_read(host, port, slave_id, function, address, count).await
}

/// Modbus 写单个寄存器
#[tauri::command]
pub async fn device_modbus_write(
    host: String,
    port: u16,
    slave_id: u8,
    address: u16,
    value: u16,
) -> Result<String, String> {
    device_api::modbus_write(host, port, slave_id, address, value).await
}

/// MQTT 发布消息
#[tauri::command]
pub async fn device_mqtt_publish(
    broker: String,
    port: u16,
    client_id: String,
    username: String,
    password: String,
    topic: String,
    payload: String,
    qos: u8,
) -> Result<String, String> {
    device_api::mqtt_publish(broker, port, client_id, username, password, topic, payload, qos).await
}

/// MQTT 订阅并等待消息
#[tauri::command]
pub async fn device_mqtt_subscribe(
    broker: String,
    port: u16,
    client_id: String,
    username: String,
    password: String,
    topic: String,
    timeout_ms: u64,
) -> Result<String, String> {
    device_api::mqtt_subscribe(broker, port, client_id, username, password, topic, timeout_ms).await
}

/// SNMP GET 请求
#[tauri::command]
pub async fn device_snmp_get(
    host: String,
    community: String,
    oid: String,
    version: String,
) -> Result<String, String> {
    device_api::snmp_get(host, community, oid, version).await
}

/// SNMP WALK
#[tauri::command]
pub async fn device_snmp_walk(
    host: String,
    community: String,
    oid: String,
    version: String,
) -> Result<String, String> {
    device_api::snmp_walk(host, community, oid, version).await
}

/// 获取预设设备接口模板
#[tauri::command]
pub fn device_get_templates() -> Result<String, String> {
    device_api::get_templates()
}

/// 接口压力测试
#[tauri::command]
pub async fn device_stress_test(
    url: String,
    method: String,
    concurrent: u32,
    duration_sec: u32,
    headers: String,
    body: String,
) -> Result<String, String> {
    device_api::stress_test(url, method, concurrent, duration_sec, headers, body).await
}

// ---------- Web漏洞扫描 ----------

#[tauri::command]
pub async fn vuln_scan_all(url: String, deep: bool) -> Result<String, String> {
    vuln_scanner::scan_all(url, deep).await
}

#[tauri::command]
pub async fn vuln_scan_xss(url: String, param: String, method: String) -> Result<String, String> {
    vuln_scanner::scan_xss(url, param, method).await
}

#[tauri::command]
pub async fn vuln_scan_csrf(url: String) -> Result<String, String> {
    vuln_scanner::scan_csrf(url).await
}

#[tauri::command]
pub async fn vuln_scan_file_include(url: String, param: String) -> Result<String, String> {
    vuln_scanner::scan_file_include(url, param).await
}

#[tauri::command]
pub async fn vuln_scan_cmd_injection(url: String, param: String) -> Result<String, String> {
    vuln_scanner::scan_cmd_injection(url, param).await
}

#[tauri::command]
pub async fn vuln_scan_xxe(url: String) -> Result<String, String> {
    vuln_scanner::scan_xxe(url).await
}

#[tauri::command]
pub async fn vuln_scan_ssrf(url: String, param: String) -> Result<String, String> {
    vuln_scanner::scan_ssrf(url, param).await
}

#[tauri::command]
pub async fn vuln_scan_open_redirect(url: String, param: String) -> Result<String, String> {
    vuln_scanner::scan_open_redirect(url, param).await
}

#[tauri::command]
pub async fn vuln_scan_clickjacking(url: String) -> Result<String, String> {
    vuln_scanner::scan_clickjacking(url).await
}

// ---------- 数据包捕获分析 ----------

#[tauri::command]
pub async fn packet_list_interfaces() -> Result<String, String> {
    packet_capture::list_interfaces().await
}

#[tauri::command]
pub async fn packet_start_capture(interface: String, filter: String, count: u32, duration_sec: u32) -> Result<String, String> {
    packet_capture::start_capture(interface, filter, count, duration_sec).await
}

#[tauri::command]
pub async fn packet_stop_capture() -> Result<String, String> {
    packet_capture::stop_capture().await
}

#[tauri::command]
pub async fn packet_get_stats() -> Result<String, String> {
    packet_capture::get_stats().await
}

#[tauri::command]
pub async fn packet_get_dns() -> Result<String, String> {
    packet_capture::get_dns().await
}

#[tauri::command]
pub async fn packet_get_http() -> Result<String, String> {
    packet_capture::get_http().await
}

#[tauri::command]
pub async fn packet_get_arp_table() -> Result<String, String> {
    packet_capture::get_arp_table().await
}

#[tauri::command]
pub async fn packet_detect_arp_spoof() -> Result<String, String> {
    packet_capture::detect_arp_spoof().await
}

#[tauri::command]
pub async fn packet_export(format: String, path: String) -> Result<String, String> {
    packet_capture::export(format, path).await
}

// ---------- 哈希破解与编码转换 ----------

#[tauri::command]
pub async fn hash_compute(text: String, algorithm: String) -> Result<String, String> {
    hash_crypto::compute(text, algorithm).await
}

#[tauri::command]
pub async fn hash_compute_file(file_path: String, algorithm: String) -> Result<String, String> {
    hash_crypto::compute_file(file_path, algorithm).await
}

#[tauri::command]
pub async fn hash_compute_all(text: String) -> Result<String, String> {
    hash_crypto::compute_all(text).await
}

#[tauri::command]
pub async fn hash_crack(hash: String, hash_type: String, mode: String, dict_path: String, max_length: u32) -> Result<String, String> {
    hash_crypto::crack(hash, hash_type, mode, dict_path, max_length).await
}

#[tauri::command]
pub async fn hash_identify(hash: String) -> Result<String, String> {
    hash_crypto::identify(hash).await
}

#[tauri::command]
pub async fn encode_decode(input: String, format: String, decode: bool) -> Result<String, String> {
    hash_crypto::encode_decode(input, format, decode).await
}

#[tauri::command]
pub async fn encode_batch(input: String, formats_json: String) -> Result<String, String> {
    hash_crypto::encode_batch(input, formats_json).await
}

#[tauri::command]
pub async fn crypto_aes_encrypt(plaintext: String, key: String, mode: String) -> Result<String, String> {
    hash_crypto::aes_encrypt(plaintext, key, mode).await
}

#[tauri::command]
pub async fn crypto_aes_decrypt(ciphertext: String, key: String, mode: String) -> Result<String, String> {
    hash_crypto::aes_decrypt(ciphertext, key, mode).await
}

#[tauri::command]
pub async fn crypto_xor(text: String, key: String) -> Result<String, String> {
    hash_crypto::xor(text, key).await
}

#[tauri::command]
pub async fn crypto_random(length: u32, charset: String) -> Result<String, String> {
    hash_crypto::random(length, charset).await
}

#[tauri::command]
pub async fn crypto_uuid(version: u32) -> Result<String, String> {
    hash_crypto::uuid(version).await
}

#[tauri::command]
pub async fn file_identify_format(file_path: String) -> Result<String, String> {
    hash_crypto::identify_format(file_path).await
}

#[tauri::command]
pub async fn crypto_caesar(text: String, shift: u32, decrypt: bool) -> Result<String, String> {
    hash_crypto::caesar(text, shift, decrypt).await
}

#[tauri::command]
pub async fn crypto_vigenere(text: String, key: String, decrypt: bool) -> Result<String, String> {
    hash_crypto::vigenere(text, key, decrypt).await
}

// ---------- 防火墙与DNS安全 ----------

#[tauri::command]
pub async fn fw_test_ports(target: String, ports: String) -> Result<String, String> {
    firewall_dns::test_ports(target, ports).await
}

#[tauri::command]
pub async fn fw_test_port_range(target: String, start: u16, end: u16) -> Result<String, String> {
    firewall_dns::test_port_range(target, start, end).await
}

#[tauri::command]
pub async fn fw_bypass_test(target: String, port: u16) -> Result<String, String> {
    firewall_dns::bypass_test(target, port).await
}

#[tauri::command]
pub async fn fw_audit(target: String) -> Result<String, String> {
    firewall_dns::audit(target).await
}

#[tauri::command]
pub async fn dns_get_servers() -> Result<String, String> {
    firewall_dns::get_servers().await
}

#[tauri::command]
pub async fn dns_speed_test(domains: String) -> Result<String, String> {
    firewall_dns::speed_test(domains).await
}

#[tauri::command]
pub async fn dns_leak_test() -> Result<String, String> {
    firewall_dns::leak_test().await
}

#[tauri::command]
pub async fn dns_poison_detect(domain: String) -> Result<String, String> {
    firewall_dns::poison_detect(domain).await
}

#[tauri::command]
pub async fn dns_dnssec_check(domain: String) -> Result<String, String> {
    firewall_dns::dnssec_check(domain).await
}

#[tauri::command]
pub async fn dns_email_security(domain: String) -> Result<String, String> {
    firewall_dns::email_security(domain).await
}

#[tauri::command]
pub async fn dns_reverse(ip: String) -> Result<String, String> {
    firewall_dns::reverse(ip).await
}

#[tauri::command]
pub async fn dns_tunnel_detect(domain: String) -> Result<String, String> {
    firewall_dns::tunnel_detect(domain).await
}
