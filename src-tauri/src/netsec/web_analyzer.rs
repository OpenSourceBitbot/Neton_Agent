// yxpil · NETON
//! 网页分析模块
//! 提供网页标题提取、Meta 信息分析、链接提取、图片提取、表单分析、
//! Cookie 分析、响应头安全检测、技术栈指纹识别、WAF 检测、
//! 目录结构分析、敏感信息检测等功能。

use serde::{Deserialize, Serialize};
use scraper::{Html, Selector};
use url::Url;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

// ============================================================
// 数据结构定义
// ============================================================

/// 网页分析选项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAnalysisOptions {
    /// 请求超时（毫秒）
    pub timeout_ms: u64,
    /// User-Agent
    pub user_agent: String,
    /// 是否跟随重定向
    pub follow_redirects: bool,
    /// 是否检测敏感信息
    pub detect_sensitive_info: bool,
    /// 是否进行技术栈指纹识别
    pub detect_tech_fingerprint: bool,
    /// 是否检测 WAF
    pub detect_waf: bool,
}

impl Default for WebAnalysisOptions {
    fn default() -> Self {
        Self {
            timeout_ms: 10000,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            follow_redirects: true,
            detect_sensitive_info: true,
            detect_tech_fingerprint: true,
            detect_waf: true,
        }
    }
}

/// 页面基本信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPageInfo {
    /// 页面 URL
    pub url: String,
    /// 页面标题
    pub title: String,
    /// 页面状态码
    pub status_code: u16,
    /// 最终 URL（重定向后）
    pub final_url: String,
    /// 页面大小（字节）
    pub content_length: usize,
    /// 加载时间（毫秒）
    pub load_time_ms: u64,
    /// 内容类型
    pub content_type: String,
    /// 页面编码
    pub charset: Option<String>,
    /// 页面语言
    pub language: Option<String>,
}

/// Meta 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaInfo {
    pub description: Option<String>,
    pub keywords: Option<String>,
    pub author: Option<String>,
    pub robots: Option<String>,
    pub viewport: Option<String>,
    pub generator: Option<String>,
    /// 其他 meta 标签（name -> content）
    pub others: HashMap<String, String>,
}

/// 链接信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInfo {
    pub url: String,
    pub text: String,
    /// 链接类型：internal / external
    pub link_type: String,
    /// 协议：http / https / mailto / tel / javascript 等
    pub protocol: String,
    /// 是否为锚点链接
    pub is_anchor: bool,
    /// rel 属性
    pub rel: Option<String>,
    /// target 属性
    pub target: Option<String>,
}

/// 图片信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub src: String,
    pub alt: String,
    pub title: Option<String>,
    pub width: Option<String>,
    pub height: Option<String>,
    /// 是否为站内图片
    pub is_internal: bool,
}

/// 表单字段信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: Option<String>,
    pub field_type: String,
    pub value: Option<String>,
    pub placeholder: Option<String>,
    pub required: bool,
    pub id: Option<String>,
}

/// 表单信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub enctype: Option<String>,
    pub fields: Vec<FormField>,
    /// 字段数量
    pub field_count: usize,
    /// 是否包含密码字段
    pub has_password: bool,
    /// 是否包含文件上传字段
    pub has_file_upload: bool,
}

/// Cookie 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<String>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
}

/// 安全头报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderReport {
    /// Content-Security-Policy
    pub content_security_policy: Option<String>,
    pub csp_present: bool,
    /// Strict-Transport-Security
    pub strict_transport_security: Option<String>,
    pub hsts_present: bool,
    /// X-Frame-Options
    pub x_frame_options: Option<String>,
    pub x_frame_present: bool,
    /// X-Content-Type-Options
    pub x_content_type_options: Option<String>,
    pub x_content_type_present: bool,
    /// X-XSS-Protection
    pub x_xss_protection: Option<String>,
    pub x_xss_present: bool,
    /// Referrer-Policy
    pub referrer_policy: Option<String>,
    pub referrer_policy_present: bool,
    /// Permissions-Policy
    pub permissions_policy: Option<String>,
    pub permissions_policy_present: bool,
    /// 安全头得分（满分 100）
    pub security_score: u32,
}

/// 技术指纹
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechFingerprint {
    /// 服务器
    pub server: Option<String>,
    /// CMS 系统
    pub cms: Vec<String>,
    /// 前端框架
    pub frontend_frameworks: Vec<String>,
    /// 后端语言/框架
    pub backend_tech: Vec<String>,
    /// JavaScript 库
    pub js_libraries: Vec<String>,
    /// CSS 框架
    pub css_frameworks: Vec<String>,
    /// 分析工具
    pub analytics: Vec<String>,
    /// 广告网络
    pub ad_networks: Vec<String>,
    /// 其他技术
    pub others: Vec<String>,
}

/// WAF 检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetectionResult {
    pub detected: bool,
    pub waf_name: Option<String>,
    pub confidence: u8,
    /// 检测依据
    pub evidence: Vec<String>,
}

/// 敏感信息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveInfo {
    pub info_type: String,
    pub value: String,
    pub context: String,
    pub line_number: usize,
}

/// 目录结构节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryNode {
    pub path: String,
    pub children: Vec<String>,
    pub depth: usize,
}

/// 综合分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAnalysisResult {
    pub page_info: WebPageInfo,
    pub meta_info: MetaInfo,
    pub links: Vec<LinkInfo>,
    pub internal_links: Vec<String>,
    pub external_links: Vec<String>,
    pub images: Vec<ImageInfo>,
    pub forms: Vec<FormInfo>,
    pub cookies: Vec<CookieInfo>,
    pub security_headers: SecurityHeaderReport,
    pub tech_fingerprint: TechFingerprint,
    pub waf_detection: WafDetectionResult,
    pub directory_structure: Vec<DirectoryNode>,
    pub sensitive_info: Vec<SensitiveInfo>,
    pub all_response_headers: HashMap<String, String>,
}

// ============================================================
// 核心分析函数
// ============================================================

/// 分析网页
pub fn analyze_webpage(url: String, options: WebAnalysisOptions) -> Result<String, String> {
    let start_time = Instant::now();

    // 构建 HTTP 客户端
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(options.timeout_ms))
        .user_agent(&options.user_agent)
        .redirect(if options.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()
        .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))?;

    // 发送请求
    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("请求失败: {}", e))?;

    let status_code = response.status().as_u16();
    let final_url = response.url().to_string();
    let load_time_ms = start_time.elapsed().as_millis() as u64;

    // 收集响应头
    let mut headers_map = HashMap::new();
    for (key, value) in response.headers().iter() {
        headers_map.insert(
            key.to_string(),
            value.to_str().unwrap_or("").to_string(),
        );
    }

    // 获取内容类型
    let content_type = headers_map
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    // 提取 Cookie
    let cookies = extract_cookies(&response);

    // 读取响应体
    let body = response
        .text()
        .map_err(|e| format!("读取响应体失败: {}", e))?;
    let content_length = body.len();

    // 解析 HTML
    let document = Html::parse_document(&body);

    // 提取页面基本信息
    let page_info = extract_page_info(
        &url,
        &final_url,
        status_code,
        content_length,
        load_time_ms,
        &content_type,
        &document,
    );

    // 提取 Meta 信息
    let meta_info = extract_meta_info(&document);

    // 提取链接
    let links = extract_links(&document, &final_url);
    let internal_links: Vec<String> = links
        .iter()
        .filter(|l| l.link_type == "internal")
        .map(|l| l.url.clone())
        .collect();
    let external_links: Vec<String> = links
        .iter()
        .filter(|l| l.link_type == "external")
        .map(|l| l.url.clone())
        .collect();

    // 提取图片
    let images = extract_images(&document, &final_url);

    // 提取表单
    let forms = extract_forms(&document, &final_url);

    // 安全头分析
    let security_headers = analyze_security_headers(&headers_map);

    // 技术栈指纹识别
    let tech_fingerprint = if options.detect_tech_fingerprint {
        detect_tech_fingerprint(&document, &headers_map, &body)
    } else {
        TechFingerprint {
            server: headers_map.get("server").cloned(),
            cms: vec![],
            frontend_frameworks: vec![],
            backend_tech: vec![],
            js_libraries: vec![],
            css_frameworks: vec![],
            analytics: vec![],
            ad_networks: vec![],
            others: vec![],
        }
    };

    // WAF 检测
    let waf_detection = if options.detect_waf {
        detect_waf(&headers_map, &body, status_code)
    } else {
        WafDetectionResult {
            detected: false,
            waf_name: None,
            confidence: 0,
            evidence: vec![],
        }
    };

    // 目录结构分析
    let directory_structure = analyze_directory_structure(&links);

    // 敏感信息检测
    let sensitive_info = if options.detect_sensitive_info {
        detect_sensitive_info(&body)
    } else {
        vec![]
    };

    // 构建综合结果
    let result = WebAnalysisResult {
        page_info,
        meta_info,
        links,
        internal_links,
        external_links,
        images,
        forms,
        cookies,
        security_headers,
        tech_fingerprint,
        waf_detection,
        directory_structure,
        sensitive_info,
        all_response_headers: headers_map,
    };

    serde_json::to_string(&result).map_err(|e| format!("序列化失败: {}", e))
}

// ============================================================
// 页面基本信息提取
// ============================================================

fn extract_page_info(
    url: &str,
    final_url: &str,
    status_code: u16,
    content_length: usize,
    load_time_ms: u64,
    content_type: &str,
    document: &Html,
) -> WebPageInfo {
    // 提取标题
    let title_selector = Selector::parse("title").unwrap();
    let title = document
        .select(&title_selector)
        .next()
        .map(|e| e.text().collect::<String>().trim().to_string())
        .unwrap_or_default();

    // 提取编码
    let charset_selector = Selector::parse("meta[charset]").unwrap();
    let charset = document
        .select(&charset_selector)
        .next()
        .and_then(|e| e.value().attr("charset").map(|s| s.to_string()));

    // 提取语言
    let html_selector = Selector::parse("html").unwrap();
    let language = document
        .select(&html_selector)
        .next()
        .and_then(|e| e.value().attr("lang").map(|s| s.to_string()));

    WebPageInfo {
        url: url.to_string(),
        title,
        status_code,
        final_url: final_url.to_string(),
        content_length,
        load_time_ms,
        content_type: content_type.to_string(),
        charset,
        language,
    }
}

// ============================================================
// Meta 信息提取
// ============================================================

fn extract_meta_info(document: &Html) -> MetaInfo {
    let mut meta_info = MetaInfo {
        description: None,
        keywords: None,
        author: None,
        robots: None,
        viewport: None,
        generator: None,
        others: HashMap::new(),
    };

    let meta_selector = Selector::parse("meta").unwrap();

    for meta in document.select(&meta_selector) {
        let name = meta
            .value()
            .attr("name")
            .or_else(|| meta.value().attr("property"))
            .map(|s| s.to_lowercase());
        let content = meta.value().attr("content").map(|s| s.to_string());

        if let (Some(name), Some(content)) = (name, content) {
            match name.as_str() {
                "description" => meta_info.description = Some(content),
                "keywords" => meta_info.keywords = Some(content),
                "author" => meta_info.author = Some(content),
                "robots" => meta_info.robots = Some(content),
                "viewport" => meta_info.viewport = Some(content),
                "generator" => meta_info.generator = Some(content),
                _ => {
                    meta_info.others.insert(name, content);
                }
            }
        }
    }

    meta_info
}

// ============================================================
// 链接提取
// ============================================================

fn extract_links(document: &Html, base_url: &str) -> Vec<LinkInfo> {
    let mut links = Vec::new();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return links,
    };
    let base_host = base.host_str().unwrap_or("").to_string();

    let link_selector = Selector::parse("a[href]").unwrap();

    for link in document.select(&link_selector) {
        let href = match link.value().attr("href") {
            Some(h) => h.to_string(),
            None => continue,
        };

        let text = link.text().collect::<String>().trim().to_string();
        let rel = link.value().attr("rel").map(|s| s.to_string());
        let target = link.value().attr("target").map(|s| s.to_string());

        // 解析链接类型
        let (link_type, protocol, is_anchor, full_url) =
            classify_link(&href, &base, &base_host);

        links.push(LinkInfo {
            url: full_url,
            text,
            link_type,
            protocol,
            is_anchor,
            rel,
            target,
        });
    }

    links
}

fn classify_link(
    href: &str,
    base: &Url,
    base_host: &str,
) -> (String, String, bool, String) {
    let href_lower = href.to_lowercase();

    // 锚点链接
    if href.starts_with('#') {
        return (
            "internal".to_string(),
            "anchor".to_string(),
            true,
            href.to_string(),
        );
    }

    // 特殊协议
    if href_lower.starts_with("mailto:") {
        return (
            "external".to_string(),
            "mailto".to_string(),
            false,
            href.to_string(),
        );
    }
    if href_lower.starts_with("tel:") {
        return (
            "external".to_string(),
            "tel".to_string(),
            false,
            href.to_string(),
        );
    }
    if href_lower.starts_with("javascript:") {
        return (
            "internal".to_string(),
            "javascript".to_string(),
            false,
            href.to_string(),
        );
    }
    if href_lower.starts_with("data:") {
        return (
            "internal".to_string(),
            "data".to_string(),
            false,
            href.to_string(),
        );
    }

    // 解析绝对或相对 URL
    let parsed = match Url::parse(href) {
        Ok(u) => u,
        Err(_) => {
            // 相对路径，尝试基于 base 解析
            match base.join(href) {
                Ok(u) => u,
                Err(_) => {
                    return (
                        "unknown".to_string(),
                        "unknown".to_string(),
                        false,
                        href.to_string(),
                    );
                }
            }
        }
    };

    let protocol = parsed.scheme().to_string();
    let host = parsed.host_str().unwrap_or("").to_string();
    let is_anchor = parsed.fragment().is_some() && href.starts_with('#');

    let link_type = if host.is_empty() || host == base_host {
        "internal".to_string()
    } else {
        "external".to_string()
    };

    (link_type, protocol, is_anchor, parsed.to_string())
}

// ============================================================
// 图片提取
// ============================================================

fn extract_images(document: &Html, base_url: &str) -> Vec<ImageInfo> {
    let mut images = Vec::new();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return images,
    };
    let base_host = base.host_str().unwrap_or("").to_string();

    let img_selector = Selector::parse("img[src]").unwrap();

    for img in document.select(&img_selector) {
        let src = match img.value().attr("src") {
            Some(s) => s.to_string(),
            None => continue,
        };

        let alt = img
            .value()
            .attr("alt")
            .unwrap_or("")
            .to_string();
        let title = img.value().attr("title").map(|s| s.to_string());
        let width = img.value().attr("width").map(|s| s.to_string());
        let height = img.value().attr("height").map(|s| s.to_string());

        // 解析图片 URL
        let (full_src, is_internal) = resolve_asset_url(&src, &base, &base_host);

        images.push(ImageInfo {
            src: full_src,
            alt,
            title,
            width,
            height,
            is_internal,
        });
    }

    images
}

fn resolve_asset_url(src: &str, base: &Url, base_host: &str) -> (String, bool) {
    if src.starts_with("data:") {
        return (src.to_string(), true);
    }

    let parsed = match Url::parse(src) {
        Ok(u) => u,
        Err(_) => match base.join(src) {
            Ok(u) => u,
            Err(_) => return (src.to_string(), false),
        },
    };

    let host = parsed.host_str().unwrap_or("").to_string();
    let is_internal = host.is_empty() || host == base_host;

    (parsed.to_string(), is_internal)
}

// ============================================================
// 表单分析
// ============================================================

fn extract_forms(document: &Html, base_url: &str) -> Vec<FormInfo> {
    let mut forms = Vec::new();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return forms,
    };

    let form_selector = Selector::parse("form").unwrap();
    let input_selector = Selector::parse("input, select, textarea").unwrap();

    for form in document.select(&form_selector) {
        let action_attr = form.value().attr("action").unwrap_or("").to_string();
        let action = if action_attr.is_empty() {
            base_url.to_string()
        } else {
            match base.join(&action_attr) {
                Ok(u) => u.to_string(),
                Err(_) => action_attr.clone(),
            }
        };

        let method = form
            .value()
            .attr("method")
            .unwrap_or("get")
            .to_string()
            .to_uppercase();
        let id = form.value().attr("id").map(|s| s.to_string());
        let name = form.value().attr("name").map(|s| s.to_string());
        let enctype = form.value().attr("enctype").map(|s| s.to_string());

        // 提取表单字段
        let mut fields = Vec::new();
        let mut has_password = false;
        let mut has_file_upload = false;

        for field in form.select(&input_selector) {
            let field_name = field.value().attr("name").map(|s| s.to_string());
            let field_type = field
                .value()
                .attr("type")
                .unwrap_or("text")
                .to_string()
                .to_lowercase();
            let value = field.value().attr("value").map(|s| s.to_string());
            let placeholder = field.value().attr("placeholder").map(|s| s.to_string());
            let required = field.value().attr("required").is_some();
            let field_id = field.value().attr("id").map(|s| s.to_string());

            if field_type == "password" {
                has_password = true;
            }
            if field_type == "file" {
                has_file_upload = true;
            }

            // 检查 select/textarea 的类型
            let tag_name = field.value().name().to_lowercase();
            let actual_type = if tag_name == "select" {
                "select".to_string()
            } else if tag_name == "textarea" {
                "textarea".to_string()
            } else {
                field_type
            };

            fields.push(FormField {
                name: field_name,
                field_type: actual_type,
                value,
                placeholder,
                required,
                id: field_id,
            });
        }

        let field_count = fields.len();

        forms.push(FormInfo {
            action,
            method,
            id,
            name,
            enctype,
            fields,
            field_count,
            has_password,
            has_file_upload,
        });
    }

    forms
}

// ============================================================
// Cookie 提取
// ============================================================

fn extract_cookies(response: &reqwest::blocking::Response) -> Vec<CookieInfo> {
    let mut cookies = Vec::new();

    for cookie in response.cookies() {
        cookies.push(CookieInfo {
            name: cookie.name().to_string(),
            value: cookie.value().to_string(),
            domain: cookie.domain().map(|s| s.to_string()),
            path: cookie.path().map(|s| s.to_string()),
            expires: cookie
                .expires()
                .map(|t| format!("{:?}", t)),
            http_only: cookie.http_only(),
            secure: cookie.secure(),
            same_site: None,
        });
    }

    cookies
}

// ============================================================
// 安全头分析
// ============================================================

fn analyze_security_headers(headers: &HashMap<String, String>) -> SecurityHeaderReport {
    let csp = headers.get("content-security-policy").cloned();
    let csp_present = csp.is_some();

    let hsts = headers.get("strict-transport-security").cloned();
    let hsts_present = hsts.is_some();

    let x_frame = headers.get("x-frame-options").cloned();
    let x_frame_present = x_frame.is_some();

    let x_content_type = headers.get("x-content-type-options").cloned();
    let x_content_type_present = x_content_type.is_some();

    let x_xss = headers.get("x-xss-protection").cloned();
    let x_xss_present = x_xss.is_some();

    let referrer_policy = headers.get("referrer-policy").cloned();
    let referrer_policy_present = referrer_policy.is_some();

    let permissions_policy = headers.get("permissions-policy").cloned();
    let permissions_policy_present = permissions_policy.is_some();

    // 计算安全头得分
    let mut score = 0u32;
    let headers_count = 7u32;
    if csp_present { score += 1; }
    if hsts_present { score += 1; }
    if x_frame_present { score += 1; }
    if x_content_type_present { score += 1; }
    if x_xss_present { score += 1; }
    if referrer_policy_present { score += 1; }
    if permissions_policy_present { score += 1; }
    let security_score = (score * 100) / headers_count;

    SecurityHeaderReport {
        content_security_policy: csp,
        csp_present,
        strict_transport_security: hsts,
        hsts_present,
        x_frame_options: x_frame,
        x_frame_present,
        x_content_type_options: x_content_type,
        x_content_type_present,
        x_xss_protection: x_xss,
        x_xss_present,
        referrer_policy,
        referrer_policy_present,
        permissions_policy,
        permissions_policy_present,
        security_score,
    }
}

// ============================================================
// 技术栈指纹识别
// ============================================================

fn detect_tech_fingerprint(
    document: &Html,
    headers: &HashMap<String, String>,
    body: &str,
) -> TechFingerprint {
    let mut fingerprint = TechFingerprint {
        server: headers.get("server").cloned(),
        cms: vec![],
        frontend_frameworks: vec![],
        backend_tech: vec![],
        js_libraries: vec![],
        css_frameworks: vec![],
        analytics: vec![],
        ad_networks: vec![],
        others: vec![],
    };

    let body_lower = body.to_lowercase();

    // 从响应头检测
    if let Some(powered_by) = headers.get("x-powered-by") {
        fingerprint.backend_tech.push(powered_by.clone());
    }

    // CMS 检测
    let cms_patterns = vec![
        ("wordpress", vec!["wp-content", "wp-includes", "wordpress", "wp-json"]),
        ("drupal", vec!["drupal", "sites/default/files", "drupalSettings"]),
        ("joomla", vec!["joomla", "com_content", "media/system/js"]),
        ("shopify", vec!["shopify", "myshopify.com", "cdn.shopify.com"]),
        ("magento", vec!["magento", "static/frontend", "mage/cookies"]),
        ("ghost", vec!["ghost.org", "ghost.min.css", "/ghost/"]),
        ("hexo", vec!["hexo", "hexo-generator"]),
        ("hugo", vec!["hugo", "gohugoio"]),
        ("jekyll", vec!["jekyll"]),
        ("typecho", vec!["typecho", "usr/themes"]),
    ];

    for (cms_name, patterns) in &cms_patterns {
        if patterns.iter().any(|p| body_lower.contains(p)) {
            fingerprint.cms.push(cms_name.to_string());
        }
    }

    // 前端框架检测
    let frontend_patterns = vec![
        ("react", vec!["react-dom", "_reactroot", "react.production.min.js"]),
        ("vue.js", vec!["vue.js", "vue.min.js", "__vue__", "v-app"]),
        ("angular", vec!["angular.js", "ng-app", "ng-version", "@angular"]),
        ("svelte", vec!["svelte-", "svelte.dev"]),
        ("next.js", vec!["__next", "_next/static", "next.js"]),
        ("nuxt.js", vec!["__nuxt", "nuxt.js", "_nuxt/"]),
        ("gatsby", vec!["gatsby-", "___gatsby"]),
    ];

    for (fw_name, patterns) in &frontend_patterns {
        if patterns.iter().any(|p| body_lower.contains(p)) {
            fingerprint.frontend_frameworks.push(fw_name.to_string());
        }
    }

    // JavaScript 库检测
    let js_patterns = vec![
        ("jquery", vec!["jquery.min.js", "jquery.js", "jquery.com"]),
        ("bootstrap", vec!["bootstrap.min.js", "bootstrap.js"]),
        ("lodash", vec!["lodash", "underscore"]),
        ("moment.js", vec!["moment.min.js", "moment.js"]),
        ("axios", vec!["axios.min.js", "axios.js"]),
        ("d3.js", vec!["d3.min.js", "d3.v"]),
        ("three.js", vec!["three.min.js", "three.js"]),
    ];

    for (lib_name, patterns) in &js_patterns {
        if patterns.iter().any(|p| body_lower.contains(p)) {
            fingerprint.js_libraries.push(lib_name.to_string());
        }
    }

    // CSS 框架检测
    let css_patterns = vec![
        ("bootstrap", vec!["bootstrap.min.css", "bootstrap.css"]),
        ("tailwindcss", vec!["tailwind", "tailwindcss"]),
        ("bulma", vec!["bulma.min.css", "bulma.css"]),
        ("foundation", vec!["foundation.min.css", "foundation.css"]),
        ("materialize", vec!["materialize.min.css", "materialize.css"]),
        ("semantic-ui", vec!["semantic.min.css", "semantic-ui"]),
        ("ant-design", vec!["antd", "ant.design"]),
    ];

    for (css_name, patterns) in &css_patterns {
        if patterns.iter().any(|p| body_lower.contains(p)) {
            fingerprint.css_frameworks.push(css_name.to_string());
        }
    }

    // 分析工具检测
    let analytics_patterns = vec![
        ("google-analytics", vec!["google-analytics.com", "ga.js", "gtag.js", "analytics.js"]),
        ("baidu-tongji", vec!["hm.baidu.com", "baidu tongji"]),
        ("cnzz", vec!["cnzz.com", "zz.stat"]),
        ("51.la", vec!["51.la", "js.users.51.la"]),
        ("umami", vec!["umami.is", "umami.dev"]),
        ("plausible", vec!["plausible.io", "plausible-analytics"]),
    ];

    for (tool_name, patterns) in &analytics_patterns {
        if patterns.iter().any(|p| body_lower.contains(p)) {
            fingerprint.analytics.push(tool_name.to_string());
        }
    }

    // 广告网络检测
    let ad_patterns = vec![
        ("google-adsense", vec!["googlesyndication.com", "adsbygoogle"]),
        ("baidu-ad", vec!["pos.baidu.com", "baidu ad"]),
        ("alimama", vec!["alimama.com", "tanx.com"]),
    ];

    for (ad_name, patterns) in &ad_patterns {
        if patterns.iter().any(|p| body_lower.contains(p)) {
            fingerprint.ad_networks.push(ad_name.to_string());
        }
    }

    // 后端技术检测
    let backend_patterns = vec![
        ("php", vec![".php", "phpmyadmin", "php session"]),
        ("asp.net", vec![".aspx", "asp.net", "__viewstate"]),
        ("java", vec![".jsp", "jsessionid", "java servlet"]),
        ("python", vec!["django", "flask", "wsgi"]),
        ("ruby", vec!["rails", "ruby on rails", ".erb"]),
        ("node.js", vec!["node.js", "express", "socket.io"]),
    ];

    for (tech_name, patterns) in &backend_patterns {
        if patterns.iter().any(|p| body_lower.contains(p)) {
            fingerprint.backend_tech.push(tech_name.to_string());
        }
    }

    // 从 meta generator 检测
    let meta_selector = Selector::parse("meta[name=generator]").unwrap();
    for meta in document.select(&meta_selector) {
        if let Some(content) = meta.value().attr("content") {
            fingerprint.others.push(format!("generator: {}", content));
        }
    }

    fingerprint
}

// ============================================================
// WAF 检测
// ============================================================

fn detect_waf(headers: &HashMap<String, String>, body: &str, status_code: u16) -> WafDetectionResult {
    let mut evidence = Vec::new();
    let mut waf_name = None;
    let mut confidence = 0u8;

    let body_lower = body.to_lowercase();

    // WAF 特征库
    let waf_signatures = vec![
        ("Cloudflare", vec![
            "cloudflare",
            "cf-ray",
            "__cfduid",
            "cf-cache-status",
            "error code: 1020",
            "error code: 1010",
        ]),
        ("Akamai", vec![
            "akamai",
            "akamaighost",
            "x-akamai",
            "akgzip",
        ]),
        ("Incapsula/Imperva", vec![
            "incapsula",
            "imperva",
            "incap_ses",
            "visid_incap",
            "x-iinfo",
        ]),
        ("F5 BIG-IP ASM", vec![
            "bigip",
            "f5 networks",
            "ts_cookie",
            "f5_siteprotector",
        ]),
        ("ModSecurity", vec![
            "mod_security",
            "modsecurity",
            "web server at",
            "not acceptable",
        ]),
        ("Sucuri", vec![
            "sucuri",
            "sucuri firewall",
            "sucuri website firewall",
        ]),
        ("Wordfence", vec![
            "wordfence",
            "wfvt_",
            "wfls_",
        ]),
        ("Barracuda", vec![
            "barracuda",
            "barracudanetworks",
        ]),
        ("Citrix NetScaler", vec![
            "netscaler",
            "citrix",
            "ns_af",
        ]),
        ("Palo Alto", vec![
            "palo alto",
            "paloalto",
        ]),
        ("DDoS-Guard", vec![
            "ddos-guard",
            "ddos guard",
        ]),
        ("Qiniu WAF", vec![
            "qiniu",
            "x-qiniu",
        ]),
        ("Aliyun WAF", vec![
            "aliyunwaf",
            "aliyun waf",
            "x-alibaba",
        ]),
        ("Tencent WAF", vec![
            "tencent",
            "waf.tencent",
        ]),
        ("Baidu WAF", vec![
            "baidu yunjiasu",
            "yunjiasu",
        ]),
    ];

    for (name, signatures) in &waf_signatures {
        let mut matched = 0;
        for sig in signatures {
            let sig_lower = sig.to_lowercase();
            // 在响应头中查找
            if headers.keys().any(|k| k.to_lowercase().contains(&sig_lower))
                || headers.values().any(|v| v.to_lowercase().contains(&sig_lower))
            {
                matched += 1;
                evidence.push(format!("Header 匹配: {} -> {}", sig, name));
            }
            // 在响应体中查找
            if body_lower.contains(&sig_lower) {
                matched += 1;
                evidence.push(format!("Body 匹配: {} -> {}", sig, name));
            }
        }
        if matched > 0 && waf_name.is_none() {
            waf_name = Some(name.to_string());
            confidence = std::cmp::min(matched * 25, 100) as u8;
        }
    }

    // 额外的检测：特定状态码 + 特征页
    if status_code == 403 && body_lower.contains("forbidden") {
        evidence.push("403 Forbidden (可能被 WAF 拦截)".to_string());
        confidence = std::cmp::min(confidence + 10, 100);
    }
    if status_code == 429 {
        evidence.push("429 Too Many Requests (速率限制，可能有 WAF)".to_string());
        confidence = std::cmp::min(confidence + 10, 100);
    }
    if status_code == 503 && body_lower.contains("service unavailable") {
        evidence.push("503 Service Unavailable (可能有 WAF/CDN)".to_string());
        confidence = std::cmp::min(confidence + 5, 100);
    }

    let detected = !evidence.is_empty() && confidence >= 25;

    WafDetectionResult {
        detected,
        waf_name,
        confidence,
        evidence,
    }
}

// ============================================================
// 目录结构分析
// ============================================================

fn analyze_directory_structure(links: &[LinkInfo]) -> Vec<DirectoryNode> {
    let mut paths = HashSet::new();

    for link in links {
        if link.link_type != "internal" {
            continue;
        }
        if link.protocol != "http" && link.protocol != "https" {
            continue;
        }

        if let Ok(url) = Url::parse(&link.url) {
            let path = url.path().to_string();
            if !path.is_empty() && path != "/" {
                paths.insert(path);
            }
        }
    }

    // 构建目录树
    let mut dir_map: HashMap<String, HashSet<String>> = HashMap::new();

    for path in &paths {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if parts.len() <= 1 {
            continue;
        }

        let mut current_path = String::new();
        for (i, part) in parts.iter().enumerate() {
            if i < parts.len() - 1 {
                let parent = current_path.clone();
                current_path.push('/');
                current_path.push_str(part);

                let child = if i + 1 < parts.len() - 1 {
                    format!("{}/{}", current_path, parts[i + 1])
                } else {
                    format!("{}/{}", current_path, parts[i + 1])
                };

                dir_map
                    .entry(parent)
                    .or_insert_with(HashSet::new)
                    .insert(child);
            }
        }
    }

    let mut result = Vec::new();
    let mut sorted_keys: Vec<String> = dir_map.keys().cloned().collect();
    sorted_keys.sort();

    for dir in &sorted_keys {
        let depth = dir.matches('/').count();
        let mut children: Vec<String> = dir_map.get(dir).cloned().unwrap_or_default().into_iter().collect();
        children.sort();

        result.push(DirectoryNode {
            path: if dir.is_empty() { "/".to_string() } else { dir.clone() },
            children,
            depth,
        });
    }

    result
}

// ============================================================
// 敏感信息检测
// ============================================================

fn detect_sensitive_info(body: &str) -> Vec<SensitiveInfo> {
    let mut results = Vec::new();
    let lines: Vec<&str> = body.lines().collect();

    for (line_num, line) in lines.iter().enumerate() {
        let line_num_1based = line_num + 1;
        let line_lower = line.to_lowercase();

        // 邮箱检测（简单模式：包含 @ 和 . 的字符串）
        find_emails(line, line_num_1based, &mut results);

        // 手机号检测（中国大陆：11位数字，以1开头）
        find_phone_numbers(line, line_num_1based, &mut results);

        // 身份证号检测（18位数字或17位+X）
        find_id_cards(line, line_num_1based, &mut results);

        // API Key 关键字检测
        find_api_keys(line, &line_lower, line_num_1based, &mut results);
    }

    // 去重（同一行同类型同值保留一个）
    results.dedup_by(|a, b| {
        a.info_type == b.info_type && a.value == b.value && a.line_number == b.line_number
    });

    // 限制返回数量
    results.truncate(100);

    results
}

/// 检测邮箱地址
fn find_emails(line: &str, line_num: usize, results: &mut Vec<SensitiveInfo>) {
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '@' {
            // 向前找本地部分
            let mut start = i;
            while start > 0 {
                let c = chars[start - 1];
                if c.is_alphanumeric() || c == '.' || c == '_' || c == '%' || c == '+' || c == '-' {
                    start -= 1;
                } else {
                    break;
                }
            }

            // 向后找域名部分
            let mut end = i + 1;
            let mut has_dot = false;
            while end < len {
                let c = chars[end];
                if c.is_alphanumeric() || c == '.' || c == '-' {
                    if c == '.' {
                        has_dot = true;
                    }
                    end += 1;
                } else {
                    break;
                }
            }

            if start < i && end > i + 1 && has_dot {
                let email: String = chars[start..end].iter().collect();
                // 过滤假阳性
                if !email.ends_with(".png")
                    && !email.ends_with(".jpg")
                    && !email.ends_with(".gif")
                    && !email.ends_with(".svg")
                    && !email.ends_with(".webp")
                {
                    results.push(SensitiveInfo {
                        info_type: "email".to_string(),
                        value: email,
                        context: line.trim().to_string(),
                        line_number: line_num,
                    });
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
}

/// 检测中国大陆手机号
fn find_phone_numbers(line: &str, line_num: usize, results: &mut Vec<SensitiveInfo>) {
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();

    for i in 0..len.saturating_sub(10) {
        if chars[i] == '1' {
            // 第二位必须是 3-9
            if let Some(second) = chars.get(i + 1) {
                if *second >= '3' && *second <= '9' {
                    // 检查后面是否还有 9 位数字
                    let mut is_phone = true;
                    for j in 2..11 {
                        if let Some(c) = chars.get(i + j) {
                            if !c.is_ascii_digit() {
                                is_phone = false;
                                break;
                            }
                        } else {
                            is_phone = false;
                            break;
                        }
                    }

                    if is_phone {
                        // 检查前后不是数字（避免匹配更长的数字串）
                        let before_ok = i == 0 || !chars[i - 1].is_ascii_digit();
                        let after_ok = i + 11 >= len || !chars[i + 11].is_ascii_digit();

                        if before_ok && after_ok {
                            let phone: String = chars[i..i + 11].iter().collect();
                            results.push(SensitiveInfo {
                                info_type: "phone".to_string(),
                                value: phone,
                                context: line.trim().to_string(),
                                line_number: line_num,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// 检测中国大陆身份证号
fn find_id_cards(line: &str, line_num: usize, results: &mut Vec<SensitiveInfo>) {
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();

    for i in 0..len.saturating_sub(17) {
        // 18 位身份证
        if chars[i].is_ascii_digit() && chars[i] != '0' {
            let mut is_id = true;
            for j in 1..17 {
                if let Some(c) = chars.get(i + j) {
                    if !c.is_ascii_digit() {
                        is_id = false;
                        break;
                    }
                } else {
                    is_id = false;
                    break;
                }
            }

            // 第 18 位是数字或 X/x
            if is_id {
                if let Some(last) = chars.get(i + 17) {
                    if !last.is_ascii_digit() && *last != 'X' && *last != 'x' {
                        is_id = false;
                    }
                } else {
                    is_id = false;
                }
            }

            if is_id {
                // 简单校验：第7-10位应该是合理的年份
                let year_str: String = chars[i + 6..i + 10].iter().collect();
                if let Ok(year) = year_str.parse::<u32>() {
                    if year >= 1900 && year <= 2100 {
                        let before_ok = i == 0 || !chars[i - 1].is_ascii_digit();
                        let after_ok = i + 18 >= len || !chars[i + 18].is_ascii_digit();

                        if before_ok && after_ok {
                            let id_card: String = chars[i..i + 18].iter().collect();
                            results.push(SensitiveInfo {
                                info_type: "id_card".to_string(),
                                value: id_card,
                                context: line.trim().to_string(),
                                line_number: line_num,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// 检测 API Key / Token / Secret 等敏感信息
fn find_api_keys(line: &str, line_lower: &str, line_num: usize, results: &mut Vec<SensitiveInfo>) {
    let key_indicators = [
        ("api_key", "api_key"),
        ("api-key", "api_key"),
        ("apikey", "api_key"),
        ("secret_key", "secret_key"),
        ("secret-key", "secret_key"),
        ("secretkey", "secret_key"),
        ("access_token", "access_token"),
        ("access-token", "access_token"),
        ("accesstoken", "access_token"),
        ("auth_token", "auth_token"),
        ("bearer ", "bearer_token"),
        ("password", "password"),
        ("private_key", "private_key"),
    ];

    for (indicator, info_type) in &key_indicators {
        if let Some(pos) = line_lower.find(indicator) {
            // 找后面的值部分
            let rest = &line[pos + indicator.len()..];
            let rest_trimmed = rest.trim_start_matches(|c: char| c == ' ' || c == '=' || c == ':' || c == '\t');
            let value = rest_trimmed
                .split(|c: char| c == ' ' || c == ',' || c == ';' || c == '\n' || c == '\r' || c == '"' || c == '\'')
                .next()
                .unwrap_or("");

            // 值需要有一定长度才可能是 key
            if value.len() >= 16 {
                results.push(SensitiveInfo {
                    info_type: info_type.to_string(),
                    value: format!("{}={}", indicator, &value[..value.len().min(30)]),
                    context: line.trim().to_string(),
                    line_number: line_num,
                });
            }
        }
    }

    // AWS Access Key 检测
    if let Some(pos) = line.find("AKIA") {
        if pos + 20 <= line.len() {
            let rest = &line[pos..pos + 20];
            if rest.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                results.push(SensitiveInfo {
                    info_type: "aws_access_key".to_string(),
                    value: rest.to_string(),
                    context: line.trim().to_string(),
                    line_number: line_num,
                });
            }
        }
    }

    // Stripe Key 检测
    if let Some(pos) = line.find("sk_") {
        let rest = &line[pos..];
        if rest.len() > 12 {
            let value_end = rest
                .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                .unwrap_or(rest.len());
            if value_end >= 12 {
                results.push(SensitiveInfo {
                    info_type: "stripe_key".to_string(),
                    value: rest[..value_end.min(30)].to_string(),
                    context: line.trim().to_string(),
                    line_number: line_num,
                });
            }
        }
    }

    // GitHub Token 检测
    if let Some(pos) = line.find("ghp_") {
        let rest = &line[pos..];
        if rest.len() > 10 {
            let value_end = rest
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            if value_end >= 10 {
                results.push(SensitiveInfo {
                    info_type: "github_token".to_string(),
                    value: rest[..value_end.min(30)].to_string(),
                    context: line.trim().to_string(),
                    line_number: line_num,
                });
            }
        }
    }

    // Google API Key 检测
    if let Some(pos) = line.find("AIza") {
        if pos + 39 <= line.len() {
            let rest = &line[pos..pos + 39];
            if rest.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                results.push(SensitiveInfo {
                    info_type: "google_api_key".to_string(),
                    value: rest.to_string(),
                    context: line.trim().to_string(),
                    line_number: line_num,
                });
            }
        }
    }
}

// ============================================================
// 工具函数：提取链接（供外部和爬虫模块使用的辅助函数）
// ============================================================

/// 从 HTML 中提取所有链接（公共辅助函数）
pub fn extract_links_from_html(html: &str, base_url: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let links = extract_links(&document, base_url);
    links
        .into_iter()
        .filter(|l| l.protocol == "http" || l.protocol == "https")
        .map(|l| l.url)
        .collect()
}

// ============================================================
// 兼容层：commands_netsec.rs 中使用的函数
// ============================================================

/// URL 快速分析：提取页面链接
pub fn extract_links_from_url(url: String) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("创建客户端失败: {}", e))?;

    let resp = client.get(&url).send().map_err(|e| format!("请求失败: {}", e))?;
    let body = resp.text().unwrap_or_default();
    let links = extract_links_from_html(&body, &url);

    serde_json::to_string(&links).map_err(|e| format!("序列化失败: {}", e))
}

/// URL 快速分析：提取页面表单
pub fn extract_forms_from_url(url: String) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("创建客户端失败: {}", e))?;

    let resp = client.get(&url).send().map_err(|e| format!("请求失败: {}", e))?;
    let body = resp.text().unwrap_or_default();
    let document = Html::parse_document(&body);
    let forms = extract_forms(&document, &url);

    serde_json::to_string(&forms).map_err(|e| format!("序列化失败: {}", e))
}

/// 安全头检测
pub fn check_security_headers(url: String) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("创建客户端失败: {}", e))?;

    let resp = client.get(&url).send().map_err(|e| format!("请求失败: {}", e))?;

    let mut headers_map = std::collections::HashMap::new();
    for (key, value) in resp.headers().iter() {
        headers_map.insert(
            key.as_str().to_string(),
            value.to_str().unwrap_or("").to_string(),
        );
    }

    let report = analyze_security_headers(&headers_map);
    serde_json::to_string(&report).map_err(|e| format!("序列化失败: {}", e))
}

/// 技术栈指纹识别
pub fn detect_tech(url: String) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("创建客户端失败: {}", e))?;

    let resp = client.get(&url).send().map_err(|e| format!("请求失败: {}", e))?;

    let mut headers_map = std::collections::HashMap::new();
    for (key, value) in resp.headers().iter() {
        headers_map.insert(
            key.as_str().to_string(),
            value.to_str().unwrap_or("").to_string(),
        );
    }

    let body = resp.text().unwrap_or_default();

    let document = Html::parse_document(&body);
    let fingerprint = detect_tech_fingerprint(&document, &headers_map, &body);
    serde_json::to_string(&fingerprint).map_err(|e| format!("序列化失败: {}", e))
}

/// 敏感信息检测
pub fn find_sensitive(url: String) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("创建客户端失败: {}", e))?;

    let resp = client.get(&url).send().map_err(|e| format!("请求失败: {}", e))?;
    let body = resp.text().unwrap_or_default();

    let sensitive = detect_sensitive_info(&body);
    serde_json::to_string(&sensitive).map_err(|e| format!("序列化失败: {}", e))
}
