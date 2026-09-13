// yxpil · NETON
//! 虚拟浏览器集成工具
//! Headless browser 封装（概念性实现）

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 浏览器引擎类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserEngine {
    /// Chromium (Chrome/Edge)
    Chromium,
    /// Firefox
    Firefox,
    /// WebKit (Safari)
    Webkit,
}

/// 浏览器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualBrowserConfig {
    /// 浏览器引擎
    pub engine: BrowserEngine,
    /// 是否无头模式
    pub headless: bool,
    /// 视口宽度
    pub viewport_width: u32,
    /// 视口高度
    pub viewport_height: u32,
    /// User-Agent
    pub user_agent: Option<String>,
    /// 页面加载超时（毫秒）
    pub page_timeout_ms: u64,
    /// 是否禁用图片加载
    pub disable_images: bool,
    /// 是否禁用 JavaScript
    pub disable_javascript: bool,
    /// 代理设置
    pub proxy: Option<String>,
    /// 自定义请求头
    pub extra_headers: Option<std::collections::HashMap<String, String>>,
}

impl Default for VirtualBrowserConfig {
    fn default() -> Self {
        Self {
            engine: BrowserEngine::Chromium,
            headless: true,
            viewport_width: 1920,
            viewport_height: 1080,
            user_agent: Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    .to_string(),
            ),
            page_timeout_ms: 30000,
            disable_images: false,
            disable_javascript: false,
            proxy: None,
            extra_headers: None,
        }
    }
}

/// 页面信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    pub url: String,
    pub title: String,
    pub status_code: u16,
    pub content_length: usize,
    pub content_type: String,
    pub final_url: String,
    pub redirect_count: u32,
    pub load_time_ms: u64,
    pub cookies: Vec<CookieInfo>,
}

/// Cookie 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
}

/// 截图配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotConfig {
    /// 输出路径
    pub output_path: String,
    /// 格式：png, jpeg, webp
    pub format: String,
    /// 质量 (1-100，仅 jpeg/webp)
    pub quality: u8,
    /// 是否整页截图
    pub full_page: bool,
}

impl Default for ScreenshotConfig {
    fn default() -> Self {
        Self {
            output_path: "screenshot.png".to_string(),
            format: "png".to_string(),
            quality: 80,
            full_page: false,
        }
    }
}

/// 浏览器实例状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInstance {
    pub id: String,
    pub engine: String,
    pub headless: bool,
    pub is_running: bool,
    pub current_url: Option<String>,
    pub pages_count: usize,
    pub started_at: i64,
}

/// 虚拟浏览器管理器
pub struct VirtualBrowserManager {
    instances: std::collections::HashMap<String, BrowserInstance>,
}

impl VirtualBrowserManager {
    pub fn new() -> Self {
        Self {
            instances: std::collections::HashMap::new(),
        }
    }
}

// 使用静态变量存储浏览器管理器（简化实现）
use std::sync::{Mutex, OnceLock};

static BROWSER_MANAGER: OnceLock<Mutex<VirtualBrowserManager>> = OnceLock::new();

fn get_browser_manager() -> &'static Mutex<VirtualBrowserManager> {
    BROWSER_MANAGER.get_or_init(|| Mutex::new(VirtualBrowserManager::new()))
}

/// 启动虚拟浏览器实例
pub async fn launch_browser(config: VirtualBrowserConfig) -> Result<String, String> {
    let instance_id = uuid::Uuid::new_v4().to_string();
    let engine_str = match config.engine {
        BrowserEngine::Chromium => "Chromium",
        BrowserEngine::Firefox => "Firefox",
        BrowserEngine::Webkit => "WebKit",
    }
    .to_string();

    // 概念性实现：实际需要集成 headless_chrome、fantoccini 或 thirtyfour 等库
    // 这里模拟浏览器启动

    let instance = BrowserInstance {
        id: instance_id.clone(),
        engine: engine_str,
        headless: config.headless,
        is_running: true,
        current_url: None,
        pages_count: 1,
        started_at: chrono::Utc::now().timestamp(),
    };

    let mut manager = get_browser_manager().lock().map_err(|e| e.to_string())?;
    manager.instances.insert(instance_id.clone(), instance.clone());

    let result = serde_json::json!({
        "instance_id": instance_id,
        "browser": instance,
        "note": "概念性实现，实际需要 headless_chrome / thirtyfour 等库",
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "浏览器启动成功"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 关闭浏览器实例
pub async fn close_browser(instance_id: String) -> Result<String, String> {
    let mut manager = get_browser_manager().lock().map_err(|e| e.to_string())?;

    if manager.instances.remove(&instance_id).is_some() {
        let result = serde_json::json!({
            "instance_id": instance_id,
            "closed": true,
        });
        serde_json::to_string(&crate::netsec::ToolResult::ok(result, "浏览器已关闭"))
            .map_err(|e| format!("序列化失败: {}", e))
    } else {
        Err(format!("浏览器实例不存在: {}", instance_id))
    }
}

/// 获取所有浏览器实例
pub fn list_browsers() -> Result<String, String> {
    let manager = get_browser_manager().lock().map_err(|e| e.to_string())?;

    let instances: Vec<&BrowserInstance> = manager.instances.values().collect();

    let result = serde_json::json!({
        "total": instances.len(),
        "instances": instances,
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "获取浏览器列表成功"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 访问 URL 并获取页面信息（概念性实现，使用 reqwest 模拟）
pub async fn navigate_to(instance_id: String, url: String) -> Result<String, String> {
    // 检查浏览器实例是否存在
    {
        let manager = get_browser_manager().lock().map_err(|e| e.to_string())?;
        if !manager.instances.contains_key(&instance_id) {
            return Err(format!("浏览器实例不存在: {}", instance_id));
        }
    }

    let start_time = std::time::Instant::now();

    // 概念性实现：使用 reqwest 获取页面内容
    // 实际的 headless browser 应该能执行 JavaScript、渲染页面等
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(30000))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client
        .get(&url)
        .header(reqwest::header::USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .send()
        .await
        .map_err(|e| format!("请求失败: {}", e))?;

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let final_url = response.url().to_string();

    // 计算重定向次数（简化处理）
    let redirect_count = if final_url != url { 1 } else { 0 };

    let body = response.text().await.unwrap_or_default();
    let content_length = body.len();

    // 从 HTML 中提取标题
    let title = extract_title(&body);

    // 提取 cookies
    let cookies = vec![]; // 简化处理

    let page_info = PageInfo {
        url: url.clone(),
        title,
        status_code: status,
        content_length,
        content_type,
        final_url: final_url.clone(),
        redirect_count,
        load_time_ms: start_time.elapsed().as_millis() as u64,
        cookies,
    };

    // 更新浏览器实例状态
    {
        let mut manager = get_browser_manager().lock().map_err(|e| e.to_string())?;
        if let Some(instance) = manager.instances.get_mut(&instance_id) {
            instance.current_url = Some(final_url);
        }
    }

    serde_json::to_string(&crate::netsec::ToolResult::ok(
        page_info,
        "页面加载完成（概念性实现，使用 HTTP 请求模拟）",
    ))
    .map_err(|e| format!("序列化失败: {}", e))
}

/// 从 HTML 中提取标题
fn extract_title(html: &str) -> String {
    if let Some(start) = html.to_lowercase().find("<title>") {
        let start = start + 7;
        if let Some(end) = html[start..].to_lowercase().find("</title>") {
            return html[start..start + end].trim().to_string();
        }
    }
    String::new()
}

/// 页面截图（概念性实现）
pub async fn take_screenshot(
    instance_id: String,
    config: ScreenshotConfig,
) -> Result<String, String> {
    // 检查浏览器实例
    let manager = get_browser_manager().lock().map_err(|e| e.to_string())?;
    if !manager.instances.contains_key(&instance_id) {
        return Err(format!("浏览器实例不存在: {}", instance_id));
    }
    drop(manager);

    // 概念性实现：实际需要使用 headless browser 截图
    // 这里创建一个占位说明

    let result = serde_json::json!({
        "instance_id": instance_id,
        "output_path": config.output_path,
        "format": config.format,
        "full_page": config.full_page,
        "success": false,
        "note": "截图功能需要真实的 headless browser（概念性实现暂不生成实际图片）",
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(
        result,
        "截图请求已处理（概念性实现）",
    ))
    .map_err(|e| format!("序列化失败: {}", e))
}

/// 执行 JavaScript（概念性实现）
pub async fn evaluate_javascript(instance_id: String, script: String) -> Result<String, String> {
    let manager = get_browser_manager().lock().map_err(|e| e.to_string())?;
    if !manager.instances.contains_key(&instance_id) {
        return Err(format!("浏览器实例不存在: {}", instance_id));
    }
    drop(manager);

    // 概念性实现
    let result = serde_json::json!({
        "instance_id": instance_id,
        "script": script,
        "result": null,
        "success": false,
        "note": "JavaScript 执行需要真实的 headless browser（概念性实现）",
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(
        result,
        "JS 执行请求已处理（概念性实现）",
    ))
    .map_err(|e| format!("序列化失败: {}", e))
}

/// 获取页面 HTML 内容（概念性实现，使用 reqwest）
pub async fn get_page_source(url: String) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client
        .get(&url)
        .header(reqwest::header::USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .send()
        .await
        .map_err(|e| format!("请求失败: {}", e))?;

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    let result = serde_json::json!({
        "url": url,
        "status_code": status,
        "content_length": body.len(),
        "content": body,
        "note": "使用 HTTP 请求获取（不执行 JavaScript）",
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "页面源码获取成功"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 快速页面渲染检测
pub async fn quick_page_check(url: String) -> Result<String, String> {
    let start_time = std::time::Instant::now();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status();
            let headers: std::collections::HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body = response.text().await.unwrap_or_default();
            let title = extract_title(&body);

            let result = serde_json::json!({
                "url": url,
                "status_code": status.as_u16(),
                "status_text": status.canonical_reason().unwrap_or(""),
                "title": title,
                "content_length": body.len(),
                "headers": headers,
                "response_time_ms": start_time.elapsed().as_millis() as u64,
                "is_success": status.is_success(),
                "is_redirect": status.is_redirection(),
                "is_client_error": status.is_client_error(),
                "is_server_error": status.is_server_error(),
            });

            serde_json::to_string(&crate::netsec::ToolResult::ok(result, "页面检测完成"))
                .map_err(|e| format!("序列化失败: {}", e))
        }
        Err(e) => Err(format!("请求失败: {}", e)),
    }
}
