// yxpil · NETON
//! 网络爬虫模块
//! 提供 BFS/DFS 爬取、深度/页数限制、域名黑白名单、速率控制、
//! robots.txt 遵守、链接去重、页面内容提取、链接图谱构建、
//! 死链接检测、爬取统计等功能。

use serde::{Deserialize, Serialize};
use scraper::{Html, Selector};
use url::Url;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use std::thread;

// ============================================================
// 数据结构定义
// ============================================================

/// 爬取策略
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrawlStrategy {
    Bfs,
    Dfs,
}

impl Default for CrawlStrategy {
    fn default() -> Self {
        CrawlStrategy::Bfs
    }
}

/// 爬虫配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerConfig {
    /// 爬取策略：BFS / DFS
    pub strategy: CrawlStrategy,
    /// 最大爬取深度
    pub max_depth: usize,
    /// 最大爬取页数
    pub max_pages: usize,
    /// 请求超时（毫秒）
    pub timeout_ms: u64,
    /// 请求间隔（毫秒），速率限制
    pub delay_ms: u64,
    /// User-Agent
    pub user_agent: String,
    /// 域名白名单（为空则不限制）
    pub allowed_domains: Vec<String>,
    /// 域名黑名单
    pub blocked_domains: Vec<String>,
    /// 是否只爬取站内链接
    pub same_domain_only: bool,
    /// 是否遵守 robots.txt
    pub respect_robots_txt: bool,
    /// 是否检测死链接
    pub check_dead_links: bool,
    /// 是否跟随重定向
    pub follow_redirects: bool,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            strategy: CrawlStrategy::Bfs,
            max_depth: 3,
            max_pages: 50,
            timeout_ms: 10000,
            delay_ms: 500,
            user_agent: "Mozilla/5.0 (compatible; NETON-Crawler/1.0)".to_string(),
            allowed_domains: vec![],
            blocked_domains: vec![],
            same_domain_only: true,
            respect_robots_txt: true,
            check_dead_links: false,
            follow_redirects: true,
        }
    }
}

/// 已爬取页面数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawledPage {
    /// 页面 URL
    pub url: String,
    /// 页面标题
    pub title: String,
    /// 页面状态码
    pub status_code: u16,
    /// 页面大小（字节）
    pub content_length: usize,
    /// 内容类型
    pub content_type: String,
    /// 爬取深度
    pub depth: usize,
    /// 加载时间（毫秒）
    pub load_time_ms: u64,
    /// 页面描述
    pub description: Option<String>,
    /// 页面关键词
    pub keywords: Option<String>,
    /// 页面正文摘要（前 500 字符）
    pub summary: Option<String>,
    /// 该页面包含的链接数
    pub link_count: usize,
    /// 该页面包含的站内链接
    pub internal_links: Vec<String>,
    /// 该页面包含的站外链接
    pub external_links: Vec<String>,
    /// 爬取时间戳
    pub crawled_at: i64,
}

/// 爬取统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlStats {
    /// 已爬取页数
    pub pages_crawled: usize,
    /// 失败页数
    pub pages_failed: usize,
    /// 发现的总链接数
    pub total_links_found: usize,
    /// 总下载大小（字节）
    pub total_bytes: usize,
    /// 总耗时（毫秒）
    pub total_time_ms: u64,
    /// 平均页面大小（字节）
    pub avg_page_size: f64,
    /// 平均加载时间（毫秒）
    pub avg_load_time: f64,
    /// 爬取速率（页/秒）
    pub pages_per_second: f64,
    /// 死链接数量
    pub dead_links: usize,
}

/// 链接图谱节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkGraphNode {
    /// 页面 URL
    pub url: String,
    /// 页面标题
    pub title: String,
    /// 入链数（被其他页面链接的次数）
    pub in_degree: usize,
    /// 出链数（链接到其他页面的次数）
    pub out_degree: usize,
    /// 链接到的页面 URL 列表
    pub links_to: Vec<String>,
}

/// 链接图谱
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkGraph {
    pub nodes: Vec<LinkGraphNode>,
    pub total_nodes: usize,
    pub total_edges: usize,
}

/// 死链接信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLinkInfo {
    pub url: String,
    pub status_code: Option<u16>,
    pub error_message: Option<String>,
    pub found_on_page: String,
}

/// 爬取结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlResult {
    /// 起始 URL
    pub start_url: String,
    /// 爬取配置
    pub config: CrawlerConfig,
    /// 已爬取页面列表
    pub pages: Vec<CrawledPage>,
    /// 爬取统计
    pub stats: CrawlStats,
    /// 链接图谱
    pub link_graph: LinkGraph,
    /// 死链接列表
    pub dead_links: Vec<DeadLinkInfo>,
    /// 失败页面列表
    pub failed_pages: Vec<FailedPage>,
}

/// 失败页面
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedPage {
    pub url: String,
    pub error: String,
    pub depth: usize,
}

// ============================================================
// 核心爬取函数
// ============================================================

/// 开始爬取网站
pub fn crawl_website(start_url: String, config: CrawlerConfig) -> Result<String, String> {
    let start_time = Instant::now();

    // 验证起始 URL
    let start_parsed = Url::parse(&start_url).map_err(|e| format!("无效的起始 URL: {}", e))?;
    let start_host = start_parsed
        .host_str()
        .ok_or_else(|| "无法解析起始 URL 的域名".to_string())?
        .to_string();

    // 构建 HTTP 客户端
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .user_agent(&config.user_agent)
        .redirect(if config.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()
        .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))?;

    // 已访问 URL 集合
    let mut visited: HashSet<String> = HashSet::new();
    // 已爬取页面
    let mut pages: Vec<CrawledPage> = Vec::new();
    // 失败页面
    let mut failed_pages: Vec<FailedPage> = Vec::new();
    // 死链接
    let mut dead_links: Vec<DeadLinkInfo> = Vec::new();
    // 链接图：url -> 链接到的 url 列表
    let mut link_map: HashMap<String, Vec<String>> = HashMap::new();
    // 入链计数
    let mut in_degree_map: HashMap<String, usize> = HashMap::new();
    // 总字节数
    let mut total_bytes: usize = 0;
    // 总加载时间
    let mut total_load_time: u64 = 0;
    // 发现的总链接数
    let mut total_links_found: usize = 0;

    // 获取 robots.txt 规则
    let robots_disallowed = if config.respect_robots_txt {
        fetch_robots_txt(&client, &start_parsed)
    } else {
        Vec::new()
    };

    // 待爬取队列（用于 BFS）或栈（用于 DFS）
    // 每个元素: (url, depth, referrer)
    let mut queue: VecDeque<(String, usize, String)> = VecDeque::new();
    queue.push_back((start_url.clone(), 0, String::new()));
    visited.insert(start_url.clone());

    // 爬取循环
    while !queue.is_empty() && pages.len() < config.max_pages {
        let (current_url, depth, referrer) = match config.strategy {
            CrawlStrategy::Bfs => queue.pop_front().unwrap(),
            CrawlStrategy::Dfs => queue.pop_back().unwrap(),
        };

        // 检查深度限制
        if depth > config.max_depth {
            continue;
        }

        // 检查 robots.txt
        if config.respect_robots_txt && is_disallowed_by_robots(&current_url, &robots_disallowed) {
            continue;
        }

        // 速率限制
        if config.delay_ms > 0 && !pages.is_empty() {
            thread::sleep(Duration::from_millis(config.delay_ms));
        }

        // 爬取页面
        let page_result = crawl_page(&client, &current_url, depth);

        match page_result {
            Ok(page) => {
                total_bytes += page.content_length;
                total_load_time += page.load_time_ms;
                total_links_found += page.link_count;

                // 提取页面链接
                let (internal_links, external_links) =
                    classify_page_links(&page.internal_links, &page.external_links, &start_host, &config);

                // 更新链接图
                let mut links_to = Vec::new();
                for link in &internal_links {
                    links_to.push(link.clone());
                    *in_degree_map.entry(link.clone()).or_insert(0) += 1;
                }
                link_map.insert(current_url.clone(), links_to);

                // 将新链接加入队列
                for link in &internal_links {
                    if !visited.contains(link) {
                        visited.insert(link.clone());
                        queue.push_back((link.clone(), depth + 1, current_url.clone()));
                    }
                }

                // 检测死链接
                if config.check_dead_links {
                    for link in &external_links {
                        check_dead_link(
                            &client,
                            link,
                            &current_url,
                            &mut dead_links,
                            config.timeout_ms,
                        );
                    }
                }

                pages.push(page);
            }
            Err(e) => {
                failed_pages.push(FailedPage {
                    url: current_url.clone(),
                    error: e,
                    depth,
                });

                // 记录死链接
                if !referrer.is_empty() {
                    dead_links.push(DeadLinkInfo {
                        url: current_url.clone(),
                        status_code: None,
                        error_message: Some(failed_pages.last().unwrap().error.clone()),
                        found_on_page: referrer,
                    });
                }
            }
        }
    }

    let total_time_ms = start_time.elapsed().as_millis() as u64;

    // 计算统计数据
    let pages_crawled = pages.len();
    let pages_failed = failed_pages.len();
    let dead_links_count = dead_links.len();

    let avg_page_size = if pages_crawled > 0 {
        total_bytes as f64 / pages_crawled as f64
    } else {
        0.0
    };

    let avg_load_time = if pages_crawled > 0 {
        total_load_time as f64 / pages_crawled as f64
    } else {
        0.0
    };

    let pages_per_second = if total_time_ms > 0 {
        (pages_crawled as f64 * 1000.0) / total_time_ms as f64
    } else {
        0.0
    };

    let stats = CrawlStats {
        pages_crawled,
        pages_failed,
        total_links_found,
        total_bytes,
        total_time_ms,
        avg_page_size,
        avg_load_time,
        pages_per_second,
        dead_links: dead_links_count,
    };

    // 构建链接图谱
    let link_graph = build_link_graph(&pages, &link_map, &in_degree_map);

    let result = CrawlResult {
        start_url,
        config,
        pages,
        stats,
        link_graph,
        dead_links,
        failed_pages,
    };

    serde_json::to_string(&result).map_err(|e| format!("序列化失败: {}", e))
}

/// 从 HTML 中提取所有链接
pub fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let mut links = Vec::new();

    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return links,
    };

    let link_selector = Selector::parse("a[href]").unwrap();

    for link in document.select(&link_selector) {
        let href = match link.value().attr("href") {
            Some(h) => h.to_string(),
            None => continue,
        };

        // 跳过非 HTTP 链接
        let href_lower = href.to_lowercase();
        if href_lower.starts_with("mailto:")
            || href_lower.starts_with("tel:")
            || href_lower.starts_with("javascript:")
            || href_lower.starts_with("#")
            || href_lower.starts_with("data:")
        {
            continue;
        }

        // 解析 URL
        let parsed = match Url::parse(&href) {
            Ok(u) => u,
            Err(_) => match base.join(&href) {
                Ok(u) => u,
                Err(_) => continue,
            },
        };

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            continue;
        }

        // 标准化 URL（去掉 fragment）
        let mut normalized = parsed.clone();
        normalized.set_fragment(None);

        links.push(normalized.to_string());
    }

    // 去重
    links.sort();
    links.dedup();

    links
}

// ============================================================
// 页面爬取
// ============================================================

fn crawl_page(
    client: &reqwest::blocking::Client,
    url: &str,
    depth: usize,
) -> Result<CrawledPage, String> {
    let start_time = Instant::now();

    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("请求失败: {}", e))?;

    let status_code = response.status().as_u16();
    let final_url = response.url().to_string();
    let load_time_ms = start_time.elapsed().as_millis() as u64;

    // 检查状态码
    if !response.status().is_success() {
        return Err(format!("HTTP 状态码: {}", status_code));
    }

    // 获取内容类型
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // 只处理 HTML 内容
    if !content_type.to_lowercase().contains("text/html") {
        return Err(format!("非 HTML 内容: {}", content_type));
    }

    // 读取响应体
    let body = response
        .text()
        .map_err(|e| format!("读取响应体失败: {}", e))?;
    let content_length = body.len();

    // 解析 HTML
    let document = Html::parse_document(&body);

    // 提取标题
    let title_selector = Selector::parse("title").unwrap();
    let title = document
        .select(&title_selector)
        .next()
        .map(|e| e.text().collect::<String>().trim().to_string())
        .unwrap_or_default();

    // 提取 description
    let mut description = None;
    let mut keywords = None;
    let meta_selector = Selector::parse("meta").unwrap();
    for meta in document.select(&meta_selector) {
        let name = meta
            .value()
            .attr("name")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let content = meta.value().attr("content").map(|s| s.to_string());

        match name.as_str() {
            "description" => description = content,
            "keywords" => keywords = content,
            _ => {}
        }
    }

    // 提取正文摘要
    let summary = extract_summary(&document);

    // 提取链接
    let all_links = extract_links(&body, &final_url);
    let link_count = all_links.len();

    // 分离站内和站外链接
    let base_host = Url::parse(&final_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default();

    let mut internal_links = Vec::new();
    let mut external_links = Vec::new();

    for link in &all_links {
        if let Ok(link_url) = Url::parse(link) {
            if link_url.host_str().unwrap_or("") == base_host {
                internal_links.push(link.clone());
            } else {
                external_links.push(link.clone());
            }
        }
    }

    Ok(CrawledPage {
        url: final_url,
        title,
        status_code,
        content_length,
        content_type,
        depth,
        load_time_ms,
        description,
        keywords,
        summary,
        link_count,
        internal_links,
        external_links,
        crawled_at: chrono::Utc::now().timestamp(),
    })
}

// ============================================================
// 正文摘要提取
// ============================================================

fn extract_summary(document: &Html) -> Option<String> {
    // 尝试从常见的正文容器中提取
    let selectors = vec![
        "article",
        "main",
        ".content",
        ".article-content",
        ".post-content",
        "#content",
        "body",
    ];

    for selector_str in &selectors {
        if let Ok(selector) = Selector::parse(selector_str) {
            if let Some(element) = document.select(&selector).next() {
                let text: String = element
                    .text()
                    .collect::<String>()
                    .split_whitespace()
                    .collect::<Vec<&str>>()
                    .join(" ");

                if text.len() > 50 {
                    let summary = if text.len() > 500 {
                        text.chars().take(500).collect::<String>() + "..."
                    } else {
                        text
                    };
                    return Some(summary);
                }
            }
        }
    }

    None
}

// ============================================================
// 链接分类
// ============================================================

fn classify_page_links(
    internal: &[String],
    external: &[String],
    start_host: &str,
    config: &CrawlerConfig,
) -> (Vec<String>, Vec<String>) {
    let mut result_internal = Vec::new();
    let mut result_external = Vec::new();

    for link in internal {
        if should_crawl_url(link, start_host, config) {
            result_internal.push(link.clone());
        } else {
            result_external.push(link.clone());
        }
    }

    for link in external {
        result_external.push(link.clone());
    }

    (result_internal, result_external)
}

fn should_crawl_url(url: &str, start_host: &str, config: &CrawlerConfig) -> bool {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let host = match parsed.host_str() {
        Some(h) => h.to_string(),
        None => return false,
    };

    // 只爬取站内链接
    if config.same_domain_only && host != start_host {
        return false;
    }

    // 白名单检查
    if !config.allowed_domains.is_empty() {
        if !config
            .allowed_domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{}", d)))
        {
            return false;
        }
    }

    // 黑名单检查
    if config
        .blocked_domains
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{}", d)))
    {
        return false;
    }

    true
}

// ============================================================
// robots.txt 处理
// ============================================================

fn fetch_robots_txt(client: &reqwest::blocking::Client, start_url: &Url) -> Vec<String> {
    let mut disallowed = Vec::new();

    let robots_url = format!(
        "{}://{}{}robots.txt",
        start_url.scheme(),
        start_url.host_str().unwrap_or(""),
        if start_url.port().is_some() {
            format!(":{}", start_url.port().unwrap())
        } else {
            String::new()
        }
    );

    if let Ok(response) = client.get(&robots_url).send() {
        if response.status().is_success() {
            if let Ok(body) = response.text() {
                let mut in_user_agent = false;
                for line in body.lines() {
                    let line = line.trim();
                    let line_lower = line.to_lowercase();

                    if line_lower.starts_with("user-agent:") {
                        let ua = line_lower
                            .strip_prefix("user-agent:")
                            .unwrap_or("")
                            .trim();
                        in_user_agent = ua == "*" || ua.contains("neton");
                    } else if in_user_agent && line_lower.starts_with("disallow:") {
                        let path = line
                            .strip_prefix("Disallow:")
                            .or_else(|| line.strip_prefix("disallow:"))
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if !path.is_empty() && path != "/" {
                            disallowed.push(path);
                        }
                    }
                }
            }
        }
    }

    disallowed
}

fn is_disallowed_by_robots(url: &str, disallowed: &[String]) -> bool {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let path = parsed.path().to_string();

    for rule in disallowed {
        if rule.ends_with('*') {
            let prefix = &rule[..rule.len() - 1];
            if path.starts_with(prefix) {
                return true;
            }
        } else if path.starts_with(rule) {
            return true;
        }
    }

    false
}

// ============================================================
// 死链接检测
// ============================================================

fn check_dead_link(
    client: &reqwest::blocking::Client,
    url: &str,
    referrer: &str,
    dead_links: &mut Vec<DeadLinkInfo>,
    timeout_ms: u64,
) {
    // 使用 HEAD 请求检测
    let result = client
        .head(url)
        .timeout(Duration::from_millis(timeout_ms))
        .send();

    match result {
        Ok(response) => {
            let status = response.status().as_u16();
            // 4xx 和 5xx 视为死链接（429 除外，可能是速率限制）
            if (status >= 400 && status < 500 && status != 429) || status >= 500 {
                dead_links.push(DeadLinkInfo {
                    url: url.to_string(),
                    status_code: Some(status),
                    error_message: Some(format!("HTTP {}", status)),
                    found_on_page: referrer.to_string(),
                });
            }
        }
        Err(e) => {
            dead_links.push(DeadLinkInfo {
                url: url.to_string(),
                status_code: None,
                error_message: Some(e.to_string()),
                found_on_page: referrer.to_string(),
            });
        }
    }
}

// ============================================================
// 链接图谱构建
// ============================================================

fn build_link_graph(
    pages: &[CrawledPage],
    link_map: &HashMap<String, Vec<String>>,
    in_degree_map: &HashMap<String, usize>,
) -> LinkGraph {
    let mut nodes = Vec::new();
    let mut total_edges = 0;

    for page in pages {
        let links_to = link_map.get(&page.url).cloned().unwrap_or_default();
        let out_degree = links_to.len();
        let in_degree = *in_degree_map.get(&page.url).unwrap_or(&0);
        total_edges += out_degree;

        nodes.push(LinkGraphNode {
            url: page.url.clone(),
            title: page.title.clone(),
            in_degree,
            out_degree,
            links_to,
        });
    }

    LinkGraph {
        total_nodes: nodes.len(),
        total_edges,
        nodes,
    }
}
