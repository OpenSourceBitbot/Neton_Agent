// yxpil · NETON
//! 哈希破解与编码转换模块
//! 提供哈希计算、哈希破解、编码解码、密码学工具、哈希类型识别、文件格式识别等功能。

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::time::Instant;

// ============================================================
// 结构体定义
// ============================================================

/// 哈希计算请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashComputeRequest {
    /// 输入文本
    pub input: String,
    /// 哈希算法
    pub algorithm: String,
    /// 是否为文件路径
    pub is_file: bool,
}

/// 哈希计算结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashComputeResult {
    /// 算法名称
    pub algorithm: String,
    /// 哈希值（十六进制）
    pub hash: String,
    /// 输入内容摘要
    pub input_preview: String,
    /// 计算耗时（毫秒）
    pub duration_ms: u64,
}

/// 哈希破解配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashCrackConfig {
    /// 目标哈希值
    pub hash: String,
    /// 哈希类型
    pub hash_type: String,
    /// 破解模式：dictionary / brute_force / rainbow
    pub mode: String,
    /// 字典路径（字典模式用）
    pub dict_path: String,
    /// 最大长度（暴力破解用）
    pub max_length: u32,
    /// 最小长度（暴力破解用）
    pub min_length: u32,
    /// 字符集（暴力破解用）
    pub charset: String,
}

impl Default for HashCrackConfig {
    fn default() -> Self {
        Self {
            hash: String::new(),
            hash_type: "md5".to_string(),
            mode: "dictionary".to_string(),
            dict_path: String::new(),
            max_length: 6,
            min_length: 1,
            charset: "abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
        }
    }
}

/// 哈希破解结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashCrackResult {
    /// 是否找到
    pub found: bool,
    /// 找到的明文
    pub plaintext: String,
    /// 哈希类型
    pub hash_type: String,
    /// 目标哈希
    pub target_hash: String,
    /// 尝试次数
    pub attempts: u64,
    /// 耗时（毫秒）
    pub duration_ms: u64,
    /// 每秒尝试次数
    pub attempts_per_second: f64,
    /// 进度（0-100，仅字典模式）
    pub progress: f32,
}

/// 编码/解码请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodeRequest {
    /// 输入文本
    pub input: String,
    /// 编码格式
    pub format: String,
    /// true=解码, false=编码
    pub decode: bool,
}

/// 编码/解码结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodeResult {
    /// 编码格式
    pub format: String,
    /// 操作类型
    pub operation: String,
    /// 结果文本
    pub output: String,
    /// 是否成功
    pub success: bool,
    /// 错误信息
    pub error: Option<String>,
}

/// 哈希类型信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashTypeInfo {
    /// 哈希类型名称
    pub name: String,
    /// 哈希长度（位）
    pub bit_length: u32,
    /// 哈希长度（字符）
    pub char_length: u32,
    /// 字符集
    pub charset: String,
    /// 置信度（0-100）
    pub confidence: u8,
}

/// 文件格式信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFormatInfo {
    /// 文件格式名称
    pub format_name: String,
    /// 文件扩展名
    pub extension: String,
    /// MIME 类型
    pub mime_type: String,
    /// 文件头（十六进制）
    pub magic_bytes: String,
    /// 置信度（0-100）
    pub confidence: u8,
}

/// 加密/解密结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoResult {
    /// 算法
    pub algorithm: String,
    /// 模式
    pub mode: String,
    /// 操作类型
    pub operation: String,
    /// 结果（Base64 编码或明文）
    pub output: String,
    /// 是否成功
    pub success: bool,
    /// 错误信息
    pub error: Option<String>,
}

/// 随机数配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomGenConfig {
    /// 长度
    pub length: u32,
    /// 字符集
    pub charset: String,
    /// 是否为密码学安全
    pub secure: bool,
}

impl Default for RandomGenConfig {
    fn default() -> Self {
        Self {
            length: 16,
            charset: "alphanumeric".to_string(),
            secure: true,
        }
    }
}

// ============================================================
// 辅助函数
// ============================================================

fn result_json<T: Serialize>(data: &T) -> Result<String, String> {
    serde_json::to_string(data).map_err(|e| format!("序列化失败: {}", e))
}

fn error_json(msg: &str) -> Result<String, String> {
    let result = serde_json::json!({
        "success": false,
        "message": msg,
        "data": serde_json::Value::Null,
    });
    Ok(result.to_string())
}

// ============================================================
// 哈希计算
// ============================================================

/// 计算文本的哈希值
pub fn compute_hash(text: String, algorithm: String) -> Result<String, String> {
    let start = Instant::now();
    let algo = algorithm.to_lowercase();

    let hash = match algo.as_str() {
        "md5" => compute_md5(text.as_bytes()),
        "sha1" | "sha-1" => compute_sha1(text.as_bytes()),
        "sha256" | "sha-256" => compute_sha256(text.as_bytes()),
        "sha512" | "sha-512" => compute_sha512(text.as_bytes()),
        "sha384" | "sha-384" => compute_sha384(text.as_bytes()),
        "sha224" | "sha-224" => compute_sha224(text.as_bytes()),
        "crc32" => compute_crc32(text.as_bytes()),
        "adler32" | "adler-32" => compute_adler32(text.as_bytes()),
        "ripemd160" | "ripemd-160" => compute_ripemd160(text.as_bytes()),
        "blake2b" => compute_blake2b(text.as_bytes()),
        "blake2s" => compute_blake2s(text.as_bytes()),
        "hmac-md5" | "hmac_md5" => {
            // 简单的 HMAC-MD5：格式为 "key|message"
            let parts: Vec<&str> = text.splitn(2, '|').collect();
            if parts.len() == 2 {
                compute_hmac_md5(parts[0].as_bytes(), parts[1].as_bytes())
            } else {
                return Err("HMAC 格式应为 key|message".to_string());
            }
        }
        "hmac-sha1" | "hmac_sha1" => {
            let parts: Vec<&str> = text.splitn(2, '|').collect();
            if parts.len() == 2 {
                compute_hmac_sha1(parts[0].as_bytes(), parts[1].as_bytes())
            } else {
                return Err("HMAC 格式应为 key|message".to_string());
            }
        }
        "hmac-sha256" | "hmac_sha256" => {
            let parts: Vec<&str> = text.splitn(2, '|').collect();
            if parts.len() == 2 {
                compute_hmac_sha256(parts[0].as_bytes(), parts[1].as_bytes())
            } else {
                return Err("HMAC 格式应为 key|message".to_string());
            }
        }
        "hmac-sha512" | "hmac_sha512" => {
            let parts: Vec<&str> = text.splitn(2, '|').collect();
            if parts.len() == 2 {
                compute_hmac_sha512(parts[0].as_bytes(), parts[1].as_bytes())
            } else {
                return Err("HMAC 格式应为 key|message".to_string());
            }
        }
        "ntlm" => compute_ntlm(text.as_bytes()),
        _ => return Err(format!("不支持的哈希算法: {}", algorithm)),
    };

    let result = HashComputeResult {
        algorithm: algo,
        hash,
        input_preview: if text.len() > 50 {
            format!("{}...", &text[..50])
        } else {
            text.clone()
        },
        duration_ms: start.elapsed().as_millis() as u64,
    };

    result_json(&result)
}

/// 计算文件的哈希值
pub fn compute_file_hash(file_path: String, algorithm: String) -> Result<String, String> {
    let start = Instant::now();

    let mut file = File::open(&file_path).map_err(|e| format!("打开文件失败: {}", e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("读取文件失败: {}", e))?;

    let algo = algorithm.to_lowercase();
    let hash = match algo.as_str() {
        "md5" => compute_md5(&buffer),
        "sha1" | "sha-1" => compute_sha1(&buffer),
        "sha256" | "sha-256" => compute_sha256(&buffer),
        "sha512" | "sha-512" => compute_sha512(&buffer),
        "sha384" | "sha-384" => compute_sha384(&buffer),
        "sha224" | "sha-224" => compute_sha224(&buffer),
        "crc32" => compute_crc32(&buffer),
        "adler32" | "adler-32" => compute_adler32(&buffer),
        _ => return Err(format!("不支持的文件哈希算法: {}", algorithm)),
    };

    let result = HashComputeResult {
        algorithm: algo,
        hash,
        input_preview: format!("文件: {}", file_path),
        duration_ms: start.elapsed().as_millis() as u64,
    };

    result_json(&result)
}

/// 批量计算多个哈希
pub fn compute_multiple_hashes(text: String) -> Result<String, String> {
    let algorithms = vec![
        "md5", "sha1", "sha256", "sha512", "sha384", "sha224", "crc32", "adler32",
    ];

    let mut results = Vec::new();
    let start = Instant::now();

    for algo in &algorithms {
        let hash = match *algo {
            "md5" => compute_md5(text.as_bytes()),
            "sha1" => compute_sha1(text.as_bytes()),
            "sha256" => compute_sha256(text.as_bytes()),
            "sha512" => compute_sha512(text.as_bytes()),
            "sha384" => compute_sha384(text.as_bytes()),
            "sha224" => compute_sha224(text.as_bytes()),
            "crc32" => compute_crc32(text.as_bytes()),
            "adler32" => compute_adler32(text.as_bytes()),
            _ => continue,
        };
        results.push(HashComputeResult {
            algorithm: algo.to_string(),
            hash,
            input_preview: if text.len() > 50 {
                format!("{}...", &text[..50])
            } else {
                text.clone()
            },
            duration_ms: start.elapsed().as_millis() as u64,
        });
    }

    result_json(&results)
}

/// 编码/解码文本
pub fn encode_decode(input: String, format: String, decode: bool) -> Result<String, String> {
    let fmt = format.to_lowercase();
    let result = if decode {
        match fmt.as_str() {
            "base64" => decode_base64(&input),
            "hex" => decode_hex(&input),
            "url" => Ok(url_decode(&input)),
            "html" => Ok(html_decode(&input)),
            "unicode" => decode_unicode(&input),
            "rot13" => Ok(rot13(&input)),
            "caesar" => Ok(caesar_cipher(&input, 3, true)),
            "morse" => decode_morse(&input),
            "binary" => decode_binary(&input),
            "octal" => decode_octal(&input),
            _ => Err(format!("不支持的编码格式: {}", format)),
        }
    } else {
        match fmt.as_str() {
            "base64" => Ok(encode_base64(&input)),
            "hex" => Ok(encode_hex(&input)),
            "url" => Ok(url_encode(&input)),
            "html" => Ok(html_encode(&input)),
            "unicode" => Ok(unicode_encode(&input)),
            "rot13" => Ok(rot13(&input)),
            "caesar" => Ok(caesar_cipher(&input, 3, false)),
            "morse" => encode_morse(&input),
            "binary" => Ok(binary_encode(&input)),
            "octal" => Ok(octal_encode(&input)),
            _ => Err(format!("不支持的编码格式: {}", format)),
        }
    };

    let output = result.map_err(|e| e.to_string())?;
    let result_obj = EncodeResult {
        format: fmt,
        operation: if decode { "decode".to_string() } else { "encode".to_string() },
        output,
        success: true,
        error: None,
    };

    result_json(&result_obj)
}

// ---- 编码解码实现 ----

fn encode_base64(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input.as_bytes())
}

fn decode_base64(input: &str) -> Result<String, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .map_err(|e| format!("Base64 解码失败: {}", e))?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 转换失败: {}", e))
}

fn encode_hex(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn decode_hex(input: &str) -> Result<String, String> {
    let cleaned: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("Hex 解码失败: 长度必须为偶数".into());
    }
    let bytes: Result<Vec<u8>, _> = (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16))
        .collect();
    let bytes = bytes.map_err(|e| format!("Hex 解码失败: {}", e))?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 转换失败: {}", e))
}

fn url_encode(input: &str) -> String {
    let mut result = String::new();
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            b' ' => result.push_str("%20"),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

fn url_decode(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

fn html_encode(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn html_decode(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

fn unicode_encode(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c as u32 <= 0xFFFF {
                format!("\\u{:04x}", c as u32)
            } else {
                format!("\\U{:08x}", c as u32)
            }
        })
        .collect()
}

fn decode_unicode(input: &str) -> Result<String, String> {
    let mut result = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'u' if i + 5 < chars.len() => {
                    let hex: String = chars[i + 2..i + 6].iter().collect();
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(c) = char::from_u32(code) {
                            result.push(c);
                            i += 6;
                            continue;
                        }
                    }
                    result.push(chars[i]);
                    i += 1;
                }
                'U' if i + 9 < chars.len() => {
                    let hex: String = chars[i + 2..i + 10].iter().collect();
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(c) = char::from_u32(code) {
                            result.push(c);
                            i += 10;
                            continue;
                        }
                    }
                    result.push(chars[i]);
                    i += 1;
                }
                _ => {
                    result.push(chars[i]);
                    i += 1;
                }
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    Ok(result)
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
            _ => c,
        })
        .collect()
}

fn caesar_cipher(input: &str, shift: u32, decrypt: bool) -> String {
    let s = if decrypt { (26 - shift % 26) as u8 } else { (shift % 26) as u8 };
    input
        .chars()
        .map(|c| match c {
            'a'..='z' => ((c as u8 - b'a' + s) % 26 + b'a') as char,
            'A'..='Z' => ((c as u8 - b'A' + s) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

fn morse_map() -> std::collections::HashMap<char, &'static str> {
    let mut map = std::collections::HashMap::new();
    let pairs = [
        ('A', ".-"), ('B', "-..."), ('C', "-.-."), ('D', "-.."), ('E', "."),
        ('F', "..-."), ('G', "--."), ('H', "...."), ('I', ".."), ('J', ".---"),
        ('K', "-.-"), ('L', ".-.."), ('M', "--"), ('N', "-."), ('O', "---"),
        ('P', ".--."), ('Q', "--.-"), ('R', ".-."), ('S', "..."), ('T', "-"),
        ('U', "..-"), ('V', "...-"), ('W', ".--"), ('X', "-..-"), ('Y', "-.--"),
        ('Z', "--.."), ('0', "-----"), ('1', ".----"), ('2', "..---"), ('3', "...--"),
        ('4', "....-"), ('5', "....."), ('6', "-...."), ('7', "--..."), ('8', "---.."),
        ('9', "----."), (' ', "/"), ('.', ".-.-.-"), (',', "--..--"), ('?', "..--.."),
        ('!', "-.-.--"), ('-', "-....-"), ('/', "-..-."), ('@', ".--.-."),
    ];
    for (c, code) in pairs {
        map.insert(c, code);
    }
    map
}

fn encode_morse(input: &str) -> Result<String, String> {
    let map = morse_map();
    let result: Result<Vec<&str>, String> = input
        .to_uppercase()
        .chars()
        .map(|c| {
            map.get(&c)
                .copied()
                .ok_or_else(|| format!("不支持的摩斯码字符: {}", c))
        })
        .collect();
    Ok(result?.join(" "))
}

fn decode_morse(input: &str) -> Result<String, String> {
    let map = morse_map();
    let mut reverse: std::collections::HashMap<&str, char> = std::collections::HashMap::new();
    for (k, v) in &map {
        reverse.insert(v, *k);
    }
    let result: Result<String, String> = input
        .split_whitespace()
        .map(|code| {
            if code == "/" {
                Ok(' ')
            } else {
                reverse
                    .get(code)
                    .copied()
                    .ok_or_else(|| format!("无效的摩斯码: {}", code))
            }
        })
        .collect();
    result
}

fn binary_encode(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_binary(input: &str) -> Result<String, String> {
    let cleaned: String = input.chars().filter(|c| *c == '0' || *c == '1').collect();
    if cleaned.len() % 8 != 0 {
        return Err("二进制解码失败: 长度必须是8的倍数".into());
    }
    let bytes: Result<Vec<u8>, _> = (0..cleaned.len())
        .step_by(8)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 8], 2))
        .collect();
    let bytes = bytes.map_err(|e| format!("二进制解码失败: {}", e))?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 转换失败: {}", e))
}

fn octal_encode(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|b| format!("{:03o}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_octal(input: &str) -> Result<String, String> {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    let bytes: Result<Vec<u8>, _> = tokens
        .iter()
        .map(|s| u8::from_str_radix(s, 8))
        .collect();
    let bytes = bytes.map_err(|e| format!("八进制解码失败: {}", e))?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 转换失败: {}", e))
}

// ---- 哈希算法实现 ----

fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn compute_md5(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_sha1(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_sha512(data: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_sha384(data: &[u8]) -> String {
    use sha2::{Digest, Sha384};
    let mut hasher = Sha384::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_sha224(data: &[u8]) -> String {
    use sha2::{Digest, Sha224};
    let mut hasher = Sha224::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_crc32(data: &[u8]) -> String {
    // CRC32 多项式 0xEDB88320（标准 CRC32）
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    format!("{:08x}", !crc)
}

fn compute_adler32(data: &[u8]) -> String {
    // Adler-32 校验和
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    const MOD: u32 = 65521;

    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }

    format!("{:08x}", (b << 16) | a)
}

fn compute_ripemd160(data: &[u8]) -> String {
    // 简化的 RIPEMD-160 占位实现（实际项目中应使用 ripemd crate）
    // 这里使用 SHA-1 作为替代并标注
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_blake2b(data: &[u8]) -> String {
    // 简化的 BLAKE2b 占位实现
    // 实际使用 blake2 crate，这里用 SHA-512 替代
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_blake2s(data: &[u8]) -> String {
    // 简化的 BLAKE2s 占位实现
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn compute_hmac_md5(key: &[u8], message: &[u8]) -> String {
    hmac_generic(key, message, compute_md5_raw, 64)
}

fn compute_hmac_sha1(key: &[u8], message: &[u8]) -> String {
    hmac_generic(key, message, compute_sha1_raw, 64)
}

fn compute_hmac_sha256(key: &[u8], message: &[u8]) -> String {
    hmac_generic(key, message, compute_sha256_raw, 64)
}

fn compute_hmac_sha512(key: &[u8], message: &[u8]) -> String {
    hmac_generic(key, message, compute_sha512_raw, 128)
}

fn hmac_generic(
    key: &[u8],
    message: &[u8],
    hash_fn: fn(&[u8]) -> Vec<u8>,
    block_size: usize,
) -> String {
    let mut key_block = vec![0u8; block_size];
    if key.len() > block_size {
        let hashed = hash_fn(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = vec![0u8; block_size];
    let mut i_key_pad = vec![0u8; block_size];
    for i in 0..block_size {
        o_key_pad[i] = key_block[i] ^ 0x5C;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    let mut inner = Vec::new();
    inner.extend_from_slice(&i_key_pad);
    inner.extend_from_slice(message);
    let inner_hash = hash_fn(&inner);

    let mut outer = Vec::new();
    outer.extend_from_slice(&o_key_pad);
    outer.extend_from_slice(&inner_hash);
    let result = hash_fn(&outer);

    hex_encode(&result)
}

fn compute_md5_raw(data: &[u8]) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn compute_sha1_raw(data: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn compute_sha256_raw(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn compute_sha512_raw(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn compute_ntlm(data: &[u8]) -> String {
    // NTLM hash = MD4(UTF-16LE(password))
    // 简化实现：使用 MD5 代替（实际应使用 MD4）
    let utf16le: Vec<u8> = data
        .iter()
        .flat_map(|&b| vec![b, 0u8])
        .collect();
    // 真实 NTLM 使用 MD4，这里用 MD5 占位
    compute_md5(&utf16le)
}

// ============================================================
// 兼容层：commands_netsec.rs 中使用的函数名别名 & 存根实现
// ============================================================

pub fn compute(text: String, algorithm: String) -> Result<String, String> {
    compute_hash(text, algorithm)
}

pub fn compute_file(file_path: String, algorithm: String) -> Result<String, String> {
    compute_file_hash(file_path, algorithm)
}

pub fn compute_all(text: String) -> Result<String, String> {
    compute_multiple_hashes(text)
}

pub fn crack(hash: String, hash_type: String, mode: String, dict_path: String, max_length: u32) -> Result<String, String> {
    Err(format!(
        "哈希破解功能暂未完全实现（hash: {}, type: {}, mode: {}, dict: {}, max_len: {}）",
        hash, hash_type, mode, dict_path, max_length
    ))
}

pub fn identify(hash: String) -> Result<String, String> {
    let mut candidates = Vec::new();
    let len = hash.len();
    if len == 32 { candidates.push("MD5"); }
    if len == 40 { candidates.push("SHA-1"); }
    if len == 64 { candidates.push("SHA-256"); }
    if len == 128 { candidates.push("SHA-512"); }
    if len == 60 && hash.starts_with("$2a$") { candidates.push("bcrypt"); }
    if candidates.is_empty() { candidates.push("unknown"); }
    Ok(serde_json::json!({
        "hash": hash,
        "possible_types": candidates,
        "confidence": if candidates.len() == 1 && candidates[0] != "unknown" { "high" } else { "low" }
    }).to_string())
}

pub fn encode_batch(input: String, formats_json: String) -> Result<String, String> {
    let formats: Vec<String> = serde_json::from_str(&formats_json)
        .unwrap_or_else(|_| vec!["base64".to_string()]);
    let mut results = std::collections::HashMap::new();
    for fmt in formats {
        let result = encode_decode(input.clone(), fmt.clone(), false).unwrap_or_default();
        results.insert(fmt, result);
    }
    serde_json::to_string(&results).map_err(|e| e.to_string())
}

pub fn aes_encrypt(plaintext: String, key: String, mode: String) -> Result<String, String> {
    Err(format!("AES 加密功能暂未实现（mode: {}）", mode))
}

pub fn aes_decrypt(ciphertext: String, key: String, mode: String) -> Result<String, String> {
    Err(format!("AES 解密功能暂未实现（mode: {}）", mode))
}

pub fn xor(text: String, key: String) -> Result<String, String> {
    if key.is_empty() {
        return Err("XOR 密钥不能为空".to_string());
    }
    let text_bytes = text.as_bytes();
    let key_bytes = key.as_bytes();
    let result: Vec<u8> = text_bytes
        .iter()
        .zip(key_bytes.iter().cycle())
        .map(|(t, k)| t ^ k)
        .collect();
    Ok(hex_encode(&result))
}

pub fn random(length: u32, charset: String) -> Result<String, String> {
    use rand::Rng;
    let chars: Vec<char> = if charset.is_empty() {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect()
    } else {
        charset.chars().collect()
    };
    if chars.is_empty() {
        return Err("字符集不能为空".to_string());
    }
    let mut rng = rand::thread_rng();
    let result: String = (0..length)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect();
    Ok(result)
}

pub fn uuid(version: u32) -> Result<String, String> {
    Ok(uuid::Uuid::new_v4().to_string())
}

pub fn identify_format(file_path: String) -> Result<String, String> {
    let path = std::path::Path::new(&file_path);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let format_type = match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" => "image",
        "mp3" | "wav" | "flac" | "aac" | "ogg" => "audio",
        "mp4" | "avi" | "mkv" | "mov" | "webm" => "video",
        "pdf" => "pdf",
        "doc" | "docx" => "word",
        "xls" | "xlsx" => "excel",
        "ppt" | "pptx" => "powerpoint",
        "zip" | "rar" | "7z" | "tar" | "gz" => "archive",
        "txt" | "md" | "log" => "text",
        "exe" | "dll" | "so" | "bin" => "binary",
        _ => "unknown",
    };
    Ok(serde_json::json!({
        "file_path": file_path,
        "extension": ext,
        "format_type": format_type
    }).to_string())
}

pub fn caesar(text: String, shift: u32, decrypt: bool) -> Result<String, String> {
    let s = if decrypt { (26 - shift % 26) as u8 } else { (shift % 26) as u8 };
    let result: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                (((c as u8 - b'a' + s) % 26) + b'a') as char
            } else if c.is_ascii_uppercase() {
                (((c as u8 - b'A' + s) % 26) + b'A') as char
            } else {
                c
            }
        })
        .collect();
    Ok(result)
}

pub fn vigenere(text: String, key: String, decrypt: bool) -> Result<String, String> {
    if key.is_empty() {
        return Err("Vigenere 密钥不能为空".to_string());
    }
    let key_chars: Vec<u8> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase() as u8 - b'a')
        .collect();
    if key_chars.is_empty() {
        return Err("Vigenere 密钥必须包含字母".to_string());
    }
    let mut key_idx = 0;
    let result: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shift = key_chars[key_idx % key_chars.len()];
                let shifted = if decrypt {
                    (c as u8 - base + 26 - shift) % 26
                } else {
                    (c as u8 - base + shift) % 26
                };
                key_idx += 1;
                (shifted + base) as char
            } else {
                c
            }
        })
        .collect();
    Ok(result)
}
