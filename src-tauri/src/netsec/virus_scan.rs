// yxpil · NETON
//! 病毒库搜索与特征匹配工具
//! 文件哈希查询、简单特征码匹配

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha1, Md5};
use std::collections::HashMap;

/// 扫描类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    /// 仅哈希比对
    HashOnly,
    /// 特征码匹配
    Signature,
    /// 启发式扫描
    Heuristic,
    /// 全面扫描
    Full,
}

/// 扫描配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusScanConfig {
    /// 文件路径
    pub file_path: String,
    /// 扫描类型
    pub scan_type: ScanType,
    /// 是否计算多种哈希
    pub multi_hash: bool,
    /// 最大文件大小（MB）
    pub max_file_size_mb: u64,
}

impl Default for VirusScanConfig {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            scan_type: ScanType::HashOnly,
            multi_hash: true,
            max_file_size_mb: 100,
        }
    }
}

/// 文件哈希信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: String,
    pub file_size: u64,
    pub file_name: String,
}

/// 病毒检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusDetection {
    pub threat_name: String,
    pub threat_type: String,
    pub severity: String,
    pub detection_method: String,
    pub confidence: f32,
    pub location: Option<String>,
}

/// 病毒扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusScanResult {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub is_infected: bool,
    pub detections: Vec<VirusDetection>,
    pub hashes: FileHashes,
    pub scan_type: String,
    pub duration_ms: u64,
    pub virus_db_version: String,
}

/// 恶意软件特征码（概念性）
struct MalwareSignature {
    name: String,
    threat_type: String,
    severity: String,
    signature: Vec<u8>,
    offset: Option<usize>,
}

/// 获取内置病毒特征库（概念性示例）
fn get_malware_signatures() -> Vec<MalwareSignature> {
    vec![
        MalwareSignature {
            name: "EICAR-Test-File".to_string(),
            threat_type: "Test".to_string(),
            severity: "Low".to_string(),
            signature: b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
            offset: None,
        },
        MalwareSignature {
            name: "Trojan.Generic".to_string(),
            threat_type: "Trojan".to_string(),
            severity: "High".to_string(),
            signature: vec![0x4D, 0x5A, 0x90, 0x00, 0x03], // PE 文件头特征（示例）
            offset: Some(0),
        },
    ]
}

/// 已知恶意文件哈希库（概念性）
fn get_malware_hash_db() -> HashMap<String, (String, String, String)> {
    let mut db = HashMap::new();

    // EICAR 测试文件 SHA256
    db.insert(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        (
            "EICAR-Test-File".to_string(),
            "Test".to_string(),
            "Low".to_string(),
        ),
    );

    // 一些示例恶意软件哈希
    db.insert(
        "ce298d793f274a92329d93d0717ecb6c2f893a8b".to_string(),
        (
            "WannaCry.Ransomware".to_string(),
            "Ransomware".to_string(),
            "Critical".to_string(),
        ),
    );

    db.insert(
        "fd0488ec106e65489ad0f5d58a5e8a4b63e82e3b".to_string(),
        (
            "Mirai.Botnet".to_string(),
            "Botnet".to_string(),
            "High".to_string(),
        ),
    );

    db
}

/// 计算文件哈希
pub fn compute_file_hashes(file_path: &str, multi_hash: bool) -> Result<FileHashes, String> {
    use std::fs::File;
    use std::io::Read;

    let path = std::path::Path::new(file_path);
    if !path.exists() {
        return Err(format!("文件不存在: {}", file_path));
    }

    let metadata = std::fs::metadata(file_path).map_err(|e| e.to_string())?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    let mut file = File::open(file_path).map_err(|e| e.to_string())?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| e.to_string())?;

    // 计算 SHA256
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(&buffer);
    let sha256 = format!("{:x}", sha256_hasher.finalize());

    let md5 = if multi_hash {
        let mut md5_hasher = Md5::new();
        md5_hasher.update(&buffer);
        Some(format!("{:x}", md5_hasher.finalize()))
    } else {
        None
    };

    let sha1 = if multi_hash {
        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&buffer);
        Some(format!("{:x}", sha1_hasher.finalize()))
    } else {
        None
    };

    Ok(FileHashes {
        md5,
        sha1,
        sha256,
        file_size: metadata.len(),
        file_name,
    })
}

/// 哈希比对检测
fn scan_by_hash(hashes: &FileHashes) -> Vec<VirusDetection> {
    let db = get_malware_hash_db();
    let mut detections = Vec::new();

    if let Some((name, threat_type, severity)) = db.get(&hashes.sha256) {
        detections.push(VirusDetection {
            threat_name: name.clone(),
            threat_type: threat_type.clone(),
            severity: severity.clone(),
            detection_method: "SHA256 哈希匹配".to_string(),
            confidence: 1.0,
            location: None,
        });
    }

    detections
}

/// 特征码匹配检测
fn scan_by_signature(file_path: &str) -> Vec<VirusDetection> {
    let mut detections = Vec::new();

    // 读取文件
    let content = match std::fs::read(file_path) {
        Ok(c) => c,
        Err(_) => return detections,
    };

    let signatures = get_malware_signatures();

    for sig in signatures {
        let found = if let Some(offset) = sig.offset {
            // 检查指定偏移位置
            if offset + sig.signature.len() <= content.len() {
                &content[offset..offset + sig.signature.len()] == sig.signature.as_slice()
            } else {
                false
            }
        } else {
            // 在整个文件中搜索
            content
                .windows(sig.signature.len())
                .any(|window| window == sig.signature.as_slice())
        };

        if found {
            detections.push(VirusDetection {
                threat_name: sig.name,
                threat_type: sig.threat_type,
                severity: sig.severity,
                detection_method: "特征码匹配".to_string(),
                confidence: 0.95,
                location: None,
            });
        }
    }

    detections
}

/// 启发式扫描（概念性）
fn scan_heuristic(file_path: &str) -> Vec<VirusDetection> {
    let mut detections = Vec::new();

    let path = std::path::Path::new(file_path);
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // 检查可疑扩展名
    let suspicious_exts = ["exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "wsf"];
    if suspicious_exts.contains(&extension.as_str()) {
        // 读取文件头部进行简单检查
        if let Ok(content) = std::fs::read(file_path) {
            // 检查 PE 文件头
            if content.len() >= 2 && content[0] == 0x4D && content[1] == 0x5A {
                // 这是一个 PE 文件，检查是否有可疑特征
                // 概念性：检查是否有 UPX 加壳迹象
                if content.windows(3).any(|w| w == b"UPX") {
                    detections.push(VirusDetection {
                        threat_name: "Suspicious.Packed".to_string(),
                        threat_type: "Suspicious".to_string(),
                        severity: "Medium".to_string(),
                        detection_method: "启发式（加壳检测）".to_string(),
                        confidence: 0.5,
                        location: None,
                    });
                }
            }
        }
    }

    detections
}

/// 执行病毒扫描
pub fn scan_file(config: VirusScanConfig) -> Result<String, String> {
    let start_time = std::time::Instant::now();

    if config.file_path.is_empty() {
        return Err("文件路径不能为空".to_string());
    }

    let path = std::path::Path::new(&config.file_path);
    if !path.exists() {
        return Err(format!("文件不存在: {}", config.file_path));
    }

    let metadata = std::fs::metadata(&config.file_path).map_err(|e| e.to_string())?;

    // 检查文件大小
    let max_size = config.max_file_size_mb * 1024 * 1024;
    if metadata.len() > max_size {
        return Err(format!(
            "文件过大（{} bytes），超过限制（{} MB）",
            metadata.len(),
            config.max_file_size_mb
        ));
    }

    // 计算哈希
    let hashes = compute_file_hashes(&config.file_path, config.multi_hash)?;

    let mut all_detections = Vec::new();

    // 哈希比对
    if matches!(config.scan_type, ScanType::HashOnly | ScanType::Full) {
        all_detections.extend(scan_by_hash(&hashes));
    }

    // 特征码匹配
    if matches!(config.scan_type, ScanType::Signature | ScanType::Full) {
        all_detections.extend(scan_by_signature(&config.file_path));
    }

    // 启发式扫描
    if matches!(config.scan_type, ScanType::Heuristic | ScanType::Full) {
        all_detections.extend(scan_heuristic(&config.file_path));
    }

    let is_infected = !all_detections.is_empty();
    let scan_type_str = match config.scan_type {
        ScanType::HashOnly => "哈希比对",
        ScanType::Signature => "特征码匹配",
        ScanType::Heuristic => "启发式扫描",
        ScanType::Full => "全面扫描",
    }
    .to_string();

    let result = VirusScanResult {
        file_path: config.file_path.clone(),
        file_name: hashes.file_name.clone(),
        file_size: hashes.file_size,
        is_infected,
        detections: all_detections,
        hashes,
        scan_type: scan_type_str,
        duration_ms: start_time.elapsed().as_millis() as u64,
        virus_db_version: "local-v1.0 (概念性)".to_string(),
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "病毒扫描完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 批量扫描目录
pub fn scan_directory(dir_path: String, recursive: bool) -> Result<String, String> {
    let start_time = std::time::Instant::now();

    let path = std::path::Path::new(&dir_path);
    if !path.exists() || !path.is_dir() {
        return Err(format!("目录不存在或不是目录: {}", dir_path));
    }

    let mut results = Vec::new();
    let mut total_files = 0u32;
    let mut infected_files = 0u32;

    fn scan_dir_recursive(
        dir: &std::path::Path,
        recursive: bool,
        results: &mut Vec<serde_json::Value>,
        total_files: &mut u32,
        infected_files: &mut u32,
    ) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    *total_files += 1;
                    let config = VirusScanConfig {
                        file_path: path.to_string_lossy().to_string(),
                        scan_type: ScanType::HashOnly,
                        multi_hash: false,
                        max_file_size_mb: 50,
                    };
                    if let Ok(result_str) = scan_file(config) {
                        if let Ok(tool_result) =
                            serde_json::from_str::<crate::netsec::ToolResult<serde_json::Value>>(
                                &result_str,
                            )
                        {
                            if let Some(data) = tool_result.data {
                                if data.get("is_infected").and_then(|v| v.as_bool()).unwrap_or(false)
                                {
                                    *infected_files += 1;
                                }
                                results.push(data);
                            }
                        }
                    }
                } else if path.is_dir() && recursive {
                    scan_dir_recursive(&path, recursive, results, total_files, infected_files);
                }
            }
        }
    }

    scan_dir_recursive(
        path,
        recursive,
        &mut results,
        &mut total_files,
        &mut infected_files,
    );

    let summary = serde_json::json!({
        "directory": dir_path,
        "recursive": recursive,
        "total_files": total_files,
        "infected_files": infected_files,
        "clean_files": total_files - infected_files,
        "results": results,
        "duration_ms": start_time.elapsed().as_millis() as u64,
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(summary, "目录扫描完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 在线哈希查询（概念性，使用 VirusTotal 等 API 的框架）
pub async fn online_hash_check(hash: String) -> Result<String, String> {
    // 概念性实现
    // 实际应用中可以集成 VirusTotal、Hybrid Analysis 等 API

    let db = get_malware_hash_db();
    let hash_lower = hash.to_lowercase();

    let result = if let Some((name, threat_type, severity)) = db.get(&hash_lower) {
        serde_json::json!({
            "hash": hash,
            "found": true,
            "threat_name": name,
            "threat_type": threat_type,
            "severity": severity,
            "source": "本地病毒库",
            "detection_rate": 1.0,
        })
    } else {
        serde_json::json!({
            "hash": hash,
            "found": false,
            "threat_name": null,
            "threat_type": null,
            "severity": "Unknown",
            "source": "本地病毒库",
            "detection_rate": 0.0,
            "note": "本地库未找到，建议使用在线服务如 VirusTotal 进一步查询",
        })
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "哈希查询完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}
