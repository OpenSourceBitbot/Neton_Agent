// yxpil · NETON
//! 设备接入接口请求模块
//! 类似 Postman 但聚焦于设备接入场景（IoT 设备、网络设备、摄像头、路由器等的 API 接口测试）
//!
//! 功能：
//! - HTTP 请求引擎（GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS）
//! - Modbus TCP 工业设备协议
//! - MQTT IoT 消息协议
//! - SNMP 网络设备管理
//! - SSH / Telnet 命令执行
//! - RTSP 流媒体地址探测
//! - 请求历史记录
//! - 设备接口模板库
//! - 简易压力测试

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ============================================================
// 1. HTTP 请求引擎
// ============================================================

/// HTTP 方法
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    fn to_reqwest_method(&self) -> reqwest::Method {
        match self {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        }
    }
}

/// Body 类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BodyType {
    None,
    FormData,
    XWwwFormUrlencoded,
    Raw,
    Binary,
}

/// Raw Body 子类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawBodyFormat {
    Json,
    Xml,
    Text,
    Html,
    Javascript,
}

/// HTTP 请求配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceApiRequest {
    /// 请求方法
    pub method: HttpMethod,
    /// 请求 URL
    pub url: String,
    /// 请求头（键值对列表）
    pub headers: Vec<(String, String)>,
    /// 查询参数
    pub params: Vec<(String, String)>,
    /// Body 类型
    pub body_type: BodyType,
    /// Raw Body 内容
    pub raw_body: Option<String>,
    /// Raw Body 格式
    pub raw_format: Option<RawBodyFormat>,
    /// Form Data
    pub form_data: Option<Vec<(String, String)>>,
    /// x-www-form-urlencoded
    pub form_urlencoded: Option<Vec<(String, String)>>,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
    /// 代理地址（可选）
    pub proxy: Option<String>,
}

impl Default for DeviceApiRequest {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            url: "http://localhost:80".to_string(),
            headers: vec![],
            params: vec![],
            body_type: BodyType::None,
            raw_body: None,
            raw_format: Some(RawBodyFormat::Json),
            form_data: None,
            form_urlencoded: None,
            timeout_ms: 10000,
            proxy: None,
        }
    }
}

/// HTTP 响应结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceApiResponse {
    /// 状态码
    pub status_code: u16,
    /// 状态文本
    pub status_text: String,
    /// 响应头
    pub headers: Vec<(String, String)>,
    /// 响应体
    pub body: String,
    /// 响应时间（毫秒）
    pub response_time_ms: u64,
    /// 响应大小（字节）
    pub response_size_bytes: usize,
    /// Cookie 列表
    pub cookies: Vec<(String, String)>,
    /// 是否成功
    pub success: bool,
    /// 错误信息
    pub error: Option<String>,
}

// ============================================================
// 2. Modbus TCP
// ============================================================

/// Modbus 功能码
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModbusFunction {
    /// 读保持寄存器 (0x03)
    ReadHoldingRegisters,
    /// 读输入寄存器 (0x04)
    ReadInputRegisters,
    /// 读线圈 (0x01)
    ReadCoils,
    /// 读离散输入 (0x02)
    ReadDiscreteInputs,
    /// 写单个寄存器 (0x06)
    WriteSingleRegister,
    /// 写单个线圈 (0x05)
    WriteSingleCoil,
}

impl ModbusFunction {
    fn code(&self) -> u8 {
        match self {
            ModbusFunction::ReadHoldingRegisters => 0x03,
            ModbusFunction::ReadInputRegisters => 0x04,
            ModbusFunction::ReadCoils => 0x01,
            ModbusFunction::ReadDiscreteInputs => 0x02,
            ModbusFunction::WriteSingleRegister => 0x06,
            ModbusFunction::WriteSingleCoil => 0x05,
        }
    }
}

/// Modbus 请求配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusRequest {
    /// 主机地址
    pub host: String,
    /// 端口（默认 502）
    pub port: u16,
    /// 从站 ID
    pub slave_id: u8,
    /// 功能码
    pub function: ModbusFunction,
    /// 起始地址
    pub address: u16,
    /// 数量（读操作）
    pub count: u16,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
}

impl Default for ModbusRequest {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 502,
            slave_id: 1,
            function: ModbusFunction::ReadHoldingRegisters,
            address: 0,
            count: 10,
            timeout_ms: 5000,
        }
    }
}

/// Modbus 读取结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusResult {
    /// 寄存器值列表
    pub registers: Vec<u16>,
    /// 线圈状态列表
    pub coils: Vec<bool>,
    /// 响应时间（毫秒）
    pub response_time_ms: u64,
    /// 事务 ID
    pub transaction_id: u16,
    /// 是否成功
    pub success: bool,
    /// 错误信息
    pub error: Option<String>,
}

// ============================================================
// 3. MQTT
// ============================================================

/// MQTT 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttConfig {
    /// Broker 地址
    pub broker: String,
    /// 端口（默认 1883）
    pub port: u16,
    /// 客户端 ID
    pub client_id: String,
    /// 用户名（可选）
    pub username: Option<String>,
    /// 密码（可选）
    pub password: Option<String>,
    /// 保持连接时间（秒）
    pub keep_alive: u16,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            broker: "127.0.0.1".to_string(),
            port: 1883,
            client_id: format!("neton_{}", uuid::Uuid::new_v4().simple()),
            username: None,
            password: None,
            keep_alive: 60,
            timeout_ms: 5000,
        }
    }
}

/// MQTT 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttMessage {
    /// 主题
    pub topic: String,
    /// 负载
    pub payload: String,
    /// QoS 等级 (0, 1, 2)
    pub qos: u8,
    /// 是否保留消息
    pub retain: bool,
}

/// MQTT 订阅结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttSubscribeResult {
    /// 收到的消息列表
    pub messages: Vec<MqttMessage>,
    /// 订阅主题
    pub topic: String,
    /// 等待时间（毫秒）
    pub wait_time_ms: u64,
    /// 是否成功
    pub success: bool,
    /// 错误信息
    pub error: Option<String>,
}

// ============================================================
// 4. SNMP
// ============================================================

/// SNMP 版本
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
}

impl SnmpVersion {
    fn version_byte(&self) -> u8 {
        match self {
            SnmpVersion::V1 => 0,
            SnmpVersion::V2c => 1,
            SnmpVersion::V3 => 3,
        }
    }
}

/// SNMP 请求配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpRequest {
    /// 主机地址
    pub host: String,
    /// 端口（默认 161）
    pub port: u16,
    /// Community 字符串
    pub community: String,
    /// OID
    pub oid: String,
    /// SNMP 版本
    pub version: SnmpVersion,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
    /// Walk 最大数量
    pub walk_max: u32,
}

impl Default for SnmpRequest {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 161,
            community: "public".to_string(),
            oid: "1.3.6.1.2.1.1.1.0".to_string(),
            version: SnmpVersion::V2c,
            timeout_ms: 3000,
            walk_max: 100,
        }
    }
}

/// SNMP 变量绑定
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpVarBind {
    pub oid: String,
    pub value: String,
    pub value_type: String,
}

/// SNMP 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpResult {
    /// 变量绑定列表
    pub var_binds: Vec<SnmpVarBind>,
    /// 响应时间（毫秒）
    pub response_time_ms: u64,
    /// 是否成功
    pub success: bool,
    /// 错误信息
    pub error: Option<String>,
}

// ============================================================
// 5. SSH / Telnet
// ============================================================

/// SSH 命令执行配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCommandConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub command: String,
    pub timeout_ms: u64,
}

impl Default for SshCommandConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 22,
            username: "admin".to_string(),
            password: "".to_string(),
            command: "show version".to_string(),
            timeout_ms: 10000,
        }
    }
}

/// Telnet 命令执行配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnetConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub command: String,
    pub timeout_ms: u64,
    pub prompt: Option<String>,
}

impl Default for TelnetConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 23,
            username: None,
            password: None,
            command: "show version".to_string(),
            timeout_ms: 10000,
            prompt: Some(">".to_string()),
        }
    }
}

/// 命令执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub output: String,
    pub exit_code: Option<i32>,
    pub response_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
}

// ============================================================
// 6. RTSP
// ============================================================

/// RTSP 探测配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtspProbeConfig {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout_ms: u64,
}

impl Default for RtspProbeConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 554,
            path: "/Streaming/Channels/101".to_string(),
            username: None,
            password: None,
            timeout_ms: 5000,
        }
    }
}

/// RTSP 探测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtspResult {
    pub rtsp_url: String,
    pub status_code: Option<u16>,
    pub status_text: String,
    pub sdp: Option<String>,
    pub response_time_ms: u64,
    pub accessible: bool,
    pub error: Option<String>,
}

// ============================================================
// 7. 请求历史
// ============================================================

/// 历史请求记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHistoryItem {
    /// 唯一 ID
    pub id: String,
    /// 请求类型：http, modbus, mqtt, snmp, ssh, telnet, rtsp
    pub request_type: String,
    /// 请求方法/功能描述
    pub method: String,
    /// URL/地址
    pub target: String,
    /// 请求时间戳
    pub timestamp: i64,
    /// 状态码/结果状态
    pub status: String,
    /// 响应时间（毫秒）
    pub response_time_ms: u64,
    /// 请求摘要（JSON 字符串）
    pub request_snapshot: String,
}

/// 历史记录管理
static REQUEST_HISTORY: Mutex<Vec<RequestHistoryItem>> = Mutex::new(Vec::new());
const MAX_HISTORY_SIZE: usize = 200;

/// 历史过滤条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFilter {
    pub request_type: Option<String>,
    pub method: Option<String>,
    pub keyword: Option<String>,
    pub limit: Option<usize>,
}

// ============================================================
// 8. 设备接口模板
// ============================================================

/// 设备类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCategory {
    /// 摄像头
    Camera,
    /// 路由器
    Router,
    /// 工业 PLC
    Plc,
    /// 智能设备
    SmartDevice,
    /// 网络交换机
    Switch,
    /// 防火墙
    Firewall,
    /// 其他
    Other,
}

/// 模板请求项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRequestItem {
    pub name: String,
    pub description: String,
    pub request_type: String,
    pub request: DeviceApiRequest,
}

/// 设备接口模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTemplate {
    /// 模板 ID
    pub id: String,
    /// 设备类型
    pub category: DeviceCategory,
    /// 厂商名称
    pub vendor: String,
    /// 设备型号/系列
    pub model: String,
    /// 模板名称
    pub name: String,
    /// 模板描述
    pub description: String,
    /// 默认主机地址（示例）
    pub default_host: String,
    /// 请求列表
    pub requests: Vec<TemplateRequestItem>,
}

// ============================================================
// 9. 压力测试
// ============================================================

/// 压力测试配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestConfig {
    /// 请求配置
    pub request: DeviceApiRequest,
    /// 并发数
    pub concurrency: usize,
    /// 持续时间（秒）
    pub duration_seconds: u64,
    /// 总请求数（与持续时间二选一，0 表示不限）
    pub total_requests: u64,
    /// 请求间隔（毫秒），0 表示无间隔
    pub interval_ms: u64,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            request: DeviceApiRequest::default(),
            concurrency: 10,
            duration_seconds: 30,
            total_requests: 0,
            interval_ms: 0,
        }
    }
}

/// 压力测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestResult {
    /// 总请求数
    pub total_requests: u64,
    /// 成功请求数
    pub success_count: u64,
    /// 失败请求数
    pub fail_count: u64,
    /// 成功率（百分比）
    pub success_rate: f64,
    /// 平均响应时间（毫秒）
    pub avg_response_time_ms: f64,
    /// 最小响应时间（毫秒）
    pub min_response_time_ms: u64,
    /// 最大响应时间（毫秒）
    pub max_response_time_ms: u64,
    /// QPS
    pub qps: f64,
    /// 总耗时（秒）
    pub total_duration_seconds: f64,
    /// 响应时间分布（百分比 -> 毫秒）
    pub response_time_distribution: HashMap<String, u64>,
    /// 错误统计
    pub error_counts: HashMap<String, u64>,
    /// 并发数
    pub concurrency: usize,
}

// ============================================================
// 10. 综合结果封装
// ============================================================

/// 综合结果封装
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceApiResult<T: Serialize> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
    pub timestamp: i64,
}

impl<T: Serialize> DeviceApiResult<T> {
    pub fn ok(data: T, message: &str) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            data: Some(data),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            message: message.to_string(),
            data: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}

fn to_json_result<T: Serialize>(result: &DeviceApiResult<T>) -> Result<String, String> {
    serde_json::to_string(result).map_err(|e| format!("序列化失败: {}", e))
}

// ============================================================
// 公共函数 - HTTP 请求
// ============================================================

/// 发送 HTTP 请求
pub fn send_http_request(request: DeviceApiRequest) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<DeviceApiResponse, String> {
        let client_builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(request.timeout_ms))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10));

        let client_builder = if let Some(proxy_url) = &request.proxy {
            if proxy_url.is_empty() {
                client_builder
            } else {
                match reqwest::Proxy::all(proxy_url) {
                    Ok(p) => client_builder.proxy(p),
                    Err(e) => return Err(format!("代理配置失败: {}", e)),
                }
            }
        } else {
            client_builder
        };

        let client = client_builder
            .build()
            .map_err(|e| format!("创建客户端失败: {}", e))?;

        // 构建 URL + 查询参数
        let mut url =
            reqwest::Url::parse(&request.url).map_err(|e| format!("URL 解析失败: {}", e))?;

        if !request.params.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in &request.params {
                pairs.append_pair(k, v);
            }
        }

        let mut req = client.request(request.method.to_reqwest_method(), url);

        // 添加 Headers
        for (k, v) in &request.headers {
            if !k.is_empty() {
                req = req.header(k, v);
            }
        }

        // 添加 Body
        match request.body_type {
            BodyType::Raw => {
                if let Some(body) = &request.raw_body {
                    let content_type =
                        match request.raw_format.as_ref().unwrap_or(&RawBodyFormat::Json) {
                            RawBodyFormat::Json => "application/json",
                            RawBodyFormat::Xml => "application/xml",
                            RawBodyFormat::Text => "text/plain",
                            RawBodyFormat::Html => "text/html",
                            RawBodyFormat::Javascript => "application/javascript",
                        };
                    req = req.header("Content-Type", content_type);
                    req = req.body(body.clone());
                }
            }
            BodyType::XWwwFormUrlencoded => {
                if let Some(form) = &request.form_urlencoded {
                    let form_vec: Vec<(String, String)> = form.clone();
                    req = req.form(&form_vec);
                }
            }
            BodyType::FormData => {
                if let Some(form) = &request.form_data {
                    let mut multipart = reqwest::blocking::multipart::Form::new();
                    for (k, v) in form {
                        multipart = multipart.text(k.clone(), v.clone());
                    }
                    req = req.multipart(multipart);
                }
            }
            BodyType::Binary | BodyType::None => {}
        }

        let resp = req.send().map_err(|e| format!("请求失败: {}", e))?;

        let status_code = resp.status().as_u16();
        let status_text = resp.status().canonical_reason().unwrap_or("").to_string();

        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let cookies: Vec<(String, String)> = resp
            .cookies()
            .map(|c| (c.name().to_string(), c.value().to_string()))
            .collect();

        let body_bytes = resp.bytes().map_err(|e| format!("读取响应体失败: {}", e))?;
        let response_size = body_bytes.len();

        let body = String::from_utf8_lossy(&body_bytes).to_string();

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(DeviceApiResponse {
            status_code,
            status_text,
            headers,
            body,
            response_time_ms: elapsed,
            response_size_bytes: response_size,
            cookies,
            success: status_code >= 200 && status_code < 400,
            error: None,
        })
    })();

    let api_result = match result {
        Ok(resp) => {
            // 记录到历史
            add_to_history(RequestHistoryItem {
                id: uuid::Uuid::new_v4().to_string(),
                request_type: "http".to_string(),
                method: format!("{:?}", request.method),
                target: request.url.clone(),
                timestamp: chrono::Utc::now().timestamp(),
                status: resp.status_code.to_string(),
                response_time_ms: resp.response_time_ms,
                request_snapshot: serde_json::to_string(&request).unwrap_or_default(),
            });

            DeviceApiResult::ok(resp, "请求成功")
        }
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

// ============================================================
// 公共函数 - Modbus TCP
// ============================================================

/// Modbus TCP 读操作
pub fn modbus_read(config: ModbusRequest) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<ModbusResult, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let addr = format!("{}:{}", config.host, config.port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .to_socket_addrs_first()
                .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], config.port))),
            Duration::from_millis(config.timeout_ms),
        )
        .map_err(|e| format!("连接 Modbus TCP 失败: {}", e))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        let transaction_id: u16 = rand::random::<u16>();
        let protocol_id: u16 = 0;
        let length: u16 = 6;
        let unit_id = config.slave_id;
        let function_code = config.function.code();
        let start_addr = config.address;
        let quantity = config.count;

        // 构建 Modbus TCP ADU
        let mut adu = Vec::new();
        adu.extend_from_slice(&transaction_id.to_be_bytes());
        adu.extend_from_slice(&protocol_id.to_be_bytes());
        adu.extend_from_slice(&length.to_be_bytes());
        adu.push(unit_id);
        adu.push(function_code);
        adu.extend_from_slice(&start_addr.to_be_bytes());
        adu.extend_from_slice(&quantity.to_be_bytes());

        stream
            .write_all(&adu)
            .map_err(|e| format!("发送 Modbus 请求失败: {}", e))?;

        // 读取响应头（7 字节 MBAP + 功能码 + 字节数）
        let mut header = [0u8; 9];
        stream
            .read_exact(&mut header)
            .map_err(|e| format!("读取 Modbus 响应头失败: {}", e))?;

        let resp_transaction_id = u16::from_be_bytes([header[0], header[1]]);
        let resp_function = header[7];

        // 检查异常响应
        if resp_function & 0x80 != 0 {
            let exception_code = header[8];
            return Err(format!(
                "Modbus 异常: 功能码 0x{:02X}, 异常码 0x{:02X}",
                resp_function, exception_code
            ));
        }

        let byte_count = header[8] as usize;
        let mut data = vec![0u8; byte_count];
        if byte_count > 0 {
            stream
                .read_exact(&mut data)
                .map_err(|e| format!("读取 Modbus 数据失败: {}", e))?;
        }

        let elapsed = start.elapsed().as_millis() as u64;

        // 解析寄存器或线圈
        match config.function {
            ModbusFunction::ReadHoldingRegisters | ModbusFunction::ReadInputRegisters => {
                let mut registers = Vec::new();
                for chunk in data.chunks(2) {
                    if chunk.len() == 2 {
                        registers.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                    }
                }
                Ok(ModbusResult {
                    registers,
                    coils: vec![],
                    response_time_ms: elapsed,
                    transaction_id: resp_transaction_id,
                    success: true,
                    error: None,
                })
            }
            ModbusFunction::ReadCoils | ModbusFunction::ReadDiscreteInputs => {
                let mut coils = Vec::new();
                for i in 0..quantity as usize {
                    let byte_idx = i / 8;
                    let bit_idx = i % 8;
                    if byte_idx < data.len() {
                        coils.push((data[byte_idx] >> bit_idx) & 1 == 1);
                    } else {
                        coils.push(false);
                    }
                }
                Ok(ModbusResult {
                    registers: vec![],
                    coils,
                    response_time_ms: elapsed,
                    transaction_id: resp_transaction_id,
                    success: true,
                    error: None,
                })
            }
            _ => Err("该功能码不适用于读操作".to_string()),
        }
    })();

    let api_result = match result {
        Ok(r) => {
            add_to_history(RequestHistoryItem {
                id: uuid::Uuid::new_v4().to_string(),
                request_type: "modbus".to_string(),
                method: format!("{:?}", config.function),
                target: format!("{}:{}", config.host, config.port),
                timestamp: chrono::Utc::now().timestamp(),
                status: "OK".to_string(),
                response_time_ms: r.response_time_ms,
                request_snapshot: serde_json::to_string(&config).unwrap_or_default(),
            });
            DeviceApiResult::ok(r, "Modbus 读取成功")
        }
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

/// Modbus TCP 写操作（单个寄存器/线圈）
pub fn modbus_write(config: ModbusRequest, value: u16) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<ModbusResult, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let addr = format!("{}:{}", config.host, config.port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .to_socket_addrs_first()
                .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], config.port))),
            Duration::from_millis(config.timeout_ms),
        )
        .map_err(|e| format!("连接 Modbus TCP 失败: {}", e))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        let transaction_id: u16 = rand::random::<u16>();
        let protocol_id: u16 = 0;
        let length: u16 = 6;
        let unit_id = config.slave_id;
        let function_code = config.function.code();
        let address = config.address;

        let mut adu = Vec::new();
        adu.extend_from_slice(&transaction_id.to_be_bytes());
        adu.extend_from_slice(&protocol_id.to_be_bytes());
        adu.extend_from_slice(&length.to_be_bytes());
        adu.push(unit_id);
        adu.push(function_code);
        adu.extend_from_slice(&address.to_be_bytes());
        adu.extend_from_slice(&value.to_be_bytes());

        stream
            .write_all(&adu)
            .map_err(|e| format!("发送 Modbus 写请求失败: {}", e))?;

        // 读取响应（12 字节）
        let mut resp = [0u8; 12];
        stream
            .read_exact(&mut resp)
            .map_err(|e| format!("读取 Modbus 响应失败: {}", e))?;

        let resp_transaction_id = u16::from_be_bytes([resp[0], resp[1]]);
        let resp_function = resp[7];

        if resp_function & 0x80 != 0 {
            let exception_code = resp[8];
            return Err(format!(
                "Modbus 异常: 功能码 0x{:02X}, 异常码 0x{:02X}",
                resp_function, exception_code
            ));
        }

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(ModbusResult {
            registers: vec![value],
            coils: vec![value != 0],
            response_time_ms: elapsed,
            transaction_id: resp_transaction_id,
            success: true,
            error: None,
        })
    })();

    let api_result = match result {
        Ok(r) => {
            add_to_history(RequestHistoryItem {
                id: uuid::Uuid::new_v4().to_string(),
                request_type: "modbus".to_string(),
                method: format!("{:?}", config.function),
                target: format!("{}:{}", config.host, config.port),
                timestamp: chrono::Utc::now().timestamp(),
                status: "OK".to_string(),
                response_time_ms: r.response_time_ms,
                request_snapshot: serde_json::to_string(&config).unwrap_or_default(),
            });
            DeviceApiResult::ok(r, "Modbus 写入成功")
        }
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

// 辅助 trait：解析 socket addr 的第一个
trait ToSocketAddrsFirst {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr>;
}

impl ToSocketAddrsFirst for String {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok().and_then(|mut iter| iter.next())
    }
}

// ============================================================
// 公共函数 - MQTT
// ============================================================

/// MQTT 发布消息
pub fn mqtt_publish(
    config: MqttConfig,
    topic: String,
    payload: String,
    qos: u8,
) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<MqttMessage, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let addr = format!("{}:{}", config.broker, config.port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .to_socket_addrs_first()
                .ok_or("无法解析 MQTT Broker 地址")?,
            Duration::from_millis(config.timeout_ms),
        )
        .map_err(|e| format!("连接 MQTT Broker 失败: {}", e))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        // --- 构建 CONNECT 报文 ---
        let protocol_name = b"MQTT";
        let protocol_level: u8 = 4; // MQTT 3.1.1
        let mut connect_flags: u8 = 0b0000_0010; // Clean Session

        let client_id_bytes = config.client_id.as_bytes();
        let mut payload_data = Vec::new();
        // Client ID
        payload_data.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
        payload_data.extend_from_slice(client_id_bytes);

        // 用户名
        if let Some(username) = &config.username {
            connect_flags |= 0b1000_0000;
            let uname_bytes = username.as_bytes();
            payload_data.extend_from_slice(&(uname_bytes.len() as u16).to_be_bytes());
            payload_data.extend_from_slice(uname_bytes);
        }

        // 密码
        if let Some(password) = &config.password {
            connect_flags |= 0b0100_0000;
            let pwd_bytes = password.as_bytes();
            payload_data.extend_from_slice(&(pwd_bytes.len() as u16).to_be_bytes());
            payload_data.extend_from_slice(pwd_bytes);
        }

        // 可变头
        let mut variable_header = Vec::new();
        variable_header.extend_from_slice(&(protocol_name.len() as u16).to_be_bytes());
        variable_header.extend_from_slice(protocol_name);
        variable_header.push(protocol_level);
        variable_header.push(connect_flags);
        variable_header.extend_from_slice(&config.keep_alive.to_be_bytes());

        let remaining_length = variable_header.len() + payload_data.len();
        let mut connect_packet = Vec::new();
        connect_packet.push(0x10); // CONNECT
        connect_packet.extend_from_slice(&encode_remaining_length(remaining_length));
        connect_packet.extend_from_slice(&variable_header);
        connect_packet.extend_from_slice(&payload_data);

        stream
            .write_all(&connect_packet)
            .map_err(|e| format!("发送 CONNECT 失败: {}", e))?;

        // 读取 CONNACK
        let mut connack_header = [0u8; 4];
        stream
            .read_exact(&mut connack_header)
            .map_err(|e| format!("读取 CONNACK 失败: {}", e))?;

        if connack_header[0] != 0x20 {
            return Err("未收到 CONNACK 响应".to_string());
        }

        let return_code = connack_header[3];
        if return_code != 0 {
            return Err(format!("MQTT 连接被拒绝，返回码: {}", return_code));
        }

        // --- 构建 PUBLISH 报文 ---
        let topic_bytes = topic.as_bytes();
        let payload_bytes = payload.as_bytes();

        let mut publish_variable = Vec::new();
        publish_variable.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
        publish_variable.extend_from_slice(topic_bytes);

        // QoS > 0 需要包标识符
        let qos_level = qos.min(2);
        if qos_level > 0 {
            let packet_id: u16 = rand::random::<u16>();
            publish_variable.extend_from_slice(&packet_id.to_be_bytes());
        }

        let publish_remaining = publish_variable.len() + payload_bytes.len();

        let mut publish_flags: u8 = 0x30; // PUBLISH
        publish_flags |= (qos_level << 1) & 0x06;

        let mut publish_packet = Vec::new();
        publish_packet.push(publish_flags);
        publish_packet.extend_from_slice(&encode_remaining_length(publish_remaining));
        publish_packet.extend_from_slice(&publish_variable);
        publish_packet.extend_from_slice(payload_bytes);

        stream
            .write_all(&publish_packet)
            .map_err(|e| format!("发送 PUBLISH 失败: {}", e))?;

        // 如果 QoS > 0，等待确认
        if qos_level == 1 {
            let mut puback = [0u8; 4];
            stream
                .read_exact(&mut puback)
                .map_err(|e| format!("读取 PUBACK 失败: {}", e))?;
        } else if qos_level == 2 {
            let mut pubrec = [0u8; 4];
            stream
                .read_exact(&mut pubrec)
                .map_err(|e| format!("读取 PUBREC 失败: {}", e))?;
            // 发送 PUBREL
            let packet_id = u16::from_be_bytes([pubrec[2], pubrec[3]]);
            let mut pubrel = vec![0x62, 0x02];
            pubrel.extend_from_slice(&packet_id.to_be_bytes());
            let _ = stream.write_all(&pubrel);
            // 等待 PUBCOMP
            let mut pubcomp = [0u8; 4];
            let _ = stream.read_exact(&mut pubcomp);
        }

        // 发送 DISCONNECT
        let _ = stream.write_all(&[0xE0, 0x00]);

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(MqttMessage {
            topic,
            payload,
            qos: qos_level,
            retain: false,
        })
    })();

    let api_result = match result {
        Ok(msg) => {
            add_to_history(RequestHistoryItem {
                id: uuid::Uuid::new_v4().to_string(),
                request_type: "mqtt".to_string(),
                method: "PUBLISH".to_string(),
                target: format!("{}:{}", config.broker, config.port),
                timestamp: chrono::Utc::now().timestamp(),
                status: "OK".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
                request_snapshot: serde_json::to_string(&config).unwrap_or_default(),
            });
            DeviceApiResult::ok(msg, "MQTT 发布成功")
        }
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

/// MQTT 订阅消息（等待指定时间后返回收到的消息）
pub fn mqtt_subscribe(
    config: MqttConfig,
    topic: String,
    timeout_ms: u64,
) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<MqttSubscribeResult, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let addr = format!("{}:{}", config.broker, config.port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .to_socket_addrs_first()
                .ok_or("无法解析 MQTT Broker 地址")?,
            Duration::from_millis(config.timeout_ms),
        )
        .map_err(|e| format!("连接 MQTT Broker 失败: {}", e))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        // CONNECT
        let protocol_name = b"MQTT";
        let mut connect_flags: u8 = 0b0000_0010;
        let client_id_bytes = config.client_id.as_bytes();

        let mut payload_data = Vec::new();
        payload_data.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
        payload_data.extend_from_slice(client_id_bytes);

        if let Some(username) = &config.username {
            connect_flags |= 0b1000_0000;
            let uname_bytes = username.as_bytes();
            payload_data.extend_from_slice(&(uname_bytes.len() as u16).to_be_bytes());
            payload_data.extend_from_slice(uname_bytes);
        }
        if let Some(password) = &config.password {
            connect_flags |= 0b0100_0000;
            let pwd_bytes = password.as_bytes();
            payload_data.extend_from_slice(&(pwd_bytes.len() as u16).to_be_bytes());
            payload_data.extend_from_slice(pwd_bytes);
        }

        let mut variable_header = Vec::new();
        variable_header.extend_from_slice(&(protocol_name.len() as u16).to_be_bytes());
        variable_header.extend_from_slice(protocol_name);
        variable_header.push(4); // protocol level
        variable_header.push(connect_flags);
        variable_header.extend_from_slice(&config.keep_alive.to_be_bytes());

        let remaining_length = variable_header.len() + payload_data.len();
        let mut connect_packet = vec![0x10];
        connect_packet.extend_from_slice(&encode_remaining_length(remaining_length));
        connect_packet.extend_from_slice(&variable_header);
        connect_packet.extend_from_slice(&payload_data);

        stream
            .write_all(&connect_packet)
            .map_err(|e| format!("发送 CONNECT 失败: {}", e))?;

        // CONNACK
        let mut connack_header = [0u8; 4];
        let _ = stream.read_exact(&mut connack_header);

        // SUBSCRIBE
        let packet_id: u16 = rand::random::<u16>();
        let topic_bytes = topic.as_bytes();

        let mut subscribe_payload = Vec::new();
        subscribe_payload.extend_from_slice(&packet_id.to_be_bytes());
        subscribe_payload.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
        subscribe_payload.extend_from_slice(topic_bytes);
        subscribe_payload.push(0); // QoS 0

        let sub_remaining = subscribe_payload.len();
        let mut subscribe_packet = vec![0x82];
        subscribe_packet.extend_from_slice(&encode_remaining_length(sub_remaining));
        subscribe_packet.extend_from_slice(&subscribe_payload);

        stream
            .write_all(&subscribe_packet)
            .map_err(|e| format!("发送 SUBSCRIBE 失败: {}", e))?;

        // SUBACK
        let mut suback = [0u8; 5];
        let _ = stream.read_exact(&mut suback);

        // 等待消息
        let mut messages = Vec::new();
        let wait_start = Instant::now();

        while wait_start.elapsed().as_millis() < timeout_ms as u128 {
            let mut byte1 = [0u8; 1];
            match stream.read_exact(&mut byte1) {
                Ok(_) => {}
                Err(_) => continue, // 超时继续
            }

            let packet_type = byte1[0] >> 4;

            // 读取 remaining length
            let remaining = match read_remaining_length(&mut stream) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let mut payload = vec![0u8; remaining];
            if remaining > 0 {
                match stream.read_exact(&mut payload) {
                    Ok(_) => {}
                    Err(_) => continue,
                }
            }

            if packet_type == 3 {
                // PUBLISH
                let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                let topic_name = String::from_utf8_lossy(&payload[2..2 + topic_len]).to_string();

                let mut offset = 2 + topic_len;
                let qos_bits = (byte1[0] >> 1) & 0x03;
                if qos_bits > 0 {
                    offset += 2; // packet identifier
                }

                let msg_payload = String::from_utf8_lossy(&payload[offset..]).to_string();

                messages.push(MqttMessage {
                    topic: topic_name,
                    payload: msg_payload,
                    qos: qos_bits,
                    retain: (byte1[0] & 0x01) == 1,
                });
            }
        }

        // DISCONNECT
        let _ = stream.write_all(&[0xE0, 0x00]);

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(MqttSubscribeResult {
            messages,
            topic,
            wait_time_ms: elapsed,
            success: true,
            error: None,
        })
    })();

    let api_result = match result {
        Ok(r) => DeviceApiResult::ok(r, "MQTT 订阅完成"),
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

// MQTT 辅助：编码剩余长度
fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if len == 0 {
            break;
        }
    }
    result
}

// MQTT 辅助：读取剩余长度
fn read_remaining_length(stream: &mut std::net::TcpStream) -> Result<usize, String> {
    use std::io::Read;
    let mut multiplier = 1usize;
    let mut value = 0usize;
    loop {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("读取 remaining length 失败: {}", e))?;
        value += ((byte[0] & 0x7F) as usize) * multiplier;
        if (byte[0] & 0x80) == 0 {
            break;
        }
        multiplier *= 128;
        if multiplier > 128 * 128 * 128 {
            return Err("remaining length 过大".to_string());
        }
    }
    Ok(value)
}

// ============================================================
// 公共函数 - SNMP
// ============================================================

/// SNMP GET 请求
pub fn snmp_get(config: SnmpRequest) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<SnmpResult, String> {
        use std::net::UdpSocket;

        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("创建 UDP socket 失败: {}", e))?;

        socket
            .set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        let addr = format!("{}:{}", config.host, config.port);
        let target_addr = addr
            .to_socket_addrs_first()
            .ok_or("无法解析 SNMP 目标地址")?;

        // 构建 SNMPv2c GET 请求 PDU
        let request_id: i32 = rand::random::<i32>();
        let community_bytes = config.community.as_bytes();
        let oid_bytes = encode_oid(&config.oid)?;

        // Variable binding: OID + NULL value
        let mut var_bind = Vec::new();
        var_bind.extend_from_slice(&encode_oid_sequence(&oid_bytes)); // OID (SEQUENCE)
        var_bind.extend_from_slice(&[0x05, 0x00]); // NULL value

        // VarBindList (SEQUENCE of VarBind)
        let var_bind_list = encode_sequence(&var_bind);

        // PDU: GetRequest-PDU (context 0, constructed)
        let mut pdu_content = Vec::new();
        pdu_content.extend_from_slice(&encode_integer(request_id)); // request-id
        pdu_content.extend_from_slice(&encode_integer(0)); // error-status
        pdu_content.extend_from_slice(&encode_integer(0)); // error-index
        pdu_content.extend_from_slice(&var_bind_list);

        let pdu = encode_context_pdu(0, &pdu_content);

        // SNMP Message
        let mut message_content = Vec::new();
        message_content.extend_from_slice(&encode_integer(config.version.version_byte() as i32)); // version
        message_content.extend_from_slice(&encode_octet_string(community_bytes)); // community
        message_content.extend_from_slice(&pdu); // PDU

        let message = encode_sequence(&message_content);

        socket
            .send_to(&message, target_addr)
            .map_err(|e| format!("发送 SNMP 请求失败: {}", e))?;

        // 接收响应
        let mut buf = [0u8; 65536];
        let (n, _) = socket
            .recv_from(&mut buf)
            .map_err(|e| format!("接收 SNMP 响应失败: {}", e))?;

        let response = &buf[..n];
        let var_binds = parse_snmp_response(response)?;

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(SnmpResult {
            var_binds,
            response_time_ms: elapsed,
            success: true,
            error: None,
        })
    })();

    let api_result = match result {
        Ok(r) => {
            add_to_history(RequestHistoryItem {
                id: uuid::Uuid::new_v4().to_string(),
                request_type: "snmp".to_string(),
                method: "GET".to_string(),
                target: format!("{}:{}", config.host, config.port),
                timestamp: chrono::Utc::now().timestamp(),
                status: "OK".to_string(),
                response_time_ms: r.response_time_ms,
                request_snapshot: serde_json::to_string(&config).unwrap_or_default(),
            });
            DeviceApiResult::ok(r, "SNMP GET 成功")
        }
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

/// SNMP WALK
pub fn snmp_walk(config: SnmpRequest) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<SnmpResult, String> {
        use std::net::UdpSocket;

        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("创建 UDP socket 失败: {}", e))?;

        socket
            .set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        let addr = format!("{}:{}", config.host, config.port);
        let target_addr = addr
            .to_socket_addrs_first()
            .ok_or("无法解析 SNMP 目标地址")?;

        let mut all_var_binds = Vec::new();
        let mut current_oid = config.oid.clone();
        let base_oid = config.oid.clone();
        let mut iterations = 0;
        let max_iter = config.walk_max;

        while iterations < max_iter {
            iterations += 1;

            let request_id: i32 = rand::random::<i32>();
            let community_bytes = config.community.as_bytes();
            let oid_bytes = encode_oid(&current_oid)?;

            let mut var_bind = Vec::new();
            var_bind.extend_from_slice(&encode_oid_sequence(&oid_bytes));
            var_bind.extend_from_slice(&[0x05, 0x00]);

            let var_bind_list = encode_sequence(&var_bind);

            let mut pdu_content = Vec::new();
            pdu_content.extend_from_slice(&encode_integer(request_id));
            pdu_content.extend_from_slice(&encode_integer(0));
            pdu_content.extend_from_slice(&encode_integer(0));
            pdu_content.extend_from_slice(&var_bind_list);

            // GetNextRequest-PDU (context 1)
            let pdu = encode_context_pdu(1, &pdu_content);

            let mut message_content = Vec::new();
            message_content
                .extend_from_slice(&encode_integer(config.version.version_byte() as i32));
            message_content.extend_from_slice(&encode_octet_string(community_bytes));
            message_content.extend_from_slice(&pdu);

            let message = encode_sequence(&message_content);

            socket
                .send_to(&message, target_addr)
                .map_err(|e| format!("发送 SNMP 请求失败: {}", e))?;

            let mut buf = [0u8; 65536];
            let (n, _) = match socket.recv_from(&mut buf) {
                Ok(r) => r,
                Err(_) => break,
            };

            let response = &buf[..n];
            let var_binds = match parse_snmp_response(response) {
                Ok(v) => v,
                Err(_) => break,
            };

            if var_binds.is_empty() {
                break;
            }

            let first = &var_binds[0];

            // 检查是否已经走出 base_oid 范围（Walk 结束条件）
            if !first.oid.starts_with(&base_oid) && first.oid != base_oid {
                break;
            }

            // 检查是否结束（返回相同 OID 或 end-of-mib-view）
            if first.oid == current_oid && iterations > 1 {
                break;
            }

            all_var_binds.push(first.clone());
            current_oid = first.oid.clone();
        }

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(SnmpResult {
            var_binds: all_var_binds,
            response_time_ms: elapsed,
            success: true,
            error: None,
        })
    })();

    let api_result = match result {
        Ok(r) => DeviceApiResult::ok(r, "SNMP WALK 完成"),
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

// SNMP BER 编码辅助
fn encode_oid(oid: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<u32> = oid
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().map_err(|e| format!("OID 解析失败: {}", e)))
        .collect::<Result<Vec<_>, _>>()?;

    if parts.len() < 2 {
        return Err("OID 至少需要 2 个部分".to_string());
    }

    let mut result = Vec::new();
    // 前两个部分合并为一个字节: 40 * first + second
    let first_byte = (parts[0] * 40 + parts[1]) as u8;
    result.push(first_byte);

    for &part in &parts[2..] {
        result.extend_from_slice(&encode_oid_component(part));
    }

    Ok(result)
}

fn encode_oid_component(mut value: u32) -> Vec<u8> {
    if value < 128 {
        return vec![value as u8];
    }

    let mut result = Vec::new();
    let mut mask = 0u8;

    loop {
        result.push(((value & 0x7F) as u8) | mask);
        value >>= 7;
        mask = 0x80;
        if value == 0 {
            break;
        }
    }

    result.reverse();
    result
}

fn encode_oid_sequence(oid_bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0x06]; // OID tag
    result.extend_from_slice(&encode_length(oid_bytes.len()));
    result.extend_from_slice(oid_bytes);
    result
}

fn encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut result = vec![0x30]; // SEQUENCE tag
    result.extend_from_slice(&encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

fn encode_integer(value: i32) -> Vec<u8> {
    let mut result = vec![0x02]; // INTEGER tag
    if value == 0 {
        result.extend_from_slice(&[1, 0]);
        return result;
    }

    let mut bytes = Vec::new();
    let mut v = value;

    if value > 0 {
        while v > 0 {
            bytes.push((v & 0xFF) as u8);
            v >>= 8;
        }
        // 确保最高位为 0（正数）
        if bytes.last().unwrap_or(&0) & 0x80 != 0 {
            bytes.push(0);
        }
    } else {
        // 负数补码处理
        let mut uv = value as u32;
        while uv != 0xFFFFFFFF || bytes.is_empty() || bytes.last().unwrap() & 0x80 == 0 {
            bytes.push((uv & 0xFF) as u8);
            uv >>= 8;
            if bytes.len() >= 5 {
                break;
            }
        }
        // 移除多余的 0xFF
        while bytes.len() > 1
            && bytes[bytes.len() - 1] == 0xFF
            && bytes[bytes.len() - 2] & 0x80 != 0
        {
            bytes.pop();
        }
    }

    bytes.reverse();
    result.extend_from_slice(&encode_length(bytes.len()));
    result.extend_from_slice(&bytes);
    result
}

fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    result.extend_from_slice(&encode_length(data.len()));
    result.extend_from_slice(data);
    result
}

fn encode_context_pdu(context_tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![0xA0 | context_tag]; // context-specific, constructed
    result.extend_from_slice(&encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

// SNMP 响应解析
fn parse_snmp_response(data: &[u8]) -> Result<Vec<SnmpVarBind>, String> {
    if data.len() < 10 || data[0] != 0x30 {
        return Err("无效的 SNMP 响应".to_string());
    }

    let (msg_content, _) = parse_tlv(data)?;

    // 解析 message content: version, community, pdu
    let mut offset = 0;

    // version
    let (_ver_bytes, ver_value, consumed) = parse_tlv_at_offset(&msg_content, offset)?;
    offset += consumed;

    // community
    let (_comm_bytes, comm_value, consumed) = parse_tlv_at_offset(&msg_content, offset)?;
    let _community = String::from_utf8_lossy(&comm_value).to_string();
    offset += consumed;

    // PDU (context-specific, constructed)
    let pdu_tag = msg_content[offset];
    let (pdu_content, pdu_consumed) = parse_tlv_at_offset_content(&msg_content, offset)?;
    offset += pdu_consumed;

    let _pdu_type = pdu_tag & 0x0F;

    // 解析 PDU content: request-id, error-status, error-index, var-bind-list
    let mut pdu_offset = 0;

    // request-id
    let (_req_id_bytes, _req_id_value, consumed) = parse_tlv_at_offset(&pdu_content, pdu_offset)?;
    pdu_offset += consumed;

    // error-status
    let (_err_status_bytes, err_status_value, consumed) =
        parse_tlv_at_offset(&pdu_content, pdu_offset)?;
    let error_status = if !err_status_value.is_empty() {
        err_status_value[0] as u32
    } else {
        0
    };
    pdu_offset += consumed;

    if error_status != 0 {
        return Err(format!("SNMP 错误状态: {}", error_status));
    }

    // error-index
    let (_err_idx_bytes, _err_idx_value, consumed) = parse_tlv_at_offset(&pdu_content, pdu_offset)?;
    pdu_offset += consumed;

    // var-bind-list (SEQUENCE)
    let (var_bind_list, _consumed) = parse_tlv_at_offset_content(&pdu_content, pdu_offset)?;

    // 解析每个 varbind
    let mut var_binds = Vec::new();
    let mut vb_offset = 0;

    while vb_offset < var_bind_list.len() {
        let (var_bind_content, vb_consumed) =
            parse_tlv_at_offset_content(&var_bind_list, vb_offset)?;
        vb_offset += vb_consumed;

        // OID
        let (_oid_bytes, oid_value, consumed) = parse_tlv_at_offset(&var_bind_content, 0)?;
        let oid = decode_oid(&oid_value);
        let mut vb_content_offset = consumed;

        // Value
        let (value_tag, value_data, _consumed) =
            parse_tlv_at_offset(&var_bind_content, vb_content_offset)?;

        let (value_str, value_type) = decode_snmp_value(&value_tag, &value_data);

        var_binds.push(SnmpVarBind {
            oid,
            value: value_str,
            value_type,
        });
    }

    Ok(var_binds)
}

fn parse_tlv(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    parse_tlv_at_offset_content(data, 0)
}

fn parse_tlv_at_offset(data: &[u8], offset: usize) -> Result<(Vec<u8>, Vec<u8>, usize), String> {
    if offset >= data.len() {
        return Err("数据越界".to_string());
    }
    let tag = data[offset];
    let (length, len_bytes) = parse_length(data, offset + 1)?;
    let value_start = offset + 1 + len_bytes;
    let value_end = value_start + length;
    if value_end > data.len() {
        return Err("TLV 长度超出数据范围".to_string());
    }
    let value = data[value_start..value_end].to_vec();
    let total_consumed = 1 + len_bytes + length;
    Ok((vec![tag], value, total_consumed))
}

fn parse_tlv_at_offset_content(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize), String> {
    let (_, content, consumed) = parse_tlv_at_offset(data, offset)?;
    Ok((content, consumed))
}

fn parse_length(data: &[u8], offset: usize) -> Result<(usize, usize), String> {
    if offset >= data.len() {
        return Err("长度字段越界".to_string());
    }
    let first = data[offset];
    if first & 0x80 == 0 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err("不支持的长度编码".to_string());
        }
        if offset + 1 + num_bytes > data.len() {
            return Err("长度字段越界".to_string());
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | data[offset + 1 + i] as usize;
        }
        Ok((length, 1 + num_bytes))
    }
}

fn decode_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let mut parts = Vec::new();
    let first = bytes[0] as u32;
    parts.push(first / 40);
    parts.push(first % 40);

    let mut i = 1;
    while i < bytes.len() {
        let mut value: u32 = 0;
        loop {
            if i >= bytes.len() {
                break;
            }
            let b = bytes[i];
            value = (value << 7) | (b & 0x7F) as u32;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        parts.push(value);
    }

    parts
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn decode_snmp_value(tag: &[u8], data: &[u8]) -> (String, String) {
    let tag_byte = if tag.is_empty() { 0 } else { tag[0] };
    match tag_byte {
        0x02 => {
            // INTEGER
            let val = decode_integer(data);
            (val.to_string(), "integer".to_string())
        }
        0x04 => {
            // OCTET STRING
            let s = String::from_utf8_lossy(data).to_string();
            (s, "string".to_string())
        }
        0x05 => ("NULL".to_string(), "null".to_string()),
        0x06 => (decode_oid(data), "oid".to_string()),
        0x40 => (decode_ip_address(data), "ipaddress".to_string()),
        0x41 => {
            // Counter32
            let val = decode_unsigned(data);
            (val.to_string(), "counter32".to_string())
        }
        0x42 => {
            // Gauge32
            let val = decode_unsigned(data);
            (val.to_string(), "gauge32".to_string())
        }
        0x43 => {
            // TimeTicks
            let val = decode_unsigned(data);
            (val.to_string(), "timeticks".to_string())
        }
        0x46 => {
            // Counter64
            let val = decode_counter64(data);
            (val.to_string(), "counter64".to_string())
        }
        _ => (
            format!("0x{}", hex_encode(data)),
            format!("unknown(0x{:02X})", tag_byte),
        ),
    }
}

fn decode_integer(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    let mut value: i64 = if data[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in data {
        value = (value << 8) | b as i64;
    }
    value
}

fn decode_unsigned(data: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for &b in data {
        value = (value << 8) | b as u64;
    }
    value
}

fn decode_counter64(data: &[u8]) -> u64 {
    decode_unsigned(data)
}

fn decode_ip_address(data: &[u8]) -> String {
    if data.len() == 4 {
        format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3])
    } else {
        hex_encode(data)
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

// ============================================================
// 公共函数 - SSH 命令执行
// ============================================================

/// SSH 命令执行（使用本地系统 ssh 命令作为回退方案）
pub fn ssh_execute(config: SshCommandConfig) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<CommandResult, String> {
        // 使用 sshpass + ssh 或者直接尝试 ssh
        // 由于没有 ssh2 库依赖，这里使用基础 TCP 连接测试 + 提示
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let addr = format!("{}:{}", config.host, config.port);
        let mut stream = TcpStream::connect_timeout(
            &addr.to_socket_addrs_first().ok_or("无法解析 SSH 地址")?,
            Duration::from_millis(config.timeout_ms),
        )
        .map_err(|e| format!("SSH 端口连接失败: {}", e))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        // 读取 SSH banner
        let mut banner = vec![0u8; 1024];
        let n = stream
            .read(&mut banner)
            .map_err(|e| format!("读取 SSH banner 失败: {}", e))?;

        let ssh_banner = String::from_utf8_lossy(&banner[..n]).trim().to_string();

        if !ssh_banner.starts_with("SSH-") {
            return Err(format!("不是 SSH 服务，Banner: {}", ssh_banner));
        }

        let elapsed = start.elapsed().as_millis() as u64;

        // 完整 SSH 实现需要 ssh2 或 russh 库
        // 这里提供基础探测结果
        Ok(CommandResult {
            output: format!("SSH 服务可用\nBanner: {}\n\n注意：完整命令执行需要 SSH 客户端库支持 (ssh2/russh)。当前版本仅支持 SSH 端口探测和 Banner 获取。", ssh_banner),
            exit_code: None,
            response_time_ms: elapsed,
            success: true,
            error: None,
        })
    })();

    let api_result = match result {
        Ok(r) => {
            add_to_history(RequestHistoryItem {
                id: uuid::Uuid::new_v4().to_string(),
                request_type: "ssh".to_string(),
                method: "EXEC".to_string(),
                target: format!("{}:{}", config.host, config.port),
                timestamp: chrono::Utc::now().timestamp(),
                status: "OK".to_string(),
                response_time_ms: r.response_time_ms,
                request_snapshot: serde_json::to_string(&config).unwrap_or_default(),
            });
            DeviceApiResult::ok(r, "SSH 探测完成")
        }
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

// ============================================================
// 公共函数 - Telnet
// ============================================================

/// Telnet 命令执行
pub fn telnet_execute(config: TelnetConfig) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<CommandResult, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let addr = format!("{}:{}", config.host, config.port);
        let mut stream = TcpStream::connect_timeout(
            &addr.to_socket_addrs_first().ok_or("无法解析 Telnet 地址")?,
            Duration::from_millis(config.timeout_ms),
        )
        .map_err(|e| format!("Telnet 连接失败: {}", e))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        // 读取初始数据（可能包含 IAC 协商）
        let mut initial_data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    initial_data.extend_from_slice(&buf[..n]);
                }
                Err(_) => break,
            }
            if initial_data.len() > 8192 {
                break;
            }
        }

        // 处理 IAC 协商（简单回应 WONT/DO/DONT）
        let negotiated = handle_telnet_negotiation(&initial_data, &mut stream);

        // 登录（如果有用户名密码）
        let mut output = String::new();

        if let Some(username) = &config.username {
            // 等待 Username/login 提示
            let login_prompt = read_until_prompt(
                &mut stream,
                &["login:", "Username:", "username:", "user name:"],
            );
            output.push_str(&login_prompt);

            // 发送用户名
            let _ = stream.write_all(format!("{}\r\n", username).as_bytes());
        }

        if let Some(password) = &config.password {
            // 等待 Password 提示
            let pass_prompt = read_until_prompt(&mut stream, &["Password:", "password:"]);
            output.push_str(&pass_prompt);

            // 发送密码
            let _ = stream.write_all(format!("{}\r\n", password).as_bytes());
        }

        // 等待提示符
        let prompt_str = config.prompt.as_deref().unwrap_or(">");
        let before_cmd = read_until_prompt(&mut stream, &[prompt_str, "#", "$"]);
        output.push_str(&before_cmd);

        // 发送命令
        let _ = stream.write_all(format!("{}\r\n", config.command).as_bytes());

        // 读取命令输出
        let cmd_output = read_until_prompt(&mut stream, &[prompt_str, "#", "$"]);
        output.push_str(&cmd_output);

        let elapsed = start.elapsed().as_millis() as u64;

        // 清理 Telnet 控制字符
        let clean_output = clean_telnet_output(&output);

        Ok(CommandResult {
            output: clean_output,
            exit_code: None,
            response_time_ms: elapsed,
            success: true,
            error: None,
        })
    })();

    let api_result = match result {
        Ok(r) => {
            add_to_history(RequestHistoryItem {
                id: uuid::Uuid::new_v4().to_string(),
                request_type: "telnet".to_string(),
                method: "EXEC".to_string(),
                target: format!("{}:{}", config.host, config.port),
                timestamp: chrono::Utc::now().timestamp(),
                status: "OK".to_string(),
                response_time_ms: r.response_time_ms,
                request_snapshot: serde_json::to_string(&config).unwrap_or_default(),
            });
            DeviceApiResult::ok(r, "Telnet 执行完成")
        }
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

fn handle_telnet_negotiation(data: &[u8], stream: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Write;
    let mut result = Vec::new();
    let mut i = 0;
    let mut response = Vec::new();

    while i < data.len() {
        if data[i] == 0xFF {
            // IAC
            if i + 2 < data.len() {
                let command = data[i + 1];
                let option = data[i + 2];

                match command {
                    0xFB => {
                        // WILL -> respond DONT
                        response.extend_from_slice(&[0xFF, 0xFE, option]);
                    }
                    0xFC => {
                        // WONT -> respond DONT
                        response.extend_from_slice(&[0xFF, 0xFE, option]);
                    }
                    0xFD => {
                        // DO -> respond WONT
                        response.extend_from_slice(&[0xFF, 0xFC, option]);
                    }
                    0xFE => {
                        // DONT -> respond WONT
                        response.extend_from_slice(&[0xFF, 0xFC, option]);
                    }
                    _ => {}
                }
                i += 3;
            } else {
                break;
            }
        } else {
            result.push(data[i]);
            i += 1;
        }
    }

    if !response.is_empty() {
        let _ = stream.write_all(&response);
    }

    result
}

fn read_until_prompt(stream: &mut std::net::TcpStream, prompts: &[&str]) -> String {
    use std::io::Read;
    let mut output = Vec::new();
    let mut buf = [0u8; 1024];
    let start = Instant::now();
    let timeout = Duration::from_secs(10);

    while start.elapsed() < timeout {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // 处理 IAC
                let clean = handle_telnet_negotiation(&buf[..n], stream);
                output.extend_from_slice(&clean);

                let text = String::from_utf8_lossy(&output).to_lowercase();
                for prompt in prompts {
                    if text.contains(&prompt.to_lowercase()) {
                        return String::from_utf8_lossy(&output).to_string();
                    }
                }
            }
            Err(_) => {
                if !output.is_empty() {
                    break;
                }
            }
        }
    }

    String::from_utf8_lossy(&output).to_string()
}

fn clean_telnet_output(output: &str) -> String {
    // 移除 ANSI 转义序列和控制字符
    let mut result = String::new();
    let chars: Vec<char> = output.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c == '\x1b' {
            // ESC 序列
            i += 1;
            if i < chars.len() && chars[i] == '[' {
                i += 1;
                // CSI 序列: 数字+参数+字母
                while i < chars.len()
                    && (chars[i].is_ascii_digit() || chars[i] == ';' || chars[i] == '?')
                {
                    i += 1;
                }
                if i < chars.len() {
                    i += 1; // 跳过结束字符
                }
            }
            continue;
        }
        if c == '\r' {
            // 保留换行，但处理 \r\n
            if i + 1 < chars.len() && chars[i + 1] == '\n' {
                result.push('\n');
                i += 2;
                continue;
            }
            result.push('\n');
            i += 1;
            continue;
        }
        if c.is_control() && c != '\n' && c != '\t' {
            i += 1;
            continue;
        }
        result.push(c);
        i += 1;
    }

    result
}

// ============================================================
// 公共函数 - RTSP 探测
// ============================================================

/// RTSP 流媒体地址探测
pub fn rtsp_probe(config: RtspProbeConfig) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<RtspResult, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let addr = format!("{}:{}", config.host, config.port);
        let mut stream = TcpStream::connect_timeout(
            &addr.to_socket_addrs_first().ok_or("无法解析 RTSP 地址")?,
            Duration::from_millis(config.timeout_ms),
        )
        .map_err(|e| format!("RTSP 连接失败: {}", e))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|e| format!("设置读超时失败: {}", e))?;

        let rtsp_url = format!("rtsp://{}:{}{}", config.host, config.port, config.path);
        let cseq = rand::random::<u16>();

        // 构建 OPTIONS 请求（探测 RTSP 服务是否可用）
        let mut request = format!("OPTIONS {} RTSP/1.0\r\n", rtsp_url);
        request.push_str(&format!("CSeq: {}\r\n", cseq));

        if config.username.is_some() && config.password.is_some() {
            // 简单 Basic auth（RTSP 也用 HTTP 风格的 auth）
            let auth = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!(
                    "{}:{}",
                    config.username.as_deref().unwrap_or(""),
                    config.password.as_deref().unwrap_or("")
                ),
            );
            request.push_str(&format!("Authorization: Basic {}\r\n", auth));
        }

        request.push_str("User-Agent: NETON-DeviceAPI/1.0\r\n");
        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("发送 RTSP OPTIONS 失败: {}", e))?;

        // 读取响应
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    // 检查响应头是否完整（\r\n\r\n）
                    let resp_str = String::from_utf8_lossy(&response);
                    if resp_str.contains("\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
            if response.len() > 65536 {
                break;
            }
        }

        let resp_text = String::from_utf8_lossy(&response).to_string();
        let mut lines = resp_text.lines();
        let status_line = lines.next().unwrap_or("");

        // 解析状态码
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        let status_code = if parts.len() >= 2 {
            parts[1].parse::<u16>().ok()
        } else {
            None
        };

        let status_text = if parts.len() >= 3 {
            parts[2..].join(" ")
        } else {
            String::new()
        };

        // 如果 401 Unauthorized，尝试带认证再请求 DESCRIBE
        let mut sdp = None;
        let mut accessible = status_code.is_some();

        if status_code == Some(200) || status_code == Some(401) {
            // 尝试 DESCRIBE 获取 SDP
            let cseq2 = cseq + 1;
            let mut describe_req = format!("DESCRIBE {} RTSP/1.0\r\n", rtsp_url);
            describe_req.push_str(&format!("CSeq: {}\r\n", cseq2));
            describe_req.push_str("Accept: application/sdp\r\n");

            if config.username.is_some() && config.password.is_some() {
                let auth = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!(
                        "{}:{}",
                        config.username.as_deref().unwrap_or(""),
                        config.password.as_deref().unwrap_or("")
                    ),
                );
                describe_req.push_str(&format!("Authorization: Basic {}\r\n", auth));
            }

            describe_req.push_str("User-Agent: NETON-DeviceAPI/1.0\r\n");
            describe_req.push_str("\r\n");

            let _ = stream.write_all(describe_req.as_bytes());

            let mut desc_resp = Vec::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        desc_resp.extend_from_slice(&buf[..n]);
                        let desc_str = String::from_utf8_lossy(&desc_resp);
                        if desc_str.contains("\r\n\r\n") {
                            // 检查 Content-Length 决定是否继续读 body
                            if let Some(cl) = get_content_length(&desc_str) {
                                let header_end = desc_str.find("\r\n\r\n").unwrap() + 4;
                                if desc_resp.len() >= header_end + cl {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
                if desc_resp.len() > 65536 {
                    break;
                }
            }

            let desc_text = String::from_utf8_lossy(&desc_resp).to_string();
            let desc_lines: Vec<&str> = desc_text.lines().collect();
            if let Some(first_line) = desc_lines.first() {
                let dp: Vec<&str> = first_line.split_whitespace().collect();
                if dp.len() >= 2 {
                    if let Ok(code) = dp[1].parse::<u16>() {
                        if code == 200 {
                            accessible = true;
                            // 提取 SDP
                            if let Some(body_start) = desc_text.find("\r\n\r\n") {
                                sdp = Some(desc_text[body_start + 4..].trim().to_string());
                            }
                        }
                    }
                }
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(RtspResult {
            rtsp_url,
            status_code,
            status_text,
            sdp,
            response_time_ms: elapsed,
            accessible,
            error: None,
        })
    })();

    let api_result = match result {
        Ok(r) => {
            add_to_history(RequestHistoryItem {
                id: uuid::Uuid::new_v4().to_string(),
                request_type: "rtsp".to_string(),
                method: "PROBE".to_string(),
                target: format!("{}:{}", config.host, config.port),
                timestamp: chrono::Utc::now().timestamp(),
                status: if r.accessible { "OK" } else { "FAILED" }.to_string(),
                response_time_ms: r.response_time_ms,
                request_snapshot: serde_json::to_string(&config).unwrap_or_default(),
            });
            DeviceApiResult::ok(r, "RTSP 探测完成")
        }
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

fn get_content_length(response: &str) -> Option<usize> {
    for line in response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            let val = line.split(':').nth(1)?.trim();
            return val.parse::<usize>().ok();
        }
    }
    None
}

// ============================================================
// 公共函数 - 请求历史
// ============================================================

/// 添加到历史记录
fn add_to_history(item: RequestHistoryItem) {
    if let Ok(mut history) = REQUEST_HISTORY.lock() {
        history.insert(0, item);
        if history.len() > MAX_HISTORY_SIZE {
            history.truncate(MAX_HISTORY_SIZE);
        }
    }
}

/// 获取请求历史
pub fn get_request_history(filter: Option<HistoryFilter>) -> Result<String, String> {
    let result = (|| -> Result<Vec<RequestHistoryItem>, String> {
        let history = REQUEST_HISTORY
            .lock()
            .map_err(|e| format!("获取历史锁失败: {}", e))?;

        let mut filtered: Vec<RequestHistoryItem> = history.clone();

        if let Some(f) = filter {
            if let Some(req_type) = &f.request_type {
                filtered.retain(|item| item.request_type == *req_type);
            }
            if let Some(method) = &f.method {
                filtered.retain(|item| item.method.to_lowercase().contains(&method.to_lowercase()));
            }
            if let Some(keyword) = &f.keyword {
                let kw = keyword.to_lowercase();
                filtered.retain(|item| {
                    item.target.to_lowercase().contains(&kw)
                        || item.method.to_lowercase().contains(&kw)
                        || item.request_snapshot.to_lowercase().contains(&kw)
                });
            }
            if let Some(limit) = f.limit {
                filtered.truncate(limit);
            }
        }

        Ok(filtered)
    })();

    let api_result = match result {
        Ok(items) => DeviceApiResult::ok(items, "获取历史记录成功"),
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

/// 清空历史记录
pub fn clear_request_history() -> Result<String, String> {
    let result = (|| -> Result<(), String> {
        let mut history = REQUEST_HISTORY
            .lock()
            .map_err(|e| format!("获取历史锁失败: {}", e))?;
        history.clear();
        Ok(())
    })();

    let api_result = match result {
        Ok(()) => DeviceApiResult::ok(true, "历史记录已清空"),
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

// ============================================================
// 公共函数 - 设备模板
// ============================================================

/// 获取预设设备接口模板
pub fn get_device_templates() -> Result<String, String> {
    let templates = build_default_templates();
    let result = DeviceApiResult::ok(templates, "获取设备模板成功");
    to_json_result(&result)
}

fn build_default_templates() -> Vec<DeviceTemplate> {
    vec![
        // 海康威视摄像头
        DeviceTemplate {
            id: "hikvision-camera".to_string(),
            category: DeviceCategory::Camera,
            vendor: "海康威视".to_string(),
            model: "IP Camera (ISAPI)".to_string(),
            name: "海康威视摄像头 ISAPI".to_string(),
            description: "海康威视网络摄像头 ISAPI 接口集合，包含设备信息、通道、录像等常用接口".to_string(),
            default_host: "http://192.168.1.64".to_string(),
            requests: vec![
                TemplateRequestItem {
                    name: "获取设备信息".to_string(),
                    description: "获取摄像头基本设备信息".to_string(),
                    request_type: "http".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "http://192.168.1.64/ISAPI/System/deviceInfo".to_string(),
                        headers: vec![
                            ("Authorization".to_string(), "Basic YWRtaW46MTIzNDU=".to_string()),
                        ],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: Some(RawBodyFormat::Xml),
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "获取通道列表".to_string(),
                    description: "获取视频通道列表".to_string(),
                    request_type: "http".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "http://192.168.1.64/ISAPI/System/Video/inputs/channels".to_string(),
                        headers: vec![
                            ("Authorization".to_string(), "Basic YWRtaW46MTIzNDU=".to_string()),
                        ],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: Some(RawBodyFormat::Xml),
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "RTSP 地址探测".to_string(),
                    description: "探测摄像头 RTSP 流媒体地址".to_string(),
                    request_type: "rtsp".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "rtsp://192.168.1.64:554/Streaming/Channels/101".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 5000,
                        proxy: None,
                    },
                },
            ],
        },
        // 大华摄像头
        DeviceTemplate {
            id: "dahua-camera".to_string(),
            category: DeviceCategory::Camera,
            vendor: "大华".to_string(),
            model: "IP Camera (HTTP API)".to_string(),
            name: "大华摄像头 HTTP API".to_string(),
            description: "大华网络摄像头 HTTP API 接口集合".to_string(),
            default_host: "http://192.168.1.108".to_string(),
            requests: vec![
                TemplateRequestItem {
                    name: "获取设备类型".to_string(),
                    description: "获取大华摄像头设备类型信息".to_string(),
                    request_type: "http".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "http://192.168.1.108/cgi-bin/magicBox.cgi".to_string(),
                        headers: vec![],
                        params: vec![("action".to_string(), "getDeviceType".to_string())],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "获取软件版本".to_string(),
                    description: "获取软件版本信息".to_string(),
                    request_type: "http".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "http://192.168.1.108/cgi-bin/magicBox.cgi".to_string(),
                        headers: vec![],
                        params: vec![("action".to_string(), "getSoftwareVersion".to_string())],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
            ],
        },
        // ONVIF 通用摄像头
        DeviceTemplate {
            id: "onvif-camera".to_string(),
            category: DeviceCategory::Camera,
            vendor: "ONVIF".to_string(),
            model: "ONVIF Profile S".to_string(),
            name: "ONVIF 通用摄像头".to_string(),
            description: "ONVIF 协议通用摄像头接口，适用于支持 ONVIF 的网络摄像头".to_string(),
            default_host: "http://192.168.1.100:8080".to_string(),
            requests: vec![
                TemplateRequestItem {
                    name: "GetDeviceInformation".to_string(),
                    description: "ONVIF 获取设备信息".to_string(),
                    request_type: "http".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Post,
                        url: "http://192.168.1.100:8080/onvif/device_service".to_string(),
                        headers: vec![
                            ("Content-Type".to_string(), "application/soap+xml".to_string()),
                        ],
                        params: vec![],
                        body_type: BodyType::Raw,
                        raw_body: Some(r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Body>
    <tds:GetDeviceInformation/>
  </soap:Body>
</soap:Envelope>"#.to_string()),
                        raw_format: Some(RawBodyFormat::Xml),
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "GetProfiles".to_string(),
                    description: "ONVIF 获取媒体配置文件".to_string(),
                    request_type: "http".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Post,
                        url: "http://192.168.1.100:8080/onvif/Media".to_string(),
                        headers: vec![
                            ("Content-Type".to_string(), "application/soap+xml".to_string()),
                        ],
                        params: vec![],
                        body_type: BodyType::Raw,
                        raw_body: Some(r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
  <soap:Body>
    <trt:GetProfiles/>
  </soap:Body>
</soap:Envelope>"#.to_string()),
                        raw_format: Some(RawBodyFormat::Xml),
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
            ],
        },
        // OpenWrt 路由器
        DeviceTemplate {
            id: "openwrt-router".to_string(),
            category: DeviceCategory::Router,
            vendor: "OpenWrt".to_string(),
            model: "LuCI / UCI".to_string(),
            name: "OpenWrt 路由器".to_string(),
            description: "OpenWrt 路由器管理接口，包含 LuCI Web 和 UCI 命令行".to_string(),
            default_host: "http://192.168.1.1".to_string(),
            requests: vec![
                TemplateRequestItem {
                    name: "LuCI 登录".to_string(),
                    description: "OpenWrt LuCI 登录接口".to_string(),
                    request_type: "http".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Post,
                        url: "http://192.168.1.1/cgi-bin/luci".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::XWwwFormUrlencoded,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: Some(vec![
                            ("luci_username".to_string(), "root".to_string()),
                            ("luci_password".to_string(), "password".to_string()),
                        ]),
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "SSH 登录执行命令".to_string(),
                    description: "通过 SSH 执行 OpenWrt 命令".to_string(),
                    request_type: "ssh".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "ssh://192.168.1.1:22".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
            ],
        },
        // MikroTik 路由器
        DeviceTemplate {
            id: "mikrotik-router".to_string(),
            category: DeviceCategory::Router,
            vendor: "MikroTik".to_string(),
            model: "RouterOS".to_string(),
            name: "MikroTik 路由器".to_string(),
            description: "MikroTik RouterOS 管理接口，支持 API 和 Telnet/SSH".to_string(),
            default_host: "192.168.88.1".to_string(),
            requests: vec![
                TemplateRequestItem {
                    name: "API 登录".to_string(),
                    description: "MikroTik API 登录 (端口 8728)".to_string(),
                    request_type: "telnet".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "192.168.88.1:8728".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 5000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "SNMP 系统信息".to_string(),
                    description: "通过 SNMP 获取 RouterOS 系统信息".to_string(),
                    request_type: "snmp".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "192.168.88.1:161".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 3000,
                        proxy: None,
                    },
                },
            ],
        },
        // 工业 PLC - Modbus
        DeviceTemplate {
            id: "modbus-plc".to_string(),
            category: DeviceCategory::Plc,
            vendor: "通用".to_string(),
            model: "Modbus TCP".to_string(),
            name: "工业 PLC (Modbus TCP)".to_string(),
            description: "通用 Modbus TCP 工业 PLC 寄存器读写模板，适用于支持 Modbus TCP 的 PLC、变频器、仪表等设备".to_string(),
            default_host: "192.168.1.100:502".to_string(),
            requests: vec![
                TemplateRequestItem {
                    name: "读保持寄存器 40001-40010".to_string(),
                    description: "读取保持寄存器 (功能码 0x03)，地址 0-9".to_string(),
                    request_type: "modbus".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "modbus://192.168.1.100:502".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 5000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "读输入寄存器 30001-30010".to_string(),
                    description: "读取输入寄存器 (功能码 0x04)，地址 0-9".to_string(),
                    request_type: "modbus".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "modbus://192.168.1.100:502".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 5000,
                        proxy: None,
                    },
                },
            ],
        },
        // 智能设备 MQTT
        DeviceTemplate {
            id: "smart-device-mqtt".to_string(),
            category: DeviceCategory::SmartDevice,
            vendor: "通用".to_string(),
            model: "MQTT IoT".to_string(),
            name: "智能设备 (MQTT)".to_string(),
            description: "通用 MQTT 智能设备模板，适用于 ESP32、智能家居传感器等支持 MQTT 的设备".to_string(),
            default_host: "mqtt://broker.hivemq.com:1883".to_string(),
            requests: vec![
                TemplateRequestItem {
                    name: "发布控制命令".to_string(),
                    description: "向设备发送控制命令".to_string(),
                    request_type: "mqtt".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Post,
                        url: "mqtt://broker.hivemq.com:1883".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::Raw,
                        raw_body: Some(r#"{"command":"on","device":"light_01"}"#.to_string()),
                        raw_format: Some(RawBodyFormat::Json),
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 5000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "订阅状态上报".to_string(),
                    description: "订阅设备状态上报主题".to_string(),
                    request_type: "mqtt".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "mqtt://broker.hivemq.com:1883".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
            ],
        },
        // 网络交换机 SNMP
        DeviceTemplate {
            id: "network-switch-snmp".to_string(),
            category: DeviceCategory::Switch,
            vendor: "通用".to_string(),
            model: "SNMP v2c".to_string(),
            name: "网络交换机 (SNMP)".to_string(),
            description: "通用网络交换机 SNMP 管理模板，适用于支持 SNMP 的交换机、路由器等网络设备".to_string(),
            default_host: "192.168.1.254:161".to_string(),
            requests: vec![
                TemplateRequestItem {
                    name: "系统描述 (sysDescr)".to_string(),
                    description: "获取系统描述信息 OID: 1.3.6.1.2.1.1.1.0".to_string(),
                    request_type: "snmp".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "192.168.1.254:161".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 3000,
                        proxy: None,
                    },
                },
                TemplateRequestItem {
                    name: "接口列表 (ifTable)".to_string(),
                    description: "Walk 获取所有接口信息 OID: 1.3.6.1.2.1.2.2.1".to_string(),
                    request_type: "snmp".to_string(),
                    request: DeviceApiRequest {
                        method: HttpMethod::Get,
                        url: "192.168.1.254:161".to_string(),
                        headers: vec![],
                        params: vec![],
                        body_type: BodyType::None,
                        raw_body: None,
                        raw_format: None,
                        form_data: None,
                        form_urlencoded: None,
                        timeout_ms: 10000,
                        proxy: None,
                    },
                },
            ],
        },
    ]
}

// ============================================================
// 公共函数 - 压力测试
// ============================================================

/// 压力测试
pub fn stress_test(config: StressTestConfig) -> Result<String, String> {
    let start = Instant::now();

    let result = (|| -> Result<StressTestResult, String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let concurrency = config.concurrency.max(1);
        let total_requests = config.total_requests;
        let duration_seconds = config.duration_seconds;

        let success_count = Arc::new(AtomicU64::new(0));
        let fail_count = Arc::new(AtomicU64::new(0));
        let total_count = Arc::new(AtomicU64::new(0));

        // 收集响应时间
        let response_times: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let error_map: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));

        let mut handles = Vec::new();

        for _ in 0..concurrency {
            let req = config.request.clone();
            let success = Arc::clone(&success_count);
            let fail = Arc::clone(&fail_count);
            let total = Arc::clone(&total_count);
            let times = Arc::clone(&response_times);
            let errors = Arc::clone(&error_map);
            let interval = config.interval_ms;
            let total_limit = total_requests;
            let duration = duration_seconds;
            let thread_start = start;

            let handle = std::thread::spawn(move || {
                let client_builder = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_millis(req.timeout_ms))
                    .danger_accept_invalid_certs(true)
                    .pool_max_idle_per_host(10);

                let client = match client_builder.build() {
                    Ok(c) => c,
                    Err(_) => return,
                };

                loop {
                    // 检查是否达到总数限制
                    if total_limit > 0 && total.load(Ordering::Relaxed) >= total_limit {
                        break;
                    }

                    // 检查是否达到时间限制
                    if duration > 0 && thread_start.elapsed().as_secs() >= duration {
                        break;
                    }

                    let req_start = Instant::now();

                    let result = send_single_request(&client, &req);
                    let elapsed = req_start.elapsed().as_millis() as u64;

                    total.fetch_add(1, Ordering::Relaxed);

                    match result {
                        Ok(_) => {
                            success.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            fail.fetch_add(1, Ordering::Relaxed);
                            if let Ok(mut err_map) = errors.lock() {
                                let err_key = if e.len() > 100 {
                                    e[..100].to_string()
                                } else {
                                    e
                                };
                                *err_map.entry(err_key).or_insert(0) += 1;
                            }
                        }
                    }

                    if let Ok(mut times_lock) = times.lock() {
                        times_lock.push(elapsed);
                    }

                    if interval > 0 {
                        std::thread::sleep(Duration::from_millis(interval));
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        let total_duration = start.elapsed();
        let total_req = total_count.load(Ordering::Relaxed);
        let succ = success_count.load(Ordering::Relaxed);
        let failed = fail_count.load(Ordering::Relaxed);

        let success_rate = if total_req > 0 {
            (succ as f64 / total_req as f64) * 100.0
        } else {
            0.0
        };

        let qps = if total_duration.as_secs_f64() > 0.0 {
            total_req as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };

        // 计算响应时间统计
        let mut all_times = response_times.lock().unwrap().clone();
        all_times.sort();

        let (min_time, max_time, avg_time) = if !all_times.is_empty() {
            let min = *all_times.first().unwrap_or(&0);
            let max = *all_times.last().unwrap_or(&0);
            let avg: f64 = all_times.iter().sum::<u64>() as f64 / all_times.len() as f64;
            (min, max, avg)
        } else {
            (0, 0, 0.0)
        };

        // 计算响应时间分布（P50, P90, P95, P99）
        let mut distribution = HashMap::new();
        if !all_times.is_empty() {
            distribution.insert("p50".to_string(), percentile(&all_times, 50.0));
            distribution.insert("p90".to_string(), percentile(&all_times, 90.0));
            distribution.insert("p95".to_string(), percentile(&all_times, 95.0));
            distribution.insert("p99".to_string(), percentile(&all_times, 99.0));
            distribution.insert("min".to_string(), min_time);
            distribution.insert("max".to_string(), max_time);
        }

        let error_counts = error_map.lock().unwrap().clone();

        Ok(StressTestResult {
            total_requests: total_req,
            success_count: succ,
            fail_count: failed,
            success_rate,
            avg_response_time_ms: avg_time,
            min_response_time_ms: min_time,
            max_response_time_ms: max_time,
            qps,
            total_duration_seconds: total_duration.as_secs_f64(),
            response_time_distribution: distribution,
            error_counts,
            concurrency,
        })
    })();

    let api_result = match result {
        Ok(r) => DeviceApiResult::ok(r, "压力测试完成"),
        Err(e) => DeviceApiResult::error(&e),
    };

    to_json_result(&api_result)
}

fn send_single_request(
    client: &reqwest::blocking::Client,
    req: &DeviceApiRequest,
) -> Result<(), String> {
    let mut url = reqwest::Url::parse(&req.url).map_err(|e| e.to_string())?;

    if !req.params.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (k, v) in &req.params {
            pairs.append_pair(k, v);
        }
    }

    let mut request = client.request(req.method.to_reqwest_method(), url);

    for (k, v) in &req.headers {
        if !k.is_empty() {
            request = request.header(k, v);
        }
    }

    match req.body_type {
        BodyType::Raw => {
            if let Some(body) = &req.raw_body {
                request = request.body(body.clone());
            }
        }
        BodyType::XWwwFormUrlencoded => {
            if let Some(form) = &req.form_urlencoded {
                request = request.form(form);
            }
        }
        _ => {}
    }

    let resp = request.send().map_err(|e| e.to_string())?;
    let _ = resp.bytes();
    Ok(())
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ============================================================
// 兼容层：commands_netsec.rs 中使用的函数名别名 & 参数适配
// ============================================================

pub fn http_request(
    method: String,
    url: String,
    headers: String,
    body: String,
    body_type: String,
    params: String,
    timeout_ms: u32,
) -> Result<String, String> {
    let http_method = match method.to_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        _ => HttpMethod::Get,
    };

    let header_map: Vec<(String, String)> = if headers.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&headers).unwrap_or_default()
    };

    let param_map: Vec<(String, String)> = if params.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&params).unwrap_or_default()
    };

    let body_type_enum = match body_type.to_lowercase().as_str() {
        "form" | "form_data" | "multipart" => BodyType::FormData,
        "urlencoded" | "form_urlencoded" | "x-www-form-urlencoded" => BodyType::XWwwFormUrlencoded,
        "json" | "xml" | "text" | "raw" => BodyType::Raw,
        _ => BodyType::Raw,
    };

    let request = DeviceApiRequest {
        method: http_method,
        url,
        headers: header_map,
        params: param_map,
        body_type: body_type_enum,
        raw_body: if body.is_empty() { None } else { Some(body) },
        raw_format: None,
        form_data: None,
        form_urlencoded: None,
        timeout_ms: timeout_ms as u64,
        proxy: None,
    };

    send_http_request(request)
}

pub fn get_templates() -> Result<String, String> {
    get_device_templates()
}

pub fn modbus_read_simple(
    host: String,
    port: u16,
    slave_id: u8,
    function: u8,
    address: u16,
    count: u16,
) -> Result<String, String> {
    let func = match function {
        1 => ModbusFunction::ReadCoils,
        2 => ModbusFunction::ReadDiscreteInputs,
        3 => ModbusFunction::ReadHoldingRegisters,
        4 => ModbusFunction::ReadInputRegisters,
        _ => ModbusFunction::ReadHoldingRegisters,
    };

    let config = ModbusRequest {
        host,
        port,
        slave_id,
        function: func,
        address,
        count,
        timeout_ms: 5000,
    };

    modbus_read(config)
}

pub fn modbus_write_simple(
    host: String,
    port: u16,
    slave_id: u8,
    address: u16,
    value: u16,
) -> Result<String, String> {
    let config = ModbusRequest {
        host,
        port,
        slave_id,
        function: ModbusFunction::WriteSingleRegister,
        address,
        count: 1,
        timeout_ms: 5000,
    };

    modbus_write(config, value)
}

pub fn mqtt_publish_compat(
    broker: String,
    port: u16,
    client_id: String,
    username: String,
    password: String,
    topic: String,
    payload: String,
    qos: u8,
) -> Result<String, String> {
    let config = MqttConfig {
        broker,
        port,
        client_id,
        username: if username.is_empty() { None } else { Some(username) },
        password: if password.is_empty() { None } else { Some(password) },
        keep_alive: 60,
        timeout_ms: 5000,
    };

    mqtt_publish(config, topic, payload, qos)
}

pub fn mqtt_subscribe_compat(
    broker: String,
    port: u16,
    client_id: String,
    username: String,
    password: String,
    topic: String,
    timeout_ms: u64,
) -> Result<String, String> {
    let config = MqttConfig {
        broker,
        port,
        client_id,
        username: if username.is_empty() { None } else { Some(username) },
        password: if password.is_empty() { None } else { Some(password) },
        keep_alive: 60,
        timeout_ms: 5000,
    };

    mqtt_subscribe(config, topic, timeout_ms)
}

pub fn snmp_get_simple(
    host: String,
    community: String,
    oid: String,
    version: String,
) -> Result<String, String> {
    let ver = match version.to_lowercase().as_str() {
        "v1" | "1" => SnmpVersion::V1,
        "v2c" | "v2" | "2c" | "2" => SnmpVersion::V2c,
        "v3" | "3" => SnmpVersion::V3,
        _ => SnmpVersion::V2c,
    };

    let config = SnmpRequest {
        host,
        port: 161,
        community,
        oid,
        version: ver,
        timeout_ms: 5000,
        walk_max: 100,
    };

    snmp_get(config)
}

pub fn snmp_walk_simple(
    host: String,
    community: String,
    oid: String,
    version: String,
) -> Result<String, String> {
    let ver = match version.to_lowercase().as_str() {
        "v1" | "1" => SnmpVersion::V1,
        "v2c" | "v2" | "2c" | "2" => SnmpVersion::V2c,
        "v3" | "3" => SnmpVersion::V3,
        _ => SnmpVersion::V2c,
    };

    let config = SnmpRequest {
        host,
        port: 161,
        community,
        oid,
        version: ver,
        timeout_ms: 5000,
        walk_max: 100,
    };

    snmp_walk(config)
}

pub fn stress_test_compat(
    url: String,
    method: String,
    concurrent: u32,
    duration_sec: u32,
    headers: String,
    body: String,
) -> Result<String, String> {
    let http_method = match method.to_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        _ => HttpMethod::Get,
    };

    let header_map: Vec<(String, String)> = if headers.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&headers).unwrap_or_default()
    };

    let request = DeviceApiRequest {
        method: http_method,
        url,
        headers: header_map,
        params: Vec::new(),
        body_type: BodyType::Raw,
        raw_body: if body.is_empty() { None } else { Some(body) },
        raw_format: None,
        form_data: None,
        form_urlencoded: None,
        timeout_ms: 10000,
        proxy: None,
    };

    let config = StressTestConfig {
        request,
        concurrency: concurrent as usize,
        duration_seconds: duration_sec as u64,
        total_requests: 0,
        interval_ms: 0,
    };

    stress_test(config)
}
