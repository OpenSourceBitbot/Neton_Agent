// yxpil · NETON
//! 网络拓扑分析工具
//! 路由追踪、节点发现

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 路由追踪配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteConfig {
    /// 目标地址
    pub target: String,
    /// 最大跳数
    pub max_hops: u8,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
    /// 每跳探测次数
    pub probes_per_hop: u8,
    /// 起始 TTL
    pub start_ttl: u8,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            target: "8.8.8.8".to_string(),
            max_hops: 30,
            timeout_ms: 2000,
            probes_per_hop: 3,
            start_ttl: 1,
        }
    }
}

/// 路由跳点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInfo {
    pub hop: u8,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub response_times_ms: Vec<f64>,
    pub avg_time_ms: f64,
    pub loss_rate: f32,
    pub is_timeout: bool,
}

/// 路由追踪结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    pub target: String,
    pub target_ip: Option<String>,
    pub total_hops: u8,
    pub hops: Vec<HopInfo>,
    pub reached_target: bool,
    pub duration_ms: u64,
}

/// 网络节点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub node_type: NodeType,
    pub location: Option<String>,
    pub isp: Option<String>,
    pub latency_ms: f64,
    pub is_alive: bool,
}

/// 节点类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    Local,
    Gateway,
    Router,
    Server,
    Firewall,
    Unknown,
}

/// 网络拓扑图
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub nodes: Vec<NetworkNode>,
    pub edges: Vec<TopologyEdge>,
    pub local_ip: String,
    pub gateway_ip: Option<String>,
}

/// 拓扑边
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub from: String,
    pub to: String,
    pub latency_ms: f64,
    pub hop_count: u8,
}

/// 执行路由追踪（概念性实现）
/// 实际实现需要使用 ICMP 或 UDP 包并设置 TTL
pub async fn traceroute(config: TracerouteConfig) -> Result<String, String> {
    let start_time = std::time::Instant::now();
    let mut hops = Vec::new();
    let mut reached_target = false;

    // 解析目标 IP
    let target_ip = match tokio::net::lookup_host(format!("{}:0", config.target)).await {
        Ok(mut addrs) => addrs.next().map(|a| a.ip().to_string()),
        Err(_) => None,
    };

    // 概念性实现：模拟路由追踪
    // 实际实现需要使用原始套接字发送 ICMP Echo Request 并递增 TTL
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // 模拟跳点数据
    let simulated_hops = std::cmp::min(config.max_hops, 15);

    for hop in config.start_ttl..=simulated_hops {
        let mut response_times = Vec::new();
        let mut timeouts = 0;

        for _ in 0..config.probes_per_hop {
            // 模拟响应时间（随跳数增加而增加）
            let base_time = (hop as f64) * 5.0 + rng.gen_range(1.0..10.0);
            let jitter = rng.gen_range(-2.0..5.0);
            let response_time = (base_time + jitter).max(0.1);

            // 模拟偶尔超时
            if rng.gen_range(0..100) < 10 {
                timeouts += 1;
            } else {
                response_times.push(response_time);
            }
        }

        let avg_time = if response_times.is_empty() {
            0.0
        } else {
            response_times.iter().sum::<f64>() / response_times.len() as f64
        };

        let loss_rate = (timeouts as f32) / (config.probes_per_hop as f32) * 100.0;

        // 生成模拟 IP
        let ip = if hop == simulated_hops {
            reached_target = true;
            target_ip.clone()
        } else if timeouts == config.probes_per_hop {
            None
        } else {
            Some(format!(
                "10.{}.{}.{}",
                hop,
                rng.gen_range(0..255),
                rng.gen_range(1..254)
            ))
        };

        hops.push(HopInfo {
            hop,
            ip,
            hostname: None,
            response_times_ms: response_times,
            avg_time_ms: avg_time,
            loss_rate,
            is_timeout: timeouts == config.probes_per_hop,
        });

        if reached_target {
            break;
        }
    }

    let result = TracerouteResult {
        target: config.target,
        target_ip,
        total_hops: hops.len() as u8,
        hops,
        reached_target,
        duration_ms: start_time.elapsed().as_millis() as u64,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(
        result,
        "路由追踪完成（概念性实现，数据为模拟）",
    ))
    .map_err(|e| format!("序列化失败: {}", e))
}

/// 获取本机网络拓扑信息
pub async fn get_local_topology() -> Result<String, String> {
    use if_addrs::get_if_addrs;

    let interfaces = get_if_addrs().map_err(|e| format!("获取网络接口失败: {}", e))?;

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut local_ip = String::new();
    let mut gateway_ip = None;

    for (idx, iface) in interfaces.iter().enumerate() {
        let ip = iface.ip().to_string();
        let node_id = format!("node_{}", idx);

        if iface.is_loopback() {
            continue;
        }

        if ip.starts_with("192.168.") || ip.starts_with("10.") || ip.starts_with("172.") {
            local_ip = ip.clone();

            // 猜测网关地址（通常为网络的第一个地址）
            if let if_addrs::IfAddr::V4(v4) = &iface.addr {
                let octets = v4.ip.octets();
                let gw = format!("{}.{}.{}.1", octets[0], octets[1], octets[2]);
                gateway_ip = Some(gw.clone());

                // 添加网关节点
                nodes.push(NetworkNode {
                    id: "gateway".to_string(),
                    ip: gw,
                    hostname: Some("Gateway".to_string()),
                    node_type: NodeType::Gateway,
                    location: None,
                    isp: None,
                    latency_ms: 1.0,
                    is_alive: true,
                });

                // 添加本地到网关的边
                edges.push(TopologyEdge {
                    from: node_id.clone(),
                    to: "gateway".to_string(),
                    latency_ms: 1.0,
                    hop_count: 1,
                });
            }
        }

        nodes.push(NetworkNode {
            id: node_id,
            ip: ip.clone(),
            hostname: Some(iface.name.clone()),
            node_type: NodeType::Local,
            location: None,
            isp: None,
            latency_ms: 0.0,
            is_alive: true,
        });
    }

    let topology = NetworkTopology {
        nodes,
        edges,
        local_ip,
        gateway_ip,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(topology, "本地拓扑获取完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// Ping 测试
pub async fn ping(target: String, count: u32, timeout_ms: u64) -> Result<String, String> {
    let start_time = std::time::Instant::now();
    let mut results = Vec::new();
    let mut success_count = 0;
    let mut total_time = 0.0;
    let mut min_time = f64::MAX;
    let mut max_time = 0.0f64;

    // 使用 TCP 连接到常见端口作为存活检测（概念性替代 ping）
    for i in 0..count {
        let probe_start = std::time::Instant::now();
        let target_clone = target.clone();

        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            tokio::net::TcpStream::connect(format!("{}:80", target_clone)),
        )
        .await;

        let elapsed = probe_start.elapsed().as_secs_f64() * 1000.0;

        let success = result.is_ok() && result.unwrap().is_ok();

        if success {
            success_count += 1;
            total_time += elapsed;
            min_time = min_time.min(elapsed);
            max_time = max_time.max(elapsed);
        }

        results.push(serde_json::json!({
            "seq": i + 1,
            "success": success,
            "time_ms": elapsed,
        }));
    }

    let loss_rate = if count > 0 {
        (count - success_count) as f32 / count as f32 * 100.0
    } else {
        0.0
    };

    let avg_time = if success_count > 0 {
        total_time / success_count as f64
    } else {
        0.0
    };

    let ping_result = serde_json::json!({
        "target": target,
        "count": count,
        "success": success_count,
        "loss_rate": loss_rate,
        "min_time_ms": if success_count > 0 { min_time } else { 0.0 },
        "max_time_ms": if success_count > 0 { max_time } else { 0.0 },
        "avg_time_ms": avg_time,
        "results": results,
        "duration_ms": start_time.elapsed().as_millis() as u64,
        "note": "使用 TCP 80 端口探测（概念性实现，非真实 ICMP ping）",
    });

    serde_json::to_string(&crate::netsec::ToolResult::ok(ping_result, "Ping 测试完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}
