# NETON — 网络安全分析工具集

> 开源 BIT 的网络安全分支 · AI 驱动的家庭/小型网络安全工具箱

[![Release](https://img.shields.io/github/v/release/yxpil/NETON?style=flat-square&label=版本)](https://github.com/yxpil/NETON/releases/latest)
[![License](https://img.shields.io/github/license/yxpil/NETON?style=flat-square)](https://github.com/yxpil/NETON/blob/main/LICENSE)
[![平台](https://img.shields.io/badge/平台-Windows%20·%20macOS%20·%20Linux-black?style=flat-square)](#安装使用)
[![基于 Tauri 2](https://img.shields.io/badge/基于-Tauri%202-FFC131?style=flat-square&logo=tauri)](https://tauri.app)

NETON 是一个基于 **Tauri 2 + React** 的桌面应用，聚焦网络安全分析与渗透测试。在 BIT 原有的 AI Agent 能力基础上，集成了 **20+ 网络安全工具**，支持 AI 对话调用安全工具进行自动化分析。从端口扫描到 Web 漏洞检测，从密码强度评估到 DNS 安全审计——NETON 把专业级安全能力装进一个轻量桌面应用，让家庭用户和小型团队也能轻松守护网络安全。

**NETON 永久免费**：完全开源（Apache-2.0），所有功能对个人与商业用户永久免费——无内购、无订阅、无功能锁、无遥测，可随时自行编译。

---

## 目录

[功能特性](#功能特性) · [AI 工具调用](#ai-工具调用) · [技术栈](#技术栈) · [安装使用](#安装使用) · [开发](#开发) · [项目结构](#项目结构) · [安全与隐私](#安全与隐私) · [许可](#许可)

---

## 功能特性

### 🤖 AI 安全助手

让 AI 成为你的安全分析搭档，用自然语言驱动专业安全工具。

- **流式 AI 对话**：支持 OpenAI / Gemini / Claude 等多模型提供商，前后端全链路流式响应
- **Function Calling**：AI 可直接调用 10+ 安全工具，无需手动操作
- **自动化安全分析**：输入目标，AI 自动编排工具链完成扫描 → 分析 → 报告生成
- **多模态输入**：支持图片上传，可用于验证码识别、截图分析等场景
- **审计留痕**：所有 AI 工具调用全程记录，可回溯可审查

---

### 🔍 网络扫描与探测

快速摸清网络拓扑与设备状况，发现潜在风险点。

- **端口扫描**：TCP 全连接扫描 / 快速扫描模式，内置 28+ 常见服务指纹识别
- **ARP 设备扫描**：局域网设备自动发现，MAC 地址厂商识别，设备清单一键导出
- **网络拓扑分析**：路由追踪可视化，节点图谱展示网络路径
- **NAT 类型分析**：基于 STUN 协议，支持 6 种 NAT 类型判定（Full Cone / Restricted / Port Restricted / Symmetric 等）

---

### 💻 Web 安全测试

一站式 Web 应用安全检测，覆盖 OWASP Top 10 常见漏洞。

- **Web 漏洞扫描**：内置 XSS / CSRF / SQLi / LFI / RFI / XXE / SSRF / 点击劫持 / 命令注入 等 9 种漏洞检测引擎
- **SQL 注入测试**：5 种检测类型（布尔盲注 / 时间盲注 / 报错注入 / 联合查询 / 堆叠查询），多种 payload 策略
- **网页分析**：链接提取、表单分析、安全响应头检测、技术栈指纹识别
- **网络爬虫**：BFS / DFS 双模式爬取，死链接检测，网站结构自动梳理
- **站点情报**：CMS 识别、服务器指纹、SSL 证书分析、综合安全评分

---

### 🔐 密码与加密

密码安全评估与加解密工具箱，覆盖哈希、编码、加密等常用场景。

- **密码爆破**：支持 SSH / FTP / HTTP Basic Auth，内置 80+ 常用字典
- **弱口令分析**：6 级强度评估算法，100+ 万弱密码库实时比对
- **哈希计算**：MD5 / SHA1 / SHA256 / SHA512 / SHA3 / BLAKE2 等 10+ 种算法
- **哈希破解**：字典攻击 + 暴力破解（可配置字符集与长度范围）
- **编码/解码**：Base64 / Hex / URL / Unicode / 凯撒密码 / 摩斯密码 / 栅栏密码 / Atbash 等 13 种
- **对称加密**：AES（ECB/CBC/CFB/OFB/CTR）、XOR 加密解密
- **随机数生成**：密码学安全随机数、密码生成器

---

### 🌐 域名与 DNS 安全

全面的域名资产分析与 DNS 安全检测。

- **域名分析**：DNS 记录查询（A/AAAA/CNAME/MX/TXT/NS/SOA/PTR）、WHOIS 信息查询、子域名枚举
- **DNS 速度测试**：多 DNS 服务器响应速度对比
- **DNS 泄露检测**：检测真实 DNS 请求是否泄露
- **DNS 投毒检测**：比对多个 DNS 源的解析结果一致性
- **DNSSEC 验证**：检查域名 DNSSEC 签名有效性
- **邮件安全**：SPF / DKIM / DMARC 记录检测与安全评级
- **DNS 隧道检测**：异常 DNS 流量特征识别

---

### 📡 设备接入与协议

多种网络协议调试工具，覆盖 Web、IoT、工业设备。

- **HTTP 请求调试**：类 Postman 体验，支持 GET/POST/PUT/DELETE 等方法、自定义 Header、Body 格式（JSON/Form/XML）
- **Modbus TCP**：工业设备寄存器读写，适用于 PLC / 工控设备调试
- **MQTT**：IoT 设备消息发布订阅调试，支持 QoS 0/1/2
- **SNMP**：网络设备信息查询（OID 读取、WALK 遍历）
- **SSH / Telnet**：远程命令执行，批量脚本执行
- **RTSP 摄像头探测**：局域网 RTSP 摄像头发现与流地址探测

---

### 📊 数据包与系统

底层网络数据包分析与系统安全工具。

- **网络接口列表**：网卡信息、IP 地址、MAC 地址、流量统计
- **数据包捕获分析**：实时抓包，协议分布统计，DNS / HTTP 请求提取
- **ARP 欺骗检测**：监控局域网 ARP 响应，检测中间人攻击
- **防火墙规则测试**：出站 / 入站端口连通性测试，防火墙策略审计
- **病毒特征匹配**：多哈希校验 + 特征码匹配，快速检测可疑文件

---

### 🛡️ 其他安全工具

实用安全小工具合集。

- **CVE 漏洞搜索**：本地漏洞库 + NVD API 双源查询，按严重程度分级
- **验证码识别**：支持多种常见验证码类型（数字字母 / 滑块 / 点选等）
- **虚拟浏览器**：Headless 浏览器自动化，支持页面截图、Cookie 操作
- **文件格式识别**：基于文件头魔数的真实格式检测，识破伪装扩展名

---

## AI 工具调用

NETON 的核心特色在于 **AI 与安全工具的深度融合**。你不需要记住每个工具的参数，只需用自然语言描述你的需求，AI 会自动选择合适的工具并执行。

**举个例子：**

> **你说**：帮我扫描一下 `example.com` 这个网站有什么漏洞

**AI 会自动执行：**
1. 调用「端口扫描」→ 发现开放端口与服务
2. 调用「站点情报」→ 识别 CMS 与服务器指纹
3. 调用「Web 漏洞扫描」→ 检测 XSS / SQLi 等常见漏洞
4. 调用「网页分析」→ 提取链接与表单，分析安全头
5. 汇总结果 → 生成结构化安全报告

**更多场景：**

- 「帮我看看我家局域网里都有什么设备」→ ARP 设备扫描
- 「测试一下这个密码强度怎么样」→ 弱口令分析
- 「查一下这个域名的 DNS 记录」→ 域名分析
- 「计算一下这个字符串的 MD5 和 SHA256」→ 哈希计算
- 「这个 Base64 帮我解码」→ 编码/解码

---

## 技术栈

| 层 | 技术 |
|----|------|
| 前端 | React 18、Vite 6、Tailwind CSS 4 |
| 桌面 | Tauri 2（Rust） |
| 后端 | reqwest、tokio、scraper、trust-dns |
| AI | 多提供商（OpenAI / Gemini / Claude 协议） |

---

## 安装使用

### 下载安装

从 [Releases](https://github.com/yxpil/NETON/releases) 下载对应平台的安装包：

| 平台 | 安装包 | 说明 |
|---|---|---|
| Windows x64 | `*-setup.exe` 或 `*.msi` | 双击安装即可 |
| macOS Apple Silicon | `*_aarch64.dmg` | M 系列芯片，拖入 Applications |
| macOS Intel | `*_x64.dmg` | 拖入 Applications 安装 |
| Linux x64 | `*.deb` / `*.AppImage` / `*.rpm` | 按发行版习惯选择 |

### 首次使用

1. 打开 NETON，进入「AI 设置」页面
2. 添加一个 AI 提供商（协议 / Base URL / API Key / 模型）
3. 点击激活按钮启用
4. 回到「对话」或「安全工具」页面开始使用

> 提示：安全工具可独立使用，无需配置 AI；AI 对话功能需要配置模型提供商。

---

## 开发

前置要求：[Node.js](https://nodejs.org/)、[Rust](https://www.rust-lang.org/) 工具链、Tauri 系统依赖。

```bash
npm install          # 安装前端依赖
npm run tauri dev    # 开发模式（热更新）
npm run tauri build  # 构建 release 版本
```

---

## 项目结构

```
src/                    React 前端
  pages/               对话 / AI 设置 / 安全工具 / 主题
  components/netsec/   21 个安全工具组件
src-tauri/             Tauri (Rust) 后端
  src/netsec/          16 个网络安全模块
  src/ai.rs            AI 引擎与工具调用
  src/registry.rs      工具注册与分发
```

---

## 安全与隐私

- **数据本地化**：所有扫描数据、会话记录、配置信息全部保存在本机，无任何遥测上传
- **工具调用审计**：每一次工具调用都有完整日志，可在审计页面回溯
- **AI 工具审批**：可配置 AI 调用工具前需要人工确认，防止误操作
- **沙箱执行**：部分高危操作在受限环境中运行，降低安全风险

---

## 许可

[Apache License 2.0](LICENSE) — **NETON 永久免费**：所有功能无内购、无订阅、无功能锁，个人与商业使用均免费。
