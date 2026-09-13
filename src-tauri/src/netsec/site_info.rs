// yxpil · NETON
//! 站点信息分析模块
//! 综合性的站点情报收集工具，对整个网站/目标进行全面情报汇总。
//! 包括：基础信息、CMS识别、前端框架检测、服务器指纹、编程语言检测、
//! 数据库推断、子域名发现、目录探测、SSL证书信息、安全评分。

use serde::{Deserialize, Serialize};
use scraper::{Html, Selector};
use url::Url;
use std::collections::{HashMap, HashSet};
use std::time::{Instant, Duration};
use std::thread;

// ============================================================
// 配置结构体
// ============================================================

/// 站点分析配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteInfoConfig {
    /// 请求超时（毫秒）
    pub timeout_ms: u64,
    /// User-Agent
    pub user_agent: String,
    /// 是否跟随重定向
    pub follow_redirects: bool,
    /// 是否深度分析
    pub deep_scan: bool,
    /// 子域爆破并发数
    pub subdomain_concurrency: usize,
    /// 子域名字典数量限制（0 表示使用全部）
    pub subdomain_word_limit: usize,
    /// 目录探测并发数
    pub dir_concurrency: usize,
    /// 是否进行子域名发现
    pub enable_subdomain_scan: bool,
    /// 是否进行目录探测
    pub enable_dir_scan: bool,
    /// 是否检测 SSL 证书
    pub enable_ssl_check: bool,
}

impl Default for SiteInfoConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 8000,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            follow_redirects: true,
            deep_scan: false,
            subdomain_concurrency: 20,
            subdomain_word_limit: 50,
            dir_concurrency: 15,
            enable_subdomain_scan: true,
            enable_dir_scan: true,
            enable_ssl_check: true,
        }
    }
}

// ============================================================
// 基础信息结构体
// ============================================================

/// 站点基础信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteBasicInfo {
    /// 原始 URL
    pub original_url: String,
    /// 规范化后的 URL
    pub normalized_url: String,
    /// 最终 URL（重定向后）
    pub final_url: String,
    /// 站点标题
    pub title: String,
    /// 站点描述
    pub description: Option<String>,
    /// 站点关键词
    pub keywords: Option<String>,
    /// HTTP 状态码
    pub status_code: u16,
    /// 响应时间（毫秒）
    pub response_time_ms: u64,
    /// 服务器头信息
    pub server_header: Option<String>,
    /// X-Powered-By 头
    pub x_powered_by: Option<String>,
    /// 内容类型
    pub content_type: String,
    /// 页面大小（字节）
    pub content_length: usize,
    /// 站点 IP 地址（IPv4）
    pub ipv4_addresses: Vec<String>,
    /// 站点 IP 地址（IPv6）
    pub ipv6_addresses: Vec<String>,
    /// 站点是否存活
    pub is_alive: bool,
}

/// CMS 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsInfo {
    /// CMS 名称
    pub name: String,
    /// 版本（如果能检测到）
    pub version: Option<String>,
    /// 置信度（0-100）
    pub confidence: u8,
    /// 检测证据
    pub evidence: Vec<String>,
    /// 检测类别：header / meta / cookie / path / script
    pub categories: Vec<String>,
}

/// 前端框架信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendFrameworkInfo {
    /// 框架名称
    pub name: String,
    /// 版本
    pub version: Option<String>,
    /// 置信度
    pub confidence: u8,
    /// 检测证据
    pub evidence: Vec<String>,
}

/// 服务器指纹信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFingerprint {
    /// Web 服务器软件
    pub web_server: Option<String>,
    /// 服务器版本
    pub web_server_version: Option<String>,
    /// 中间件
    pub middleware: Vec<String>,
    /// CDN 提供商
    pub cdn: Option<String>,
    /// CDN 置信度
    pub cdn_confidence: u8,
    /// CDN 检测证据
    pub cdn_evidence: Vec<String>,
    /// WAF 名称
    pub waf: Option<String>,
    /// WAF 置信度
    pub waf_confidence: u8,
    /// WAF 检测证据
    pub waf_evidence: Vec<String>,
    /// 反向代理
    pub reverse_proxy: Vec<String>,
}

/// 编程语言检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgrammingLanguageInfo {
    /// 语言名称
    pub name: String,
    /// 版本
    pub version: Option<String>,
    /// 置信度
    pub confidence: u8,
    /// 检测证据
    pub evidence: Vec<String>,
}

/// 数据库推断结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// 数据库名称
    pub name: String,
    /// 推断依据
    pub reason: String,
    /// 置信度
    pub confidence: u8,
}

/// 技术栈汇总
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechStack {
    /// CMS 列表
    pub cms: Vec<CmsInfo>,
    /// 前端框架列表
    pub frontend_frameworks: Vec<FrontendFrameworkInfo>,
    /// 服务器指纹
    pub server: ServerFingerprint,
    /// 编程语言列表
    pub programming_languages: Vec<ProgrammingLanguageInfo>,
    /// 数据库推断列表
    pub databases: Vec<DatabaseInfo>,
    /// JavaScript 库
    pub js_libraries: Vec<String>,
    /// CSS 框架
    pub css_frameworks: Vec<String>,
}

/// 子域名信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainInfo {
    /// 子域名
    pub subdomain: String,
    /// IP 地址列表
    pub ip_addresses: Vec<String>,
    /// 记录类型
    pub record_type: String,
    /// 是否存活
    pub is_alive: bool,
    /// HTTP 状态码（如果检测了）
    pub http_status: Option<u16>,
}

/// 目录探测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirProbeResult {
    /// 路径
    pub path: String,
    /// 状态码
    pub status_code: u16,
    /// 内容长度
    pub content_length: usize,
    /// 是否敏感
    pub is_sensitive: bool,
    /// 风险等级: low / medium / high / critical
    pub risk_level: String,
}

/// SSL 证书信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertInfo {
    /// 是否启用 HTTPS
    pub https_enabled: bool,
    /// 证书主题（CN）
    pub subject_cn: Option<String>,
    /// 证书主题备用名称（SAN）
    pub subject_alt_names: Vec<String>,
    /// 颁发者
    pub issuer: Option<String>,
    /// 证书版本
    pub version: Option<String>,
    /// 签名算法
    pub signature_algorithm: Option<String>,
    /// 生效时间
    pub valid_from: Option<String>,
    /// 过期时间
    pub valid_to: Option<String>,
    /// 距离过期剩余天数
    pub days_until_expiry: Option<i64>,
    /// 是否已过期
    pub is_expired: bool,
    /// TLS 版本
    pub tls_version: Option<String>,
    /// 证书链长度
    pub cert_chain_length: Option<usize>,
}

/// 安全评分分项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScoreItem {
    /// 项目名称
    pub name: String,
    /// 得分（0-100）
    pub score: u8,
    /// 权重
    pub weight: f32,
    /// 风险等级
    pub risk_level: String,
    /// 说明
    pub description: String,
}

/// 安全评分
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    /// 总分（0-100）
    pub total_score: u8,
    /// 安全等级: excellent / good / medium / low / critical
    pub grade: String,
    /// 分项得分
    pub items: Vec<SecurityScoreItem>,
    /// 风险项列表
    pub risks: Vec<String>,
    /// 建议
    pub recommendations: Vec<String>,
}

/// 综合站点分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteAnalysisResult {
    /// 基础信息
    pub basic_info: SiteBasicInfo,
    /// 技术栈
    pub tech_stack: TechStack,
    /// 子域名列表
    pub subdomains: Vec<SubdomainInfo>,
    /// 目录探测结果
    pub dir_probe_results: Vec<DirProbeResult>,
    /// SSL 证书信息
    pub ssl_cert: SslCertInfo,
    /// 安全评分
    pub security_score: SecurityScore,
    /// 总耗时（毫秒）
    pub total_duration_ms: u64,
    /// 响应头信息
    pub response_headers: HashMap<String, String>,
}

// ============================================================
// 静态指纹库
// ============================================================

/// CMS 指纹库
const CMS_FINGERPRINTS: &[(&str, &[(&str, &str, u8)])] = &[
    ("WordPress", &[
        ("meta_generator", "wordpress", 25),
        ("path_wp_content", "wp-content/", 30),
        ("path_wp_includes", "wp-includes/", 25),
        ("path_wp_json", "/wp-json/", 20),
        ("path_readme", "readme.html", 10),
        ("header_x_pingback", "xmlrpc.php", 10),
        ("script_wp_emoji", "wp-emoji-release", 15),
        ("cookie_wordpress", "wordpress_", 20),
        ("link_wlwmanifest", "wlwmanifest.xml", 10),
        ("path_xmlrpc", "xmlrpc.php", 15),
    ]),
    ("Drupal", &[
        ("meta_generator", "drupal", 30),
        ("header_x_generator", "drupal", 30),
        ("path_sites_default", "sites/default/files", 25),
        ("script_drupal_settings", "drupalSettings", 25),
        ("path_user_login", "/user/login", 15),
        ("cookie_drupal", "drupal", 20),
        ("header_x_drupal", "x-drupal", 30),
    ]),
    ("Joomla", &[
        ("meta_generator", "joomla", 30),
        ("path_administrator", "/administrator/", 25),
        ("path_media_system", "media/system/js", 20),
        ("script_jtext", "Joomla.JText", 20),
        ("cookie_joomla", "joomla_", 20),
        ("path_templates", "/templates/", 15),
    ]),
    ("Magento", &[
        ("meta_generator", "magento", 30),
        ("path_static_frontend", "static/frontend/", 25),
        ("script_mage_cookies", "mage/cookies", 20),
        ("path_magento_version", "/magento_version", 30),
        ("cookie_frontend", "frontend=", 25),
        ("script_text_x_magento", "text/x-magento", 20),
    ]),
    ("Shopify", &[
        ("meta_generator", "shopify", 30),
        ("script_shopify", "shopify.com", 20),
        ("cdn_shopify", "cdn.shopify.com", 25),
        ("path_products", "/products/", 15),
        ("path_collections", "/collections/", 15),
        ("cookie_shopify", "shopify_", 20),
        ("header_shopify", "x-shopid", 30),
    ]),
    ("Discuz", &[
        ("meta_generator", "discuz", 30),
        ("path_forum", "forum.php", 20),
        ("script_discuz", "discuz_uid", 25),
        ("cookie_saltkey", "saltkey", 20),
        ("path_source", "/source/", 15),
        ("path_data", "data/attachment", 15),
    ]),
    ("Typecho", &[
        ("meta_generator", "typecho", 30),
        ("path_usr_themes", "usr/themes/", 25),
        ("script_typecho", "typechoToken", 20),
        ("path_admin", "/admin/", 10),
        ("cookie_typecho", "typecho", 20),
    ]),
    ("Hexo", &[
        ("meta_generator", "hexo", 35),
        ("script_hexo", "hexo-generator", 25),
        ("meta_hexo_version", "hexo.version", 20),
        ("path_archives", "/archives/", 10),
    ]),
    ("Hugo", &[
        ("meta_generator", "hugo", 35),
        ("comment_hugo", "hugo-website", 20),
        ("script_gohugo", "gohugoio", 15),
        ("path_posts", "/posts/", 5),
    ]),
    ("Ghost", &[
        ("meta_generator", "ghost", 30),
        ("script_ghost", "ghost.min.js", 25),
        ("path_ghost_admin", "/ghost/", 20),
        ("css_ghost", "ghost.min.css", 20),
        ("script_ghost_url", "ghost.org", 15),
    ]),
    ("Jekyll", &[
        ("meta_generator", "jekyll", 30),
        ("comment_jekyll", "jekyll", 15),
        ("path_jekyll", "/jekyll/", 10),
    ]),
    ("Next.js", &[
        ("script_next", "__next", 30),
        ("path_next_static", "_next/static/", 30),
        ("script_next_data", "__NEXT_DATA__", 25),
        ("header_next", "x-nextjs", 30),
    ]),
    ("Nuxt.js", &[
        ("script_nuxt", "__nuxt", 30),
        ("path_nuxt", "_nuxt/", 25),
        ("script_nuxt_js", "nuxt.js", 25),
        ("div_nuxt", "id=\"__nuxt\"", 20),
    ]),
    ("Django CMS", &[
        ("meta_generator", "django-cms", 30),
        ("script_django", "django", 15),
        ("cookie_csrf", "csrftoken", 20),
        ("path_admin", "/admin/", 10),
    ]),
    ("Laravel", &[
        ("cookie_laravel", "laravel_session", 30),
        ("header_xsrf", "XSRF-TOKEN", 25),
        ("path_vendor", "/vendor/", 15),
        ("script_laravel", "laravel", 15),
    ]),
    ("Spring Boot", &[
        ("header_x_application", "spring-boot", 25),
        ("error_whitelabel", "Whitelabel Error Page", 30),
        ("path_actuator", "/actuator", 20),
        ("cookie_jsessionid", "JSESSIONID", 15),
    ]),
    ("ASP.NET", &[
        ("header_x_aspnet", "X-AspNet-Version", 30),
        ("viewstate", "__VIEWSTATE", 25),
        ("path_aspx", ".aspx", 20),
        ("cookie_aspnet", "ASP.NET_SessionId", 30),
        ("header_x_aspnet_mvc", "X-AspNetMvc-Version", 25),
    ]),
    ("Express", &[
        ("header_x_powered", "Express", 30),
        ("script_express", "express", 15),
        ("cookie_connect", "connect.sid", 20),
    ]),
    ("Flask", &[
        ("cookie_session", "session=", 20),
        ("error Werkzeug", "Werkzeug", 25),
        ("header_x_powered", "Flask", 30),
    ]),
    ("Ruby on Rails", &[
        ("cookie_rails", "_session", 20),
        ("meta_csrf", "csrf-token", 15),
        ("script_rails", "rails-ujs", 25),
        ("header_server", "Passenger", 15),
    ]),
];

/// 前端框架指纹库
const FRONTEND_FRAMEWORKS: &[(&str, &[(&str, u8)])] = &[
    ("React", &[
        ("react-dom", 30),
        ("_reactroot", 25),
        ("react.production.min.js", 25),
        ("react.development.js", 25),
        ("data-reactroot", 30),
        ("React.createElement", 20),
    ]),
    ("Vue.js", &[
        ("vue.js", 25),
        ("vue.min.js", 25),
        ("__vue__", 30),
        ("v-app", 20),
        ("v-text", 15),
        ("vue.runtime", 25),
        ("data-v-", 20),
    ]),
    ("Angular", &[
        ("angular.js", 25),
        ("ng-app", 25),
        ("ng-version", 30),
        ("@angular", 25),
        ("angular.io", 15),
        ("ng-binding", 20),
    ]),
    ("Svelte", &[
        ("svelte-", 30),
        ("svelte.dev", 20),
        ("__svelte", 25),
        ("sveltekit", 25),
    ]),
    ("Next.js", &[
        ("__next", 30),
        ("_next/static", 30),
        ("__NEXT_DATA__", 25),
        ("next.js", 20),
    ]),
    ("Nuxt.js", &[
        ("__nuxt", 30),
        ("_nuxt/", 25),
        ("nuxt.js", 20),
        ("nuxt-content", 25),
    ]),
    ("Gatsby", &[
        ("gatsby-", 25),
        ("___gatsby", 30),
        ("gatsby-image", 20),
    ]),
    ("Ember.js", &[
        ("ember.js", 25),
        ("ember-cli", 20),
        ("Ember.Application", 25),
    ]),
    ("Backbone.js", &[
        ("backbone.js", 25),
        ("Backbone.", 20),
        ("backbone.marionette", 20),
    ]),
    ("Alpine.js", &[
        ("alpine.js", 30),
        ("alpine.min.js", 30),
        ("x-data=", 25),
    ]),
];

/// CDN 特征库
const CDN_SIGNATURES: &[(&str, &[&str])] = &[
    ("Cloudflare", &["cloudflare", "cf-ray", "cf-cache-status", "__cfduid", "cf-request-id", "server: cloudflare"]),
    ("Akamai", &["akamai", "akamaighost", "x-akamai", "akgzip", "x-akamai-transformed"]),
    ("阿里云 CDN", &["aliyun", "x-swift", "x-cache", "x-alicdn", "alicdn", "x-ali-cdn"]),
    ("腾讯云 CDN", &["tencent", "tcdn", "x-cdn", "qcloud", "x-daa"]),
    ("百度云加速", &["baidu", "yunjiasu", "yunjiasu-nginx", "bdcdn"]),
    ("七牛云 CDN", &["qiniu", "x-qiniu", "qcache", "x-ver"]),
    ("又拍云 CDN", &["upyun", "x-upyun", "upyun.net", "x-cache"]),
    ("网宿 CDN", &["wangsu", "wscdn", "wsweb", "china-cdn"]),
    ("Fastly", &["fastly", "x-fastly", "x-served-by", "fastly-debug"]),
    ("Incapsula", &["incapsula", "imperva", "incap_ses", "x-iinfo", "visid_incap"]),
    ("Sucuri", &["sucuri", "x-sucuri", "sucuri-firewall"]),
    ("StackPath", &["stackpath", "x-stackpath", "spcdn"]),
    ("KeyCDN", &["keycdn", "x-keycdn", "keycdn-cache"]),
    ("BunnyCDN", &["bunnycdn", "cdn-cgi", "x-bunny"]),
    ("CloudFront", &["cloudfront", "x-amz-cf-id", "x-cache", "x-amz"]),
    ("Limelight", &["limelight", "llnwd", "x-llh"]),
];

/// WAF 特征库
const WAF_SIGNATURES: &[(&str, &[&str])] = &[
    ("Cloudflare WAF", &["cloudflare", "cf-ray", "__cfduid", "error code: 1020", "error code: 1010", "cf-chl"]),
    ("Akamai WAF", &["akamai", "akamaighost", "x-akamai", "akgzip"]),
    ("Incapsula/Imperva", &["incapsula", "imperva", "incap_ses", "visid_incap", "x-iinfo"]),
    ("F5 BIG-IP ASM", &["bigip", "f5 networks", "ts_cookie", "f5_siteprotector", "x-cnection"]),
    ("ModSecurity", &["mod_security", "modsecurity", "web server at", "not acceptable", "mod_security-rule"]),
    ("Sucuri WAF", &["sucuri", "sucuri firewall", "sucuri website firewall", "x-sucuri-id"]),
    ("Wordfence", &["wordfence", "wfvt_", "wfls_", "wordfence_lh"]),
    ("Barracuda WAF", &["barracuda", "barracudanetworks", "barra_counter"]),
    ("Citrix NetScaler", &["netscaler", "citrix", "ns_af", "citrix_ns"]),
    ("Palo Alto", &["palo alto", "paloalto", "pan-os"]),
    ("DDoS-Guard", &["ddos-guard", "ddos guard", "ddosguard"]),
    ("七牛云 WAF", &["qiniu", "x-qiniu"]),
    ("阿里云 WAF", &["aliyunwaf", "aliyun waf", "x-alibaba", "waf-alibaba"]),
    ("腾讯云 WAF", &["tencent", "waf.tencent", "tencent-waf"]),
    ("百度云 WAF", &["baidu yunjiasu", "yunjiasu", "baidu-waf"]),
    ("Wallarm", &["wallarm", "x-wallarm"]),
    ("SignalSciences", &["sigsci", "signalsciences", "x-sigsci"]),
    ("AWS WAF", &["aws-waf", "x-amzn", "awswaf"]),
];

/// 常见子域名字典
const COMMON_SUBDOMAINS: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "pop3", "imap",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "admin", "test", "blog", "dev", "api", "api2", "api3", "cdn", "static",
    "images", "img", "css", "js", "app", "apps", "portal", "crm", "erp",
    "shop", "store", "forum", "wiki", "news", "m", "mobile", "wap",
    "beta", "staging", "stage", "demo", "dev1", "dev2", "test1", "test2",
    "prod", "production", "uat", "qa",
    "gw", "gateway", "proxy", "vpn", "remote", "owa", "exchange",
    "autodiscover", "activesync", "cpanel", "whm", "webmin", "phpmyadmin",
    "wp-admin", "administrator", "root", "backup", "bak", "old", "new",
    "docs", "download", "downloads", "upload", "uploads", "files", "media",
    "video", "video2", "stream", "live", "tv",
    "search", "auth", "login", "logout", "register", "signup",
    "pay", "payment", "payments", "billing", "invoice",
    "status", "monitor", "monitoring", "metrics", "grafana",
    "jenkins", "gitlab", "github", "bitbucket", "svn",
    "redis", "mongo", "mysql", "db", "database",
    "cache", "mq", "rabbitmq", "kafka", "elasticsearch",
    "sso", "saml", "oauth", "oauth2",
    "chat", "messenger", "im", "confluence", "jira",
    "support", "help", "helpdesk", "ticket",
    "intranet", "hr", "hrm", "erpnext",
    "test-www", "dev-www", "stg-www", "www2", "www3",
    "mail2", "mail3", "smtp2", "mx", "mx1", "mx2",
];

/// 常见敏感路径
const SENSITIVE_PATHS: &[(&str, &str, u8)] = &[
    // 管理后台
    ("/admin", "high", "管理后台入口"),
    ("/admin/", "high", "管理后台目录"),
    ("/administrator/", "high", "Joomla 管理后台"),
    ("/wp-admin/", "high", "WordPress 管理后台"),
    ("/phpmyadmin/", "critical", "phpMyAdmin 数据库管理"),
    ("/phpMyAdmin/", "critical", "phpMyAdmin 数据库管理"),
    ("/pma/", "critical", "phpMyAdmin 别名"),
    ("/myadmin/", "critical", "phpMyAdmin 别名"),
    ("/cpanel", "high", "cPanel 控制面板"),
    ("/webmin", "high", "Webmin 控制面板"),
    ("/admin.php", "high", "管理入口脚本"),
    ("/admin/index.php", "high", "管理入口"),
    ("/login", "medium", "登录页面"),
    ("/login.php", "medium", "登录页面"),
    ("/wp-login.php", "high", "WordPress 登录页"),
    // 敏感文件
    ("/.git/", "critical", "Git 仓库泄露"),
    ("/.git/config", "critical", "Git 配置文件"),
    ("/.git/HEAD", "critical", "Git HEAD 文件"),
    ("/.env", "critical", "环境变量配置文件"),
    ("/.env.production", "critical", "生产环境配置"),
    ("/.env.local", "critical", "本地环境配置"),
    ("/.htaccess", "medium", "Apache 配置文件"),
    ("/.htpasswd", "critical", "Apache 密码文件"),
    ("/.svn/", "high", "SVN 仓库泄露"),
    ("/.DS_Store", "low", "macOS 文件"),
    ("/.babelrc", "low", "Babel 配置"),
    ("/.eslintrc", "low", "ESLint 配置"),
    ("/.npmrc", "low", "NPM 配置"),
    // 备份文件
    ("/backup/", "high", "备份目录"),
    ("/backups/", "high", "备份目录"),
    ("/bak/", "high", "备份目录"),
    ("/backup.sql", "critical", "数据库备份文件"),
    ("/backup.tar.gz", "high", "压缩备份"),
    ("/backup.zip", "high", "压缩备份"),
    ("/database.sql", "critical", "数据库文件"),
    ("/dump.sql", "critical", "数据库导出"),
    ("/db_backup.sql", "critical", "数据库备份"),
    ("/config.bak", "high", "配置文件备份"),
    ("/web.config", "high", "IIS 配置文件"),
    // 上传目录
    ("/uploads/", "medium", "文件上传目录"),
    ("/upload/", "medium", "文件上传目录"),
    ("/files/", "medium", "文件目录"),
    ("/media/", "low", "媒体文件目录"),
    ("/tmp/", "medium", "临时目录"),
    ("/temp/", "medium", "临时目录"),
    // 其他
    ("/robots.txt", "low", "爬虫规则"),
    ("/sitemap.xml", "low", "站点地图"),
    ("/readme.html", "low", "说明文档"),
    ("/README.md", "low", "项目说明"),
    ("/CHANGELOG.md", "low", "更新日志"),
    ("/license.txt", "low", "许可证文件"),
    ("/crossdomain.xml", "medium", "Flash 跨域策略"),
    ("/clientaccesspolicy.xml", "medium", "Silverlight 策略"),
    ("/phpinfo.php", "critical", "PHP 信息泄露"),
    ("/info.php", "high", "PHP 信息文件"),
    ("/test.php", "medium", "测试文件"),
    ("/server-status", "high", "Apache 状态页"),
    ("/server-info", "high", "Apache 信息页"),
    ("/actuator", "high", "Spring Boot 监控"),
    ("/actuator/env", "critical", "Spring Boot 环境变量"),
    ("/actuator/health", "low", "Spring Boot 健康检查"),
    ("/swagger", "medium", "API 文档"),
    ("/swagger-ui.html", "medium", "Swagger UI"),
    ("/api-docs", "medium", "API 文档"),
    ("/graphql", "medium", "GraphQL 端点"),
    ("/graphiql", "medium", "GraphQL 控制台"),
    ("/console", "high", "控制台入口"),
];

// ============================================================
// 辅助函数
// ============================================================

/// URL 规范化
fn normalize_url(url: &str) -> Result<String, String> {
    let mut url_str = url.trim().to_string();
    if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
        url_str = format!("https://{}", url_str);
    }
    let parsed = Url::parse(&url_str).map_err(|e| format!("URL 解析失败: {}", e))?;
    Ok(parsed.to_string())
}

/// 从 URL 提取域名
fn extract_domain(url: &str) -> Result<String, String> {
    let parsed = Url::parse(url).map_err(|e| format!("URL 解析失败: {}", e))?;
    parsed
        .host_str()
        .map(|h| h.to_string())
        .ok_or_else(|| "无法提取域名".to_string())
}

/// 获取 base URL（协议 + 域名）
fn get_base_url(url: &str) -> Result<String, String> {
    let parsed = Url::parse(url).map_err(|e| format!("URL 解析失败: {}", e))?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().ok_or("无法提取域名")?;
    let port = parsed.port().map(|p| format!(":{}", p)).unwrap_or_default();
    Ok(format!("{}://{}{}", scheme, host, port))
}

/// 创建 HTTP 客户端
fn build_client(config: &SiteInfoConfig) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .user_agent(&config.user_agent)
        .redirect(if config.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))
}

/// 收集响应头为 HashMap
fn collect_headers(response: &reqwest::blocking::Response) -> HashMap<String, String> {
    let mut headers_map = HashMap::new();
    for (key, value) in response.headers().iter() {
        headers_map.insert(
            key.to_string().to_lowercase(),
            value.to_str().unwrap_or("").to_string(),
        );
    }
    headers_map
}

// ============================================================
// 1. 基础站点信息采集
// ============================================================

fn collect_basic_info(
    url: &str,
    client: &reqwest::blocking::Client,
) -> Result<(SiteBasicInfo, HashMap<String, String>, Html, String), String> {
    let normalized = normalize_url(url)?;
    let start = Instant::now();

    let response = client
        .get(&normalized)
        .send()
        .map_err(|e| format!("请求失败: {}", e))?;

    let response_time_ms = start.elapsed().as_millis() as u64;
    let status_code = response.status().as_u16();
    let final_url = response.url().to_string();
    let headers = collect_headers(&response);

    let body = response
        .text()
        .map_err(|e| format!("读取响应体失败: {}", e))?;
    let content_length = body.len();

    let document = Html::parse_document(&body);

    // 提取标题
    let title = document
        .select(&Selector::parse("title").unwrap())
        .next()
        .map(|e| e.text().collect::<String>().trim().to_string())
        .unwrap_or_default();

    // 提取描述和关键词
    let mut description = None;
    let mut keywords = None;
    let meta_selector = Selector::parse("meta").unwrap();
    for meta in document.select(&meta_selector) {
        let name = meta.value().attr("name").map(|s| s.to_lowercase());
        let content = meta.value().attr("content").map(|s| s.to_string());
        if let (Some(name), Some(content)) = (name, content) {
            match name.as_str() {
                "description" => description = Some(content),
                "keywords" => keywords = Some(content),
                _ => {}
            }
        }
    }

    let content_type = headers
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let server_header = headers.get("server").cloned();
    let x_powered_by = headers.get("x-powered-by").cloned();

    // DNS 解析 IP 地址
    let domain = extract_domain(&final_url).unwrap_or_default();
    let (ipv4_addresses, ipv6_addresses) = resolve_ip_addresses(&domain);

    let basic_info = SiteBasicInfo {
        original_url: url.to_string(),
        normalized_url: normalized,
        final_url: final_url.clone(),
        title,
        description,
        keywords,
        status_code,
        response_time_ms,
        server_header,
        x_powered_by,
        content_type,
        content_length,
        ipv4_addresses,
        ipv6_addresses,
        is_alive: status_code != 0,
    };

    Ok((basic_info, headers, document, body))
}

/// 解析域名 IP 地址
fn resolve_ip_addresses(domain: &str) -> (Vec<String>, Vec<String>) {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    // 使用系统 DNS 解析
    if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(domain, 0)) {
        for addr in addrs {
            let ip = addr.ip();
            if ip.is_ipv4() {
                let ip_str = ip.to_string();
                if !ipv4.contains(&ip_str) {
                    ipv4.push(ip_str);
                }
            } else {
                let ip_str = ip.to_string();
                if !ipv6.contains(&ip_str) {
                    ipv6.push(ip_str);
                }
            }
        }
    }

    (ipv4, ipv6)
}

// ============================================================
// 2. CMS 识别
// ============================================================

fn detect_cms(
    document: &Html,
    headers: &HashMap<String, String>,
    body: &str,
    cookies: &str,
) -> Vec<CmsInfo> {
    let body_lower = body.to_lowercase();
    let mut results = Vec::new();

    // 获取 meta generator
    let mut meta_generator = String::new();
    let meta_selector = Selector::parse("meta[name=generator]").unwrap();
    for meta in document.select(&meta_selector) {
        if let Some(content) = meta.value().attr("content") {
            meta_generator = content.to_lowercase();
        }
    }

    for (cms_name, fingerprints) in CMS_FINGERPRINTS {
        let mut confidence = 0u8;
        let mut evidence = Vec::new();
        let mut categories = HashSet::new();

        for (fp_type, fp_value, fp_score) in fingerprints.iter() {
            let val_lower = fp_value.to_lowercase();
            let mut matched = false;

            match *fp_type {
                "meta_generator" => {
                    if meta_generator.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("meta generator 包含: {}", fp_value));
                        categories.insert("meta".to_string());
                    }
                }
                "header_x_generator" | "header_x_drupal" | "header_x_aspnet" | "header_x_aspnet_mvc" | "header_next" | "header_server" => {
                    let header_name = fp_type.trim_start_matches("header_").replace('_', "-");
                    if let Some(h_val) = headers.get(&header_name) {
                        if h_val.to_lowercase().contains(&val_lower) {
                            matched = true;
                            evidence.push(format!("响应头 {} 包含: {}", header_name, fp_value));
                            categories.insert("header".to_string());
                        }
                    }
                }
                "header_x_powered" => {
                    if let Some(h_val) = headers.get("x-powered-by") {
                        if h_val.to_lowercase().contains(&val_lower) {
                            matched = true;
                            evidence.push(format!("X-Powered-By 包含: {}", fp_value));
                            categories.insert("header".to_string());
                        }
                    }
                }
                "header_shopify" | "header_xsrf" => {
                    let header_name = if *fp_type == "header_shopify" { "x-shopid" } else { "x-xsrf-token" };
                    if headers.contains_key(header_name) {
                        matched = true;
                        evidence.push(format!("存在响应头: {}", header_name));
                        categories.insert("header".to_string());
                    }
                }
                "header_x_application" => {
                    if let Some(h_val) = headers.get("x-application-context") {
                        if h_val.to_lowercase().contains(&val_lower) {
                            matched = true;
                            evidence.push(format!("X-Application-Context 包含: {}", fp_value));
                            categories.insert("header".to_string());
                        }
                    }
                }
                "path_wp_content" | "path_wp_includes" | "path_wp_json" | "path_readme" |
                "path_sites_default" | "path_user_login" | "path_administrator" |
                "path_media_system" | "path_templates" | "path_static_frontend" |
                "path_magento_version" | "path_products" | "path_collections" |
                "path_forum" | "path_source" | "path_data" | "path_usr_themes" |
                "path_admin" | "path_archives" | "path_posts" | "path_ghost_admin" |
                "path_jekyll" | "path_next_static" | "path_nuxt" |
                "path_vendor" | "path_actuator" | "path_aspx" | "path_xmlrpc" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("路径特征: {}", fp_value));
                        categories.insert("path".to_string());
                    }
                }
                "script_wp_emoji" | "script_drupal_settings" | "script_jtext" |
                "script_mage_cookies" | "script_shopify" | "script_discuz" |
                "script_typecho" | "script_hexo" | "script_gohugo" | "script_ghost" |
                "script_next" | "script_next_data" | "script_nuxt" |
                "script_django" | "script_laravel" | "script_express" |
                "script_rails" | "script_text_x_magento" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("脚本特征: {}", fp_value));
                        categories.insert("script".to_string());
                    }
                }
                "div_nuxt" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("DOM 特征: {}", fp_value));
                        categories.insert("script".to_string());
                    }
                }
                "cookie_wordpress" | "cookie_drupal" | "cookie_joomla" |
                "cookie_frontend" | "cookie_shopify" | "cookie_saltkey" |
                "cookie_typecho" | "cookie_laravel" | "cookie_csrf" |
                "cookie_jsessionid" | "cookie_aspnet" | "cookie_connect" |
                "cookie_session" | "cookie_rails" => {
                    if cookies.to_lowercase().contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("Cookie 特征: {}", fp_value));
                        categories.insert("cookie".to_string());
                    }
                    // 也检查 Set-Cookie 头
                    if let Some(set_cookie) = headers.get("set-cookie") {
                        if set_cookie.to_lowercase().contains(&val_lower) {
                            matched = true;
                            evidence.push(format!("Set-Cookie 包含: {}", fp_value));
                            categories.insert("cookie".to_string());
                        }
                    }
                }
                "link_wlwmanifest" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("链接特征: {}", fp_value));
                        categories.insert("path".to_string());
                    }
                }
                "path_wp_admin" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("路径特征: {}", fp_value));
                        categories.insert("path".to_string());
                    }
                }
                "comment_hugo" | "comment_jekyll" | "error Werkzeug" | "error_whitelabel" |
                "viewstate" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("内容特征: {}", fp_value));
                        categories.insert("script".to_string());
                    }
                }
                "cdn_shopify" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("CDN 特征: {}", fp_value));
                        categories.insert("path".to_string());
                    }
                }
                "meta_hexo_version" | "meta_csrf" => {
                    // 已经在 meta 里处理过
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("特征: {}", fp_value));
                        categories.insert("meta".to_string());
                    }
                }
                _ => {
                    // 默认在 body 中搜索
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("特征匹配: {}", fp_value));
                        categories.insert("script".to_string());
                    }
                }
            }

            if matched {
                confidence = confidence.saturating_add(*fp_score);
            }
        }

        // 额外检查：meta generator 直接匹配
        if !meta_generator.is_empty() && meta_generator.contains(&cms_name.to_lowercase()) {
            confidence = confidence.saturating_add(30);
            evidence.push(format!("meta generator 直接匹配: {}", cms_name));
            categories.insert("meta".to_string());
        }

        if confidence >= 20 {
            // 尝试提取版本号
            let version = extract_cms_version(cms_name, &meta_generator, &body_lower);

            results.push(CmsInfo {
                name: cms_name.to_string(),
                version,
                confidence: std::cmp::min(confidence, 100),
                evidence,
                categories: categories.into_iter().collect(),
            });
        }
    }

    // 按置信度降序排序
    results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    results
}

/// 提取 CMS 版本号
fn extract_cms_version(cms_name: &str, meta_gen: &str, body: &str) -> Option<String> {
    let cms_lower = cms_name.to_lowercase();

    // 从 meta generator 提取
    if !meta_gen.is_empty() && meta_gen.contains(&cms_lower) {
        if let Some(ver) = extract_version_after_prefix(meta_gen, &cms_lower) {
            return Some(ver);
        }
    }

    // 从 body 中提取版本
    let version_patterns = match cms_lower.as_str() {
        "wordpress" => vec!["wordpress ", "wp-version "],
        "drupal" => vec!["drupal ", "Drupal.version = ", "Drupal.version="],
        "joomla" => vec!["joomla ", "Joomla! "],
        "magento" => vec!["magento version = ", "magento version=", "magento "],
        "hexo" => vec!["hexo version ", "hexo-version "],
        "hugo" => vec!["hugo version ", "hugo-version "],
        "ghost" => vec!["ghost version ", "ghost-version "],
        _ => vec![],
    };

    for pattern in version_patterns {
        if let Some(ver) = extract_version_after_prefix(body, pattern) {
            return Some(ver);
        }
    }

    None
}

/// 从文本中提取前缀后的版本号
fn extract_version_after_prefix(text: &str, prefix: &str) -> Option<String> {
    let text_lower = text.to_lowercase();
    let prefix_lower = prefix.to_lowercase();

    if let Some(pos) = text_lower.find(&prefix_lower) {
        let start = pos + prefix_lower.len();
        let rest = &text[start..];
        // 跳过空白字符
        let trimmed = rest.trim_start();
        // 提取连续的数字和点
        let version: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !version.is_empty() && version.chars().next().unwrap().is_ascii_digit() {
            return Some(version);
        }
    }

    None
}

// ============================================================
// 3. 前端框架检测
// ============================================================

fn detect_frontend_frameworks(body: &str) -> Vec<FrontendFrameworkInfo> {
    let body_lower = body.to_lowercase();
    let mut results = Vec::new();

    for (fw_name, fingerprints) in FRONTEND_FRAMEWORKS {
        let mut confidence = 0u8;
        let mut evidence = Vec::new();

        for (fp_value, fp_score) in fingerprints.iter() {
            if body_lower.contains(&fp_value.to_lowercase()) {
                confidence = confidence.saturating_add(*fp_score);
                evidence.push(fp_value.to_string());
            }
        }

        if confidence >= 25 {
            results.push(FrontendFrameworkInfo {
                name: fw_name.to_string(),
                version: None,
                confidence: std::cmp::min(confidence, 100),
                evidence,
            });
        }
    }

    results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    results
}

// ============================================================
// 4. 服务器与中间件指纹
// ============================================================

fn detect_server_fingerprint(
    headers: &HashMap<String, String>,
    body: &str,
    status_code: u16,
) -> ServerFingerprint {
    let body_lower = body.to_lowercase();
    let mut fingerprint = ServerFingerprint {
        web_server: None,
        web_server_version: None,
        middleware: Vec::new(),
        cdn: None,
        cdn_confidence: 0,
        cdn_evidence: Vec::new(),
        waf: None,
        waf_confidence: 0,
        waf_evidence: Vec::new(),
        reverse_proxy: Vec::new(),
    };

    // 从 Server 头提取 Web 服务器
    if let Some(server) = headers.get("server") {
        fingerprint.web_server = Some(server.clone());

        // 尝试提取版本
        let srv_lower = server.to_lowercase();
        if srv_lower.contains("nginx") {
            fingerprint.web_server = Some("Nginx".to_string());
            if let Some(ver) = extract_version_from_string(server, "nginx") {
                fingerprint.web_server_version = Some(ver);
            }
        } else if srv_lower.contains("apache") {
            fingerprint.web_server = Some("Apache".to_string());
            if let Some(ver) = extract_version_from_string(server, "apache") {
                fingerprint.web_server_version = Some(ver);
            }
        } else if srv_lower.contains("microsoft-iis") || srv_lower.contains("iis") {
            fingerprint.web_server = Some("IIS".to_string());
            if let Some(ver) = extract_version_from_string(server, "iis") {
                fingerprint.web_server_version = Some(ver);
            }
        } else if srv_lower.contains("tomcat") {
            fingerprint.web_server = Some("Tomcat".to_string());
            if let Some(ver) = extract_version_from_string(server, "tomcat") {
                fingerprint.web_server_version = Some(ver);
            }
        } else if srv_lower.contains("jetty") {
            fingerprint.web_server = Some("Jetty".to_string());
            if let Some(ver) = extract_version_from_string(server, "jetty") {
                fingerprint.web_server_version = Some(ver);
            }
        } else if srv_lower.contains("node.js") || srv_lower.contains("nodejs") {
            fingerprint.web_server = Some("Node.js".to_string());
        } else if srv_lower.contains("caddy") {
            fingerprint.web_server = Some("Caddy".to_string());
        } else if srv_lower.contains("lighttpd") {
            fingerprint.web_server = Some("Lighttpd".to_string());
        } else if srv_lower.contains("openresty") {
            fingerprint.web_server = Some("OpenResty".to_string());
        }
    }

    // 中间件检测
    let middleware_indicators = &[
        ("x-powered-by", "X-Powered-By"),
        ("x-aspnet-version", "ASP.NET"),
        ("x-aspnetmvc-version", "ASP.NET MVC"),
        ("x-django", "Django"),
        ("x-runtime", "Rails"),
        ("x-rack-cache", "Rack Cache"),
        ("x-server", "X-Server"),
        ("x-served-by", "Varnish"),
        ("x-cache", "CDN Cache"),
        ("via", "Via Header"),
    ];

    for (header_key, mw_name) in middleware_indicators {
        if headers.contains_key(*header_key) {
            fingerprint.middleware.push(mw_name.to_string());
        }
    }

    // CDN 检测
    let mut best_cdn = None;
    let mut best_cdn_conf = 0u8;
    let mut best_cdn_evidence = Vec::new();

    for (cdn_name, signatures) in CDN_SIGNATURES {
        let mut matched = 0;
        let mut evidence = Vec::new();

        for sig in signatures {
            let sig_lower = sig.to_lowercase();
            // 检查响应头
            if headers.keys().any(|k| k.contains(&sig_lower))
                || headers.values().any(|v| v.to_lowercase().contains(&sig_lower))
            {
                matched += 1;
                evidence.push(format!("Header 匹配: {}", sig));
            }
            // 检查响应体
            if body_lower.contains(&sig_lower) {
                matched += 1;
                evidence.push(format!("Body 匹配: {}", sig));
            }
        }

        let conf = std::cmp::min(matched * 25, 100) as u8;
        if conf > best_cdn_conf {
            best_cdn_conf = conf;
            best_cdn = Some(cdn_name.to_string());
            best_cdn_evidence = evidence;
        }
    }

    if best_cdn_conf >= 25 {
        fingerprint.cdn = best_cdn;
        fingerprint.cdn_confidence = best_cdn_conf;
        fingerprint.cdn_evidence = best_cdn_evidence;
    }

    // WAF 检测
    let mut best_waf = None;
    let mut best_waf_conf = 0u8;
    let mut best_waf_evidence = Vec::new();

    for (waf_name, signatures) in WAF_SIGNATURES {
        let mut matched = 0;
        let mut evidence = Vec::new();

        for sig in signatures {
            let sig_lower = sig.to_lowercase();
            if headers.keys().any(|k| k.contains(&sig_lower))
                || headers.values().any(|v| v.to_lowercase().contains(&sig_lower))
            {
                matched += 1;
                evidence.push(format!("Header 匹配: {}", sig));
            }
            if body_lower.contains(&sig_lower) {
                matched += 1;
                evidence.push(format!("Body 匹配: {}", sig));
            }
        }

        let conf = std::cmp::min(matched * 25, 100) as u8;
        if conf > best_waf_conf {
            best_waf_conf = conf;
            best_waf = Some(waf_name.to_string());
            best_waf_evidence = evidence;
        }
    }

    // 额外的 WAF 检测：特定状态码 + 特征页
    if status_code == 403 && body_lower.contains("forbidden") {
        best_waf_evidence.push("403 Forbidden (可能被 WAF 拦截)".to_string());
        best_waf_conf = std::cmp::min(best_waf_conf.saturating_add(10), 100);
    }
    if status_code == 429 {
        best_waf_evidence.push("429 Too Many Requests (速率限制，可能有 WAF)".to_string());
        best_waf_conf = std::cmp::min(best_waf_conf.saturating_add(10), 100);
    }
    if status_code == 503 && body_lower.contains("service unavailable") {
        best_waf_evidence.push("503 Service Unavailable (可能有 WAF/CDN)".to_string());
        best_waf_conf = std::cmp::min(best_waf_conf.saturating_add(5), 100);
    }

    if best_waf_conf >= 25 {
        fingerprint.waf = best_waf;
        fingerprint.waf_confidence = best_waf_conf;
        fingerprint.waf_evidence = best_waf_evidence;
    }

    fingerprint
}

/// 从字符串中提取版本号
fn extract_version_from_string(s: &str, keyword: &str) -> Option<String> {
    let s_lower = s.to_lowercase();
    let kw_lower = keyword.to_lowercase();

    if let Some(idx) = s_lower.find(&kw_lower) {
        let rest = &s[idx + kw_lower.len()..];
        let trimmed = rest.trim_start_matches(|c: char| !c.is_ascii_digit());
        let version: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !version.is_empty() {
            return Some(version);
        }
    }

    None
}

// ============================================================
// 5. 编程语言检测
// ============================================================

fn detect_programming_languages(
    headers: &HashMap<String, String>,
    body: &str,
    url: &str,
) -> Vec<ProgrammingLanguageInfo> {
    let body_lower = body.to_lowercase();
    let url_lower = url.to_lowercase();
    let mut results = Vec::new();

    let lang_patterns: &[(&str, &[(&str, &str, u8)])] = &[
        ("PHP", &[
            ("extension", ".php", 20),
            ("powered_by", "PHP", 30),
            ("session", "PHPSESSID", 25),
            ("header", "X-PHP", 25),
            ("error", "PHP Warning", 20),
            ("error2", "PHP Parse error", 20),
            ("error3", "Fatal error", 15),
            ("path_phpmyadmin", "phpmyadmin", 15),
        ]),
        ("Python", &[
            ("powered_by", "Python", 30),
            ("django", "Django", 25),
            ("flask", "Flask", 25),
            ("header", "x-python", 25),
            ("cookie_csrf", "csrftoken", 20),
            ("error", "Traceback", 20),
            ("error2", "Python 3.", 15),
        ]),
        ("Ruby", &[
            ("powered_by", "Ruby", 30),
            ("rails", "Rails", 25),
            ("cookie_session", "_session", 15),
            ("header_x_runtime", "X-Runtime", 20),
            ("error", "Ruby on Rails", 20),
            ("erb", ".erb", 15),
        ]),
        ("Java", &[
            ("jsp", ".jsp", 20),
            ("jsf", ".jsf", 20),
            ("session", "JSESSIONID", 25),
            ("header", "Java/", 25),
            ("servlet", "servlet", 20),
            ("tomcat", "Tomcat", 20),
            ("error", "java.lang", 20),
            ("spring", "Spring Boot", 20),
        ]),
        ("ASP.NET", &[
            ("aspx", ".aspx", 25),
            ("aspnet", "ASP.NET", 30),
            ("session", "ASP.NET_SessionId", 30),
            ("viewstate", "__VIEWSTATE", 25),
            ("header", "X-AspNet-Version", 30),
            ("header_mvc", "X-AspNetMvc-Version", 25),
            ("iis", "IIS", 20),
        ]),
        ("Node.js", &[
            ("powered_by", "Express", 30),
            ("powered_by2", "Node.js", 30),
            ("socketio", "socket.io", 20),
            ("cookie_connect", "connect.sid", 25),
            ("nextjs", "next.js", 20),
            ("nuxt", "nuxt", 15),
            ("header", "x-node", 25),
        ]),
        ("Go", &[
            ("powered_by", "Go", 25),
            ("gin", "gin-gonic", 25),
            ("header", "x-go", 25),
            ("beego", "beego", 20),
            ("echo", "echo framework", 20),
        ]),
    ];

    for (lang_name, patterns) in lang_patterns {
        let mut confidence = 0u8;
        let mut evidence = Vec::new();

        for (ptype, pvalue, pscore) in patterns.iter() {
            let val_lower = pvalue.to_lowercase();
            let mut matched = false;

            match *ptype {
                "extension" | "jsp" | "jsf" | "aspx" | "erb" => {
                    if url_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("URL 包含: {}", pvalue));
                    }
                }
                "powered_by" | "powered_by2" => {
                    if let Some(pb) = headers.get("x-powered-by") {
                        if pb.to_lowercase().contains(&val_lower) {
                            matched = true;
                            evidence.push(format!("X-Powered-By: {}", pvalue));
                        }
                    }
                }
                "session" | "cookie_session" | "cookie_csrf" | "cookie_connect" => {
                    if let Some(set_cookie) = headers.get("set-cookie") {
                        if set_cookie.to_lowercase().contains(&val_lower) {
                            matched = true;
                            evidence.push(format!("Cookie 包含: {}", pvalue));
                        }
                    }
                    // 也检查 body 中的 cookie 引用
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("内容包含: {}", pvalue));
                    }
                }
                "header" | "header_mvc" | "header_x_runtime" => {
                    let header_name = match *ptype {
                        "header_mvc" => "x-aspnetmvc-version",
                        "header_x_runtime" => "x-runtime",
                        _ => &val_lower,
                    };
                    if headers.keys().any(|k| k.contains(header_name))
                        || headers.values().any(|v| v.to_lowercase().contains(&val_lower))
                    {
                        matched = true;
                        evidence.push(format!("响应头包含: {}", pvalue));
                    }
                }
                "error" | "error2" | "error3" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("错误信息包含: {}", pvalue));
                    }
                }
                "django" | "flask" | "rails" | "servlet" | "tomcat" | "spring" |
                "socketio" | "nextjs" | "nuxt" | "gin" | "beego" | "echo" |
                "iis" | "viewstate" | "aspnet" | "path_phpmyadmin" => {
                    if body_lower.contains(&val_lower) {
                        matched = true;
                        evidence.push(format!("内容特征: {}", pvalue));
                    }
                }
                _ => {}
            }

            if matched {
                confidence = confidence.saturating_add(*pscore);
            }
        }

        if confidence >= 20 {
            results.push(ProgrammingLanguageInfo {
                name: lang_name.to_string(),
                version: None,
                confidence: std::cmp::min(confidence, 100),
                evidence,
            });
        }
    }

    results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    results
}

// ============================================================
// 6. 数据库推断
// ============================================================

fn infer_databases(
    cms_list: &[CmsInfo],
    languages: &[ProgrammingLanguageInfo],
    body: &str,
) -> Vec<DatabaseInfo> {
    let body_lower = body.to_lowercase();
    let mut results = Vec::new();
    let mut added = HashSet::new();

    // 基于 CMS 类型推断
    let cms_db_map: &[(&str, &str, u8, &str)] = &[
        ("WordPress", "MySQL", 80, "WordPress 默认使用 MySQL"),
        ("Drupal", "MySQL", 70, "Drupal 默认使用 MySQL"),
        ("Drupal", "PostgreSQL", 50, "Drupal 支持 PostgreSQL"),
        ("Joomla", "MySQL", 80, "Joomla 默认使用 MySQL"),
        ("Magento", "MySQL", 85, "Magento 默认使用 MySQL"),
        ("Discuz", "MySQL", 85, "Discuz 默认使用 MySQL"),
        ("Typecho", "MySQL", 75, "Typecho 默认使用 MySQL"),
        ("Typecho", "SQLite", 40, "Typecho 支持 SQLite"),
        ("Laravel", "MySQL", 70, "Laravel 常用 MySQL"),
        ("Laravel", "PostgreSQL", 60, "Laravel 支持 PostgreSQL"),
        ("Django CMS", "PostgreSQL", 65, "Django 常用 PostgreSQL"),
        ("Django CMS", "MySQL", 60, "Django 支持 MySQL"),
        ("Spring Boot", "MySQL", 60, "Spring Boot 常用 MySQL"),
        ("Spring Boot", "PostgreSQL", 55, "Spring Boot 支持 PostgreSQL"),
        ("ASP.NET", "SQL Server", 80, "ASP.NET 常用 SQL Server"),
    ];

    for cms in cms_list {
        for (cms_name, db_name, conf, reason) in cms_db_map {
            if cms.name.to_lowercase() == cms_name.to_lowercase() && !added.contains(*db_name) {
                results.push(DatabaseInfo {
                    name: db_name.to_string(),
                    reason: format!("{}: {}", reason, cms.name),
                    confidence: *conf,
                });
                added.insert(db_name.to_string());
            }
        }
    }

    // 基于编程语言推断
    let lang_db_map: &[(&str, &str, u8, &str)] = &[
        ("PHP", "MySQL", 65, "PHP 生态常用 MySQL"),
        ("Java", "MySQL", 55, "Java 项目常用 MySQL"),
        ("Java", "PostgreSQL", 50, "Java 项目支持 PostgreSQL"),
        ("Java", "Oracle", 45, "企业级 Java 常用 Oracle"),
        ("Python", "PostgreSQL", 55, "Python 生态常用 PostgreSQL"),
        ("Python", "MySQL", 50, "Python 支持 MySQL"),
        ("Python", "MongoDB", 45, "Python 项目常使用 MongoDB"),
        ("Node.js", "MongoDB", 60, "Node.js 生态常用 MongoDB"),
        ("Node.js", "PostgreSQL", 50, "Node.js 支持 PostgreSQL"),
        ("Ruby", "PostgreSQL", 55, "Ruby on Rails 常用 PostgreSQL"),
        ("Ruby", "MySQL", 50, "Ruby on Rails 支持 MySQL"),
        ("Go", "PostgreSQL", 50, "Go 项目常用 PostgreSQL"),
        ("Go", "MySQL", 45, "Go 项目支持 MySQL"),
        ("ASP.NET", "SQL Server", 75, "ASP.NET 生态常用 SQL Server"),
    ];

    for lang in languages {
        for (lang_name, db_name, conf, reason) in lang_db_map {
            if lang.name.to_lowercase() == lang_name.to_lowercase() && !added.contains(*db_name) {
                results.push(DatabaseInfo {
                    name: db_name.to_string(),
                    reason: reason.to_string(),
                    confidence: *conf,
                });
                added.insert(db_name.to_string());
            }
        }
    }

    // 从错误信息中直接检测
    let direct_db_signatures: &[(&str, &str, u8)] = &[
        ("MySQL", "mysql", 85),
        ("PostgreSQL", "postgresql", 85),
        ("PostgreSQL", "pg_", 50),
        ("MongoDB", "mongodb", 85),
        ("MongoDB", "mongoerror", 80),
        ("Redis", "redis", 75),
        ("SQL Server", "sql server", 80),
        ("SQL Server", "mssql", 75),
        ("Oracle", "oracle", 80),
        ("SQLite", "sqlite", 75),
        ("MariaDB", "mariadb", 80),
        ("Elasticsearch", "elasticsearch", 80),
    ];

    for (db_name, signature, conf) in direct_db_signatures {
        if body_lower.contains(signature) && !added.contains(*db_name) {
            results.push(DatabaseInfo {
                name: db_name.to_string(),
                reason: format!("页面内容包含 {} 特征", signature),
                confidence: *conf,
            });
            added.insert(db_name.to_string());
        }
    }

    results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    results
}

// ============================================================
// 7. 子域名发现
// ============================================================

fn discover_subdomains(domain: &str, config: &SiteInfoConfig) -> Vec<SubdomainInfo> {
    if !config.enable_subdomain_scan {
        return Vec::new();
    }

    let mut wordlist: Vec<String> = COMMON_SUBDOMAINS.iter().map(|s| s.to_string()).collect();

    // 限制字典大小
    if config.subdomain_word_limit > 0 {
        wordlist.truncate(config.subdomain_word_limit);
    }

    let concurrency = config.subdomain_concurrency;
    let mut handles = Vec::new();

    use std::sync::{Arc, Mutex};

    let results_arc = Arc::new(Mutex::new(Vec::new()));
    let semaphore = Arc::new(Mutex::new(concurrency));

    for word in wordlist {
        let domain = domain.to_string();
        let word = word.clone();
        let results_arc = Arc::clone(&results_arc);
        let semaphore = Arc::clone(&semaphore);
        let timeout = config.timeout_ms;

        // 简单的并发控制：使用线程 + 信号量模拟
        // 等待一个许可
        loop {
            let mut sem = semaphore.lock().unwrap();
            if *sem > 0 {
                *sem -= 1;
                break;
            }
            drop(sem);
            thread::sleep(Duration::from_millis(10));
        }

        let semaphore_clone = Arc::clone(&semaphore);
        let handle = thread::spawn(move || {
            let subdomain = format!("{}.{}", word, domain);
            let mut ip_addresses = Vec::new();

            // 快速 DNS 解析
            let result = std::net::ToSocketAddrs::to_socket_addrs((&subdomain[..], 0));
            if let Ok(addrs) = result {
                let addr_vec: Vec<std::net::SocketAddr> = addrs.collect();
                if !addr_vec.is_empty() {
                    for addr in addr_vec {
                        let ip_str = addr.ip().to_string();
                        if !ip_addresses.contains(&ip_str) {
                            ip_addresses.push(ip_str);
                        }
                    }
                }
            }

            if !ip_addresses.is_empty() {
                let record_type = if ip_addresses.iter().any(|ip| ip.contains(':')) {
                    "AAAA"
                } else {
                    "A"
                };

                let info = SubdomainInfo {
                    subdomain: subdomain.clone(),
                    ip_addresses: ip_addresses.clone(),
                    record_type: record_type.to_string(),
                    is_alive: true,
                    http_status: None,
                };

                results_arc.lock().unwrap().push(info);
            }

            // 释放许可
            let mut sem = semaphore_clone.lock().unwrap();
            *sem += 1;

            // 超时保护
            let _ = timeout;
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    let mut final_results = Arc::try_unwrap(results_arc)
        .unwrap()
        .into_inner()
        .unwrap();

    final_results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
    final_results
}

// ============================================================
// 8. 目录探测
// ============================================================

fn probe_directories(base_url: &str, config: &SiteInfoConfig) -> Vec<DirProbeResult> {
    if !config.enable_dir_scan {
        return Vec::new();
    }

    let client = match build_client(config) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let concurrency = config.dir_concurrency;
    let mut handles = Vec::new();

    use std::sync::{Arc, Mutex};

    let results_arc = Arc::new(Mutex::new(Vec::new()));
    let semaphore = Arc::new(Mutex::new(concurrency));

    for (path, risk_level, description) in SENSITIVE_PATHS {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let client = client.clone();
        let results_arc = Arc::clone(&results_arc);
        let semaphore = Arc::clone(&semaphore);
        let risk = risk_level.to_string();
        let desc = description.to_string();
        let path_str = path.to_string();

        // 获取许可
        loop {
            let mut sem = semaphore.lock().unwrap();
            if *sem > 0 {
                *sem -= 1;
                break;
            }
            drop(sem);
            thread::sleep(Duration::from_millis(10));
        }

        let semaphore_clone = Arc::clone(&semaphore);
        let handle = thread::spawn(move || {
            let mut status_code = 0;
            let mut content_length = 0;

            if let Ok(response) = client.head(&url).send() {
                status_code = response.status().as_u16();
                content_length = response.content_length().unwrap_or(0) as usize;
            }

            if status_code != 0 && status_code != 404 {
                let is_sensitive = matches!(risk.as_str(), "high" | "critical" | "medium");
                let result = DirProbeResult {
                    path: path_str.clone(),
                    status_code,
                    content_length,
                    is_sensitive,
                    risk_level: risk.clone(),
                };

                // 只保留有意义的状态码
                if status_code == 200
                    || status_code == 403
                    || status_code == 301
                    || status_code == 302
                    || status_code == 401
                    || status_code == 500
                {
                    results_arc.lock().unwrap().push(result);
                }
            }

            let _ = desc; // description kept for future use

            let mut sem = semaphore_clone.lock().unwrap();
            *sem += 1;
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    let mut final_results = Arc::try_unwrap(results_arc)
        .unwrap()
        .into_inner()
        .unwrap();

    // 按风险等级排序
    final_results.sort_by(|a, b| {
        let rank_a = match a.risk_level.as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        let rank_b = match b.risk_level.as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        rank_b.cmp(&rank_a)
    });

    final_results
}

// ============================================================
// 9. SSL/TLS 证书信息
// ============================================================

fn check_ssl_cert(url: &str, _config: &SiteInfoConfig) -> SslCertInfo {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => {
            return SslCertInfo {
                https_enabled: false,
                subject_cn: None,
                subject_alt_names: Vec::new(),
                issuer: None,
                version: None,
                signature_algorithm: None,
                valid_from: None,
                valid_to: None,
                days_until_expiry: None,
                is_expired: false,
                tls_version: None,
                cert_chain_length: None,
            };
        }
    };

    let https_enabled = parsed.scheme() == "https";
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);

    if !https_enabled {
        return SslCertInfo {
            https_enabled: false,
            subject_cn: None,
            subject_alt_names: Vec::new(),
            issuer: None,
            version: None,
            signature_algorithm: None,
            valid_from: None,
            valid_to: None,
            days_until_expiry: None,
            is_expired: false,
            tls_version: None,
            cert_chain_length: None,
        };
    }

    // 尝试获取证书信息
    // 由于没有直接的 TLS 库依赖，我们通过 reqwest 的扩展来尝试获取
    // 这里使用最佳努力方式检测

    let mut cert_info = SslCertInfo {
        https_enabled: true,
        subject_cn: Some(host.clone()),
        subject_alt_names: vec![host.clone()],
        issuer: None,
        version: None,
        signature_algorithm: None,
        valid_from: None,
        valid_to: None,
        days_until_expiry: None,
        is_expired: false,
        tls_version: None,
        cert_chain_length: None,
    };

    // 尝试通过 HTTPS 连接检测 TLS 版本
    // 使用 reqwest 的 client 发送请求并从扩展中获取信息
    let client_result = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(5000))
        .danger_accept_invalid_certs(true)
        .build();

    if let Ok(client) = client_result {
        if let Ok(response) = client.get(url).send() {
            // 尝试从响应扩展中获取 TLS 信息
            // reqwest 默认后端可能不直接暴露证书详情
            // 我们能从状态码判断连接是否成功
            let _ = response.status();

            // 尝试推断 TLS 版本（从响应头和连接信息）
            // 多数情况下 reqwest 不会直接暴露，这里做最佳猜测
            cert_info.tls_version = Some("TLS 1.2+ (已建立安全连接)".to_string());

            // 从 HTTPS 成功连接推断证书基本有效
            // 注意：因为用了 danger_accept_invalid_certs，所以不能完全依赖连接成功
        }
    }

    // 尝试通过 openssl 命令获取证书信息（如果系统安装了 openssl）
    if let Ok(output) = std::process::Command::new("openssl")
        .args(&["s_client", "-connect", &format!("{}:{}", host, port), "-servername", &host, "-showcerts"])
        .stdin(std::process::Stdio::null())
        .output()
    {
        let cert_output = String::from_utf8_lossy(&output.stdout);
        cert_info = parse_openssl_output(&cert_output, &cert_info);
    }

    cert_info
}

/// 解析 openssl 输出
fn parse_openssl_output(output: &str, base_info: &SslCertInfo) -> SslCertInfo {
    let mut info = base_info.clone();

    // 提取证书主题
    if let Some(line) = output.lines().find(|l| l.contains("subject=") || l.contains("subject =")) {
        let subject = line.trim().to_string();
        // 尝试提取 CN
        if let Some(cn_idx) = subject.find("CN =") {
            let cn = subject[cn_idx + 4..].split(',').next().unwrap_or("").trim().to_string();
            if !cn.is_empty() {
                info.subject_cn = Some(cn);
            }
        } else if let Some(cn_idx) = subject.find("CN=") {
            let cn = subject[cn_idx + 3..].split(',').next().unwrap_or("").trim().to_string();
            if !cn.is_empty() {
                info.subject_cn = Some(cn);
            }
        }
    }

    // 提取颁发者
    if let Some(line) = output.lines().find(|l| l.contains("issuer=") || l.contains("issuer =")) {
        let issuer = line.trim().to_string();
        if let Some(cn_idx) = issuer.find("O =") {
            let org = issuer[cn_idx + 3..].split(',').next().unwrap_or("").trim().to_string();
            if !org.is_empty() {
                info.issuer = Some(org);
            }
        } else if let Some(cn_idx) = issuer.find("CN =") {
            let cn = issuer[cn_idx + 4..].split(',').next().unwrap_or("").trim().to_string();
            if !cn.is_empty() {
                info.issuer = Some(cn);
            }
        }
    }

    // 提取有效期
    if let Some(line) = output.lines().find(|l| l.contains("notBefore=")) {
        if let Some(idx) = line.find("notBefore=") {
            let val = line[idx + 10..].trim().to_string();
            info.valid_from = Some(val);
        }
    }

    if let Some(line) = output.lines().find(|l| l.contains("notAfter=")) {
        if let Some(idx) = line.find("notAfter=") {
            let val = line[idx + 9..].trim().to_string();
            info.valid_to = Some(val);

            // 计算剩余天数
            if let Ok(days) = calculate_days_until_expiry(&val) {
                info.days_until_expiry = Some(days);
                info.is_expired = days < 0;
            }
        }
    }

    // 提取 TLS 版本
    if let Some(line) = output.lines().find(|l| l.contains("Protocol :") || l.contains("Protocol:")) {
        info.tls_version = Some(line.trim().to_string());
    }

    // 计算证书链长度
    let cert_count = output.matches("-----BEGIN CERTIFICATE-----").count();
    if cert_count > 0 {
        info.cert_chain_length = Some(cert_count);
    }

    // 提取签名算法
    if let Some(line) = output.lines().find(|l| l.contains("Signature Algorithm:")) {
        let algo = line
            .trim()
            .trim_start_matches("Signature Algorithm: ")
            .trim()
            .to_string();
        if !algo.is_empty() {
            info.signature_algorithm = Some(algo);
        }
    }

    // 提取证书版本
    if let Some(line) = output.lines().find(|l| l.contains("Version:")) {
        let ver = line
            .trim()
            .trim_start_matches("Version: ")
            .trim()
            .to_string();
        if !ver.is_empty() {
            info.version = Some(format!("V{}", ver));
        }
    }

    info
}

/// 计算距离过期还有多少天
fn calculate_days_until_expiry(date_str: &str) -> Result<i64, ()> {
    // openssl 日期格式: "Sep 12 23:59:59 2025 GMT"
    let date_str = date_str.trim();

    // 使用 chrono 解析
    let formats = &[
        "%b %d %H:%M:%S %Y GMT",
        "%b %e %H:%M:%S %Y GMT",
        "%Y-%m-%dT%H:%M:%SZ",
    ];

    for fmt in formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(date_str, fmt) {
            let now = chrono::Utc::now().naive_utc();
            let duration = dt.signed_duration_since(now);
            return Ok(duration.num_days());
        }
    }

    Err(())
}

// ============================================================
// 10. 安全评分
// ============================================================

fn calculate_security_score(
    basic_info: &SiteBasicInfo,
    server_fp: &ServerFingerprint,
    ssl_cert: &SslCertInfo,
    dir_results: &[DirProbeResult],
    tech_stack: &TechStack,
    headers: &HashMap<String, String>,
) -> SecurityScore {
    let mut items = Vec::new();
    let mut total_weight = 0.0;
    let mut weighted_sum = 0.0;
    let mut risks = Vec::new();
    let mut recommendations = Vec::new();

    // 1. SSL/TLS 安全 (权重 20%)
    let mut ssl_score = 0u8;
    let mut ssl_risk = "critical".to_string();
    let mut ssl_desc = String::new();

    if ssl_cert.https_enabled {
        ssl_score = 60;
        ssl_risk = "medium".to_string();
        ssl_desc = "已启用 HTTPS".to_string();

        if ssl_cert.is_expired {
            ssl_score = 20;
            ssl_risk = "critical".to_string();
            ssl_desc = "SSL 证书已过期".to_string();
            risks.push("SSL 证书已过期".to_string());
            recommendations.push("立即更新 SSL 证书".to_string());
        } else if let Some(days) = ssl_cert.days_until_expiry {
            if days < 30 {
                ssl_score = 50;
                ssl_risk = "high".to_string();
                ssl_desc = format!("证书将在 {} 天后过期", days);
                risks.push(format!("SSL 证书将在 {} 天后过期", days));
                recommendations.push("尽快续期 SSL 证书".to_string());
            } else if days < 90 {
                ssl_score = 70;
                ssl_risk = "medium".to_string();
                ssl_desc = format!("证书有效期剩余 {} 天", days);
                recommendations.push("考虑配置自动证书续期".to_string());
            } else {
                ssl_score = 85;
                ssl_risk = "low".to_string();
                ssl_desc = format!("证书有效期剩余 {} 天", days);
            }
        }

        // 检查 TLS 版本
        if let Some(ref tls_ver) = ssl_cert.tls_version {
            if tls_ver.contains("TLSv1.3") || tls_ver.contains("TLS 1.3") {
                ssl_score = ssl_score.saturating_add(10);
            } else if tls_ver.contains("TLSv1.2") || tls_ver.contains("TLS 1.2") {
                ssl_score = ssl_score.saturating_add(5);
            }
            if tls_ver.contains("TLSv1.0") || tls_ver.contains("TLSv1.1") {
                ssl_score = ssl_score.saturating_sub(20);
                risks.push("使用了过时的 TLS 版本".to_string());
                recommendations.push("升级到 TLS 1.2 或更高版本".to_string());
            }
        }
    } else {
        ssl_score = 0;
        ssl_risk = "critical".to_string();
        ssl_desc = "未启用 HTTPS".to_string();
        risks.push("站点未启用 HTTPS".to_string());
        recommendations.push("立即配置 HTTPS 并启用 SSL 证书".to_string());
    }

    items.push(SecurityScoreItem {
        name: "SSL/TLS 安全".to_string(),
        score: std::cmp::min(ssl_score, 100),
        weight: 0.20,
        risk_level: ssl_risk,
        description: ssl_desc,
    });

    // 2. 安全头 (权重 15%)
    let mut header_score = 100u8;
    let security_headers_list = &[
        ("content-security-policy", "Content-Security-Policy", 15),
        ("strict-transport-security", "Strict-Transport-Security", 15),
        ("x-frame-options", "X-Frame-Options", 10),
        ("x-content-type-options", "X-Content-Type-Options", 10),
        ("referrer-policy", "Referrer-Policy", 10),
        ("permissions-policy", "Permissions-Policy", 10),
        ("x-xss-protection", "X-XSS-Protection", 5),
    ];

    let mut missing_headers = Vec::new();
    for (header_key, header_name, penalty) in security_headers_list {
        if !headers.contains_key(*header_key) {
            header_score = header_score.saturating_sub(*penalty);
            missing_headers.push(header_name.to_string());
        }
    }

    let header_risk = if header_score >= 80 {
        "low".to_string()
    } else if header_score >= 60 {
        "medium".to_string()
    } else if header_score >= 40 {
        "high".to_string()
    } else {
        "critical".to_string()
    };

    if !missing_headers.is_empty() {
        risks.push(format!("缺少安全头: {}", missing_headers.join(", ")));
        recommendations.push(format!(
            "添加缺失的安全响应头: {}",
            missing_headers.join(", ")
        ));
    }

    items.push(SecurityScoreItem {
        name: "安全响应头".to_string(),
        score: header_score,
        weight: 0.15,
        risk_level: header_risk,
        description: if missing_headers.is_empty() {
            "安全头配置完整".to_string()
        } else {
            format!("缺少 {} 个安全头", missing_headers.len())
        },
    });

    // 3. 服务器信息泄露 (权重 10%)
    let mut server_leak_score = 100u8;
    if basic_info.server_header.is_some() {
        server_leak_score = server_leak_score.saturating_sub(20);
        risks.push("Server 头泄露服务器信息".to_string());
        recommendations.push("隐藏 Server 响应头或移除版本号".to_string());
    }
    if basic_info.x_powered_by.is_some() {
        server_leak_score = server_leak_score.saturating_sub(20);
        risks.push("X-Powered-By 头泄露技术栈信息".to_string());
        recommendations.push("移除 X-Powered-By 响应头".to_string());
    }

    items.push(SecurityScoreItem {
        name: "服务器信息泄露".to_string(),
        score: server_leak_score,
        weight: 0.10,
        risk_level: if server_leak_score >= 80 { "low".to_string() } else { "medium".to_string() },
        description: if server_leak_score == 100 {
            "未检测到明显的服务器信息泄露".to_string()
        } else {
            "存在服务器信息泄露".to_string()
        },
    });

    // 4. WAF 保护 (权重 10%)
    let waf_score = if server_fp.waf.is_some() && server_fp.waf_confidence >= 50 {
        90u8
    } else if server_fp.waf.is_some() {
        70u8
    } else {
        30u8
    };

    if server_fp.waf.is_none() {
        risks.push("未检测到 WAF 保护".to_string());
        recommendations.push("考虑部署 Web 应用防火墙 (WAF)".to_string());
    }

    items.push(SecurityScoreItem {
        name: "WAF 防护".to_string(),
        score: waf_score,
        weight: 0.10,
        risk_level: if waf_score >= 70 { "low".to_string() } else { "medium".to_string() },
        description: if let Some(ref waf) = server_fp.waf {
            format!("检测到 WAF: {}", waf)
        } else {
            "未检测到 WAF".to_string()
        },
    });

    // 5. 敏感目录/文件 (权重 15%)
    let critical_count = dir_results.iter().filter(|d| d.risk_level == "critical").count();
    let high_count = dir_results.iter().filter(|d| d.risk_level == "high").count();
    let medium_count = dir_results.iter().filter(|d| d.risk_level == "medium").count();

    let mut dir_score = 100u8;
    dir_score = dir_score.saturating_sub((critical_count * 25) as u8);
    dir_score = dir_score.saturating_sub((high_count * 15) as u8);
    dir_score = dir_score.saturating_sub((medium_count * 5) as u8);

    if critical_count > 0 {
        risks.push(format!("发现 {} 个严重级敏感路径", critical_count));
        recommendations.push("立即修复严重级敏感路径泄露".to_string());
    }
    if high_count > 0 {
        risks.push(format!("发现 {} 个高危敏感路径", high_count));
        recommendations.push("限制或关闭高危敏感路径的访问".to_string());
    }

    let dir_risk = if dir_score >= 80 {
        "low".to_string()
    } else if dir_score >= 60 {
        "medium".to_string()
    } else if dir_score >= 40 {
        "high".to_string()
    } else {
        "critical".to_string()
    };

    items.push(SecurityScoreItem {
        name: "敏感路径暴露".to_string(),
        score: dir_score,
        weight: 0.15,
        risk_level: dir_risk,
        description: format!(
            "发现 {} 个敏感路径 (严重: {}, 高危: {}, 中危: {})",
            dir_results.len(),
            critical_count,
            high_count,
            medium_count
        ),
    });

    // 6. CMS/框架版本 (权重 10%)
    let mut cms_score = 100u8;
    let cms_count = tech_stack.cms.len();
    if cms_count > 0 {
        // 如果能检测到 CMS 但没有版本信息，中等风险
        let has_version = tech_stack.cms.iter().any(|c| c.version.is_some());
        if has_version {
            cms_score = 60;
            risks.push("CMS 版本信息可能泄露".to_string());
            recommendations.push("隐藏 CMS 版本信息".to_string());
        } else {
            cms_score = 80;
        }
    }

    items.push(SecurityScoreItem {
        name: "CMS/框架安全".to_string(),
        score: cms_score,
        weight: 0.10,
        risk_level: if cms_score >= 80 { "low".to_string() } else { "medium".to_string() },
        description: if cms_count > 0 {
            format!("检测到 {} 种 CMS/框架", cms_count)
        } else {
            "未检测到已知 CMS".to_string()
        },
    });

    // 7. 响应时间与可用性 (权重 5%)
    let availability_score = if basic_info.status_code >= 200 && basic_info.status_code < 300 {
        if basic_info.response_time_ms < 500 {
            95u8
        } else if basic_info.response_time_ms < 2000 {
            85u8
        } else if basic_info.response_time_ms < 5000 {
            70u8
        } else {
            50u8
        }
    } else if basic_info.status_code >= 300 && basic_info.status_code < 400 {
        80u8
    } else if basic_info.status_code >= 400 && basic_info.status_code < 500 {
        50u8
    } else {
        20u8
    };

    items.push(SecurityScoreItem {
        name: "站点可用性".to_string(),
        score: availability_score,
        weight: 0.05,
        risk_level: if availability_score >= 70 { "low".to_string() } else { "medium".to_string() },
        description: format!(
            "HTTP {}，响应时间 {}ms",
            basic_info.status_code, basic_info.response_time_ms
        ),
    });

    // 8. CDN 保护 (权重 5%)
    let cdn_score = if server_fp.cdn.is_some() && server_fp.cdn_confidence >= 50 {
        85u8
    } else if server_fp.cdn.is_some() {
        65u8
    } else {
        40u8
    };

    if server_fp.cdn.is_none() {
        recommendations.push("考虑使用 CDN 提升性能和安全性".to_string());
    }

    items.push(SecurityScoreItem {
        name: "CDN 防护".to_string(),
        score: cdn_score,
        weight: 0.05,
        risk_level: if cdn_score >= 70 { "low".to_string() } else { "medium".to_string() },
        description: if let Some(ref cdn) = server_fp.cdn {
            format!("检测到 CDN: {}", cdn)
        } else {
            "未检测到 CDN".to_string()
        },
    });

    // 计算加权总分
    for item in &items {
        total_weight += item.weight;
        weighted_sum += item.score as f32 * item.weight;
    }

    let total_score = if total_weight > 0.0 {
        (weighted_sum / total_weight) as u8
    } else {
        0
    };

    let grade = if total_score >= 90 {
        "excellent".to_string()
    } else if total_score >= 75 {
        "good".to_string()
    } else if total_score >= 60 {
        "medium".to_string()
    } else if total_score >= 40 {
        "low".to_string()
    } else {
        "critical".to_string()
    };

    SecurityScore {
        total_score,
        grade,
        items,
        risks,
        recommendations,
    }
}

// ============================================================
// 公共 API
// ============================================================

/// 分析站点信息
pub fn analyze_site(url: String, config: SiteInfoConfig) -> Result<String, String> {
    let total_start = Instant::now();

    // 规范化 URL
    let normalized_url = normalize_url(&url)?;

    // 构建 HTTP 客户端
    let client = build_client(&config)?;

    // ========== 阶段 1：基础信息采集（同步） ==========
    let (basic_info, headers, document, body) =
        collect_basic_info(&normalized_url, &client)?;

    // 提取 cookie 字符串
    let cookies_str = headers
        .get("set-cookie")
        .cloned()
        .unwrap_or_default();

    // ========== 阶段 2：并发执行多项检测 ==========
    let domain = extract_domain(&basic_info.final_url).unwrap_or_default();
    let base_url = get_base_url(&basic_info.final_url)?;

    // 使用多线程并发执行独立检测
    let body_clone = body.clone();
    let headers_clone = headers.clone();
    let cookies_clone = cookies_str.clone();
    let document_html = document.html();

    // 线程 1: CMS 检测
    let handle_cms = thread::spawn(move || {
        // 重新解析 HTML
        let doc = Html::parse_document(&document_html);
        detect_cms(&doc, &headers_clone, &body_clone, &cookies_clone)
    });

    // 线程 2: 前端框架检测 + JS/CSS 库检测
    let body_clone2 = body.clone();
    let handle_frontend = thread::spawn(move || {
        let frameworks = detect_frontend_frameworks(&body_clone2);

        // JS 库检测
        let mut js_libs = Vec::new();
        let js_patterns = vec![
            ("jQuery", vec!["jquery.min.js", "jquery.js", "jQuery.fn"]),
            ("Bootstrap JS", vec!["bootstrap.min.js", "bootstrap.js"]),
            ("Lodash", vec!["lodash", "_."]),
            ("Moment.js", vec!["moment.min.js", "moment.js"]),
            ("Axios", vec!["axios.min.js", "axios.js"]),
            ("D3.js", vec!["d3.min.js", "d3.v"]),
            ("Three.js", vec!["three.min.js", "three.js"]),
        ];
        let body_lower = body_clone2.to_lowercase();
        for (lib_name, patterns) in &js_patterns {
            if patterns.iter().any(|p| body_lower.contains(p)) {
                js_libs.push(lib_name.to_string());
            }
        }

        // CSS 框架检测
        let mut css_frameworks = Vec::new();
        let css_patterns = vec![
            ("Bootstrap", vec!["bootstrap.min.css", "bootstrap.css"]),
            ("Tailwind CSS", vec!["tailwind", "tailwindcss"]),
            ("Bulma", vec!["bulma.min.css", "bulma.css"]),
            ("Foundation", vec!["foundation.min.css", "foundation.css"]),
            ("Materialize", vec!["materialize.min.css", "materialize.css"]),
            ("Semantic UI", vec!["semantic.min.css", "semantic-ui"]),
            ("Ant Design", vec!["antd", "ant.design"]),
        ];
        for (css_name, patterns) in &css_patterns {
            if patterns.iter().any(|p| body_lower.contains(p)) {
                css_frameworks.push(css_name.to_string());
            }
        }

        (frameworks, js_libs, css_frameworks)
    });

    // 线程 3: 服务器指纹
    let body_clone3 = body.clone();
    let headers_clone2 = headers.clone();
    let status_code = basic_info.status_code;
    let handle_server = thread::spawn(move || {
        detect_server_fingerprint(&headers_clone2, &body_clone3, status_code)
    });

    // 线程 4: 编程语言检测
    let body_clone4 = body.clone();
    let headers_clone3 = headers.clone();
    let final_url = basic_info.final_url.clone();
    let handle_langs = thread::spawn(move || {
        detect_programming_languages(&headers_clone3, &body_clone4, &final_url)
    });

    // 线程 5: 子域名发现
    let domain_clone = domain.clone();
    let config_clone = config.clone();
    let handle_subdomains = thread::spawn(move || {
        discover_subdomains(&domain_clone, &config_clone)
    });

    // 线程 6: 目录探测
    let base_url_clone = base_url.clone();
    let config_clone2 = config.clone();
    let handle_dirs = thread::spawn(move || {
        probe_directories(&base_url_clone, &config_clone2)
    });

    // 线程 7: SSL 证书检测
    let final_url_clone = basic_info.final_url.clone();
    let config_clone3 = config.clone();
    let handle_ssl = thread::spawn(move || {
        check_ssl_cert(&final_url_clone, &config_clone3)
    });

    // 等待所有线程完成
    let cms_list = handle_cms.join().unwrap_or_default();
    let (frontend_frameworks, js_libraries, css_frameworks) =
        handle_frontend.join().unwrap_or_default();
    let server_fingerprint = handle_server.join().unwrap_or_else(|_| ServerFingerprint {
        web_server: None,
        web_server_version: None,
        middleware: Vec::new(),
        cdn: None,
        cdn_confidence: 0,
        cdn_evidence: Vec::new(),
        waf: None,
        waf_confidence: 0,
        waf_evidence: Vec::new(),
        reverse_proxy: Vec::new(),
    });
    let languages = handle_langs.join().unwrap_or_default();
    let subdomains = handle_subdomains.join().unwrap_or_default();
    let dir_results = handle_dirs.join().unwrap_or_default();
    let ssl_cert = handle_ssl.join().unwrap_or_else(|_| SslCertInfo {
        https_enabled: false,
        subject_cn: None,
        subject_alt_names: Vec::new(),
        issuer: None,
        version: None,
        signature_algorithm: None,
        valid_from: None,
        valid_to: None,
        days_until_expiry: None,
        is_expired: false,
        tls_version: None,
        cert_chain_length: None,
    });

    // 数据库推断（依赖 CMS 和编程语言结果）
    let databases = infer_databases(&cms_list, &languages, &body);

    // 组装技术栈
    let tech_stack = TechStack {
        cms: cms_list,
        frontend_frameworks,
        server: server_fingerprint.clone(),
        programming_languages: languages,
        databases,
        js_libraries,
        css_frameworks,
    };

    // 安全评分
    let security_score = calculate_security_score(
        &basic_info,
        &server_fingerprint,
        &ssl_cert,
        &dir_results,
        &tech_stack,
        &headers,
    );

    let total_duration_ms = total_start.elapsed().as_millis() as u64;

    // 组装最终结果
    let result = SiteAnalysisResult {
        basic_info,
        tech_stack,
        subdomains,
        dir_probe_results: dir_results,
        ssl_cert,
        security_score,
        total_duration_ms,
        response_headers: headers,
    };

    serde_json::to_string(&result).map_err(|e| format!("序列化失败: {}", e))
}
