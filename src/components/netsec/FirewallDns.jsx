import { useState } from "react";
import { api } from "../../api.js";
import { useLang } from "../../i18n.js";
import { IconPlay, IconShield, IconRefresh } from "../Icons.jsx";

/**
 * 危险端口定义
 */
const DANGEROUS_PORTS = [
  { port: 21, service: "FTP", risk: "high", desc: "FTP 明文传输，易被嗅探密码" },
  { port: 22, service: "SSH", risk: "medium", desc: "SSH 服务暴露，可能遭受暴力破解" },
  { port: 23, service: "Telnet", risk: "critical", desc: "Telnet 明文传输，极不安全" },
  { port: 135, service: "RPC", risk: "high", desc: "RPC 服务常被用于蠕虫传播" },
  { port: 139, service: "NetBIOS", risk: "high", desc: "NetBIOS 可被利用进行 SMB 攻击" },
  { port: 445, service: "SMB", risk: "critical", desc: "SMB 服务是永恒之蓝等漏洞的目标" },
  { port: 3389, service: "RDP", risk: "high", desc: "远程桌面服务暴露，易遭暴力破解" },
  { port: 3306, service: "MySQL", risk: "high", desc: "数据库端口不应暴露在公网" },
  { port: 5432, service: "PostgreSQL", risk: "high", desc: "数据库端口不应暴露在公网" },
  { port: 6379, service: "Redis", risk: "critical", desc: "Redis 默认无密码，极易被入侵" },
  { port: 27017, service: "MongoDB", risk: "high", desc: "MongoDB 默认无认证，易被入侵" },
];

/**
 * 常用 20 个端口
 */
const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
  443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080,
];

/**
 * 端口状态颜色映射
 */
const PORT_STATUS_STYLE = {
  open: { color: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-50 dark:bg-emerald-950/50" },
  closed: { color: "text-neutral-500 dark:text-neutral-400", bg: "bg-neutral-100 dark:bg-neutral-800" },
  filtered: { color: "text-orange-600 dark:text-orange-400", bg: "bg-orange-50 dark:bg-orange-950/50" },
};

/**
 * 安全评级颜色映射
 */
const GRADE_STYLE = {
  A: { color: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-50 dark:bg-emerald-950/50" },
  B: { color: "text-green-600 dark:text-green-400", bg: "bg-green-50 dark:bg-green-950/50" },
  C: { color: "text-yellow-600 dark:text-yellow-400", bg: "bg-yellow-50 dark:bg-yellow-950/50" },
  D: { color: "text-orange-600 dark:text-orange-400", bg: "bg-orange-50 dark:bg-orange-950/50" },
  F: { color: "text-red-600 dark:text-red-400", bg: "bg-red-50 dark:bg-red-950/50" },
};

/**
 * 防火墙绕过测试类型
 */
const BYPASS_TESTS = [
  { key: "fragment", name: "分片绕过" },
  { key: "source_port", name: "源端口欺骗" },
  { key: "ip_option", name: "IP 选项绕过" },
  { key: "ack_scan", name: "ACK 扫描" },
  { key: "idle_scan", name: "空闲扫描" },
  { key: "decoy", name: "诱饵扫描" },
  { key: "timing", name: "时序绕过" },
];

// ────────────────────────────────────────────
// Tab 1: 防火墙测试 - 端口结果表格
// ────────────────────────────────────────────
function PortResultTable({ results, t }) {
  if (!results || results.length === 0) {
    return (
      <div className="py-8 text-center text-xs text-neutral-400">
        {t("firewallDns.noPortResult")}
      </div>
    );
  }

  return (
    <div className="max-h-[240px] overflow-auto">
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
          <tr>
            <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.port")}</th>
            <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.service")}</th>
            <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.status")}</th>
            <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.responseTime")}</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r, i) => {
            const style = PORT_STATUS_STYLE[r.status] || PORT_STATUS_STYLE.closed;
            return (
              <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                <td className="px-3 py-2 font-mono">{r.port}</td>
                <td className="px-3 py-2 text-neutral-500 dark:text-neutral-400">{r.service || "-"}</td>
                <td className="px-3 py-2">
                  <span className={`chip text-[11px] ${style.color} ${style.bg}`}>
                    {t(`firewallDns.status_${r.status}`)}
                  </span>
                </td>
                <td className="px-3 py-2 text-neutral-500 dark:text-neutral-400 font-mono">
                  {r.latency != null ? `${r.latency}ms` : "-"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 1: 防火墙测试 - 危险端口警告
// ────────────────────────────────────────────
function DangerousPortsWarning({ results, t }) {
  const openPorts = results?.filter((r) => r.status === "open") || [];
  const dangerous = openPorts
    .map((p) => {
      const info = DANGEROUS_PORTS.find((d) => d.port === p.port);
      return info ? { ...p, ...info } : null;
    })
    .filter(Boolean);

  if (dangerous.length === 0) {
    return (
      <div className="flex items-center gap-2 rounded-xl bg-emerald-50 p-3 dark:bg-emerald-950/30">
        <IconShield size={16} className="text-emerald-500" />
        <span className="text-xs text-emerald-700 dark:text-emerald-400">
          {t("firewallDns.noDangerousPorts")}
        </span>
      </div>
    );
  }

  const riskOrder = { critical: 0, high: 1, medium: 2 };
  dangerous.sort((a, b) => (riskOrder[a.risk] ?? 9) - (riskOrder[b.risk] ?? 9));

  return (
    <div className="space-y-2">
      {dangerous.map((d, i) => {
        const riskStyle =
          d.risk === "critical"
            ? "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/50"
            : d.risk === "high"
            ? "text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/50"
            : "text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-950/50";
        return (
          <div key={i} className="rounded-xl border border-neutral-200 dark:border-neutral-800 p-3">
            <div className="mb-1 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold">{d.port}</span>
                <span className="text-xs text-neutral-500 dark:text-neutral-400">{d.service}</span>
              </div>
              <span className={`chip text-[10px] ${riskStyle}`}>
                {t(`firewallDns.risk_${d.risk}`)}
              </span>
            </div>
            <p className="text-[11px] text-neutral-500 dark:text-neutral-400">{d.desc}</p>
          </div>
        );
      })}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 1: 防火墙测试 - 概览统计卡片
// ────────────────────────────────────────────
function StatsCards({ stats, t }) {
  const cards = [
    { label: t("firewallDns.openPorts"), value: stats.open, color: "text-emerald-600 dark:text-emerald-400" },
    { label: t("firewallDns.closedPorts"), value: stats.closed, color: "text-neutral-600 dark:text-neutral-400" },
    { label: t("firewallDns.filteredPorts"), value: stats.filtered, color: "text-orange-600 dark:text-orange-400" },
    { label: t("firewallDns.elapsed"), value: stats.elapsed, color: "text-blue-600 dark:text-blue-400" },
  ];

  return (
    <div className="grid grid-cols-4 gap-2">
      {cards.map((c, i) => (
        <div key={i} className="rounded-xl bg-neutral-50 dark:bg-neutral-800/50 p-3 text-center">
          <div className={`text-xl font-bold ${c.color}`}>{c.value}</div>
          <div className="mt-0.5 text-[10px] text-neutral-500 dark:text-neutral-400">{c.label}</div>
        </div>
      ))}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 1: 子 Tab - 防火墙绕过
// ────────────────────────────────────────────
function BypassSection({ bypassResults, t }) {
  if (!bypassResults || bypassResults.length === 0) {
    return (
      <div className="py-8 text-center text-xs text-neutral-400">
        {t("firewallDns.runBypassTestHint")}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-[11px] text-neutral-500 dark:text-neutral-400 mb-2">
        {t("firewallDns.bypassDisclaimer")}
      </p>
      {bypassResults.map((r, i) => {
        const style =
          r.vulnerable
            ? "text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/50"
            : "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50";
        return (
          <div key={i} className="rounded-xl border border-neutral-200 dark:border-neutral-800 p-3">
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-medium">{r.name}</span>
              <span className={`chip text-[10px] ${style}`}>
                {r.vulnerable ? t("firewallDns.bypassPossible") : t("firewallDns.bypassBlocked")}
              </span>
            </div>
            <p className="text-[11px] text-neutral-500 dark:text-neutral-400">{r.description}</p>
          </div>
        );
      })}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 1: 子 Tab - 安全审计
// ────────────────────────────────────────────
function AuditSection({ auditResult, t }) {
  if (!auditResult) {
    return (
      <div className="py-8 text-center text-xs text-neutral-400">
        {t("firewallDns.runAuditHint")}
      </div>
    );
  }

  const gradeStyle = GRADE_STYLE[auditResult.grade] || GRADE_STYLE.F;

  return (
    <div className="space-y-4">
      {/* 安全评分 */}
      <div className="rounded-xl border border-neutral-200 dark:border-neutral-800 p-4 text-center">
        <div className={`text-5xl font-bold ${gradeStyle.color}`}>{auditResult.score}</div>
        <div className={`mt-2 inline-block chip text-sm ${gradeStyle.color} ${gradeStyle.bg}`}>
          {t("firewallDns.grade")} {auditResult.grade}
        </div>
        <p className="mt-2 text-xs text-neutral-500 dark:text-neutral-400">
          {auditResult.summary}
        </p>
      </div>

      {/* 改进建议 */}
      <div>
        <h4 className="mb-2 text-xs font-semibold text-neutral-700 dark:text-neutral-300">
          {t("firewallDns.improvementSuggestions")}
        </h4>
        <div className="space-y-2">
          {auditResult.suggestions?.map((s, i) => (
            <div key={i} className="flex gap-2 rounded-xl bg-neutral-50 dark:bg-neutral-800/50 p-2.5">
              <span className={`mt-0.5 h-2 w-2 shrink-0 rounded-full ${
                s.priority === "high" ? "bg-red-500" : s.priority === "medium" ? "bg-orange-500" : "bg-blue-500"
              }`} />
              <div className="flex-1">
                <p className="text-xs font-medium text-neutral-700 dark:text-neutral-300">{s.title}</p>
                <p className="mt-0.5 text-[11px] text-neutral-500 dark:text-neutral-400">{s.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 2: DNS 安全 - 卡片 1: DNS 服务器信息
// ────────────────────────────────────────────
function DnsServersCard({ t }) {
  const [loading, setLoading] = useState(false);
  const [servers, setServers] = useState([]);

  const fetchServers = async () => {
    setLoading(true);
    try {
      const res = await api.dnsGetServers();
      setServers(res?.servers || []);
    } catch (e) {
      setServers([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card flex flex-col gap-3 transition-all duration-200 hover:shadow-card-hover">
      <h4 className="text-sm font-semibold">{t("firewallDns.dnsServers")}</h4>
      <button
        onClick={fetchServers}
        disabled={loading}
        className="pill pill-outline pill-hover w-full justify-center text-xs"
      >
        {loading ? (
          <><span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />{t("common.running")}</>
        ) : (
          <><IconRefresh size={12} />{t("firewallDns.getDnsServers")}</>
        )}
      </button>
      {servers.length > 0 && (
        <div className="space-y-1.5">
          {servers.map((s, i) => (
            <div key={i} className="flex items-center justify-between rounded-lg bg-neutral-50 dark:bg-neutral-800/50 px-2.5 py-2">
              <div>
                <div className="font-mono text-xs">{s.address}</div>
                <div className="text-[10px] text-neutral-500 dark:text-neutral-400">
                  {s.latency != null ? `${s.latency}ms` : "-"}
                </div>
              </div>
              <span className={`chip text-[10px] ${s.dnssec
                ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
                : "text-neutral-500 dark:text-neutral-400 bg-neutral-100 dark:bg-neutral-800"
              }`}>
                {s.dnssec ? "DNSSEC" : "No DNSSEC"}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 2: DNS 安全 - 卡片 2: DNS 速度测试
// ────────────────────────────────────────────
function DnsSpeedCard({ t }) {
  const [domains, setDomains] = useState("google.com, baidu.com, github.com");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);

  const runTest = async () => {
    if (!domains.trim()) return;
    setLoading(true);
    try {
      const list = domains.split(",").map((d) => d.trim()).filter(Boolean);
      const res = await api.dnsSpeedTest(list);
      setResults(res?.results || []);
    } catch (e) {
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  const validResults = results.filter((r) => r.success);
  const times = validResults.map((r) => r.latency).filter((n) => n != null);
  const avg = times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : 0;
  const fastest = times.length ? Math.min(...times) : 0;
  const slowest = times.length ? Math.max(...times) : 0;
  const successRate = results.length ? Math.round((validResults.length / results.length) * 100) : 0;

  return (
    <div className="card flex flex-col gap-3 transition-all duration-200 hover:shadow-card-hover">
      <h4 className="text-sm font-semibold">{t("firewallDns.dnsSpeedTest")}</h4>
      <div>
        <label className="mb-1 block text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
          {t("firewallDns.domains")}
        </label>
        <input
          className="field w-full font-mono text-xs"
          value={domains}
          onChange={(e) => setDomains(e.target.value)}
          placeholder="google.com, baidu.com"
        />
      </div>
      <button
        onClick={runTest}
        disabled={loading || !domains.trim()}
        className="pill pill-hover w-full justify-center text-xs"
      >
        {loading ? (
          <><span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />{t("common.running")}</>
        ) : (
          <><IconPlay size={12} />{t("firewallDns.startTest")}</>
        )}
      </button>
      {results.length > 0 && (
        <>
          <div className="grid grid-cols-4 gap-1 text-center">
            <div className="rounded-lg bg-neutral-50 dark:bg-neutral-800/50 py-1.5">
              <div className="text-sm font-bold text-blue-600 dark:text-blue-400">{avg}ms</div>
              <div className="text-[9px] text-neutral-500 dark:text-neutral-400">{t("firewallDns.avgTime")}</div>
            </div>
            <div className="rounded-lg bg-neutral-50 dark:bg-neutral-800/50 py-1.5">
              <div className="text-sm font-bold text-emerald-600 dark:text-emerald-400">{fastest}ms</div>
              <div className="text-[9px] text-neutral-500 dark:text-neutral-400">{t("firewallDns.fastest")}</div>
            </div>
            <div className="rounded-lg bg-neutral-50 dark:bg-neutral-800/50 py-1.5">
              <div className="text-sm font-bold text-orange-600 dark:text-orange-400">{slowest}ms</div>
              <div className="text-[9px] text-neutral-500 dark:text-neutral-400">{t("firewallDns.slowest")}</div>
            </div>
            <div className="rounded-lg bg-neutral-50 dark:bg-neutral-800/50 py-1.5">
              <div className="text-sm font-bold text-purple-600 dark:text-purple-400">{successRate}%</div>
              <div className="text-[9px] text-neutral-500 dark:text-neutral-400">{t("firewallDns.successRate")}</div>
            </div>
          </div>
          <div className="max-h-[120px] overflow-auto rounded-lg border border-neutral-200 dark:border-neutral-800">
            <table className="w-full text-left text-[11px]">
              <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
                <tr>
                  <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.domain")}</th>
                  <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.resolveTime")}</th>
                  <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.result")}</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                    <td className="px-2 py-1.5 font-mono">{r.domain}</td>
                    <td className="px-2 py-1.5 text-neutral-500 dark:text-neutral-400">
                      {r.success ? `${r.latency}ms` : "-"}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-neutral-600 dark:text-neutral-400 truncate max-w-[100px]">
                      {r.success ? r.ip : t("firewallDns.failed")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 2: DNS 安全 - 卡片 3: DNS 泄露测试
// ────────────────────────────────────────────
function DnsLeakCard({ t }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const runTest = async () => {
    setLoading(true);
    try {
      const res = await api.dnsLeakTest();
      setResult(res);
    } catch (e) {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const leaking = result?.leaking;

  return (
    <div className="card flex flex-col gap-3 transition-all duration-200 hover:shadow-card-hover">
      <h4 className="text-sm font-semibold">{t("firewallDns.dnsLeakTest")}</h4>
      <button
        onClick={runTest}
        disabled={loading}
        className="pill pill-hover w-full justify-center text-xs"
      >
        {loading ? (
          <><span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />{t("common.running")}</>
        ) : (
          <><IconPlay size={12} />{t("firewallDns.startLeakTest")}</>
        )}
      </button>
      {result && (
        <>
          <div className={`flex items-center justify-center gap-2 rounded-xl py-3 ${
            leaking
              ? "bg-red-50 dark:bg-red-950/30"
              : "bg-emerald-50 dark:bg-emerald-950/30"
          }`}>
            <IconShield size={18} className={leaking ? "text-red-500" : "text-emerald-500"} />
            <span className={`text-sm font-semibold ${leaking ? "text-red-700 dark:text-red-400" : "text-emerald-700 dark:text-emerald-400"}`}>
              {leaking ? t("firewallDns.dnsLeaking") : t("firewallDns.dnsSafe")}
            </span>
          </div>
          {result.servers?.length > 0 && (
            <div>
              <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                {t("firewallDns.detectedServers")}
              </p>
              <div className="space-y-1">
                {result.servers.map((s, i) => (
                  <div key={i} className="flex items-center justify-between rounded-lg bg-neutral-50 dark:bg-neutral-800/50 px-2 py-1.5">
                    <span className="font-mono text-[11px]">{s.ip}</span>
                    <span className="text-[10px] text-neutral-500 dark:text-neutral-400">{s.isp || "-"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {result.channels?.length > 0 && (
            <div>
              <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                {t("firewallDns.leakChannels")}
              </p>
              <div className="flex flex-wrap gap-1">
                {result.channels.map((c, i) => (
                  <span key={i} className="chip text-[10px] bg-red-50 text-red-600 dark:bg-red-950/50 dark:text-red-400">
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 2: DNS 安全 - 卡片 4: DNS 投毒检测
// ────────────────────────────────────────────
function DnsPoisonCard({ t }) {
  const [domain, setDomain] = useState("google.com");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const runTest = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const res = await api.dnsPoisonDetect(domain.trim());
      setResult(res);
    } catch (e) {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const poisoned = result?.poisoned;

  return (
    <div className="card flex flex-col gap-3 transition-all duration-200 hover:shadow-card-hover">
      <h4 className="text-sm font-semibold">{t("firewallDns.dnsPoisonDetect")}</h4>
      <div>
        <label className="mb-1 block text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
          {t("firewallDns.domain")}
        </label>
        <input
          className="field w-full font-mono text-xs"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
        />
      </div>
      <button
        onClick={runTest}
        disabled={loading || !domain.trim()}
        className="pill pill-hover w-full justify-center text-xs"
      >
        {loading ? (
          <><span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />{t("common.running")}</>
        ) : (
          <><IconPlay size={12} />{t("firewallDns.detect")}</>
        )}
      </button>
      {result && (
        <>
          {poisoned && (
            <div className="rounded-xl bg-red-50 p-2.5 dark:bg-red-950/30">
              <p className="text-xs font-semibold text-red-700 dark:text-red-400">
                ⚠ {t("firewallDns.poisoningDetected")}
              </p>
              <p className="mt-1 text-[11px] text-red-600 dark:text-red-400">
                {result.warning}
              </p>
            </div>
          )}
          {result.servers?.length > 0 && (
            <div className="max-h-[140px] overflow-auto rounded-lg border border-neutral-200 dark:border-neutral-800">
              <table className="w-full text-left text-[11px]">
                <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
                  <tr>
                    <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.dnsServer")}</th>
                    <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.result")}</th>
                    <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">{t("firewallDns.status")}</th>
                  </tr>
                </thead>
                <tbody>
                  {result.servers.map((s, i) => (
                    <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                      <td className="px-2 py-1.5 font-mono text-[10px]">{s.server}</td>
                      <td className="px-2 py-1.5 font-mono text-[10px] text-neutral-600 dark:text-neutral-400">
                        {s.ips?.join(", ") || "-"}
                      </td>
                      <td className="px-2 py-1.5">
                        <span className={`chip text-[9px] ${
                          s.anomaly
                            ? "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/50"
                            : "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
                        }`}>
                          {s.anomaly ? t("firewallDns.anomaly") : t("firewallDns.normal")}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 2: DNS 安全 - 卡片 5: 邮件安全检查
// ────────────────────────────────────────────
function EmailSecurityCard({ t }) {
  const [domain, setDomain] = useState("gmail.com");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const runTest = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const res = await api.dnsEmailSecurity(domain.trim());
      setResult(res);
    } catch (e) {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const grade = result?.grade || "F";
  const gradeStyle = GRADE_STYLE[grade] || GRADE_STYLE.F;

  return (
    <div className="card flex flex-col gap-3 transition-all duration-200 hover:shadow-card-hover">
      <h4 className="text-sm font-semibold">{t("firewallDns.emailSecurity")}</h4>
      <div>
        <label className="mb-1 block text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
          {t("firewallDns.domain")}
        </label>
        <input
          className="field w-full font-mono text-xs"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
        />
      </div>
      <button
        onClick={runTest}
        disabled={loading || !domain.trim()}
        className="pill pill-hover w-full justify-center text-xs"
      >
        {loading ? (
          <><span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />{t("common.running")}</>
        ) : (
          <><IconPlay size={12} />{t("firewallDns.check")}</>
        )}
      </button>
      {result && (
        <>
          {/* 综合评级 */}
          <div className={`flex items-center justify-center gap-2 rounded-xl py-2 ${gradeStyle.bg}`}>
            <span className={`text-2xl font-bold ${gradeStyle.color}`}>{grade}</span>
            <span className={`text-xs ${gradeStyle.color}`}>{t("firewallDns.overallRating")}</span>
          </div>

          {/* SPF */}
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium">SPF</span>
              <span className={`chip text-[10px] ${
                result.spf?.exists
                  ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
                  : "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/50"
              }`}>
                {result.spf?.exists ? t("firewallDns.present") : t("firewallDns.missing")}
              </span>
            </div>
            {result.spf?.content && (
              <p className="truncate font-mono text-[10px] text-neutral-500 dark:text-neutral-400">
                {result.spf.content}
              </p>
            )}
            {result.spf?.evaluation && (
              <p className="text-[10px] text-neutral-500 dark:text-neutral-400">{result.spf.evaluation}</p>
            )}
          </div>

          {/* DKIM */}
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium">DKIM</span>
            <span className={`chip text-[10px] ${
              result.dkim?.enabled
                ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
                : "text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/50"
            }`}>
              {result.dkim?.enabled ? t("firewallDns.enabled") : t("firewallDns.notDetected")}
            </span>
          </div>

          {/* DMARC */}
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium">DMARC</span>
              <span className={`chip text-[10px] ${
                result.dmarc?.policy
                  ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
                  : "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/50"
              }`}>
                {result.dmarc?.policy ? result.dmarc.policy.toUpperCase() : t("firewallDns.missing")}
              </span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 2: DNS 安全 - 卡片 6: DNSSEC 验证
// ────────────────────────────────────────────
function DnssecCard({ t }) {
  const [domain, setDomain] = useState("cloudflare.com");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const runTest = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const res = await api.dnsDnssecCheck(domain.trim());
      setResult(res);
    } catch (e) {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const enabled = result?.enabled;

  return (
    <div className="card flex flex-col gap-3 transition-all duration-200 hover:shadow-card-hover">
      <h4 className="text-sm font-semibold">{t("firewallDns.dnssecValidation")}</h4>
      <div>
        <label className="mb-1 block text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
          {t("firewallDns.domain")}
        </label>
        <input
          className="field w-full font-mono text-xs"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
        />
      </div>
      <button
        onClick={runTest}
        disabled={loading || !domain.trim()}
        className="pill pill-hover w-full justify-center text-xs"
      >
        {loading ? (
          <><span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />{t("common.running")}</>
        ) : (
          <><IconPlay size={12} />{t("firewallDns.validate")}</>
        )}
      </button>
      {result && (
        <>
          <div className={`flex items-center justify-center gap-2 rounded-xl py-2.5 ${
            enabled
              ? "bg-emerald-50 dark:bg-emerald-950/30"
              : "bg-orange-50 dark:bg-orange-950/30"
          }`}>
            <IconShield size={18} className={enabled ? "text-emerald-500" : "text-orange-500"} />
            <span className={`text-sm font-semibold ${
              enabled ? "text-emerald-700 dark:text-emerald-400" : "text-orange-700 dark:text-orange-400"
            }`}>
              {enabled ? t("firewallDns.dnssecEnabled") : t("firewallDns.dnssecNotEnabled")}
            </span>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between rounded-lg bg-neutral-50 dark:bg-neutral-800/50 px-2 py-1.5">
              <span className="text-[11px] text-neutral-600 dark:text-neutral-400">DNSKEY</span>
              <span className={`chip text-[10px] ${
                result.dnskey
                  ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
                  : "text-neutral-500 dark:text-neutral-400 bg-neutral-100 dark:bg-neutral-800"
              }`}>
                {result.dnskey ? t("firewallDns.found") : t("firewallDns.notFound")}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg bg-neutral-50 dark:bg-neutral-800/50 px-2 py-1.5">
              <span className="text-[11px] text-neutral-600 dark:text-neutral-400">RRSIG</span>
              <span className={`chip text-[10px] ${
                result.rrsig
                  ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
                  : "text-neutral-500 dark:text-neutral-400 bg-neutral-100 dark:bg-neutral-800"
              }`}>
                {result.rrsig ? t("firewallDns.found") : t("firewallDns.notFound")}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg bg-neutral-50 dark:bg-neutral-800/50 px-2 py-1.5">
              <span className="text-[11px] text-neutral-600 dark:text-neutral-400">DS</span>
              <span className={`chip text-[10px] ${
                result.ds
                  ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
                  : "text-neutral-500 dark:text-neutral-400 bg-neutral-100 dark:bg-neutral-800"
              }`}>
                {result.ds ? t("firewallDns.found") : t("firewallDns.notFound")}
              </span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 2: 底部工具 - 反向 DNS 查询
// ────────────────────────────────────────────
function ReverseDnsTool({ t }) {
  const [ip, setIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const runLookup = async () => {
    if (!ip.trim()) return;
    setLoading(true);
    try {
      const res = await api.dnsReverse(ip.trim());
      setResult(res);
    } catch (e) {
      setResult({ error: String(e) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card flex items-center gap-2 p-2.5 transition-all duration-200 hover:shadow-card-hover">
      <input
        className="field flex-1 font-mono text-xs"
        value={ip}
        onChange={(e) => setIp(e.target.value)}
        placeholder={t("firewallDns.enterIp")}
        onKeyDown={(e) => e.key === "Enter" && runLookup()}
      />
      <button
        onClick={runLookup}
        disabled={loading || !ip.trim()}
        className="pill pill-outline pill-hover text-xs whitespace-nowrap"
      >
        {loading ? (
          <span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />
        ) : (
          <IconPlay size={12} />
        )}
        {t("firewallDns.reverseDns")}
      </button>
      {result && !result.error && result.domains?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {result.domains.slice(0, 3).map((d, i) => (
            <span key={i} className="chip text-[10px] bg-blue-50 text-blue-600 dark:bg-blue-950/50 dark:text-blue-400">
              {d}
            </span>
          ))}
          {result.domains.length > 3 && (
            <span className="chip text-[10px] bg-neutral-100 text-neutral-500 dark:bg-neutral-800 dark:text-neutral-400">
              +{result.domains.length - 3}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ────────────────────────────────────────────
// Tab 2: 底部工具 - DNS 隧道检测
// ────────────────────────────────────────────
function DnsTunnelTool({ t }) {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const runDetect = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const res = await api.dnsTunnelDetect(domain.trim());
      setResult(res);
    } catch (e) {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const suspicious = result?.suspicious;

  return (
    <div className="card flex items-center gap-2 p-2.5 transition-all duration-200 hover:shadow-card-hover">
      <input
        className="field flex-1 font-mono text-xs"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        placeholder={t("firewallDns.enterDomain")}
        onKeyDown={(e) => e.key === "Enter" && runDetect()}
      />
      <button
        onClick={runDetect}
        disabled={loading || !domain.trim()}
        className="pill pill-outline pill-hover text-xs whitespace-nowrap"
      >
        {loading ? (
          <span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />
        ) : (
          <IconPlay size={12} />
        )}
        {t("firewallDns.tunnelDetect")}
      </button>
      {result && (
        <span className={`chip text-[10px] ${
          suspicious
            ? "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/50"
            : "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50"
        }`}>
          {suspicious ? t("firewallDns.suspicious") : t("firewallDns.normal")}
        </span>
      )}
    </div>
  );
}

// ────────────────────────────────────────────
// 主组件
// ────────────────────────────────────────────
export default function FirewallDns({ onClose }) {
  const { t } = useLang();

  // 主 Tab
  const [mainTab, setMainTab] = useState("firewall");

  // ─── 防火墙测试状态 ───
  const [target, setTarget] = useState("127.0.0.1");
  const [testMode, setTestMode] = useState("quick");
  const [customPorts, setCustomPorts] = useState("");
  const [testing, setTesting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [portResults, setPortResults] = useState([]);
  const [fwError, setFwError] = useState("");
  const [fwSubTab, setFwSubTab] = useState("ports");
  const [bypassResults, setBypassResults] = useState([]);
  const [auditResult, setAuditResult] = useState(null);
  const [stats, setStats] = useState({ open: 0, closed: 0, filtered: 0, elapsed: "0s" });

  const startFwTest = async () => {
    if (!target.trim()) return;
    setTesting(true);
    setFwError("");
    setPortResults([]);
    setBypassResults([]);
    setAuditResult(null);
    setProgress(0);

    const startTime = Date.now();

    try {
      let ports;
      let res;

      if (testMode === "quick") {
        res = await api.fwTestPorts(target.trim(), COMMON_PORTS);
      } else if (testMode === "full") {
        res = await api.fwTestPortRange(target.trim(), 1, 1024);
      } else {
        ports = customPorts
          .split(",")
          .map((p) => parseInt(p.trim()))
          .filter((n) => !isNaN(n) && n > 0 && n < 65536);
        if (ports.length === 0) {
          setFwError(t("firewallDns.invalidPorts"));
          setTesting(false);
          return;
        }
        res = await api.fwTestPorts(target.trim(), ports);
      }

      // 模拟进度
      const progressInterval = setInterval(() => {
        setProgress((prev) => {
          if (prev < 90) return prev + Math.random() * 10;
          return prev;
        });
      }, 200);

      clearInterval(progressInterval);
      setProgress(100);

      const results = res?.results || [];
      setPortResults(results);

      const elapsedMs = Date.now() - startTime;
      const seconds = (elapsedMs / 1000).toFixed(1);

      const openCount = results.filter((r) => r.status === "open").length;
      const closedCount = results.filter((r) => r.status === "closed").length;
      const filteredCount = results.filter((r) => r.status === "filtered").length;

      setStats({
        open: openCount,
        closed: closedCount,
        filtered: filteredCount,
        elapsed: `${seconds}s`,
      });

      // 同时获取绕过测试和审计结果
      try {
        const [bypassRes, auditRes] = await Promise.all([
          api.fwBypassTest(target.trim(), 80),
          api.fwAudit(target.trim()),
        ]);
        setBypassResults(bypassRes?.tests || []);
        setAuditResult(auditRes);
      } catch (e) {
        // ignore secondary errors
      }
    } catch (e) {
      setFwError(typeof e === "string" ? e : String(e));
    } finally {
      setTesting(false);
    }
  };

  const mainTabs = [
    { key: "firewall", label: t("firewallDns.tabFirewall") },
    { key: "dns", label: t("firewallDns.tabDns") },
  ];

  const fwSubTabs = [
    { key: "ports", label: t("firewallDns.subTabPorts") },
    { key: "bypass", label: t("firewallDns.subTabBypass") },
    { key: "audit", label: t("firewallDns.subTabAudit") },
  ];

  return (
    <div className="flex h-full flex-col">
      {/* 标题栏 */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <h3 className="text-base font-semibold">{t("firewallDns.title")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* 主 Tab 切换 (pill 样式) */}
      <div className="mb-4 flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
        {mainTabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setMainTab(tab.key)}
            className={`flex-1 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
              mainTab === tab.key
                ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 内容区 */}
      <div className="flex-1 overflow-auto">
        {/* ─── Tab 1: 防火墙测试 ─── */}
        {mainTab === "firewall" && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {/* 左侧：测试配置 */}
              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("firewallDns.targetIp")}
                  </label>
                  <input
                    className="field w-full font-mono text-xs"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="192.168.1.1"
                  />
                </div>

                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("firewallDns.testMode")}
                  </label>
                  <div className="space-y-1.5">
                    {[
                      { key: "quick", label: t("firewallDns.modeQuick") },
                      { key: "full", label: t("firewallDns.modeFull") },
                      { key: "custom", label: t("firewallDns.modeCustom") },
                    ].map((mode) => (
                      <button
                        key={mode.key}
                        onClick={() => setTestMode(mode.key)}
                        className={`w-full rounded-xl px-3 py-2 text-left text-xs transition-colors ${
                          testMode === mode.key
                            ? "bg-neutral-900 text-white dark:bg-white dark:text-neutral-900"
                            : "bg-neutral-100 text-neutral-600 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-700"
                        }`}
                      >
                        {mode.label}
                      </button>
                    ))}
                  </div>
                </div>

                {testMode === "custom" && (
                  <div>
                    <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("firewallDns.customPorts")}
                    </label>
                    <input
                      className="field w-full font-mono text-xs"
                      value={customPorts}
                      onChange={(e) => setCustomPorts(e.target.value)}
                      placeholder="21,22,80,443,3389"
                    />
                  </div>
                )}

                <button
                  onClick={startFwTest}
                  disabled={testing || !target.trim()}
                  className="pill pill-hover w-full justify-center"
                >
                  {testing ? (
                    <>
                      <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
                      {t("common.running")}
                    </>
                  ) : (
                    <>
                      <IconPlay size={14} />
                      {t("firewallDns.startTest")}
                    </>
                  )}
                </button>

                {fwError && <p className="text-xs text-red-500">{fwError}</p>}
              </div>

              {/* 右侧：结果展示 */}
              <div className="space-y-3">
                {/* 进度条 */}
                {testing && (
                  <div>
                    <div className="mb-1 flex items-center justify-between">
                      <span className="text-xs text-neutral-500 dark:text-neutral-400">
                        {t("firewallDns.testing")}
                      </span>
                      <span className="text-xs text-neutral-500 dark:text-neutral-400">
                        {Math.round(progress)}%
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-neutral-100 dark:bg-neutral-800">
                      <div
                        className="h-full rounded-full accent-solid transition-all duration-300 ease-out"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* 概览统计 */}
                {portResults.length > 0 && <StatsCards stats={stats} t={t} />}

                {/* 子 Tab */}
                {portResults.length > 0 && (
                  <div className="flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
                    {fwSubTabs.map((tab) => (
                      <button
                        key={tab.key}
                        onClick={() => setFwSubTab(tab.key)}
                        className={`flex-1 rounded-full px-2 py-1 text-[11px] font-medium transition-colors ${
                          fwSubTab === tab.key
                            ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                            : "text-neutral-500 dark:text-neutral-400"
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>
                )}

                {/* 子 Tab 内容 */}
                {fwSubTab === "ports" && portResults.length > 0 && (
                  <div className="space-y-3">
                    <div className="rounded-2xl border border-neutral-200 dark:border-neutral-800">
                      <PortResultTable results={portResults} t={t} />
                    </div>
                    <DangerousPortsWarning results={portResults} t={t} />
                  </div>
                )}

                {fwSubTab === "bypass" && (
                  <BypassSection bypassResults={bypassResults} t={t} />
                )}

                {fwSubTab === "audit" && (
                  <AuditSection auditResult={auditResult} t={t} />
                )}

                {/* 空状态 */}
                {!testing && portResults.length === 0 && (
                  <div className="flex h-full items-center justify-center py-12">
                    <div className="text-center">
                      <div className="mb-3 mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-neutral-100 dark:bg-neutral-800">
                        <IconShield size={28} className="text-neutral-400" />
                      </div>
                      <p className="text-sm text-neutral-400">
                        {t("firewallDns.enterTargetToTest")}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ─── Tab 2: DNS 安全 ─── */}
        {mainTab === "dns" && (
          <div className="space-y-4">
            {/* 6 个功能卡片 - 2 列布局 */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <DnsServersCard t={t} />
              <DnsSpeedCard t={t} />
              <DnsLeakCard t={t} />
              <DnsPoisonCard t={t} />
              <EmailSecurityCard t={t} />
              <DnssecCard t={t} />
            </div>

            {/* 底部工具 - 单行按钮组 */}
            <div className="space-y-2">
              <p className="text-xs font-semibold text-neutral-600 dark:text-neutral-400">
                {t("firewallDns.tools")}
              </p>
              <ReverseDnsTool t={t} />
              <DnsTunnelTool t={t} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
