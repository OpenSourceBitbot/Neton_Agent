import { useState } from "react";
import { api } from "../../api.js";
import { useLang } from "../../i18n.js";
import { IconPlay, IconShield, IconChevronDown } from "../Icons.jsx";

/**
 * 漏洞等级颜色映射
 */
const SEVERITY_CONFIG = {
  critical: { label: "critical", color: "text-red-700 dark:text-red-400", bg: "bg-red-100 dark:bg-red-950", border: "border-red-500" },
  high: { label: "high", color: "text-red-500 dark:text-red-400", bg: "bg-red-50 dark:bg-red-950/50", border: "border-red-400" },
  medium: { label: "medium", color: "text-orange-500 dark:text-orange-400", bg: "bg-orange-50 dark:bg-orange-950/50", border: "border-orange-400" },
  low: { label: "low", color: "text-yellow-500 dark:text-yellow-400", bg: "bg-yellow-50 dark:bg-yellow-950/50", border: "border-yellow-400" },
  info: { label: "info", color: "text-blue-500 dark:text-blue-400", bg: "bg-blue-50 dark:bg-blue-950/50", border: "border-blue-400" },
};

/**
 * 扫描类型定义
 */
const SCAN_TYPES = [
  { key: "all", needsParam: false },
  { key: "xss", needsParam: true },
  { key: "csrf", needsParam: false },
  { key: "file_include", needsParam: true },
  { key: "cmd_injection", needsParam: true },
  { key: "xxe", needsParam: false },
  { key: "ssrf", needsParam: true },
  { key: "open_redirect", needsParam: true },
  { key: "clickjacking", needsParam: false },
];

/**
 * 漏洞卡片组件
 */
function VulnCard({ vuln, t }) {
  const [expanded, setExpanded] = useState(false);
  const severity = SEVERITY_CONFIG[vuln.severity] || SEVERITY_CONFIG.info;

  return (
    <div className={`mb-3 rounded-xl border-l-4 ${severity.border} bg-white dark:bg-neutral-900 shadow-sm`}>
      <div
        className="cursor-pointer p-3"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1">
            <div className="mb-1 flex items-center gap-2">
              <span className={`chip text-xs ${severity.color} ${severity.bg}`}>
                {t(`vulnScanner.severity_${severity.label}`)}
              </span>
              <h4 className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">
                {vuln.name}
              </h4>
            </div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              {vuln.description}
            </p>
          </div>
          <button className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300">
            <IconChevronDown size={16} className={expanded ? "rotate-180 transition-transform" : "transition-transform"} />
          </button>
        </div>
      </div>
      {expanded && (
        <div className="border-t border-neutral-100 dark:border-neutral-800 p-3 space-y-2">
          {vuln.evidence && (
            <div>
              <p className="mb-1 text-xs font-medium text-neutral-500 dark:text-neutral-400">
                {t("vulnScanner.evidence")}
              </p>
              <pre className="rounded-lg bg-neutral-50 dark:bg-neutral-800 p-2 text-xs font-mono text-neutral-700 dark:text-neutral-300 overflow-x-auto">
                {vuln.evidence}
              </pre>
            </div>
          )}
          {vuln.fix && (
            <div>
              <p className="mb-1 text-xs font-medium text-neutral-500 dark:text-neutral-400">
                {t("vulnScanner.fixSuggestion")}
              </p>
              <p className="text-xs text-neutral-600 dark:text-neutral-400">
                {vuln.fix}
              </p>
            </div>
          )}
          {vuln.payload && (
            <div>
              <p className="mb-1 text-xs font-medium text-neutral-500 dark:text-neutral-400">
                {t("vulnScanner.payload")}
              </p>
              <code className="rounded bg-neutral-100 dark:bg-neutral-800 px-2 py-1 text-xs font-mono text-red-500">
                {vuln.payload}
              </code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * 综合扫描结果概览
 */
function ScanOverview({ results, elapsed, t }) {
  const counts = {
    critical: results.filter((r) => r.severity === "critical").length,
    high: results.filter((r) => r.severity === "high").length,
    medium: results.filter((r) => r.severity === "medium").length,
    low: results.filter((r) => r.severity === "low").length,
    info: results.filter((r) => r.severity === "info").length,
  };
  const total = results.length;

  return (
    <div className="card mb-4 rounded-2xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">
          {t("vulnScanner.scanOverview")}
        </h4>
        <span className="text-xs text-neutral-500 dark:text-neutral-400">
          {t("vulnScanner.elapsedTime", { time: elapsed })}
        </span>
      </div>
      <div className="flex items-center gap-6 mb-4">
        <div className="text-center">
          <div className="text-4xl font-bold text-neutral-800 dark:text-neutral-200">
            {total}
          </div>
          <div className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
            {t("vulnScanner.totalVulns")}
          </div>
        </div>
        <div className="flex-1 grid grid-cols-5 gap-2">
          {Object.entries(counts).map(([key, count]) => {
            const sev = SEVERITY_CONFIG[key];
            return (
              <div key={key} className="text-center">
                <div className={`text-xl font-bold ${sev.color}`}>
                  {count}
                </div>
                <div className="text-[10px] text-neutral-500 dark:text-neutral-400 mt-0.5">
                  {t(`vulnScanner.severity_${key}`)}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/**
 * XSS 扫描结果
 */
function XssResults({ results, t }) {
  const categories = {
    reflected: results.filter((r) => r.type === "reflected"),
    stored: results.filter((r) => r.type === "stored"),
    dom: results.filter((r) => r.type === "dom"),
  };

  return (
    <div className="space-y-4">
      {Object.entries(categories).map(([cat, items]) => (
        <div key={cat}>
          <h4 className="mb-2 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
            {t(`vulnScanner.xss_${cat}`)}
            <span className="ml-2 text-xs font-normal text-neutral-500">
              ({items.length})
            </span>
          </h4>
          {items.length > 0 ? (
            items.map((vuln, i) => <VulnCard key={i} vuln={vuln} t={t} />)
          ) : (
            <p className="text-xs text-neutral-400 py-2">
              {t("vulnScanner.noVulnFound")}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

/**
 * CSRF 检测结果
 */
function CsrfResults({ results, t }) {
  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
        {t("vulnScanner.csrf_forms")}
      </h4>
      {results.forms?.length > 0 ? (
        results.forms.map((form, i) => (
          <div key={i} className="card rounded-xl p-3">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-mono text-neutral-600 dark:text-neutral-400">
                {form.action || "(same page)"}
              </span>
              <span className={`chip text-xs ${form.vulnerable ? "text-red-500 bg-red-50 dark:bg-red-950/50" : "text-emerald-500 bg-emerald-50 dark:bg-emerald-950/50"}`}>
                {form.vulnerable ? t("netsec.vulnerable") : t("netsec.safe")}
              </span>
            </div>
            <p className="text-xs text-neutral-500">
              {t("vulnScanner.csrf_method", { method: form.method?.toUpperCase() || "GET" })}
            </p>
            {form.fields?.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {form.fields.map((f, j) => (
                  <span key={j} className="chip text-[10px] bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400">
                    {f}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))
      ) : (
        <p className="text-xs text-neutral-400 py-2">
          {t("vulnScanner.noFormsFound")}
        </p>
      )}
    </div>
  );
}

/**
 * 文件包含检测结果
 */
function FileIncludeResults({ results, t }) {
  return (
    <div className="space-y-4">
      <div>
        <h4 className="mb-2 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
          {t("vulnScanner.lfi_test")}
        </h4>
        {results.lfi?.vulnerable ? (
          <VulnCard vuln={results.lfi} t={t} />
        ) : (
          <p className="text-xs text-emerald-500 py-2">
            {t("vulnScanner.lfi_safe")}
          </p>
        )}
      </div>
      <div>
        <h4 className="mb-2 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
          {t("vulnScanner.rfi_test")}
        </h4>
        {results.rfi?.vulnerable ? (
          <VulnCard vuln={results.rfi} t={t} />
        ) : (
          <p className="text-xs text-emerald-500 py-2">
            {t("vulnScanner.rfi_safe")}
          </p>
        )}
      </div>
      {results.payloads?.length > 0 && (
        <div>
          <h4 className="mb-2 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
            {t("vulnScanner.payloadList")}
          </h4>
          <div className="space-y-1">
            {results.payloads.map((p, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg bg-neutral-50 dark:bg-neutral-800 px-3 py-2">
                <span className={`h-2 w-2 rounded-full ${p.success ? "bg-red-500" : "bg-neutral-300"}`} />
                <code className="flex-1 text-xs font-mono text-neutral-700 dark:text-neutral-300 truncate">
                  {p.payload}
                </code>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * 命令注入检测结果
 */
function CmdInjectionResults({ results, t }) {
  return (
    <div className="space-y-4">
      {results.vulnerable ? (
        <VulnCard vuln={results} t={t} />
      ) : (
        <p className="text-xs text-emerald-500 py-2">
          {t("vulnScanner.cmdInjection_safe")}
        </p>
      )}
      {results.payloads?.length > 0 && (
        <div>
          <h4 className="mb-2 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
            {t("vulnScanner.payloadList")}
          </h4>
          <div className="space-y-1">
            {results.payloads.map((p, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg bg-neutral-50 dark:bg-neutral-800 px-3 py-2">
                <span className={`h-2 w-2 rounded-full ${p.success ? "bg-red-500" : "bg-neutral-300"}`} />
                <code className="flex-1 text-xs font-mono text-neutral-700 dark:text-neutral-300 truncate">
                  {p.payload}
                </code>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * 通用单类型结果展示
 */
function GenericResults({ results, t }) {
  if (results.vulnerable) {
    return <VulnCard vuln={results} t={t} />;
  }
  return (
    <div className="flex flex-col items-center justify-center py-8">
      <div className="mb-3 flex h-16 w-16 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-950/50">
        <IconShield size={32} className="text-emerald-500" />
      </div>
      <p className="text-sm font-medium text-emerald-600 dark:text-emerald-400">
        {t("vulnScanner.noVulnFound")}
      </p>
      {results.details && (
        <p className="mt-2 text-xs text-neutral-500 dark:text-neutral-400 text-center max-w-xs">
          {results.details}
        </p>
      )}
    </div>
  );
}

/**
 * Web 漏洞扫描组件
 * 支持综合扫描和多种单类型漏洞检测
 */
export default function VulnScanner({ onClose }) {
  const { t } = useLang();
  const [url, setUrl] = useState("");
  const [scanType, setScanType] = useState("all");
  const [param, setParam] = useState("");
  const [method, setMethod] = useState("get");
  const [scanDepth, setScanDepth] = useState("quick");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusText, setStatusText] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [elapsed, setElapsed] = useState("");

  const currentScanType = SCAN_TYPES.find((t) => t.key === scanType);
  const needsParam = currentScanType?.needsParam;

  const startScan = async () => {
    setScanning(true);
    setError("");
    setResults(null);
    setProgress(0);
    setStatusText(t("vulnScanner.scanning"));

    const startTime = Date.now();

    try {
      let res;
      const deep = scanDepth === "deep";

      // 模拟进度更新
      const progressInterval = setInterval(() => {
        setProgress((prev) => {
          if (prev < 90) return prev + Math.random() * 15;
          return prev;
        });
      }, 500);

      switch (scanType) {
        case "all":
          res = await api.vulnScanAll(url.trim(), deep);
          break;
        case "xss":
          res = await api.vulnScanXss(url.trim(), param.trim(), method);
          break;
        case "csrf":
          res = await api.vulnScanCsrf(url.trim());
          break;
        case "file_include":
          res = await api.vulnScanFileInclude(url.trim(), param.trim());
          break;
        case "cmd_injection":
          res = await api.vulnScanCmdInjection(url.trim(), param.trim());
          break;
        case "xxe":
          res = await api.vulnScanXxe(url.trim());
          break;
        case "ssrf":
          res = await api.vulnScanSsrf(url.trim(), param.trim());
          break;
        case "open_redirect":
          res = await api.vulnScanOpenRedirect(url.trim(), param.trim());
          break;
        case "clickjacking":
          res = await api.vulnScanClickjacking(url.trim());
          break;
        default:
          res = [];
      }

      clearInterval(progressInterval);
      setProgress(100);
      setStatusText(t("vulnScanner.scanComplete"));

      const elapsedMs = Date.now() - startTime;
      const seconds = (elapsedMs / 1000).toFixed(1);
      setElapsed(`${seconds}s`);

      setResults(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setScanning(false);
    }
  };

  // 按严重程度排序漏洞
  const sortedVulns = results?.vulnerabilities
    ? [...results.vulnerabilities].sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
      })
    : [];

  const renderResults = () => {
    if (!results) return null;

    if (scanType === "all") {
      return (
        <>
          <ScanOverview results={sortedVulns} elapsed={elapsed} t={t} />
          <div className="flex-1 overflow-auto">
            {sortedVulns.length > 0 ? (
              sortedVulns.map((vuln, i) => <VulnCard key={i} vuln={vuln} t={t} />)
            ) : (
              <div className="flex h-full items-center justify-center py-8">
                <p className="text-sm text-neutral-400">
                  {t("vulnScanner.noVulnFound")}
                </p>
              </div>
            )}
          </div>
        </>
      );
    }

    // 单类型扫描
    return (
      <div className="flex-1 overflow-auto">
        {scanType === "xss" && <XssResults results={results.vulnerabilities || []} t={t} />}
        {scanType === "csrf" && <CsrfResults results={results} t={t} />}
        {scanType === "file_include" && <FileIncludeResults results={results} t={t} />}
        {scanType === "cmd_injection" && <CmdInjectionResults results={results} t={t} />}
        {(scanType === "xxe" || scanType === "ssrf" || scanType === "open_redirect" || scanType === "clickjacking") && (
          <GenericResults results={results} t={t} />
        )}
      </div>
    );
  };

  return (
    <div className="flex h-full flex-col">
      {/* 标题栏 */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.catVuln")} - {t("vulnScanner.title")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* 输入区域 */}
      <div className="mb-4 space-y-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.targetUrl")}
          </label>
          <input
            className="field w-full font-mono text-xs"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="http://example.com/page.php"
          />
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("vulnScanner.scanType")}
          </label>
          <div className="grid grid-cols-3 gap-2">
            {SCAN_TYPES.map((type) => (
              <button
                key={type.key}
                onClick={() => setScanType(type.key)}
                className={`pill text-xs py-1.5 justify-center ${
                  scanType === type.key
                    ? "accent-solid"
                    : "bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-neutral-700"
                }`}
              >
                {t(`vulnScanner.type_${type.key}`)}
              </button>
            ))}
          </div>
        </div>

        {needsParam && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                {t("netsec.testParam")}
              </label>
              <input
                className="field w-full font-mono text-xs"
                value={param}
                onChange={(e) => setParam(e.target.value)}
                placeholder={t("vulnScanner.paramPlaceholder")}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                {t("netsec.requestMethod")}
              </label>
              <select className="field w-full" value={method} onChange={(e) => setMethod(e.target.value)}>
                <option value="get">GET</option>
                <option value="post">POST</option>
              </select>
            </div>
          </div>
        )}

        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("vulnScanner.scanDepth")}
          </label>
          <div className="flex gap-2">
            <button
              onClick={() => setScanDepth("quick")}
              className={`pill flex-1 text-xs py-1.5 justify-center ${
                scanDepth === "quick"
                  ? "accent-solid"
                  : "bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-neutral-700"
              }`}
            >
              {t("vulnScanner.quickScan")}
            </button>
            <button
              onClick={() => setScanDepth("deep")}
              className={`pill flex-1 text-xs py-1.5 justify-center ${
                scanDepth === "deep"
                  ? "accent-solid"
                  : "bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-neutral-700"
              }`}
            >
              {t("vulnScanner.deepScan")}
            </button>
          </div>
        </div>
      </div>

      {/* 开始扫描按钮 */}
      <button
        onClick={startScan}
        disabled={scanning || !url.trim() || (needsParam && !param.trim())}
        className="pill pill-hover mb-4 w-full justify-center"
      >
        {scanning ? (
          <>
            <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
            {t("common.running")}
          </>
        ) : (
          <>
            <IconPlay size={14} />
            {t("vulnScanner.startScan")}
          </>
        )}
      </button>

      {/* 错误信息 */}
      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 扫描进度 */}
      {scanning && (
        <div className="mb-4">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-xs text-neutral-500 dark:text-neutral-400">
              {statusText}
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

      {/* 结果展示 */}
      {renderResults()}

      {/* 空状态 */}
      {!results && !scanning && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="mb-3 flex h-16 w-16 items-center justify-center rounded-full bg-neutral-100 dark:bg-neutral-800 mx-auto">
              <IconShield size={28} className="text-neutral-400" />
            </div>
            <p className="text-sm text-neutral-400">
              {t("vulnScanner.enterUrlToScan")}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
