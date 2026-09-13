import { useState } from "react";
import { api } from "../../api.js";
import { useLang } from "../../i18n.js";
import { IconPlay, IconShield } from "../Icons.jsx";

/**
 * 安全评分圆形进度条组件
 */
function ScoreGauge({ score, size = 120, strokeWidth = 10 }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  // 根据分数确定颜色
  let color = "#10b981"; // 绿色 - 优秀
  if (score < 40) color = "#ef4444"; // 红色 - 危险
  else if (score < 70) color = "#f59e0b"; // 橙色 - 中等

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-neutral-200 dark:text-neutral-700"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold" style={{ color }}>{score}</span>
        <span className="text-[10px] text-neutral-500 dark:text-neutral-400">/ 100</span>
      </div>
    </div>
  );
}

/**
 * 骨架屏加载组件
 */
function SkeletonCard() {
  return (
    <div className="animate-pulse space-y-3">
      <div className="h-4 w-3/4 rounded bg-neutral-200 dark:bg-neutral-700" />
      <div className="h-3 w-1/2 rounded bg-neutral-200 dark:bg-neutral-700" />
      <div className="h-3 w-2/3 rounded bg-neutral-200 dark:bg-neutral-700" />
    </div>
  );
}

/**
 * 站点信息分析工具
 * 支持总览、CMS识别、技术栈、服务器信息、子域名、目录探测、SSL证书、安全评估
 */
export default function SiteAnalyzer({ onClose }) {
  const { t } = useLang();
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState("quick"); // quick, deep
  const [activeTab, setActiveTab] = useState("overview");
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");

  // 分析结果状态
  const [overview, setOverview] = useState(null);
  const [cmsInfo, setCmsInfo] = useState(null);
  const [techStack, setTechStack] = useState(null);
  const [serverInfo, setServerInfo] = useState(null);
  const [subdomains, setSubdomains] = useState([]);
  const [dirScan, setDirScan] = useState([]);
  const [sslInfo, setSslInfo] = useState(null);
  const [securityScore, setSecurityScore] = useState(null);

  const tabs = [
    { key: "overview", label: t("siteAnalyzer.tabOverview") },
    { key: "cms", label: t("siteAnalyzer.tabCms") },
    { key: "tech", label: t("siteAnalyzer.tabTechStack") },
    { key: "server", label: t("siteAnalyzer.tabServer") },
    { key: "subdomain", label: t("siteAnalyzer.tabSubdomain"), deepOnly: true },
    { key: "dirscan", label: t("siteAnalyzer.tabDirScan"), deepOnly: true },
    { key: "ssl", label: t("siteAnalyzer.tabSsl") },
    { key: "security", label: t("siteAnalyzer.tabSecurity") },
  ];

  const visibleTabs = tabs.filter((tab) => !tab.deepOnly || mode === "deep");

  const startAnalyze = async () => {
    if (!url.trim()) return;
    setAnalyzing(true);
    setError("");
    setOverview(null);
    setCmsInfo(null);
    setTechStack(null);
    setServerInfo(null);
    setSubdomains([]);
    setDirScan([]);
    setSslInfo(null);
    setSecurityScore(null);

    const targetUrl = url.trim();
    const isDeep = mode === "deep";

    try {
      // 基础分析
      const analyzeRes = await api.siteAnalyze(targetUrl, isDeep);
      setOverview(analyzeRes?.overview || null);

      // CMS 识别
      try {
        const cmsRes = await api.siteDetectCms(targetUrl);
        setCmsInfo(cmsRes || null);
      } catch (e) {
        // 忽略单项错误
      }

      // 技术栈检测
      try {
        const techRes = await api.siteDetectTechStack(targetUrl);
        setTechStack(techRes || null);
      } catch (e) {
        // 忽略单项错误
      }

      // 服务器信息检测
      try {
        const serverRes = await api.siteDetectServer(targetUrl);
        setServerInfo(serverRes || null);
      } catch (e) {
        // 忽略单项错误
      }

      // CDN 检测（合并到技术栈）
      try {
        const cdnRes = await api.siteDetectCdn(targetUrl);
        if (cdnRes?.cdn && techStack) {
          setTechStack((prev) => ({ ...(prev || {}), cdn: cdnRes.cdn }));
        }
      } catch (e) {
        // 忽略单项错误
      }

      // SSL 证书信息
      try {
        const sslRes = await api.siteSslInfo(targetUrl);
        setSslInfo(sslRes || null);
      } catch (e) {
        // 忽略单项错误
      }

      // 安全评分
      try {
        const scoreRes = await api.siteSecurityScore(targetUrl);
        setSecurityScore(scoreRes || null);
      } catch (e) {
        // 忽略单项错误
      }

      // 深度扫描功能
      if (isDeep) {
        // 子域名扫描
        try {
          const domain = targetUrl.replace(/^https?:\/\//, "").split("/")[0];
          const subRes = await api.siteSubdomainScan(domain, 50);
          setSubdomains(subRes?.subdomains || []);
        } catch (e) {
          // 忽略单项错误
        }

        // 目录探测
        try {
          const dirRes = await api.siteDirScan(targetUrl, 100);
          setDirScan(dirRes?.paths || []);
        } catch (e) {
          // 忽略单项错误
        }
      }
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setAnalyzing(false);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 70) return "text-emerald-600 dark:text-emerald-400";
    if (score >= 40) return "text-amber-600 dark:text-amber-400";
    return "text-red-600 dark:text-red-400";
  };

  const getRiskColor = (level) => {
    switch (level) {
      case "high":
        return "border-red-200 bg-red-50 dark:border-red-900/50 dark:bg-red-900/20";
      case "medium":
        return "border-amber-200 bg-amber-50 dark:border-amber-900/50 dark:bg-amber-900/20";
      case "low":
        return "border-yellow-200 bg-yellow-50 dark:border-yellow-900/50 dark:bg-yellow-900/20";
      default:
        return "border-neutral-200 dark:border-neutral-800";
    }
  };

  const getRiskBadgeColor = (level) => {
    switch (level) {
      case "high":
        return "text-red-600 dark:text-red-400";
      case "medium":
        return "text-amber-600 dark:text-amber-400";
      case "low":
        return "text-yellow-600 dark:text-yellow-400";
      default:
        return "text-neutral-500";
    }
  };

  const getRiskLabel = (level) => {
    switch (level) {
      case "high":
        return t("siteAnalyzer.riskHigh");
      case "medium":
        return t("siteAnalyzer.riskMedium");
      case "low":
        return t("siteAnalyzer.riskLow");
      default:
        return level;
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconShield size={20} />
          <h3 className="text-base font-semibold">{t("siteAnalyzer.siteAnalyzer")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* URL 输入 */}
      <div className="mb-3 flex gap-2">
        <input
          className="field flex-1 font-mono"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && startAnalyze()}
          placeholder="https://example.com"
        />
        <button
          onClick={startAnalyze}
          disabled={analyzing || !url.trim()}
          className="pill pill-hover"
        >
          {analyzing ? (
            <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
          ) : (
            <IconPlay size={14} />
          )}
          {t("siteAnalyzer.startAnalyze")}
        </button>
      </div>

      {/* 分析深度选择 */}
      <div className="mb-4 flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
        <button
          onClick={() => setMode("quick")}
          className={`flex-1 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
            mode === "quick"
              ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
              : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
          }`}
        >
          {t("siteAnalyzer.quickScan")}
        </button>
        <button
          onClick={() => setMode("deep")}
          className={`flex-1 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
            mode === "deep"
              ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
              : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
          }`}
        >
          {t("siteAnalyzer.deepScan")}
        </button>
      </div>

      {/* Tab 切换 */}
      <div className="mb-3 flex gap-1 overflow-x-auto rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
        {visibleTabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`shrink-0 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === tab.key
                ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 内容区 */}
      <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
        {/* 总览 Tab */}
        {activeTab === "overview" && (
          <div className="p-3">
            {analyzing ? (
              <div className="space-y-4">
                <SkeletonCard />
                <SkeletonCard />
              </div>
            ) : overview ? (
              <div className="space-y-4">
                {/* 站点概况 */}
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-2 text-xs">
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.siteTitle")}</p>
                      <p className="font-medium break-all">{overview.title || "-"}</p>
                    </div>
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.url")}</p>
                      <p className="font-mono break-all text-[11px]">{overview.url || "-"}</p>
                    </div>
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.ipAddress")}</p>
                      <p className="font-mono">{overview.ip || "-"}</p>
                    </div>
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.server")}</p>
                      <p className="font-medium">{overview.server || "-"}</p>
                    </div>
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.responseTime")}</p>
                      <p className="font-mono">
                        {overview.response_time ? `${overview.response_time}ms` : "-"}
                      </p>
                    </div>
                  </div>

                  {/* 安全评分仪表盘 */}
                  <div className="flex flex-col items-center justify-center">
                    <ScoreGauge score={securityScore?.score ?? 0} />
                    <p className="mt-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.securityScore")}
                    </p>
                  </div>
                </div>

                {/* 技术栈标签云 */}
                {techStack && (techStack.frontend?.length > 0 || techStack.backend?.length > 0 || techStack.web_server || techStack.cdn) && (
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.techStack")}
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {techStack.frontend?.map((item, i) => (
                        <span key={`fe-${i}`} className="chip text-[11px] bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400">
                          {item}
                        </span>
                      ))}
                      {techStack.backend?.map((item, i) => (
                        <span key={`be-${i}`} className="chip text-[11px] bg-emerald-50 text-emerald-600 dark:bg-emerald-900/30 dark:text-emerald-400">
                          {item}
                        </span>
                      ))}
                      {techStack.web_server && (
                        <span className="chip text-[11px] bg-purple-50 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400">
                          {techStack.web_server}
                        </span>
                      )}
                      {techStack.cdn && (
                        <span className="chip text-[11px] bg-amber-50 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400">
                          {techStack.cdn}
                        </span>
                      )}
                      {techStack.waf && (
                        <span className="chip text-[11px] bg-red-50 text-red-600 dark:bg-red-900/30 dark:text-red-400">
                          {techStack.waf}
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {t("siteAnalyzer.noResult")}
              </div>
            )}
          </div>
        )}

        {/* CMS 识别 Tab */}
        {activeTab === "cms" && (
          <div className="p-3">
            {analyzing ? (
              <SkeletonCard />
            ) : cmsInfo && cmsInfo.name ? (
              <div className="space-y-3">
                <div className="rounded-xl border border-neutral-200 p-4 dark:border-neutral-800">
                  <div className="mb-3 flex items-center justify-between">
                    <div>
                      <p className="text-lg font-semibold">{cmsInfo.name}</p>
                      {cmsInfo.version && (
                        <p className="font-mono text-sm text-neutral-500 dark:text-neutral-400">
                          {t("siteAnalyzer.cmsVersion")}: {cmsInfo.version}
                        </p>
                      )}
                    </div>
                    <span className={`chip text-xs ${getScoreColor(cmsInfo.confidence)}`}>
                      {t("siteAnalyzer.confidence")}: {cmsInfo.confidence}%
                    </span>
                  </div>
                </div>

                {cmsInfo.evidence && cmsInfo.evidence.length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.evidence")}
                    </p>
                    <div className="space-y-1.5">
                      {cmsInfo.evidence.map((item, i) => (
                        <div
                          key={i}
                          className="rounded-lg bg-neutral-50 px-3 py-2 text-xs dark:bg-neutral-900"
                        >
                          <p className="font-mono break-all text-neutral-700 dark:text-neutral-300">
                            {item}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("siteAnalyzer.analyzing") : t("siteAnalyzer.noCmsDetected")}
              </div>
            )}
          </div>
        )}

        {/* 技术栈 Tab */}
        {activeTab === "tech" && (
          <div className="p-3">
            {analyzing ? (
              <div className="space-y-3">
                <SkeletonCard />
                <SkeletonCard />
              </div>
            ) : techStack ? (
              <div className="space-y-3">
                {techStack.frontend && techStack.frontend.length > 0 && (
                  <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.frontend")}
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {techStack.frontend.map((item, i) => (
                        <span key={i} className="chip text-[11px] bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400">
                          {item}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {techStack.backend && techStack.backend.length > 0 && (
                  <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.backend")}
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {techStack.backend.map((item, i) => (
                        <span key={i} className="chip text-[11px] bg-emerald-50 text-emerald-600 dark:bg-emerald-900/30 dark:text-emerald-400">
                          {item}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {techStack.database && (
                  <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.database")}
                    </p>
                    <p className="font-medium text-sm">{techStack.database}</p>
                  </div>
                )}

                {techStack.web_server && (
                  <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.webServer")}
                    </p>
                    <p className="font-medium text-sm">{techStack.web_server}</p>
                  </div>
                )}

                {techStack.cdn && (
                  <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.cdn")}
                    </p>
                    <p className="font-medium text-sm">{techStack.cdn}</p>
                  </div>
                )}

                {techStack.waf && (
                  <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.waf")}
                    </p>
                    <p className="font-medium text-sm">{techStack.waf}</p>
                  </div>
                )}

                {!techStack.frontend?.length && !techStack.backend?.length && !techStack.web_server && !techStack.cdn && !techStack.waf && !techStack.database && (
                  <div className="py-6 text-center text-sm text-neutral-400">
                    {t("siteAnalyzer.noResult")}
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {t("siteAnalyzer.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 服务器信息 Tab */}
        {activeTab === "server" && (
          <div className="p-3">
            {analyzing ? (
              <div className="space-y-3">
                <SkeletonCard />
                <SkeletonCard />
              </div>
            ) : serverInfo ? (
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.serverType")}</p>
                    <p className="mt-1 font-medium">{serverInfo.server || "-"}</p>
                  </div>
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.os")}</p>
                    <p className="mt-1 font-medium">{serverInfo.os || "-"}</p>
                  </div>
                </div>

                {serverInfo.middleware && serverInfo.middleware.length > 0 && (
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="mb-2 text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.middleware")}</p>
                    <div className="flex flex-wrap gap-1">
                      {serverInfo.middleware.map((m, i) => (
                        <span key={i} className="chip text-[10px]">{m}</span>
                      ))}
                    </div>
                  </div>
                )}

                {serverInfo.headers && Object.keys(serverInfo.headers).length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.responseHeaders")}
                    </p>
                    <div className="max-h-60 overflow-auto divide-y divide-neutral-100 dark:divide-neutral-800 rounded-xl border border-neutral-200 dark:border-neutral-800">
                      {Object.entries(serverInfo.headers).map(([key, value], i) => (
                        <div key={i} className="px-3 py-2">
                          <p className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400">{key}</p>
                          <p className="font-mono text-xs break-all text-neutral-700 dark:text-neutral-300">{value}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {t("siteAnalyzer.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 子域名 Tab */}
        {activeTab === "subdomain" && (
          <div className="p-3">
            {mode !== "deep" && !analyzing && subdomains.length === 0 ? (
              <div className="py-8 text-center text-sm text-neutral-400">
                {t("siteAnalyzer.deepModeOnly")}
              </div>
            ) : subdomains.length > 0 ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("siteAnalyzer.subdomainList")}
                  </span>
                  <span className="chip text-[10px]">
                    {t("siteAnalyzer.subdomainCount")}: {subdomains.length}
                  </span>
                </div>
                <div className="max-h-72 overflow-auto divide-y divide-neutral-100 dark:divide-neutral-800 rounded-xl border border-neutral-200 dark:border-neutral-800">
                  {subdomains.map((s, i) => (
                    <div key={i} className="flex items-center justify-between px-3 py-2">
                      <span className="font-mono text-xs break-all pr-2">{s.subdomain}</span>
                      <div className="flex items-center gap-2 shrink-0">
                        {s.ip && (
                          <span className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400">
                            {s.ip}
                          </span>
                        )}
                        <span
                          className={`chip text-[10px] ${
                            s.status === "active"
                              ? "text-emerald-500"
                              : s.status === "inactive"
                              ? "text-neutral-400"
                              : "text-neutral-500"
                          }`}
                        >
                          {s.status || "-"}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("siteAnalyzer.analyzing") : t("siteAnalyzer.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 目录探测 Tab */}
        {activeTab === "dirscan" && (
          <div className="p-3">
            {mode !== "deep" && !analyzing && dirScan.length === 0 ? (
              <div className="py-8 text-center text-sm text-neutral-400">
                {t("siteAnalyzer.deepModeOnly")}
              </div>
            ) : dirScan.length > 0 ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("siteAnalyzer.sensitivePaths")}
                  </span>
                  <span className="chip text-[10px]">
                    {dirScan.length} {t("siteAnalyzer.path")}
                  </span>
                </div>
                <div className="max-h-72 overflow-auto divide-y divide-neutral-100 dark:divide-neutral-800 rounded-xl border border-neutral-200 dark:border-neutral-800">
                  {dirScan.map((item, i) => (
                    <div key={i} className="flex items-center justify-between px-3 py-2">
                      <span className="font-mono text-xs break-all pr-2">{item.path}</span>
                      <span
                        className={`chip text-[10px] font-mono shrink-0 ${
                          item.status_code === 200
                            ? "text-emerald-500"
                            : item.status_code === 301 || item.status_code === 302
                            ? "text-blue-500"
                            : item.status_code === 403
                            ? "text-amber-500"
                            : item.status_code === 404
                            ? "text-neutral-400"
                            : "text-neutral-500"
                        }`}
                      >
                        {item.status_code}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("siteAnalyzer.analyzing") : t("siteAnalyzer.noResult")}
              </div>
            )}
          </div>
        )}

        {/* SSL 证书 Tab */}
        {activeTab === "ssl" && (
          <div className="p-3">
            {analyzing ? (
              <div className="space-y-3">
                <SkeletonCard />
                <SkeletonCard />
              </div>
            ) : sslInfo ? (
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.sslIssuer")}</p>
                    <p className="mt-1 font-medium break-all">{sslInfo.issuer || "-"}</p>
                  </div>
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.sslSigAlg")}</p>
                    <p className="mt-1 font-mono">{sslInfo.signature_algorithm || "-"}</p>
                  </div>
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.sslValidFrom")}</p>
                    <p className="mt-1 font-mono">{sslInfo.valid_from || "-"}</p>
                  </div>
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("siteAnalyzer.sslValidTo")}</p>
                    <p className="mt-1 font-mono">{sslInfo.valid_to || "-"}</p>
                  </div>
                </div>

                {sslInfo.domains && sslInfo.domains.length > 0 && (
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="mb-2 text-neutral-500 dark:text-neutral-400">
                      {t("siteAnalyzer.sslDomains")}
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {sslInfo.domains.map((d, i) => (
                        <span key={i} className="chip font-mono text-[10px]">{d}</span>
                      ))}
                    </div>
                  </div>
                )}

                {sslInfo.chain && sslInfo.chain.length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.sslChain")}
                    </p>
                    <div className="space-y-1.5">
                      {sslInfo.chain.map((cert, i) => (
                        <div
                          key={i}
                          className="rounded-lg border border-neutral-200 p-2 dark:border-neutral-800"
                        >
                          <p className="font-medium text-[11px]">{cert.subject || cert.issuer || `证书 ${i + 1}`}</p>
                          {cert.issuer && (
                            <p className="font-mono text-[10px] text-neutral-500 dark:text-neutral-400">
                              {cert.issuer}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {t("siteAnalyzer.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 安全评估 Tab */}
        {activeTab === "security" && (
          <div className="p-3">
            {analyzing ? (
              <div className="space-y-3">
                <SkeletonCard />
                <SkeletonCard />
                <SkeletonCard />
              </div>
            ) : securityScore ? (
              <div className="space-y-4">
                {/* 评分详情 */}
                <div className="flex items-center justify-center">
                  <ScoreGauge score={securityScore.score ?? 0} size={140} strokeWidth={12} />
                </div>

                {/* 评分详情项 */}
                {securityScore.details && Object.keys(securityScore.details).length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.scoreDetail")}
                    </p>
                    <div className="space-y-2">
                      {Object.entries(securityScore.details).map(([key, value], i) => (
                        <div key={i} className="flex items-center justify-between text-xs">
                          <span className="text-neutral-600 dark:text-neutral-400">{key}</span>
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-24 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-700">
                              <div
                                className={`h-full rounded-full transition-all duration-500 ${
                                  value >= 70
                                    ? "bg-emerald-500"
                                    : value >= 40
                                    ? "bg-amber-500"
                                    : "bg-red-500"
                                }`}
                                style={{ width: `${value}%` }}
                              />
                            </div>
                            <span className={`font-mono text-[11px] w-8 text-right ${getScoreColor(value)}`}>
                              {value}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 风险项列表 */}
                {securityScore.risks && securityScore.risks.length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.riskItems")}
                    </p>
                    <div className="space-y-2">
                      {securityScore.risks.map((risk, i) => (
                        <div
                          key={i}
                          className={`rounded-xl border p-3 ${getRiskColor(risk.level)}`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className={`text-xs font-semibold ${getRiskBadgeColor(risk.level)}`}>
                              {risk.name}
                            </span>
                            <span className={`chip text-[10px] ${getRiskBadgeColor(risk.level)}`}>
                              {getRiskLabel(risk.level)}
                            </span>
                          </div>
                          {risk.description && (
                            <p className="text-[11px] text-neutral-600 dark:text-neutral-400">
                              {risk.description}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 改进建议 */}
                {securityScore.suggestions && securityScore.suggestions.length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("siteAnalyzer.suggestions")}
                    </p>
                    <div className="space-y-1.5">
                      {securityScore.suggestions.map((s, i) => (
                        <div
                          key={i}
                          className="flex items-start gap-2 rounded-lg bg-blue-50 p-2 dark:bg-blue-900/20"
                        >
                          <span className="text-blue-500 text-xs">•</span>
                          <p className="text-[11px] text-blue-700 dark:text-blue-400">{s}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {t("siteAnalyzer.noResult")}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
