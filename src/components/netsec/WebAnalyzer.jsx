import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconGlobe } from "../Icons.jsx";

/**
 * 网页分析工具
 * 支持页面概览、链接统计、表单分析、安全头检测、技术指纹、敏感信息检测
 */
export default function WebAnalyzer({ onClose }) {
  const { t } = useLang();
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState("quick"); // quick, deep
  const [activeTab, setActiveTab] = useState("overview");
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");

  // 分析结果
  const [overview, setOverview] = useState(null);
  const [links, setLinks] = useState(null);
  const [forms, setForms] = useState([]);
  const [securityHeaders, setSecurityHeaders] = useState([]);
  const [techFingerprint, setTechFingerprint] = useState([]);
  const [sensitiveInfo, setSensitiveInfo] = useState([]);

  const tabs = [
    { key: "overview", label: t("netsec.waOverview") },
    { key: "links", label: t("netsec.waLinks") },
    { key: "forms", label: t("netsec.waForms") },
    { key: "headers", label: t("netsec.waSecurityHeaders") },
    { key: "tech", label: t("netsec.waTechFingerprint") },
    { key: "sensitive", label: t("netsec.waSensitiveInfo") },
  ];

  const startAnalyze = async () => {
    if (!url.trim()) return;
    setAnalyzing(true);
    setError("");
    setOverview(null);
    setLinks(null);
    setForms([]);
    setSecurityHeaders([]);
    setTechFingerprint([]);
    setSensitiveInfo([]);

    try {
      const targetUrl = url.trim();
      const isDeep = mode === "deep";

      // 基础分析（概览 + 链接 + 表单）
      const analyzeRes = await invoke("web_analyze", { url: targetUrl, deep: isDeep });
      setOverview(analyzeRes?.overview || null);
      setLinks(analyzeRes?.links || null);
      setForms(analyzeRes?.forms || []);

      // 安全头检测
      try {
        const headersRes = await invoke("web_check_security_headers", { url: targetUrl });
        setSecurityHeaders(headersRes?.headers || []);
      } catch (e) {
        // 忽略单项错误
      }

      // 技术指纹识别
      try {
        const techRes = await invoke("web_detect_tech", { url: targetUrl });
        setTechFingerprint(techRes?.tech || []);
      } catch (e) {
        // 忽略单项错误
      }

      // 敏感信息检测（仅深度模式）
      if (isDeep) {
        try {
          const sensitiveRes = await invoke("web_find_sensitive", { url: targetUrl });
          setSensitiveInfo(sensitiveRes?.findings || []);
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

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconGlobe size={20} />
          <h3 className="text-base font-semibold">{t("netsec.webAnalyzer")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* URL 输入与分析按钮 */}
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
          {t("netsec.analyze")}
        </button>
      </div>

      {/* 分析模式选择 */}
      <div className="mb-4 flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
        <button
          onClick={() => setMode("quick")}
          className={`flex-1 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
            mode === "quick"
              ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
              : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
          }`}
        >
          {t("netsec.quickScan")}
        </button>
        <button
          onClick={() => setMode("deep")}
          className={`flex-1 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
            mode === "deep"
              ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
              : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
          }`}
        >
          {t("netsec.deepScan")}
        </button>
      </div>

      {/* Tab 切换 */}
      <div className="mb-3 flex gap-1 overflow-x-auto rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
        {tabs.map((tab) => (
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
        {/* 概览 */}
        {activeTab === "overview" && (
          <div className="p-3">
            {overview ? (
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.waTitle")}</p>
                    <p className="font-medium break-all">{overview.title || "-"}</p>
                  </div>
                  <div>
                    <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.status")}</p>
                    <p className="font-mono">
                      <span className={`chip ${overview.status_code && overview.status_code < 400 ? "text-emerald-600 dark:text-emerald-400" : "text-red-500"}`}>
                        {overview.status_code || "-"}
                      </span>
                    </p>
                  </div>
                  <div>
                    <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.waPageSize")}</p>
                    <p className="font-mono">{overview.page_size || "-"}</p>
                  </div>
                  <div>
                    <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.waLoadTime")}</p>
                    <p className="font-mono">{overview.load_time ? `${overview.load_time}ms` : "-"}</p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.waServer")}</p>
                    <p className="font-medium">{overview.server || "-"}</p>
                  </div>
                  {overview.content_type && (
                    <div className="col-span-2">
                      <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.waContentType")}</p>
                      <p className="font-mono">{overview.content_type}</p>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("netsec.analyzing") : t("netsec.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 链接统计 */}
        {activeTab === "links" && (
          <div className="p-3">
            {links ? (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.waInternalLinks")}</p>
                    <p className="mt-1 text-lg font-semibold text-emerald-600 dark:text-emerald-400">
                      {links.internal_count || 0}
                    </p>
                  </div>
                  <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                    <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.waExternalLinks")}</p>
                    <p className="mt-1 text-lg font-semibold text-blue-600 dark:text-blue-400">
                      {links.external_count || 0}
                    </p>
                  </div>
                </div>
                <div>
                  <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("netsec.waLinkList")}
                  </p>
                  <div className="max-h-60 overflow-auto divide-y divide-neutral-100 dark:divide-neutral-800 rounded-xl border border-neutral-200 dark:border-neutral-800">
                    {links.list && links.list.length > 0 ? (
                      links.list.map((link, i) => (
                        <div key={i} className="flex items-center justify-between px-3 py-2">
                          <span className="font-mono text-xs break-all pr-2">{link.href}</span>
                          <span className={`chip text-[10px] shrink-0 ${
                            link.type === "internal"
                              ? "text-emerald-600 dark:text-emerald-400"
                              : "text-blue-600 dark:text-blue-400"
                          }`}>
                            {link.type === "internal" ? t("netsec.waInternal") : t("netsec.waExternal")}
                          </span>
                        </div>
                      ))
                    ) : (
                      <div className="py-6 text-center text-xs text-neutral-400">
                        {t("netsec.noResult")}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("netsec.analyzing") : t("netsec.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 表单分析 */}
        {activeTab === "forms" && (
          <div className="p-3">
            {forms.length > 0 ? (
              <div className="space-y-3">
                {forms.map((form, i) => (
                  <div key={i} className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="text-xs font-medium">{t("netsec.waForm")} #{i + 1}</span>
                      <span className="chip text-[10px]">{form.method || "GET"}</span>
                    </div>
                    {form.action && (
                      <p className="mb-2 font-mono text-[11px] text-neutral-500 dark:text-neutral-400 break-all">
                        {form.action}
                      </p>
                    )}
                    {form.fields && form.fields.length > 0 && (
                      <div className="space-y-1">
                        {form.fields.map((field, j) => (
                          <div key={j} className="flex items-center gap-2 text-xs">
                            <span className="chip font-mono text-[10px]">{field.type || "text"}</span>
                            <span className="font-mono text-neutral-700 dark:text-neutral-300">
                              {field.name || "-"}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("netsec.analyzing") : t("netsec.waNoForm")}
              </div>
            )}
          </div>
        )}

        {/* 安全头检测 */}
        {activeTab === "headers" && (
          <div className="p-3">
            {securityHeaders.length > 0 ? (
              <div className="space-y-2">
                {securityHeaders.map((h, i) => (
                  <div
                    key={i}
                    className={`flex items-start gap-3 rounded-xl border p-3 ${
                      h.present
                        ? "border-emerald-200 bg-emerald-50 dark:border-emerald-900/50 dark:bg-emerald-900/20"
                        : "border-red-200 bg-red-50 dark:border-red-900/50 dark:bg-red-900/20"
                    }`}
                  >
                    <div className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${
                      h.present
                        ? "bg-emerald-500 text-white"
                        : "bg-red-500 text-white"
                    }`}>
                      <span className="text-[10px] font-bold">{h.present ? "✓" : "!"}</span>
                    </div>
                    <div className="flex-1">
                      <p className={`text-xs font-semibold ${
                        h.present
                          ? "text-emerald-700 dark:text-emerald-400"
                          : "text-red-700 dark:text-red-400"
                      }`}>
                        {h.name}
                      </p>
                      {h.value && (
                        <p className="mt-0.5 font-mono text-[11px] text-neutral-600 dark:text-neutral-400 break-all">
                          {h.value}
                        </p>
                      )}
                      {h.description && (
                        <p className="mt-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                          {h.description}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("netsec.analyzing") : t("netsec.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 技术指纹 */}
        {activeTab === "tech" && (
          <div className="p-3">
            {techFingerprint.length > 0 ? (
              <div className="space-y-2">
                {techFingerprint.map((tech, i) => (
                  <div key={i} className="flex items-center justify-between rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <div>
                      <p className="text-sm font-medium">{tech.name}</p>
                      {tech.version && (
                        <p className="font-mono text-xs text-neutral-500 dark:text-neutral-400">
                          {tech.version}
                        </p>
                      )}
                    </div>
                    <span className="chip text-[10px]">{tech.category || t("netsec.waTech")}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("netsec.analyzing") : t("netsec.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 敏感信息 */}
        {activeTab === "sensitive" && (
          <div className="p-3">
            {mode !== "deep" && !analyzing && sensitiveInfo.length === 0 ? (
              <div className="py-8 text-center text-sm text-neutral-400">
                {t("netsec.waDeepModeOnly")}
              </div>
            ) : sensitiveInfo.length > 0 ? (
              <div className="space-y-2">
                {sensitiveInfo.map((item, i) => (
                  <div key={i} className="rounded-xl border border-amber-200 bg-amber-50 p-3 dark:border-amber-900/50 dark:bg-amber-900/20">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-amber-700 dark:text-amber-400">
                        {item.type}
                      </span>
                      <span className="chip text-[10px] text-amber-600 dark:text-amber-400">
                        {t("netsec.waFound")}
                      </span>
                    </div>
                    <p className="mt-1 font-mono text-xs break-all text-neutral-700 dark:text-neutral-300">
                      {item.value}
                    </p>
                    {item.context && (
                      <p className="mt-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                        {item.context}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {analyzing ? t("netsec.analyzing") : t("netsec.waNoSensitive")}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
