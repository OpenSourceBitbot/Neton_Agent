import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay } from "../Icons.jsx";

/**
 * SQL注入测试工具
 * 对目标URL进行SQL注入漏洞检测
 */
export default function SqlInjection({ onClose }) {
  const { t } = useLang();
  const [url, setUrl] = useState("");
  const [param, setParam] = useState("id");
  const [method, setMethod] = useState("get");
  const [testType, setTestType] = useState("error");
  const [testing, setTesting] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState("");

  const startTest = async () => {
    setTesting(true);
    setError("");
    setResults([]);
    try {
      const res = await invoke("sql_injection_test", {
        url: url.trim(),
        param: param.trim(),
        method,
        testType,
      });
      setResults(res?.results || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setTesting(false);
    }
  };

  const vulnerableCount = results.filter(r => r.vulnerable).length;

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.sqlInjection")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

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
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
              {t("netsec.testParam")}
            </label>
            <input
              className="field w-full font-mono"
              value={param}
              onChange={(e) => setParam(e.target.value)}
              placeholder="id"
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
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.testType")}
          </label>
          <select className="field w-full" value={testType} onChange={(e) => setTestType(e.target.value)}>
            <option value="error">{t("netsec.sqlErrorBased")}</option>
            <option value="union">{t("netsec.sqlUnionBased")}</option>
            <option value="blind">{t("netsec.sqlBlind")}</option>
            <option value="time">{t("netsec.sqlTimeBased")}</option>
          </select>
        </div>
      </div>

      <button
        onClick={startTest}
        disabled={testing || !url.trim() || !param.trim()}
        className="pill pill-hover mb-4 w-full justify-center"
      >
        {testing ? (
          <>
            <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
            {t("common.running")}
          </>
        ) : (
          <>
            <IconPlay size={14} />
            {t("netsec.startTest")}
          </>
        )}
      </button>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {results.length > 0 && (
        <div className="mb-3 flex items-center gap-2">
          <span className={`chip ${vulnerableCount > 0 ? "text-red-500" : "text-emerald-500"}`}>
            {vulnerableCount > 0
              ? t("netsec.vulnerableFound", { n: vulnerableCount })
              : t("netsec.noVulnerability")}
          </span>
        </div>
      )}

      {/* 结果列表 */}
      <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
        {results.length > 0 ? (
          <div className="divide-y divide-neutral-100 dark:divide-neutral-800">
            {results.map((r, i) => (
              <div key={i} className="p-3">
                <div className="mb-1 flex items-center gap-2">
                  <span className={`chip ${r.vulnerable ? "text-red-500" : "text-neutral-400"}`}>
                    {r.vulnerable ? t("netsec.vulnerable") : t("netsec.safe")}
                  </span>
                  <span className="font-mono text-xs text-neutral-500 dark:text-neutral-400">
                    {r.payload}
                  </span>
                </div>
                {r.details && (
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">{r.details}</p>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="flex h-full items-center justify-center py-8 text-sm text-neutral-400">
            {testing ? t("netsec.testing") : t("netsec.noResult")}
          </div>
        )}
      </div>
    </div>
  );
}
