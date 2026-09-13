import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconSearch, IconInfo } from "../Icons.jsx";

/**
 * CVE漏洞搜索工具
 * 搜索和查询CVE漏洞详情
 */
export default function CveSearch({ onClose }) {
  const { t } = useLang();
  const [keyword, setKeyword] = useState("");
  const [searching, setSearching] = useState(false);
  const [results, setResults] = useState([]);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");

  const doSearch = async () => {
    if (!keyword.trim()) return;
    setSearching(true);
    setError("");
    setSelected(null);
    try {
      const res = await invoke("cve_search", { keyword: keyword.trim() });
      setResults(res?.cves || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setSearching(false);
    }
  };

  const viewDetail = async (cveId) => {
    try {
      const res = await invoke("cve_detail", { cveId });
      setSelected(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const severityColor = (severity) => {
    const s = (severity || "").toLowerCase();
    if (s.includes("critical") || s.includes("严重")) return "text-red-600 dark:text-red-400";
    if (s.includes("high") || s.includes("高")) return "text-orange-600 dark:text-orange-400";
    if (s.includes("medium") || s.includes("中")) return "text-yellow-600 dark:text-yellow-400";
    if (s.includes("low") || s.includes("低")) return "text-emerald-600 dark:text-emerald-400";
    return "text-neutral-500";
  };

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.3-4.3" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.cveSearch")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <div className="mb-4 flex gap-2">
        <input
          className="field flex-1"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && doSearch()}
          placeholder={t("netsec.cveSearchPlaceholder")}
        />
        <button
          onClick={doSearch}
          disabled={searching || !keyword.trim()}
          className="pill pill-hover"
        >
          {searching ? (
            <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
          ) : (
            <IconSearch size={14} />
          )}
          {t("netsec.search")}
        </button>
      </div>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 详情视图 */}
      {selected ? (
        <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 p-4 dark:border-neutral-800">
          <button
            onClick={() => setSelected(null)}
            className="mb-3 text-xs text-neutral-500 hover:text-neutral-700 dark:hover:text-white"
          >
            ← {t("netsec.backToList")}
          </button>
          <div className="mb-3 flex items-center gap-2">
            <h4 className="font-mono font-bold">{selected.id}</h4>
            {selected.severity && (
              <span className={`chip ${severityColor(selected.severity)}`}>
                {selected.severity}
              </span>
            )}
            {selected.cvss && (
              <span className="chip font-mono">CVSS {selected.cvss}</span>
            )}
          </div>
          <p className="mb-3 text-sm text-neutral-700 dark:text-neutral-300">
            {selected.description}
          </p>
          {selected.published && (
            <p className="mb-2 text-xs text-neutral-500 dark:text-neutral-400">
              {t("netsec.published")}: {selected.published}
            </p>
          )}
          {selected.references && selected.references.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                {t("netsec.references")}
              </p>
              <ul className="space-y-1">
                {selected.references.map((ref, i) => (
                  <li key={i} className="truncate font-mono text-xs text-blue-600 dark:text-blue-400">
                    {ref}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : (
        /* 搜索结果列表 */
        <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
          {results.length > 0 ? (
            <div className="divide-y divide-neutral-100 dark:divide-neutral-800">
              {results.map((cve, i) => (
                <button
                  key={i}
                  onClick={() => viewDetail(cve.id)}
                  className="w-full p-3 text-left transition-colors hover:bg-neutral-50 dark:hover:bg-neutral-900"
                >
                  <div className="mb-1 flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold">{cve.id}</span>
                    {cve.severity && (
                      <span className={`chip text-[10px] ${severityColor(cve.severity)}`}>
                        {cve.severity}
                      </span>
                    )}
                  </div>
                  <p className="line-clamp-2 text-xs text-neutral-600 dark:text-neutral-400">
                    {cve.description || t("netsec.noDescription")}
                  </p>
                </button>
              ))}
            </div>
          ) : (
            <div className="flex h-full items-center justify-center py-8 text-sm text-neutral-400">
              {searching ? t("netsec.searching") : t("netsec.enterKeyword")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
