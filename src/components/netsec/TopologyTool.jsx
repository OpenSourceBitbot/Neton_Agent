import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconGlobe } from "../Icons.jsx";

/**
 * 网络拓扑分析工具
 * 基于 traceroute 分析网络拓扑结构
 */
export default function TopologyTool({ onClose }) {
  const { t } = useLang();
  const [target, setTarget] = useState("");
  const [maxHops, setMaxHops] = useState("30");
  const [tracing, setTracing] = useState(false);
  const [hops, setHops] = useState([]);
  const [error, setError] = useState("");

  const startTrace = async () => {
    if (!target.trim()) return;
    setTracing(true);
    setError("");
    setHops([]);
    try {
      const res = await invoke("traceroute", {
        target: target.trim(),
        maxHops: parseInt(maxHops) || 30,
      });
      setHops(res?.hops || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setTracing(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <path d="M2 12h20" />
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.topologyAnalyzer")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <div className="mb-4 grid grid-cols-3 gap-2">
        <div className="col-span-2">
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.targetDomain")}
          </label>
          <input
            className="field w-full font-mono"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && startTrace()}
            placeholder="example.com"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.maxHops")}
          </label>
          <input
            className="field w-full font-mono"
            value={maxHops}
            onChange={(e) => setMaxHops(e.target.value)}
            inputMode="numeric"
          />
        </div>
      </div>

      <button
        onClick={startTrace}
        disabled={tracing || !target.trim()}
        className="pill pill-hover mb-4 w-full justify-center"
      >
        {tracing ? (
          <>
            <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
            {t("common.running")}
          </>
        ) : (
          <>
            <IconPlay size={14} />
            {t("netsec.startTrace")}
          </>
        )}
      </button>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 拓扑可视化 + 列表 */}
      <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
        {hops.length > 0 ? (
          <div className="p-3">
            {/* 简化的拓扑路径可视化 */}
            <div className="mb-4 overflow-x-auto">
              <div className="flex min-w-max items-center gap-1 pb-2">
                <div className="flex flex-col items-center">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-neutral-900 text-white dark:bg-white dark:text-neutral-900">
                    <svg width={14} height={14} viewBox="0 0 24 24" fill="currentColor">
                      <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
                    </svg>
                  </div>
                  <span className="mt-1 text-[10px] text-neutral-500">{t("netsec.local")}</span>
                </div>
                {hops.slice(0, 8).map((h, i) => (
                  <div key={i} className="flex items-center gap-1">
                    <div className="h-px w-4 bg-neutral-300 dark:bg-neutral-700" />
                    <div className="flex flex-col items-center">
                      <div className={`flex h-8 w-8 items-center justify-center rounded-full text-[10px] font-bold ${
                        h.ip ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" : "bg-neutral-100 text-neutral-400 dark:bg-neutral-800"
                      }`}>
                        {i + 1}
                      </div>
                      <span className="mt-1 max-w-16 truncate text-[10px] text-neutral-500 font-mono">
                        {h.ip || "*"}
                      </span>
                    </div>
                  </div>
                ))}
                {hops.length > 8 && (
                  <div className="flex items-center gap-1">
                    <div className="h-px w-4 bg-neutral-300 dark:bg-neutral-700" />
                    <span className="text-xs text-neutral-400">...</span>
                  </div>
                )}
              </div>
            </div>

            {/* 详细列表 */}
            <div className="space-y-1">
              {hops.map((h, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 rounded-lg px-2 py-1.5 hover:bg-neutral-50 dark:hover:bg-neutral-900"
                >
                  <span className="w-6 text-center font-mono text-xs font-bold text-neutral-400">
                    {i + 1}
                  </span>
                  <div className="flex-1 min-w-0">
                    {h.ip ? (
                      <>
                        <p className="font-mono text-xs">{h.ip}</p>
                        {h.hostname && (
                          <p className="truncate text-[11px] text-neutral-500 dark:text-neutral-400">
                            {h.hostname}
                          </p>
                        )}
                      </>
                    ) : (
                      <p className="text-xs text-neutral-400">* * * {t("netsec.requestTimeout")}</p>
                    )}
                  </div>
                  <div className="text-right">
                    {h.rtt && (
                      <span className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400">
                        {h.rtt} ms
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="flex h-full items-center justify-center py-8 text-sm text-neutral-400">
            {tracing ? t("netsec.tracing") : t("netsec.enterTarget")}
          </div>
        )}
      </div>
    </div>
  );
}
