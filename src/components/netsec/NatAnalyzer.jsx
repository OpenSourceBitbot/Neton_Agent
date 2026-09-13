import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay } from "../Icons.jsx";

/**
 * NAT类型分析工具
 * 检测当前网络的NAT类型
 */
export default function NatAnalyzer({ onClose }) {
  const { t } = useLang();
  const [detecting, setDetecting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const detectNat = async () => {
    setDetecting(true);
    setError("");
    setResult(null);
    try {
      const res = await invoke("nat_analyze");
      setResult(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setDetecting(false);
    }
  };

  const natTypeInfo = (type) => {
    const types = {
      "none": { label: t("netsec.natNone"), desc: t("netsec.natNoneDesc"), color: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-100 dark:bg-emerald-900/30" },
      "full_cone": { label: t("netsec.fullCone"), desc: t("netsec.fullConeDesc"), color: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-100 dark:bg-emerald-900/30" },
      "restricted_cone": { label: t("netsec.restrictedCone"), desc: t("netsec.restrictedConeDesc"), color: "text-blue-600 dark:text-blue-400", bg: "bg-blue-100 dark:bg-blue-900/30" },
      "port_restricted": { label: t("netsec.portRestricted"), desc: t("netsec.portRestrictedDesc"), color: "text-yellow-600 dark:text-yellow-400", bg: "bg-yellow-100 dark:bg-yellow-900/30" },
      "symmetric": { label: t("netsec.symmetric"), desc: t("netsec.symmetricDesc"), color: "text-red-600 dark:text-red-400", bg: "bg-red-100 dark:bg-red-900/30" },
      "unknown": { label: t("netsec.unknown"), desc: t("netsec.unknownDesc"), color: "text-neutral-500", bg: "bg-neutral-100 dark:bg-neutral-800" },
    };
    return types[type] || types.unknown;
  };

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.natAnalyzer")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <p className="mb-4 text-xs text-neutral-500 dark:text-neutral-400">
        {t("netsec.natDesc")}
      </p>

      <button
        onClick={detectNat}
        disabled={detecting}
        className="pill pill-hover mb-6 w-full justify-center"
      >
        {detecting ? (
          <>
            <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
            {t("netsec.detecting")}
          </>
        ) : (
          <>
            <IconPlay size={14} />
            {t("netsec.startDetect")}
          </>
        )}
      </button>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 检测结果 */}
      {result && (
        <div className="space-y-4">
          <div className={`rounded-2xl p-4 text-center ${natTypeInfo(result.type).bg}`}>
            <p className="mb-1 text-xs text-neutral-500 dark:text-neutral-400">
              {t("netsec.natType")}
            </p>
            <p className={`text-xl font-bold ${natTypeInfo(result.type).color}`}>
              {natTypeInfo(result.type).label}
            </p>
            <p className="mt-2 text-xs text-neutral-600 dark:text-neutral-400">
              {natTypeInfo(result.type).desc}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            {result.publicIp && (
              <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                  {t("netsec.publicIp")}
                </p>
                <p className="font-mono text-sm font-semibold">{result.publicIp}</p>
              </div>
            )}
            {result.localIp && (
              <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                  {t("netsec.localIp")}
                </p>
                <p className="font-mono text-sm font-semibold">{result.localIp}</p>
              </div>
            )}
            {result.mappingBehavior && (
              <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                  {t("netsec.mappingBehavior")}
                </p>
                <p className="text-sm font-medium">{result.mappingBehavior}</p>
              </div>
            )}
            {result.filteringBehavior && (
              <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                  {t("netsec.filteringBehavior")}
                </p>
                <p className="text-sm font-medium">{result.filteringBehavior}</p>
              </div>
            )}
          </div>

          {result.p2pCapable !== undefined && (
            <div className={`rounded-xl p-3 text-center text-xs ${
              result.p2pCapable
                ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/20 dark:text-emerald-400"
                : "bg-amber-50 text-amber-700 dark:bg-amber-950/20 dark:text-amber-400"
            }`}>
              {result.p2pCapable ? t("netsec.p2pCapable") : t("netsec.p2pNotCapable")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
