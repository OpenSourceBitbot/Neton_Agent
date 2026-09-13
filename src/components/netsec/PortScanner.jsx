import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconRefresh, IconTarget } from "../Icons.jsx";

/**
 * 端口扫描工具
 * 支持目标IP、端口范围、扫描类型配置
 */
export default function PortScanner({ onClose }) {
  const { t } = useLang();
  const [target, setTarget] = useState("127.0.0.1");
  const [portStart, setPortStart] = useState("1");
  const [portEnd, setPortEnd] = useState("1024");
  const [scanType, setScanType] = useState("tcp");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState("");

  const startScan = async () => {
    setScanning(true);
    setError("");
    setResults([]);
    try {
      const res = await invoke("port_scan", {
        target: target.trim(),
        portStart: parseInt(portStart) || 1,
        portEnd: parseInt(portEnd) || 1024,
        scanType,
      });
      setResults(res?.ports || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconTarget size={20} />
          <h3 className="text-base font-semibold">{t("netsec.portScanner")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* 参数配置 */}
      <div className="mb-4 grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.targetIp")}
          </label>
          <input
            className="field w-full font-mono"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="192.168.1.1"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.portStart")}
          </label>
          <input
            className="field w-full font-mono"
            value={portStart}
            onChange={(e) => setPortStart(e.target.value)}
            inputMode="numeric"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.portEnd")}
          </label>
          <input
            className="field w-full font-mono"
            value={portEnd}
            onChange={(e) => setPortEnd(e.target.value)}
            inputMode="numeric"
          />
        </div>
        <div className="col-span-2">
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.scanType")}
          </label>
          <select className="field w-full" value={scanType} onChange={(e) => setScanType(e.target.value)}>
            <option value="tcp">TCP Connect</option>
            <option value="syn">TCP SYN</option>
            <option value="udp">UDP</option>
            <option value="fin">TCP FIN</option>
          </select>
        </div>
      </div>

      <button
        onClick={startScan}
        disabled={scanning || !target.trim()}
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
            {t("netsec.startScan")}
          </>
        )}
      </button>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 结果表格 */}
      <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
            <tr>
              <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.port")}</th>
              <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.status")}</th>
              <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.service")}</th>
            </tr>
          </thead>
          <tbody>
            {results.length > 0 ? (
              results.map((r, i) => (
                <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                  <td className="px-3 py-2 font-mono">{r.port}</td>
                  <td className="px-3 py-2">
                    <span className={`chip ${r.open ? "text-emerald-600 dark:text-emerald-400" : "text-neutral-400"}`}>
                      {r.open ? t("netsec.open") : t("netsec.closed")}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-neutral-500 dark:text-neutral-400">{r.service || "-"}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={3} className="px-3 py-8 text-center text-neutral-400">
                  {scanning ? t("netsec.scanning") : t("netsec.noResult")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
