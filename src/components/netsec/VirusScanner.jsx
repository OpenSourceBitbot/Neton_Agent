import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconFile, IconShield } from "../Icons.jsx";

/**
 * 病毒扫描与文件哈希分析工具
 * 包含病毒特征匹配和文件哈希分析功能
 */
export default function VirusScanner({ onClose }) {
  const { t } = useLang();
  const [filePath, setFilePath] = useState("");
  const [scanMode, setScanMode] = useState("full");
  const [activeTab, setActiveTab] = useState("scan"); // scan, hash
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [hashResult, setHashResult] = useState(null);
  const [error, setError] = useState("");

  const selectFile = async () => {
    try {
      const path = await invoke("open_file_dialog", {
        filters: [{ name: "All Files", extensions: ["*"] }],
      });
      if (path) {
        setFilePath(path);
        setScanResult(null);
        setHashResult(null);
      }
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const startScan = async () => {
    if (!filePath) return;
    setScanning(true);
    setError("");
    setScanResult(null);
    try {
      const res = await invoke("virus_scan", { filePath, mode: scanMode });
      setScanResult(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setScanning(false);
    }
  };

  const analyzeHash = async () => {
    if (!filePath) return;
    setScanning(true);
    setError("");
    setHashResult(null);
    try {
      const res = await invoke("hash_analyze", { filePath });
      setHashResult(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setScanning(false);
    }
  };

  const runCurrent = () => {
    if (activeTab === "scan") startScan();
    else analyzeHash();
  };

  const tabs = [
    { key: "scan", label: t("netsec.virusScan") },
    { key: "hash", label: t("netsec.hashAnalyzer") },
  ];

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconShield size={20} />
          <h3 className="text-base font-semibold">{t("netsec.virusScanner")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <div className="mb-4">
        <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
          {t("netsec.targetFile")}
        </label>
        <div className="flex gap-2">
          <input
            className="field flex-1 font-mono text-xs"
            value={filePath}
            onChange={(e) => setFilePath(e.target.value)}
            placeholder={t("netsec.selectFileHint")}
            readOnly
          />
          <button onClick={selectFile} className="pill pill-outline pill-hover">
            <IconFile size={14} />
            {t("common.select")}
          </button>
        </div>
      </div>

      {activeTab === "scan" && (
        <div className="mb-4">
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.scanMode")}
          </label>
          <select className="field w-full" value={scanMode} onChange={(e) => setScanMode(e.target.value)}>
            <option value="quick">{t("netsec.quickScan")}</option>
            <option value="full">{t("netsec.fullScan")}</option>
            <option value="deep">{t("netsec.deepScan")}</option>
          </select>
        </div>
      )}

      {/* 标签切换 */}
      <div className="mb-4 flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex-1 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === tab.key
                ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <button
        onClick={runCurrent}
        disabled={scanning || !filePath}
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
            {activeTab === "scan" ? t("netsec.startScan") : t("netsec.analyzeHash")}
          </>
        )}
      </button>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 结果区 */}
      <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
        {/* 病毒扫描结果 */}
        {activeTab === "scan" && scanResult && (
          <div className="p-4">
            <div className={`mb-4 rounded-xl p-4 text-center ${
              scanResult.threats > 0
                ? "bg-red-50 dark:bg-red-950/20"
                : "bg-emerald-50 dark:bg-emerald-950/20"
            }`}>
              <p className={`text-2xl font-bold ${
                scanResult.threats > 0 ? "text-red-600 dark:text-red-400" : "text-emerald-600 dark:text-emerald-400"
              }`}>
                {scanResult.threats > 0 ? t("netsec.threatFound") : t("netsec.noThreat")}
              </p>
              <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                {t("netsec.scannedFiles", { n: scanResult.scanned || 0 })}
              </p>
            </div>

            {scanResult.threats > 0 && scanResult.detections && (
              <div>
                <p className="mb-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
                  {t("netsec.detections")}
                </p>
                <div className="space-y-2">
                  {scanResult.detections.map((d, i) => (
                    <div key={i} className="rounded-lg border border-red-200 bg-red-50/50 p-2 dark:border-red-900/30 dark:bg-red-950/10">
                      <p className="font-mono text-xs font-semibold text-red-700 dark:text-red-400">
                        {d.name}
                      </p>
                      <p className="text-[11px] text-red-600 dark:text-red-300">{d.file}</p>
                      <p className="text-[10px] text-red-500 dark:text-red-400">{d.type}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* 哈希分析结果 */}
        {activeTab === "hash" && hashResult && (
          <div className="p-4 space-y-3">
            {hashResult.md5 && (
              <div>
                <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">MD5</p>
                <p className="break-all font-mono text-xs">{hashResult.md5}</p>
              </div>
            )}
            {hashResult.sha1 && (
              <div>
                <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">SHA-1</p>
                <p className="break-all font-mono text-xs">{hashResult.sha1}</p>
              </div>
            )}
            {hashResult.sha256 && (
              <div>
                <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">SHA-256</p>
                <p className="break-all font-mono text-xs">{hashResult.sha256}</p>
              </div>
            )}
            {hashResult.size !== undefined && (
              <div>
                <p className="mb-1 text-[11px] text-neutral-500 dark:text-neutral-400">{t("netsec.fileSize")}</p>
                <p className="font-mono text-xs">{hashResult.size} bytes</p>
              </div>
            )}
          </div>
        )}

        {!scanResult && !hashResult && !scanning && (
          <div className="flex h-full items-center justify-center py-8 text-sm text-neutral-400">
            {t("netsec.selectFileToScan")}
          </div>
        )}

        {scanning && (
          <div className="flex h-full items-center justify-center py-8 text-sm text-neutral-400">
            {activeTab === "scan" ? t("netsec.scanning") : t("netsec.calculating")}
          </div>
        )}
      </div>
    </div>
  );
}
