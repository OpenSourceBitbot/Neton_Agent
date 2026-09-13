import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconStop, IconCamera, IconRefresh } from "../Icons.jsx";

/**
 * 虚拟浏览器工具
 * 启动/管理虚拟浏览器，支持URL导航和截图
 */
export default function VirtualBrowser({ onClose }) {
  const { t } = useLang();
  const [url, setUrl] = useState("https://");
  const [browserId, setBrowserId] = useState(null);
  const [running, setRunning] = useState(false);
  const [screenshot, setScreenshot] = useState("");
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const addLog = (msg, type = "info") => {
    setLogs((prev) => [...prev, { time: new Date().toLocaleTimeString(), msg, type }]);
  };

  const startBrowser = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await invoke("virtual_browser_start");
      setBrowserId(res?.id);
      setRunning(true);
      addLog(t("netsec.browserStarted"), "success");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
      addLog(String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const stopBrowser = async () => {
    if (!browserId) return;
    setBusy(true);
    setError("");
    try {
      await invoke("virtual_browser_stop", { browserId });
      setRunning(false);
      setBrowserId(null);
      addLog(t("netsec.browserStopped"), "info");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setBusy(false);
    }
  };

  const navigate = async () => {
    if (!browserId || !url.trim()) return;
    setBusy(true);
    setError("");
    try {
      await invoke("virtual_browser_navigate", { browserId, url: url.trim() });
      addLog(`${t("netsec.navigatedTo")} ${url}`, "info");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
      addLog(String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const takeScreenshot = async () => {
    if (!browserId) return;
    setBusy(true);
    setError("");
    try {
      const res = await invoke("virtual_browser_screenshot", { browserId });
      setScreenshot(res?.image_data || "");
      addLog(t("netsec.screenshotTaken"), "success");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setBusy(false);
    }
  };

  const refreshPage = async () => {
    if (!browserId) return;
    setBusy(true);
    try {
      await invoke("virtual_browser_refresh", { browserId });
      addLog(t("netsec.pageRefreshed"), "info");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setBusy(false);
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
          <h3 className="text-base font-semibold">{t("netsec.virtualBrowser")}</h3>
          {running && (
            <span className="chip text-emerald-500">{t("netsec.running")}</span>
          )}
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* 启动/停止控制 */}
      <div className="mb-4 flex gap-2">
        {!running ? (
          <button
            onClick={startBrowser}
            disabled={busy}
            className="pill pill-hover flex-1 justify-center"
          >
            <IconPlay size={14} />
            {t("netsec.startBrowser")}
          </button>
        ) : (
          <button
            onClick={stopBrowser}
            disabled={busy}
            className="pill pill-outline pill-hover flex-1 justify-center text-red-500"
          >
            <IconStop size={14} />
            {t("netsec.stopBrowser")}
          </button>
        )}
      </div>

      {/* 地址栏 */}
      <div className="mb-4">
        <div className="flex gap-2">
          <input
            className="field flex-1 font-mono text-xs"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && navigate()}
            placeholder="https://example.com"
            disabled={!running}
          />
          <button
            onClick={navigate}
            disabled={busy || !running || !url.trim()}
            className="pill pill-outline pill-hover"
          >
            {t("netsec.go")}
          </button>
          <button
            onClick={refreshPage}
            disabled={busy || !running}
            className="pill pill-outline pill-hover"
            title={t("netsec.refresh")}
          >
            <IconRefresh size={14} />
          </button>
        </div>
      </div>

      {/* 工具栏 */}
      {running && (
        <div className="mb-4 flex gap-2">
          <button
            onClick={takeScreenshot}
            disabled={busy}
            className="pill pill-outline pill-hover"
          >
            <IconCamera size={14} />
            {t("netsec.screenshot")}
          </button>
        </div>
      )}

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 内容区：截图预览 + 日志 */}
      <div className="flex flex-1 min-h-0 gap-3">
        {/* 截图预览 */}
        <div className="flex-1 rounded-2xl border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900">
          {screenshot ? (
            <img
              src={screenshot}
              alt="screenshot"
              className="h-full w-full object-contain rounded-2xl"
            />
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-neutral-400">
              {running ? t("netsec.noScreenshot") : t("netsec.browserNotStarted")}
            </div>
          )}
        </div>

        {/* 操作日志 */}
        <div className="w-48 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
          <div className="sticky top-0 bg-neutral-50 px-3 py-2 text-[11px] font-medium text-neutral-600 dark:bg-neutral-900 dark:text-neutral-400">
            {t("netsec.logs")}
          </div>
          <div className="p-2 space-y-1">
            {logs.length > 0 ? (
              logs.map((log, i) => (
                <div key={i} className="text-[10px] leading-relaxed">
                  <span className="text-neutral-400">{log.time}</span>
                  <p className={`font-mono ${
                    log.type === "error" ? "text-red-500" :
                    log.type === "success" ? "text-emerald-500" :
                    "text-neutral-600 dark:text-neutral-400"
                  }`}>
                    {log.msg}
                  </p>
                </div>
              ))
            ) : (
              <p className="py-4 text-center text-[11px] text-neutral-400">
                {t("netsec.noLogs")}
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
