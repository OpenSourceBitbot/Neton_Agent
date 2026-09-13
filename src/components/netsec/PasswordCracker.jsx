import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconFile } from "../Icons.jsx";

/**
 * 密码爆破工具
 * 支持多种协议的密码暴力破解
 */
export default function PasswordCracker({ onClose }) {
  const { t } = useLang();
  const [target, setTarget] = useState("");
  const [protocol, setProtocol] = useState("ssh");
  const [username, setUsername] = useState("");
  const [dictPath, setDictPath] = useState("");
  const [cracking, setCracking] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState({ tried: 0, total: 0 });

  const selectDictFile = async () => {
    try {
      const path = await invoke("open_file_dialog", {
        filters: [{ name: "Text Files", extensions: ["txt", "dic"] }],
      });
      if (path) setDictPath(path);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const startCrack = async () => {
    setCracking(true);
    setError("");
    setResult(null);
    setProgress({ tried: 0, total: 0 });
    try {
      const res = await invoke("password_crack", {
        target: target.trim(),
        protocol,
        username: username.trim(),
        dictPath: dictPath.trim(),
      });
      setResult(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setCracking(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="10" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.passwordCracker")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <div className="mb-4 space-y-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.target")}
          </label>
          <input
            className="field w-full font-mono"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="192.168.1.1:22"
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
              {t("netsec.protocol")}
            </label>
            <select className="field w-full" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="ssh">SSH</option>
              <option value="ftp">FTP</option>
              <option value="telnet">Telnet</option>
              <option value="mysql">MySQL</option>
              <option value="rdp">RDP</option>
              <option value="http">HTTP Basic</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
              {t("netsec.username")}
            </label>
            <input
              className="field w-full"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="root"
            />
          </div>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.dictFile")}
          </label>
          <div className="flex gap-2">
            <input
              className="field flex-1 font-mono text-xs"
              value={dictPath}
              onChange={(e) => setDictPath(e.target.value)}
              placeholder={t("netsec.dictFileHint")}
              readOnly
            />
            <button onClick={selectDictFile} className="pill pill-outline pill-hover">
              <IconFile size={14} />
              {t("common.select")}
            </button>
          </div>
        </div>
      </div>

      <button
        onClick={startCrack}
        disabled={cracking || !target.trim() || !username.trim() || !dictPath.trim()}
        className="pill pill-hover mb-4 w-full justify-center"
      >
        {cracking ? (
          <>
            <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
            {t("common.running")}
          </>
        ) : (
          <>
            <IconPlay size={14} />
            {t("netsec.startCrack")}
          </>
        )}
      </button>

      {cracking && progress.total > 0 && (
        <div className="mb-4">
          <div className="mb-1 flex justify-between text-[11px] text-neutral-500 dark:text-neutral-400">
            <span>{t("netsec.progress")}</span>
            <span className="font-mono">{progress.tried} / {progress.total}</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
            <div
              className="h-full rounded-full bg-neutral-900 dark:bg-white transition-[width] duration-200"
              style={{ width: `${(progress.tried / progress.total) * 100}%` }}
            />
          </div>
        </div>
      )}

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {result && (
        <div className="rounded-2xl border border-neutral-200 p-3 dark:border-neutral-800">
          <div className="mb-2 flex items-center gap-2">
            <span className={`chip ${result.found ? "text-emerald-600 dark:text-emerald-400" : "text-amber-600 dark:text-amber-400"}`}>
              {result.found ? t("netsec.cracked") : t("netsec.notFound")}
            </span>
          </div>
          {result.found && (
            <div className="space-y-1 font-mono text-xs">
              <p><span className="text-neutral-500 dark:text-neutral-400">{t("netsec.username")}:</span> {result.username}</p>
              <p><span className="text-neutral-500 dark:text-neutral-400">{t("netsec.password")}:</span> {result.password}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
