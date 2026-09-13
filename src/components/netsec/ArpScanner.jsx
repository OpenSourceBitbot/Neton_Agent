import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconRefresh } from "../Icons.jsx";

/**
 * ARP设备扫描工具
 * 扫描局域网内的设备列表
 */
export default function ArpScanner({ onClose }) {
  const { t } = useLang();
  const [subnet, setSubnet] = useState("192.168.1.0/24");
  const [scanning, setScanning] = useState(false);
  const [devices, setDevices] = useState([]);
  const [error, setError] = useState("");

  const startScan = async () => {
    setScanning(true);
    setError("");
    setDevices([]);
    try {
      const res = await invoke("arp_scan", { subnet: subnet.trim() });
      setDevices(res?.devices || []);
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
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2" y="7" width="20" height="10" rx="2" />
            <line x1="6" y1="12" x2="6.01" y2="12" />
            <line x1="10" y1="12" x2="10.01" y2="12" />
            <line x1="14" y1="12" x2="14.01" y2="12" />
            <line x1="18" y1="12" x2="18.01" y2="12" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.arpScanner")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <div className="mb-4">
        <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
          {t("netsec.subnet")}
        </label>
        <div className="flex gap-2">
          <input
            className="field flex-1 font-mono"
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            placeholder="192.168.1.0/24"
          />
          <button
            onClick={startScan}
            disabled={scanning || !subnet.trim()}
            className="pill pill-hover"
          >
            {scanning ? (
              <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
            ) : (
              <IconPlay size={14} />
            )}
            {scanning ? t("common.running") : t("netsec.scan")}
          </button>
        </div>
      </div>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 设备列表 */}
      <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
            <tr>
              <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">IP</th>
              <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">MAC</th>
              <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.vendor")}</th>
            </tr>
          </thead>
          <tbody>
            {devices.length > 0 ? (
              devices.map((d, i) => (
                <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                  <td className="px-3 py-2 font-mono">{d.ip}</td>
                  <td className="px-3 py-2 font-mono text-[11px]">{d.mac}</td>
                  <td className="px-3 py-2 text-neutral-500 dark:text-neutral-400">{d.vendor || "-"}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={3} className="px-3 py-8 text-center text-neutral-400">
                  {scanning ? t("netsec.scanning") : t("netsec.noDevice")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
