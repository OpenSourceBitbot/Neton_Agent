import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import PillSwitch from "../PillSwitch.jsx";
import { IconPlay, IconGlobe } from "../Icons.jsx";

/**
 * 域名综合分析工具
 * 包含 DNS 查询、子域名枚举、WHOIS 查询
 */
export default function DomainAnalysis({ onClose }) {
  const { t } = useLang();
  const [domain, setDomain] = useState("");
  const [activeTab, setActiveTab] = useState("dns"); // dns, subdomain, whois
  const [loading, setLoading] = useState(false);
  const [dnsRecords, setDnsRecords] = useState([]);
  const [subdomains, setSubdomains] = useState([]);
  const [whoisInfo, setWhoisInfo] = useState(null);
  const [error, setError] = useState("");

  const doDnsLookup = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    setError("");
    setDnsRecords([]);
    try {
      const res = await invoke("dns_lookup", { domain: domain.trim() });
      setDnsRecords(res?.records || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setLoading(false);
    }
  };

  const doSubdomainEnum = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    setError("");
    setSubdomains([]);
    try {
      const res = await invoke("subdomain_enum", { domain: domain.trim() });
      setSubdomains(res?.subdomains || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setLoading(false);
    }
  };

  const doWhoisQuery = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    setError("");
    setWhoisInfo(null);
    try {
      const res = await invoke("whois_query", { domain: domain.trim() });
      setWhoisInfo(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setLoading(false);
    }
  };

  const runCurrent = () => {
    if (activeTab === "dns") doDnsLookup();
    else if (activeTab === "subdomain") doSubdomainEnum();
    else if (activeTab === "whois") doWhoisQuery();
  };

  const tabs = [
    { key: "dns", label: t("netsec.dnsLookup") },
    { key: "subdomain", label: t("netsec.subdomainEnum") },
    { key: "whois", label: t("netsec.whoisQuery") },
  ];

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconGlobe size={20} />
          <h3 className="text-base font-semibold">{t("netsec.domainAnalysis")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <div className="mb-4 flex gap-2">
        <input
          className="field flex-1 font-mono"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runCurrent()}
          placeholder="example.com"
        />
        <button
          onClick={runCurrent}
          disabled={loading || !domain.trim()}
          className="pill pill-hover"
        >
          {loading ? (
            <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
          ) : (
            <IconPlay size={14} />
          )}
          {t("netsec.analyze")}
        </button>
      </div>

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

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 内容区 */}
      <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
        {/* DNS 查询结果 */}
        {activeTab === "dns" && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
              <tr>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.recordType")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.value")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">TTL</th>
              </tr>
            </thead>
            <tbody>
              {dnsRecords.length > 0 ? (
                dnsRecords.map((r, i) => (
                  <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                    <td className="px-3 py-2">
                      <span className="chip font-mono text-[10px]">{r.type}</span>
                    </td>
                    <td className="px-3 py-2 font-mono break-all">{r.value}</td>
                    <td className="px-3 py-2 text-neutral-500 dark:text-neutral-400">{r.ttl}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={3} className="px-3 py-8 text-center text-neutral-400">
                    {loading ? t("netsec.querying") : t("netsec.noRecord")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}

        {/* 子域名枚举结果 */}
        {activeTab === "subdomain" && (
          <div className="divide-y divide-neutral-100 dark:divide-neutral-800">
            {subdomains.length > 0 ? (
              subdomains.map((s, i) => (
                <div key={i} className="flex items-center justify-between px-3 py-2">
                  <span className="font-mono text-xs">{s.subdomain}</span>
                  <div className="flex items-center gap-2">
                    {s.ip && <span className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400">{s.ip}</span>}
                    {s.status && (
                      <span className={`chip text-[10px] ${s.status === "active" ? "text-emerald-500" : "text-neutral-400"}`}>
                        {s.status}
                      </span>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {loading ? t("netsec.enumerating") : t("netsec.noSubdomain")}
              </div>
            )}
          </div>
        )}

        {/* WHOIS 查询结果 */}
        {activeTab === "whois" && (
          <div className="p-3">
            {whoisInfo ? (
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  {whoisInfo.registrar && (
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.registrar")}</p>
                      <p className="font-medium">{whoisInfo.registrar}</p>
                    </div>
                  )}
                  {whoisInfo.status && (
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.status")}</p>
                      <p className="font-medium">{whoisInfo.status}</p>
                    </div>
                  )}
                  {whoisInfo.created && (
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.created")}</p>
                      <p className="font-mono">{whoisInfo.created}</p>
                    </div>
                  )}
                  {whoisInfo.expires && (
                    <div>
                      <p className="text-neutral-500 dark:text-neutral-400">{t("netsec.expires")}</p>
                      <p className="font-mono">{whoisInfo.expires}</p>
                    </div>
                  )}
                </div>
                {whoisInfo.nameservers && whoisInfo.nameservers.length > 0 && (
                  <div>
                    <p className="mb-1 text-neutral-500 dark:text-neutral-400">{t("netsec.nameservers")}</p>
                    <div className="flex flex-wrap gap-1">
                      {whoisInfo.nameservers.map((ns, i) => (
                        <span key={i} className="chip font-mono text-[10px]">{ns}</span>
                      ))}
                    </div>
                  </div>
                )}
                {whoisInfo.raw && (
                  <details className="rounded-xl bg-neutral-50 p-2 dark:bg-neutral-900">
                    <summary className="cursor-pointer text-neutral-500 dark:text-neutral-400">
                      {t("netsec.rawData")}
                    </summary>
                    <pre className="mt-2 max-h-40 overflow-auto font-mono text-[10px] text-neutral-600 dark:text-neutral-400">
                      {whoisInfo.raw}
                    </pre>
                  </details>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {loading ? t("netsec.querying") : t("netsec.noWhoisData")}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
