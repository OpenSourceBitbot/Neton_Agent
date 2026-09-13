import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconPause, IconRefresh, IconCopy } from "../Icons.jsx";

/**
 * 数据包捕获分析工具
 * 支持接口选择、BPF 过滤、协议分布、流量统计、DNS/HTTP/ARP 分析
 */
export default function PacketCapture({ onClose }) {
  const { t } = useLang();
  const [interfaces, setInterfaces] = useState([]);
  const [selectedIface, setSelectedIface] = useState("");
  const [filter, setFilter] = useState("");
  const [count, setCount] = useState("1000");
  const [duration, setDuration] = useState("60");
  const [capturing, setCapturing] = useState(false);
  const [activeTab, setActiveTab] = useState("protocol");
  const [error, setError] = useState("");

  // 统计数据
  const [stats, setStats] = useState({ total_packets: 0, total_bytes: 0, pps: 0, bps: 0 });

  // 各 Tab 数据
  const [protocolDist, setProtocolDist] = useState([]); // [{ name, count, percent }]
  const [topSessions, setTopSessions] = useState([]); // [{ src, dst, bytes }]
  const [topPorts, setTopPorts] = useState([]); // [{ port, count }]
  const [dnsRecords, setDnsRecords] = useState([]); // [{ time, domain, type, result, rtt }]
  const [httpRecords, setHttpRecords] = useState([]); // [{ method, url, host, status, ua }]
  const [arpTable, setArpTable] = useState([]); // [{ ip, mac, vendor }]
  const [arpSpoofResult, setArpSpoofResult] = useState(null); // { detected, details }
  const [packetList, setPacketList] = useState([]); // [{ time, src, dst, proto, len, info }]

  const statsTimerRef = useRef(null);

  // 加载接口列表
  useEffect(() => {
    loadInterfaces();
    return () => {
      if (statsTimerRef.current) clearInterval(statsTimerRef.current);
    };
  }, []);

  const loadInterfaces = async () => {
    try {
      const res = await invoke("packet_list_interfaces");
      const ifaces = res?.interfaces || [];
      setInterfaces(ifaces);
      if (ifaces.length > 0 && !selectedIface) {
        setSelectedIface(ifaces[0].name);
      }
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const startCapture = async () => {
    if (!selectedIface) return;
    setCapturing(true);
    setError("");
    // 清空数据
    setStats({ total_packets: 0, total_bytes: 0, pps: 0, bps: 0 });
    setProtocolDist([]);
    setTopSessions([]);
    setTopPorts([]);
    setDnsRecords([]);
    setHttpRecords([]);
    setArpTable([]);
    setArpSpoofResult(null);
    setPacketList([]);

    try {
      await invoke("packet_start_capture", {
        iface: selectedIface,
        filter: filter.trim(),
        count: parseInt(count) || 1000,
        durationSec: parseInt(duration) || 60,
      });
      // 启动定时刷新
      statsTimerRef.current = setInterval(refreshStats, 1000);
    } catch (e) {
      setCapturing(false);
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const stopCapture = async () => {
    try {
      await invoke("packet_stop_capture");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setCapturing(false);
      if (statsTimerRef.current) {
        clearInterval(statsTimerRef.current);
        statsTimerRef.current = null;
      }
      // 停止后再拉取一次完整数据
      refreshStats();
    }
  };

  const refreshStats = async () => {
    try {
      const res = await invoke("packet_get_stats");
      if (res) {
        setStats({
          total_packets: res.total_packets || 0,
          total_bytes: res.total_bytes || 0,
          pps: res.pps || 0,
          bps: res.bps || 0,
        });
        if (res.protocols) setProtocolDist(res.protocols);
        if (res.top_sessions) setTopSessions(res.top_sessions);
        if (res.top_ports) setTopPorts(res.top_ports);
        if (res.packets) setPacketList(res.packets);
      }
    } catch (e) {
      // 静默忽略定时刷新错误
    }
  };

  const loadDns = async () => {
    try {
      const res = await invoke("packet_get_dns");
      setDnsRecords(res?.records || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const loadHttp = async () => {
    try {
      const res = await invoke("packet_get_http");
      setHttpRecords(res?.records || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const loadArpTable = async () => {
    try {
      const res = await invoke("packet_get_arp_table");
      setArpTable(res?.entries || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const detectArpSpoof = async () => {
    try {
      const res = await invoke("packet_detect_arp_spoof");
      setArpSpoofResult(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    if (tab === "dns" && dnsRecords.length === 0) loadDns();
    else if (tab === "http" && httpRecords.length === 0) loadHttp();
    else if (tab === "arp" && arpTable.length === 0) loadArpTable();
  };

  const formatBytes = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const formatBps = (bps) => {
    if (bps < 1000) return `${bps} bps`;
    if (bps < 1000 * 1000) return `${(bps / 1000).toFixed(1)} Kbps`;
    if (bps < 1000 * 1000 * 1000) return `${(bps / (1000 * 1000)).toFixed(1)} Mbps`;
    return `${(bps / (1000 * 1000 * 1000)).toFixed(2)} Gbps`;
  };

  const tabs = [
    { key: "protocol", label: t("packetCapture.tabProtocol") },
    { key: "traffic", label: t("packetCapture.tabTraffic") },
    { key: "dns", label: t("packetCapture.tabDns") },
    { key: "http", label: t("packetCapture.tabHttp") },
    { key: "arp", label: t("packetCapture.tabArp") },
    { key: "packets", label: t("packetCapture.tabPackets") },
  ];

  const protoColors = {
    TCP: "bg-blue-500",
    UDP: "bg-emerald-500",
    ICMP: "bg-amber-500",
    ARP: "bg-purple-500",
    Other: "bg-neutral-400",
  };

  return (
    <div className="flex h-full flex-col">
      {/* 标题栏 */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M3 12h4l3-9 4 18 3-9h4" />
          </svg>
          <h3 className="text-base font-semibold">{t("packetCapture.title")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* 顶部控制栏 */}
      <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="sm:col-span-1">
          <label className="mb-1 block text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
            {t("packetCapture.interface")}
          </label>
          <select
            className="field w-full text-xs"
            value={selectedIface}
            onChange={(e) => setSelectedIface(e.target.value)}
            disabled={capturing}
          >
            {interfaces.map((iface) => (
              <option key={iface.name} value={iface.name}>
                {iface.name} {iface.description ? `(${iface.description})` : ""}
              </option>
            ))}
          </select>
        </div>
        <div className="col-span-2 sm:col-span-1">
          <label className="mb-1 block text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
            {t("packetCapture.filter")}
          </label>
          <input
            className="field w-full font-mono text-xs"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="tcp port 80"
            disabled={capturing}
          />
        </div>
        <div>
          <label className="mb-1 block text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
            {t("packetCapture.count")}
          </label>
          <input
            className="field w-full font-mono text-xs"
            value={count}
            onChange={(e) => setCount(e.target.value)}
            inputMode="numeric"
            disabled={capturing}
          />
        </div>
        <div>
          <label className="mb-1 block text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
            {t("packetCapture.duration")}
          </label>
          <input
            className="field w-full font-mono text-xs"
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            inputMode="numeric"
            disabled={capturing}
          />
        </div>
      </div>

      {/* 开始/停止按钮 */}
      <div className="mb-3 flex gap-2">
        {!capturing ? (
          <button
            onClick={startCapture}
            disabled={!selectedIface}
            className="pill pill-hover flex-1 justify-center"
          >
            <IconPlay size={14} />
            {t("packetCapture.startCapture")}
          </button>
        ) : (
          <button
            onClick={stopCapture}
            className="pill pill-hover flex-1 justify-center bg-red-500/10 text-red-600 dark:text-red-400"
          >
            <IconPause size={14} />
            {t("packetCapture.stopCapture")}
          </button>
        )}
        <button onClick={loadInterfaces} disabled={capturing} className="pill pill-outline pill-hover">
          <IconRefresh size={14} />
        </button>
      </div>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 统计面板 */}
      <div className="mb-3 grid grid-cols-4 gap-2">
        <div className="rounded-xl border border-neutral-200 bg-white p-2 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="text-lg font-semibold font-mono">{stats.total_packets.toLocaleString()}</div>
          <div className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("packetCapture.totalPackets")}</div>
        </div>
        <div className="rounded-xl border border-neutral-200 bg-white p-2 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="text-lg font-semibold font-mono">{formatBytes(stats.total_bytes)}</div>
          <div className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("packetCapture.totalBytes")}</div>
        </div>
        <div className="rounded-xl border border-neutral-200 bg-white p-2 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="text-lg font-semibold font-mono">{stats.pps.toLocaleString()}</div>
          <div className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("packetCapture.pps")}</div>
        </div>
        <div className="rounded-xl border border-neutral-200 bg-white p-2 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="text-lg font-semibold font-mono">{formatBps(stats.bps)}</div>
          <div className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("packetCapture.bps")}</div>
        </div>
      </div>

      {/* Tab 切换 */}
      <div className="mb-2 flex gap-1 overflow-x-auto rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => handleTabChange(tab.key)}
            className={`whitespace-nowrap rounded-full px-2.5 py-1 text-[11px] font-medium transition-colors ${
              activeTab === tab.key
                ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 结果区域 */}
      <div className="flex-1 overflow-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
        {/* 协议分布 */}
        {activeTab === "protocol" && (
          <div className="p-3">
            {protocolDist.length > 0 ? (
              <div className="space-y-3">
                {/* 条形图 */}
                <div className="space-y-2">
                  {protocolDist.map((p, i) => (
                    <div key={i}>
                      <div className="mb-1 flex justify-between text-[11px]">
                        <span className="font-medium">{p.name}</span>
                        <span className="font-mono text-neutral-500 dark:text-neutral-400">
                          {p.count} ({p.percent.toFixed(1)}%)
                        </span>
                      </div>
                      <div className="h-2 w-full overflow-hidden rounded-full bg-neutral-100 dark:bg-neutral-800">
                        <div
                          className={`h-full rounded-full ${protoColors[p.name] || "bg-neutral-400"}`}
                          style={{ width: `${p.percent}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
                {/* 饼图（简化版：彩色圆环） */}
                <div className="flex justify-center py-4">
                  <div className="relative h-32 w-32">
                    <svg viewBox="0 0 36 36" className="h-full w-full -rotate-90">
                      {(() => {
                        let offset = 0;
                        return protocolDist.map((p, i) => {
                          const dash = (p.percent / 100) * 251.2; // 2 * PI * 40 (r=40/2*scale)
                          const el = (
                            <circle
                              key={i}
                              cx="18"
                              cy="18"
                              r="15.9155"
                              fill="transparent"
                              stroke="currentColor"
                              strokeWidth="3"
                              strokeDasharray={`${dash} ${251.2 - dash}`}
                              strokeDashoffset={-offset}
                              className={
                                p.name === "TCP" ? "text-blue-500" :
                                p.name === "UDP" ? "text-emerald-500" :
                                p.name === "ICMP" ? "text-amber-500" :
                                p.name === "ARP" ? "text-purple-500" : "text-neutral-400"
                              }
                            />
                          );
                          offset += dash;
                          return el;
                        });
                      })()}
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <div className="text-xl font-semibold">{stats.total_packets.toLocaleString()}</div>
                      <div className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("packetCapture.totalPackets")}</div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {capturing ? t("packetCapture.capturing") : t("netsec.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 流量统计 */}
        {activeTab === "traffic" && (
          <div className="divide-y divide-neutral-100 dark:divide-neutral-800">
            <div className="p-3">
              <h4 className="mb-2 text-xs font-semibold text-neutral-700 dark:text-neutral-300">
                {t("packetCapture.topSessions")}
              </h4>
              {topSessions.length > 0 ? (
                <div className="space-y-1">
                  {topSessions.map((s, i) => (
                    <div key={i} className="flex items-center justify-between rounded-lg px-2 py-1.5 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                      <div className="flex-1 font-mono text-[11px]">
                        <span className="text-neutral-700 dark:text-neutral-300">{s.src}</span>
                        <span className="mx-1 text-neutral-400">→</span>
                        <span className="text-neutral-700 dark:text-neutral-300">{s.dst}</span>
                      </div>
                      <span className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400">
                        {formatBytes(s.bytes)}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-4 text-center text-xs text-neutral-400">{t("netsec.noResult")}</div>
              )}
            </div>
            <div className="p-3">
              <h4 className="mb-2 text-xs font-semibold text-neutral-700 dark:text-neutral-300">
                {t("packetCapture.topPorts")}
              </h4>
              {topPorts.length > 0 ? (
                <div className="grid grid-cols-2 gap-1">
                  {topPorts.map((p, i) => (
                    <div key={i} className="flex items-center justify-between rounded-lg px-2 py-1.5 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                      <span className="font-mono text-[11px] text-neutral-700 dark:text-neutral-300">: {p.port}</span>
                      <span className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400">{p.count}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-4 text-center text-xs text-neutral-400">{t("netsec.noResult")}</div>
              )}
            </div>
          </div>
        )}

        {/* DNS 查询 */}
        {activeTab === "dns" && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
              <tr>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.time")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.domain")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.queryType")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.result")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.rtt")}</th>
              </tr>
            </thead>
            <tbody>
              {dnsRecords.length > 0 ? (
                dnsRecords.map((r, i) => (
                  <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                    <td className="px-3 py-2 font-mono text-[10px] text-neutral-500 dark:text-neutral-400">{r.time}</td>
                    <td className="px-3 py-2 font-mono break-all">{r.domain}</td>
                    <td className="px-3 py-2">
                      <span className="chip font-mono text-[10px]">{r.type}</span>
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] break-all">{r.result || "-"}</td>
                    <td className="px-3 py-2 font-mono text-[10px] text-neutral-500 dark:text-neutral-400">{r.rtt || "-"}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-neutral-400">
                    {capturing ? t("packetCapture.capturing") : t("netsec.noResult")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}

        {/* HTTP 流量 */}
        {activeTab === "http" && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
              <tr>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.method")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">URL</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">Host</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.statusCode")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">User-Agent</th>
              </tr>
            </thead>
            <tbody>
              {httpRecords.length > 0 ? (
                httpRecords.map((r, i) => (
                  <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                    <td className="px-3 py-2">
                      <span className="chip font-mono text-[10px]">{r.method}</span>
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] break-all">{r.url}</td>
                    <td className="px-3 py-2 font-mono text-[11px]">{r.host}</td>
                    <td className="px-3 py-2 font-mono text-[11px]">
                      <span className={r.status && r.status >= 400 ? "text-red-500" : r.status && r.status >= 300 ? "text-amber-500" : "text-emerald-500"}>
                        {r.status || "-"}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-[11px] text-neutral-500 dark:text-neutral-400 truncate max-w-[120px]">{r.ua || "-"}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-neutral-400">
                    {capturing ? t("packetCapture.capturing") : t("netsec.noResult")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}

        {/* ARP 监控 */}
        {activeTab === "arp" && (
          <div className="p-3">
            <div className="mb-3 flex gap-2">
              <button onClick={loadArpTable} className="pill pill-outline pill-hover text-[11px]">
                <IconRefresh size={12} />
                {t("packetCapture.refreshArp")}
              </button>
              <button onClick={detectArpSpoof} className="pill pill-hover text-[11px]">
                {t("packetCapture.detectArpSpoof")}
              </button>
            </div>

            {arpSpoofResult && (
              <div className={`mb-3 rounded-xl p-2 text-xs ${
                arpSpoofResult.detected
                  ? "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400"
                  : "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
              }`}>
                {arpSpoofResult.detected ? t("packetCapture.arpSpoofDetected") : t("packetCapture.arpSpoofSafe")}
                {arpSpoofResult.details && (
                  <div className="mt-1 font-mono text-[10px] opacity-80">{arpSpoofResult.details}</div>
                )}
              </div>
            )}

            <table className="w-full text-left text-xs">
              <thead className="bg-neutral-50 dark:bg-neutral-900">
                <tr>
                  <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">IP</th>
                  <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">MAC</th>
                  <th className="px-2 py-1.5 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.vendor")}</th>
                </tr>
              </thead>
              <tbody>
                {arpTable.length > 0 ? (
                  arpTable.map((entry, i) => (
                    <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                      <td className="px-2 py-1.5 font-mono text-[11px]">{entry.ip}</td>
                      <td className="px-2 py-1.5 font-mono text-[11px]">{entry.mac}</td>
                      <td className="px-2 py-1.5 text-[11px] text-neutral-500 dark:text-neutral-400">{entry.vendor || "-"}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={3} className="px-2 py-8 text-center text-neutral-400">
                      {t("netsec.noResult")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* 数据包列表 */}
        {activeTab === "packets" && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
              <tr>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400 w-20">{t("packetCapture.time")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.source")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.dest")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400 w-16">{t("netsec.protocol")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400 w-14">{t("packetCapture.length")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("packetCapture.info")}</th>
              </tr>
            </thead>
            <tbody>
              {packetList.length > 0 ? (
                packetList.map((p, i) => (
                  <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                    <td className="px-3 py-1.5 font-mono text-[10px] text-neutral-500 dark:text-neutral-400">{p.time}</td>
                    <td className="px-3 py-1.5 font-mono text-[11px]">{p.src}</td>
                    <td className="px-3 py-1.5 font-mono text-[11px]">{p.dst}</td>
                    <td className="px-3 py-1.5">
                      <span className="chip font-mono text-[10px]">{p.proto}</span>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[11px] text-neutral-500 dark:text-neutral-400">{p.len}</td>
                    <td className="px-3 py-1.5 text-[11px] text-neutral-600 dark:text-neutral-400 truncate max-w-[200px]">{p.info}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-neutral-400">
                    {capturing ? t("packetCapture.capturing") : t("netsec.noResult")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
