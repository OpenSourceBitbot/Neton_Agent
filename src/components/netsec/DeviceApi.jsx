import { useState, useMemo, useCallback } from "react";
import { api } from "../../api.js";
import { useLang } from "../../i18n.js";
import {
  IconPlay,
  IconServer,
  IconPlus,
  IconTrash,
  IconCopy,
  IconChevronDown,
  IconChevronRight,
  IconBolt,
  IconSend,
  IconX,
} from "../Icons.jsx";

// ───────────────────────────────────────────
// 工具函数
// ───────────────────────────────────────────

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

const METHOD_COLORS = {
  GET: "text-emerald-600 dark:text-emerald-400",
  POST: "text-blue-600 dark:text-blue-400",
  PUT: "text-amber-600 dark:text-amber-400",
  DELETE: "text-red-600 dark:text-red-400",
  PATCH: "text-purple-600 dark:text-purple-400",
  HEAD: "text-neutral-600 dark:text-neutral-400",
  OPTIONS: "text-cyan-600 dark:text-cyan-400",
};

const METHOD_BG = {
  GET: "bg-emerald-50 dark:bg-emerald-900/30",
  POST: "bg-blue-50 dark:bg-blue-900/30",
  PUT: "bg-amber-50 dark:bg-amber-900/30",
  DELETE: "bg-red-50 dark:bg-red-900/30",
  PATCH: "bg-purple-50 dark:bg-purple-900/30",
  HEAD: "bg-neutral-100 dark:bg-neutral-800",
  OPTIONS: "bg-cyan-50 dark:bg-cyan-900/30",
};

function getStatusColor(code) {
  if (!code) return "text-neutral-500";
  const c = Number(code);
  if (c >= 200 && c < 300) return "text-emerald-600 dark:text-emerald-400";
  if (c >= 300 && c < 400) return "text-blue-600 dark:text-blue-400";
  if (c >= 400 && c < 500) return "text-amber-600 dark:text-amber-400";
  if (c >= 500) return "text-red-600 dark:text-red-400";
  return "text-neutral-500";
}

function formatSize(bytes) {
  if (!bytes && bytes !== 0) return "-";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(ms) {
  if (!ms && ms !== 0) return "-";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

// 简易 JSON 格式化
function formatJson(text) {
  try {
    const obj = JSON.parse(text);
    return JSON.stringify(obj, null, 2);
  } catch {
    return text;
  }
}

// JSON 语法高亮（简易版）
function highlightJson(text) {
  try {
    JSON.parse(text);
  } catch {
    return text;
  }
  let html = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  // 字符串（键或值）
  html = html.replace(/"(\\u[a-fA-F\d]{4}|\\[^u]|[^\\"])*"(\s*:)?/g, (m) => {
    const isKey = /:$/.test(m);
    if (isKey) {
      return `<span class="text-rose-500 dark:text-rose-400">${m.slice(0, -1)}</span>:`;
    }
    return `<span class="text-emerald-600 dark:text-emerald-400">${m}</span>`;
  });
  // 数字
  html = html.replace(/\b(true|false|null)\b/g, '<span class="text-blue-500 dark:text-blue-400">$1</span>');
  html = html.replace(/\b(-?\d+\.?\d*(?:[eE][+-]?\d+)?)\b/g, '<span class="text-amber-600 dark:text-amber-400">$1</span>');
  return html;
}

// 键值对表格组件
function KVTable({ rows, onChange, placeholderKey, placeholderValue, t, onAdd, onDelete }) {
  const updateRow = (idx, field, val) => {
    const next = [...rows];
    next[idx] = { ...next[idx], [field]: val };
    onChange(next);
  };

  const addRow = () => {
    onChange([...rows, { key: "", value: "", enabled: true }]);
  };

  const deleteRow = (idx) => {
    const next = rows.filter((_, i) => i !== idx);
    onChange(next);
  };

  const toggleRow = (idx) => {
    const next = [...rows];
    next[idx] = { ...next[idx], enabled: !next[idx].enabled };
    onChange(next);
  };

  return (
    <div className="space-y-1">
      <div className="grid grid-cols-[24px_1fr_1fr_28px] gap-1 px-1 text-[10px] font-medium text-neutral-500 dark:text-neutral-400">
        <span />
        <span>{t("deviceApi.key")}</span>
        <span>{t("deviceApi.value")}</span>
        <span />
      </div>
      <div className="max-h-48 overflow-auto space-y-1">
        {rows.map((row, idx) => (
          <div key={idx} className="grid grid-cols-[24px_1fr_1fr_28px] gap-1 items-center">
            <input
              type="checkbox"
              checked={row.enabled !== false}
              onChange={() => toggleRow(idx)}
              className="h-3.5 w-3.5"
            />
            <input
              className="field text-xs font-mono h-7"
              value={row.key}
              onChange={(e) => updateRow(idx, "key", e.target.value)}
              placeholder={placeholderKey || "key"}
            />
            <input
              className="field text-xs font-mono h-7"
              value={row.value}
              onChange={(e) => updateRow(idx, "value", e.target.value)}
              placeholder={placeholderValue || "value"}
            />
            <button
              onClick={() => deleteRow(idx)}
              className="flex h-7 w-7 items-center justify-center rounded text-neutral-400 hover:bg-red-50 hover:text-red-500 dark:hover:bg-red-900/30"
              title={t("deviceApi.deleteRow")}
            >
              <IconTrash size={12} />
            </button>
          </div>
        ))}
      </div>
      <button
        onClick={addRow}
        className="flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
      >
        <IconPlus size={12} />
        {t("deviceApi.addRow")}
      </button>
    </div>
  );
}

// ───────────────────────────────────────────
// 预设设备模板数据
// ───────────────────────────────────────────

const DEVICE_TEMPLATES = [
  {
    category: "camera",
    nameKey: "deviceApi.camera",
    endpoints: [
      { method: "GET", url: "/ISAPI/System/deviceInfo", desc: "设备信息" },
      { method: "GET", url: "/ISAPI/System/status", desc: "系统状态" },
      { method: "POST", url: "/ISAPI/System/reboot", desc: "设备重启" },
      { method: "GET", url: "/ISAPI/Streaming/channels", desc: "视频通道" },
    ],
  },
  {
    category: "router",
    nameKey: "deviceApi.router",
    endpoints: [
      { method: "GET", url: "/api/system/info", desc: "系统信息" },
      { method: "GET", url: "/api/interface/list", desc: "接口列表" },
      { method: "POST", url: "/api/system/reboot", desc: "重启设备" },
      { method: "GET", url: "/api/dhcp/leases", desc: "DHCP 租约" },
    ],
  },
  {
    category: "plc",
    nameKey: "deviceApi.plc",
    endpoints: [
      { method: "GET", url: "/api/plc/info", desc: "PLC 信息" },
      { method: "GET", url: "/api/plc/registers?addr=0&count=10", desc: "读寄存器" },
      { method: "POST", url: "/api/plc/registers", desc: "写寄存器" },
      { method: "GET", url: "/api/plc/status", desc: "运行状态" },
    ],
  },
  {
    category: "iot",
    nameKey: "deviceApi.iot",
    endpoints: [
      { method: "GET", url: "/api/v1/device/status", desc: "设备状态" },
      { method: "POST", url: "/api/v1/device/command", desc: "发送指令" },
      { method: "GET", url: "/api/v1/telemetry", desc: "遥测数据" },
      { method: "PUT", url: "/api/v1/device/config", desc: "配置更新" },
    ],
  },
];

// ───────────────────────────────────────────
// 主组件
// ───────────────────────────────────────────

export default function DeviceApi({ onClose }) {
  const { t } = useLang();

  // 左侧边栏 Tab
  const [sidebarTab, setSidebarTab] = useState("history"); // history | templates
  const [expandedCategories, setExpandedCategories] = useState({ camera: true });

  // 协议 Tab
  const [protocol, setProtocol] = useState("http"); // http | modbus | mqtt | snmp

  // ── HTTP 请求状态 ──
  const [httpMethod, setHttpMethod] = useState("GET");
  const [httpUrl, setHttpUrl] = useState("");
  const [httpParams, setHttpParams] = useState([{ key: "", value: "", enabled: true }]);
  const [httpHeaders, setHttpHeaders] = useState([{ key: "Content-Type", value: "application/json", enabled: true }]);
  const [httpBodyType, setHttpBodyType] = useState("none"); // none | form-data | x-www-form-urlencoded | raw | binary
  const [httpRawType, setHttpRawType] = useState("json"); // json | xml | text
  const [httpBodyRaw, setHttpBodyRaw] = useState("");
  const [httpBodyForm, setHttpBodyForm] = useState([{ key: "", value: "", enabled: true }]);
  const [httpTimeout, setHttpTimeout] = useState("30000");

  // HTTP body Tab
  const [httpBodyTab, setHttpBodyTab] = useState("form-data");

  // ── Modbus 状态 ──
  const [modbusHost, setModbusHost] = useState("");
  const [modbusPort, setModbusPort] = useState("502");
  const [modbusSlaveId, setModbusSlaveId] = useState("1");
  const [modbusFunc, setModbusFunc] = useState("read_holding");
  const [modbusAddress, setModbusAddress] = useState("0");
  const [modbusCount, setModbusCount] = useState("10");
  const [modbusValue, setModbusValue] = useState("0");

  // ── MQTT 状态 ──
  const [mqttBroker, setMqttBroker] = useState("");
  const [mqttPort, setMqttPort] = useState("1883");
  const [mqttClientId, setMqttClientId] = useState("");
  const [mqttUsername, setMqttUsername] = useState("");
  const [mqttPassword, setMqttPassword] = useState("");
  const [mqttTopic, setMqttTopic] = useState("");
  const [mqttPayload, setMqttPayload] = useState("");
  const [mqttQos, setMqttQos] = useState("0");

  // ── SNMP 状态 ──
  const [snmpHost, setSnmpHost] = useState("");
  const [snmpCommunity, setSnmpCommunity] = useState("public");
  const [snmpOid, setSnmpOid] = useState("1.3.6.1.2.1.1.1.0");
  const [snmpVersion, setSnmpVersion] = useState("v2c");

  // ── 响应状态 ──
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState(null);
  const [responseTab, setResponseTab] = useState("body"); // body | headers | cookies | stress
  const [responseBodyFormatted, setResponseBodyFormatted] = useState(false);

  // ── 历史记录 ──
  const [history, setHistory] = useState([]);

  // ── 压力测试 ──
  const [showStressPanel, setShowStressPanel] = useState(false);
  const [stressConcurrent, setStressConcurrent] = useState("10");
  const [stressDuration, setStressDuration] = useState("10");
  const [stressRunning, setStressRunning] = useState(false);
  const [stressResult, setStressResult] = useState(null);

  // ───────────────────────────────────────────
  // 历史记录管理
  // ───────────────────────────────────────────

  const addHistory = useCallback((item) => {
    setHistory((prev) => {
      const filtered = prev.filter(
        (h) => !(h.method === item.method && h.url === item.url && h.protocol === item.protocol)
      );
      return [item, ...filtered].slice(0, 20);
    });
  }, []);

  const restoreHistory = (item) => {
    if (item.protocol === "http") {
      setProtocol("http");
      setHttpMethod(item.method);
      setHttpUrl(item.url);
      if (item.params) setHttpParams(item.params);
      if (item.headers) setHttpHeaders(item.headers);
      if (item.bodyType) setHttpBodyType(item.bodyType);
      if (item.bodyRaw !== undefined) setHttpBodyRaw(item.bodyRaw);
      if (item.bodyForm) setHttpBodyForm(item.bodyForm);
    } else if (item.protocol === "modbus") {
      setProtocol("modbus");
      setModbusHost(item.host);
      setModbusPort(String(item.port));
      setModbusSlaveId(String(item.slaveId));
      setModbusFunc(item.func);
      setModbusAddress(String(item.address));
      if (item.count !== undefined) setModbusCount(String(item.count));
      if (item.value !== undefined) setModbusValue(String(item.value));
    } else if (item.protocol === "mqtt") {
      setProtocol("mqtt");
      setMqttBroker(item.broker);
      setMqttPort(String(item.port));
      setMqttTopic(item.topic);
      setMqttPayload(item.payload || "");
    } else if (item.protocol === "snmp") {
      setProtocol("snmp");
      setSnmpHost(item.host);
      setSnmpCommunity(item.community);
      setSnmpOid(item.oid);
      setSnmpVersion(item.version || "v2c");
    }
  };

  // ───────────────────────────────────────────
  // 发送请求
  // ───────────────────────────────────────────

  const sendRequest = async () => {
    setLoading(true);
    setResponse(null);
    setResponseBodyFormatted(false);
    setStressResult(null);

    try {
      if (protocol === "http") {
        const params = {};
        httpParams.forEach((p) => {
          if (p.enabled && p.key) params[p.key] = p.value;
        });
        const headers = {};
        httpHeaders.forEach((h) => {
          if (h.enabled && h.key) headers[h.key] = h.value;
        });

        let body = "";
        if (httpBodyType === "raw") {
          body = httpBodyRaw;
        } else if (httpBodyType === "form-data" || httpBodyType === "x-www-form-urlencoded") {
          const form = {};
          httpBodyForm.forEach((f) => {
            if (f.enabled && f.key) form[f.key] = f.value;
          });
          body = JSON.stringify(form);
        }

        const res = await api.deviceHttpRequest(
          httpMethod,
          httpUrl,
          headers,
          body,
          httpBodyType,
          params,
          parseInt(httpTimeout) || 30000
        );

        setResponse(res);
        addHistory({
          protocol: "http",
          method: httpMethod,
          url: httpUrl,
          params: httpParams,
          headers: httpHeaders,
          bodyType: httpBodyType,
          bodyRaw: httpBodyRaw,
          bodyForm: httpBodyForm,
          timestamp: Date.now(),
        });
      } else if (protocol === "modbus") {
        const isWrite = modbusFunc === "write_holding" || modbusFunc === "write_coil";
        let res;
        if (isWrite) {
          res = await api.deviceModbusWrite(
            modbusHost,
            parseInt(modbusPort),
            parseInt(modbusSlaveId),
            parseInt(modbusAddress),
            parseInt(modbusValue)
          );
        } else {
          res = await api.deviceModbusRead(
            modbusHost,
            parseInt(modbusPort),
            parseInt(modbusSlaveId),
            modbusFunc,
            parseInt(modbusAddress),
            parseInt(modbusCount)
          );
        }
        setResponse({ status: 200, statusText: "OK", body: JSON.stringify(res, null, 2), headers: {}, time_ms: 0, size: 0 });
        addHistory({
          protocol: "modbus",
          method: isWrite ? "WRITE" : "READ",
          url: `${modbusHost}:${modbusPort}/${modbusFunc}`,
          host: modbusHost,
          port: parseInt(modbusPort),
          slaveId: parseInt(modbusSlaveId),
          func: modbusFunc,
          address: parseInt(modbusAddress),
          count: parseInt(modbusCount),
          value: parseInt(modbusValue),
          timestamp: Date.now(),
        });
      } else if (protocol === "mqtt") {
        const res = await api.deviceMqttPublish(
          mqttBroker,
          parseInt(mqttPort),
          mqttClientId,
          mqttUsername,
          mqttPassword,
          mqttTopic,
          mqttPayload,
          parseInt(mqttQos)
        );
        setResponse({ status: 200, statusText: "OK", body: JSON.stringify(res, null, 2), headers: {}, time_ms: 0, size: 0 });
        addHistory({
          protocol: "mqtt",
          method: "PUB",
          url: `${mqttBroker}:${mqttPort}/${mqttTopic}`,
          broker: mqttBroker,
          port: parseInt(mqttPort),
          topic: mqttTopic,
          payload: mqttPayload,
          timestamp: Date.now(),
        });
      } else if (protocol === "snmp") {
        const res = await api.deviceSnmpGet(snmpHost, snmpCommunity, snmpOid, snmpVersion);
        setResponse({ status: 200, statusText: "OK", body: JSON.stringify(res, null, 2), headers: {}, time_ms: 0, size: 0 });
        addHistory({
          protocol: "snmp",
          method: "GET",
          url: `${snmpHost}/${snmpOid}`,
          host: snmpHost,
          community: snmpCommunity,
          oid: snmpOid,
          version: snmpVersion,
          timestamp: Date.now(),
        });
      }
    } catch (e) {
      setResponse({
        status: 0,
        statusText: "Error",
        body: typeof e === "string" ? e : String(e?.message || e),
        headers: {},
        time_ms: 0,
        size: 0,
      });
    } finally {
      setLoading(false);
    }
  };

  // ───────────────────────────────────────────
  // SNMP WALK
  // ───────────────────────────────────────────

  const snmpWalk = async () => {
    setLoading(true);
    setResponse(null);
    try {
      const res = await api.deviceSnmpWalk(snmpHost, snmpCommunity, snmpOid, snmpVersion);
      setResponse({ status: 200, statusText: "OK", body: JSON.stringify(res, null, 2), headers: {}, time_ms: 0, size: 0 });
      addHistory({
        protocol: "snmp",
        method: "WALK",
        url: `${snmpHost}/${snmpOid}`,
        host: snmpHost,
        community: snmpCommunity,
        oid: snmpOid,
        version: snmpVersion,
        timestamp: Date.now(),
      });
    } catch (e) {
      setResponse({
        status: 0,
        statusText: "Error",
        body: typeof e === "string" ? e : String(e?.message || e),
        headers: {},
        time_ms: 0,
        size: 0,
      });
    } finally {
      setLoading(false);
    }
  };

  // ───────────────────────────────────────────
  // MQTT 订阅
  // ───────────────────────────────────────────

  const mqttSubscribe = async () => {
    setLoading(true);
    setResponse(null);
    try {
      const res = await api.deviceMqttSubscribe(
        mqttBroker,
        parseInt(mqttPort),
        mqttClientId,
        mqttUsername,
        mqttPassword,
        mqttTopic,
        10000
      );
      setResponse({ status: 200, statusText: "OK", body: JSON.stringify(res, null, 2), headers: {}, time_ms: 0, size: 0 });
    } catch (e) {
      setResponse({
        status: 0,
        statusText: "Error",
        body: typeof e === "string" ? e : String(e?.message || e),
        headers: {},
        time_ms: 0,
        size: 0,
      });
    } finally {
      setLoading(false);
    }
  };

  // ───────────────────────────────────────────
  // 压力测试
  // ───────────────────────────────────────────

  const runStressTest = async () => {
    if (protocol !== "http" || !httpUrl) return;
    setStressRunning(true);
    setStressResult(null);
    setResponseTab("stress");

    try {
      const headers = {};
      httpHeaders.forEach((h) => {
        if (h.enabled && h.key) headers[h.key] = h.value;
      });

      const res = await api.deviceStressTest(
        httpUrl,
        httpMethod,
        parseInt(stressConcurrent),
        parseInt(stressDuration),
        headers,
        httpBodyRaw
      );
      setStressResult(res);
    } catch (e) {
      setStressResult({
        error: typeof e === "string" ? e : String(e?.message || e),
      });
    } finally {
      setStressRunning(false);
    }
  };

  // ───────────────────────────────────────────
  // 模板应用
  // ───────────────────────────────────────────

  const applyTemplate = (endpoint) => {
    setProtocol("http");
    setHttpMethod(endpoint.method);
    const baseUrl = httpUrl.replace(/\/$/, "");
    setHttpUrl(baseUrl + endpoint.url);
  };

  const toggleCategory = (cat) => {
    setExpandedCategories((prev) => ({ ...prev, [cat]: !prev[cat] }));
  };

  // ───────────────────────────────────────────
  // 复制响应
  // ───────────────────────────────────────────

  const [copied, setCopied] = useState(false);
  const copyResponseBody = () => {
    if (!response?.body) return;
    navigator.clipboard?.writeText(response.body);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const toggleFormatJson = () => {
    if (!response?.body) return;
    if (responseBodyFormatted) {
      setResponseBodyFormatted(false);
    } else {
      setResponseBodyFormatted(true);
    }
  };

  const displayBody = useMemo(() => {
    if (!response?.body) return "";
    if (responseBodyFormatted) {
      return formatJson(response.body);
    }
    return response.body;
  }, [response?.body, responseBodyFormatted]);

  const isModbusWrite = modbusFunc === "write_holding" || modbusFunc === "write_coil";

  // ───────────────────────────────────────────
  // 渲染
  // ───────────────────────────────────────────

  return (
    <div className="flex h-full flex-col">
      {/* 头部 */}
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconServer size={20} />
          <h3 className="text-base font-semibold">{t("deviceApi.deviceApi")}</h3>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowStressPanel(true)}
            className="pill pill-hover text-xs"
            title={t("deviceApi.stressTest")}
          >
            <IconBolt size={14} />
            {t("deviceApi.stressTest")}
          </button>
          <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
            <IconX size={18} />
          </button>
        </div>
      </div>

      {/* 主体布局 */}
      <div className="flex flex-1 gap-3 overflow-hidden">
        {/* ── 左侧边栏 ── */}
        <div className="flex w-[280px] shrink-0 flex-col overflow-hidden rounded-2xl border border-neutral-200 dark:border-neutral-800">
          {/* Tab 切换 */}
          <div className="flex gap-1 border-b border-neutral-200 p-1 dark:border-neutral-800">
            <button
              onClick={() => setSidebarTab("history")}
              className={`flex-1 rounded-full px-2 py-1 text-xs font-medium transition-colors ${
                sidebarTab === "history"
                  ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                  : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
              }`}
            >
              {t("deviceApi.history")}
            </button>
            <button
              onClick={() => setSidebarTab("templates")}
              className={`flex-1 rounded-full px-2 py-1 text-xs font-medium transition-colors ${
                sidebarTab === "templates"
                  ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                  : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
              }`}
            >
              {t("deviceApi.templates")}
            </button>
          </div>

          <div className="flex-1 overflow-auto p-2">
            {/* 历史记录 */}
            {sidebarTab === "history" && (
              <div className="space-y-1">
                {history.length === 0 ? (
                  <p className="py-8 text-center text-xs text-neutral-400">{t("deviceApi.noHistory")}</p>
                ) : (
                  history.map((h, i) => (
                    <button
                      key={i}
                      onClick={() => restoreHistory(h)}
                      className="w-full rounded-lg p-2 text-left hover:bg-neutral-50 dark:hover:bg-neutral-800/50"
                    >
                      <div className="flex items-center gap-2">
                        <span className={`chip text-[10px] font-bold ${METHOD_BG[h.method] || "bg-neutral-100 dark:bg-neutral-800"} ${METHOD_COLORS[h.method] || "text-neutral-600 dark:text-neutral-400"}`}>
                          {h.method}
                        </span>
                        <span className="flex-1 truncate font-mono text-[11px] text-neutral-700 dark:text-neutral-300">
                          {h.url}
                        </span>
                      </div>
                    </button>
                  ))
                )}
              </div>
            )}

            {/* 设备模板 */}
            {sidebarTab === "templates" && (
              <div className="space-y-1">
                {DEVICE_TEMPLATES.map((cat) => (
                  <div key={cat.category}>
                    <button
                      onClick={() => toggleCategory(cat.category)}
                      className="flex w-full items-center gap-1 rounded-lg px-2 py-1.5 text-left text-xs font-medium text-neutral-700 hover:bg-neutral-50 dark:text-neutral-300 dark:hover:bg-neutral-800/50"
                    >
                      {expandedCategories[cat.category] ? (
                        <IconChevronDown size={12} />
                      ) : (
                        <IconChevronRight size={12} />
                      )}
                      {t(cat.nameKey)}
                    </button>
                    {expandedCategories[cat.category] && (
                      <div className="ml-3 space-y-0.5 border-l border-neutral-200 pl-2 dark:border-neutral-700">
                        {cat.endpoints.map((ep, i) => (
                          <button
                            key={i}
                            onClick={() => applyTemplate(ep)}
                            className="flex w-full items-center gap-2 rounded-md px-2 py-1 text-left hover:bg-neutral-50 dark:hover:bg-neutral-800/50"
                          >
                            <span className={`text-[9px] font-bold ${METHOD_COLORS[ep.method]}`}>
                              {ep.method}
                            </span>
                            <div className="min-w-0 flex-1">
                              <p className="truncate text-[11px] text-neutral-700 dark:text-neutral-300">
                                {ep.desc}
                              </p>
                              <p className="truncate font-mono text-[10px] text-neutral-400">
                                {ep.url}
                              </p>
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── 右侧主区域 ── */}
        <div className="flex flex-1 flex-col overflow-hidden">
          {/* 请求区域 */}
          <div className="rounded-2xl border border-neutral-200 dark:border-neutral-800">
            {/* 请求行 */}
            <div className="flex items-center gap-2 border-b border-neutral-200 p-2 dark:border-neutral-800">
              <select
                value={httpMethod}
                onChange={(e) => setHttpMethod(e.target.value)}
                className={`field h-8 w-24 font-bold text-xs ${METHOD_COLORS[httpMethod]}`}
                disabled={protocol !== "http"}
              >
                {HTTP_METHODS.map((m) => (
                  <option key={m} value={m} className="text-neutral-900 dark:text-white">
                    {m}
                  </option>
                ))}
              </select>
              <input
                className="field flex-1 font-mono text-xs h-8"
                value={protocol === "http" ? httpUrl : ""}
                onChange={(e) => setHttpUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && protocol === "http" && sendRequest()}
                placeholder="http://192.168.1.1/api/..."
                disabled={protocol !== "http"}
              />
              <button
                onClick={sendRequest}
                disabled={loading}
                className="pill pill-hover h-8"
              >
                {loading ? (
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
                ) : (
                  <IconSend size={14} />
                )}
                {t("deviceApi.send")}
              </button>
            </div>

            {/* 协议 Tab */}
            <div className="flex gap-1 border-b border-neutral-200 px-2 pt-1 dark:border-neutral-800">
              {["http", "modbus", "mqtt", "snmp"].map((p) => (
                <button
                  key={p}
                  onClick={() => setProtocol(p)}
                  className={`px-3 py-1.5 text-xs font-medium border-b-2 transition-colors ${
                    protocol === p
                      ? "border-blue-500 text-blue-600 dark:text-blue-400"
                      : "border-transparent text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
                  }`}
                >
                  {t(`deviceApi.protocol${p.charAt(0).toUpperCase() + p.slice(1)}`)}
                </button>
              ))}
            </div>

            {/* HTTP 面板 */}
            {protocol === "http" && (
              <div className="p-2">
                {/* 子 Tab: Params / Headers / Body */}
                <div className="mb-2 flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
                  {["params", "headers", "body"].map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setHttpBodyTab(tab)}
                      className={`flex-1 rounded-full px-2 py-1 text-xs font-medium transition-colors ${
                        httpBodyTab === tab
                          ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                          : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
                      }`}
                    >
                      {t(`deviceApi.${tab}`)}
                    </button>
                  ))}
                </div>

                {/* Params */}
                {httpBodyTab === "params" && (
                  <KVTable
                    rows={httpParams}
                    onChange={setHttpParams}
                    t={t}
                    placeholderKey="param_key"
                    placeholderValue="param_value"
                  />
                )}

                {/* Headers */}
                {httpBodyTab === "headers" && (
                  <KVTable
                    rows={httpHeaders}
                    onChange={setHttpHeaders}
                    t={t}
                    placeholderKey="Header-Name"
                    placeholderValue="header value"
                  />
                )}

                {/* Body */}
                {httpBodyTab === "body" && (
                  <div className="space-y-2">
                    <div className="flex gap-1 flex-wrap">
                      {["none", "form-data", "x-www-form-urlencoded", "raw", "binary"].map((bt) => (
                        <button
                          key={bt}
                          onClick={() => setHttpBodyType(bt)}
                          className={`chip text-[11px] ${
                            httpBodyType === bt
                              ? "bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400"
                              : ""
                          }`}
                        >
                          {t(`deviceApi.${bt.replace(/-/g, "")}`)}
                        </button>
                      ))}
                    </div>

                    {httpBodyType === "form-data" && (
                      <KVTable
                        rows={httpBodyForm}
                        onChange={setHttpBodyForm}
                        t={t}
                        placeholderKey="field_name"
                        placeholderValue="field_value"
                      />
                    )}

                    {httpBodyType === "x-www-form-urlencoded" && (
                      <KVTable
                        rows={httpBodyForm}
                        onChange={setHttpBodyForm}
                        t={t}
                        placeholderKey="field_name"
                        placeholderValue="field_value"
                      />
                    )}

                    {httpBodyType === "raw" && (
                      <div className="space-y-2">
                        <div className="flex gap-1">
                          {["json", "xml", "text"].map((rt) => (
                            <button
                              key={rt}
                              onClick={() => setHttpRawType(rt)}
                              className={`chip text-[11px] ${
                                httpRawType === rt
                                  ? "bg-emerald-50 text-emerald-600 dark:bg-emerald-900/30 dark:text-emerald-400"
                                  : ""
                              }`}
                            >
                              {t(`deviceApi.${rt}`)}
                            </button>
                          ))}
                        </div>
                        <textarea
                          className="field min-h-[120px] w-full font-mono text-xs"
                          value={httpBodyRaw}
                          onChange={(e) => setHttpBodyRaw(e.target.value)}
                          placeholder={httpRawType === "json" ? '{\n  "key": "value"\n}' : "Request body..."}
                          spellCheck={false}
                        />
                      </div>
                    )}

                    {httpBodyType === "binary" && (
                      <div className="rounded-lg border border-dashed border-neutral-300 p-4 text-center text-xs text-neutral-500 dark:border-neutral-700 dark:text-neutral-400">
                        Binary body upload
                      </div>
                    )}

                    {httpBodyType === "none" && (
                      <p className="py-4 text-center text-xs text-neutral-400">
                        {t("deviceApi.none")}
                      </p>
                    )}
                  </div>
                )}

                {/* 超时设置 */}
                <div className="mt-2 flex items-center gap-2 border-t border-neutral-100 pt-2 dark:border-neutral-800">
                  <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.timeout")}:
                  </span>
                  <input
                    className="field h-6 w-24 text-xs font-mono"
                    value={httpTimeout}
                    onChange={(e) => setHttpTimeout(e.target.value)}
                  />
                </div>
              </div>
            )}

            {/* Modbus 面板 */}
            {protocol === "modbus" && (
              <div className="grid grid-cols-2 gap-2 p-3">
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.host")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={modbusHost}
                    onChange={(e) => setModbusHost(e.target.value)}
                    placeholder="192.168.1.100"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.port")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={modbusPort}
                    onChange={(e) => setModbusPort(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.slaveId")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={modbusSlaveId}
                    onChange={(e) => setModbusSlaveId(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.functionCode")}
                  </label>
                  <select
                    className="field h-8 w-full text-xs"
                    value={modbusFunc}
                    onChange={(e) => setModbusFunc(e.target.value)}
                  >
                    <option value="read_holding">{t("deviceApi.readHoldingReg")}</option>
                    <option value="read_input">{t("deviceApi.readInputReg")}</option>
                    <option value="read_coils">{t("deviceApi.readCoils")}</option>
                    <option value="read_discrete">{t("deviceApi.readDiscrete")}</option>
                    <option value="write_holding">{t("deviceApi.writeSingleReg")}</option>
                    <option value="write_coil">{t("deviceApi.writeSingleCoil")}</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.startAddress")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={modbusAddress}
                    onChange={(e) => setModbusAddress(e.target.value)}
                  />
                </div>
                {isModbusWrite ? (
                  <div>
                    <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                      {t("deviceApi.valueWrite")}
                    </label>
                    <input
                      className="field h-8 w-full font-mono text-xs"
                      value={modbusValue}
                      onChange={(e) => setModbusValue(e.target.value)}
                    />
                  </div>
                ) : (
                  <div>
                    <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                      {t("deviceApi.quantity")}
                    </label>
                    <input
                      className="field h-8 w-full font-mono text-xs"
                      value={modbusCount}
                      onChange={(e) => setModbusCount(e.target.value)}
                    />
                  </div>
                )}
              </div>
            )}

            {/* MQTT 面板 */}
            {protocol === "mqtt" && (
              <div className="grid grid-cols-2 gap-2 p-3">
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.broker")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={mqttBroker}
                    onChange={(e) => setMqttBroker(e.target.value)}
                    placeholder="broker.example.com"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.port")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={mqttPort}
                    onChange={(e) => setMqttPort(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.clientId")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={mqttClientId}
                    onChange={(e) => setMqttClientId(e.target.value)}
                    placeholder="client-001"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.qos")}
                  </label>
                  <select
                    className="field h-8 w-full text-xs"
                    value={mqttQos}
                    onChange={(e) => setMqttQos(e.target.value)}
                  >
                    <option value="0">0 - At most once</option>
                    <option value="1">1 - At least once</option>
                    <option value="2">2 - Exactly once</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.username")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={mqttUsername}
                    onChange={(e) => setMqttUsername(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.password")}
                  </label>
                  <input
                    type="password"
                    className="field h-8 w-full font-mono text-xs"
                    value={mqttPassword}
                    onChange={(e) => setMqttPassword(e.target.value)}
                  />
                </div>
                <div className="col-span-2">
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.topic")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={mqttTopic}
                    onChange={(e) => setMqttTopic(e.target.value)}
                    placeholder="device/+/telemetry"
                  />
                </div>
                <div className="col-span-2">
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.payload")}
                  </label>
                  <textarea
                    className="field min-h-[80px] w-full font-mono text-xs"
                    value={mqttPayload}
                    onChange={(e) => setMqttPayload(e.target.value)}
                    placeholder='{"temperature": 25.5}'
                    spellCheck={false}
                  />
                </div>
                <div className="col-span-2 flex gap-2">
                  <button onClick={sendRequest} disabled={loading} className="pill pill-hover flex-1">
                    <IconSend size={14} />
                    {t("deviceApi.publish")}
                  </button>
                  <button onClick={mqttSubscribe} disabled={loading} className="pill pill-hover flex-1">
                    <IconPlay size={14} />
                    {t("deviceApi.subscribe")}
                  </button>
                </div>
              </div>
            )}

            {/* SNMP 面板 */}
            {protocol === "snmp" && (
              <div className="grid grid-cols-2 gap-2 p-3">
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.host")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={snmpHost}
                    onChange={(e) => setSnmpHost(e.target.value)}
                    placeholder="192.168.1.1"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.community")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={snmpCommunity}
                    onChange={(e) => setSnmpCommunity(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.version")}
                  </label>
                  <select
                    className="field h-8 w-full text-xs"
                    value={snmpVersion}
                    onChange={(e) => setSnmpVersion(e.target.value)}
                  >
                    <option value="v1">v1</option>
                    <option value="v2c">v2c</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.oid")}
                  </label>
                  <input
                    className="field h-8 w-full font-mono text-xs"
                    value={snmpOid}
                    onChange={(e) => setSnmpOid(e.target.value)}
                    placeholder="1.3.6.1.2.1.1.1.0"
                  />
                </div>
                <div className="col-span-2 flex gap-2">
                  <button onClick={sendRequest} disabled={loading} className="pill pill-hover flex-1">
                    <IconSend size={14} />
                    {t("deviceApi.get")}
                  </button>
                  <button onClick={snmpWalk} disabled={loading} className="pill pill-hover flex-1">
                    <IconPlay size={14} />
                    {t("deviceApi.walk")}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* 响应区域 */}
          <div className="mt-3 flex flex-1 flex-col overflow-hidden rounded-2xl border border-neutral-200 dark:border-neutral-800">
            {/* 状态栏 */}
            <div className="flex items-center gap-3 border-b border-neutral-200 px-3 py-1.5 dark:border-neutral-800">
              {response && response.status ? (
                <>
                  <span className={`font-mono text-xs font-bold ${getStatusColor(response.status)}`}>
                    {response.status} {response.statusText}
                  </span>
                  <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.time")}: {formatTime(response.time_ms)}
                  </span>
                  <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
                    {t("deviceApi.size")}: {formatSize(response.size)}
                  </span>
                </>
              ) : loading ? (
                <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
                  {t("deviceApi.sending")}
                </span>
              ) : (
                <span className="text-[11px] text-neutral-400">{t("deviceApi.noResult")}</span>
              )}
            </div>

            {/* 响应 Tab */}
            <div className="flex gap-1 border-b border-neutral-200 px-2 pt-1 dark:border-neutral-800">
              {[
                { key: "body", label: t("deviceApi.responseBody") },
                { key: "headers", label: t("deviceApi.responseHeaders") },
                { key: "cookies", label: t("deviceApi.cookies") },
                { key: "stress", label: t("deviceApi.stressResult") },
              ].map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setResponseTab(tab.key)}
                  className={`px-3 py-1.5 text-xs font-medium border-b-2 transition-colors ${
                    responseTab === tab.key
                      ? "border-emerald-500 text-emerald-600 dark:text-emerald-400"
                      : "border-transparent text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* 响应内容 */}
            <div className="flex-1 overflow-auto">
              {/* Body Tab */}
              {responseTab === "body" && (
                <div className="relative h-full">
                  {response?.body ? (
                    <>
                      <div className="flex items-center gap-1 border-b border-neutral-100 bg-neutral-50 px-2 py-1 dark:border-neutral-800 dark:bg-neutral-900/50">
                        <button
                          onClick={toggleFormatJson}
                          className="chip text-[10px]"
                        >
                          {t("deviceApi.formatJson")}
                        </button>
                        <button
                          onClick={copyResponseBody}
                          className="chip text-[10px]"
                        >
                          {copied ? t("deviceApi.copied") : t("deviceApi.copy")}
                        </button>
                      </div>
                      <pre
                        className="p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all text-neutral-700 dark:text-neutral-300"
                        dangerouslySetInnerHTML={{
                          __html: responseBodyFormatted ? highlightJson(displayBody) : displayBody.replace(/</g, "&lt;").replace(/>/g, "&gt;"),
                        }}
                      />
                    </>
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-neutral-400">
                      {loading ? t("deviceApi.sending") : t("deviceApi.noResult")}
                    </div>
                  )}
                </div>
              )}

              {/* Headers Tab */}
              {responseTab === "headers" && (
                <div>
                  {response?.headers && Object.keys(response.headers).length > 0 ? (
                    <div className="divide-y divide-neutral-100 dark:divide-neutral-800">
                      {Object.entries(response.headers).map(([k, v], i) => (
                        <div key={i} className="grid grid-cols-[140px_1fr] gap-2 px-3 py-1.5">
                          <span className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400 truncate">
                            {k}
                          </span>
                          <span className="font-mono text-[11px] text-neutral-700 dark:text-neutral-300 break-all">
                            {v}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex h-full items-center justify-center py-8 text-sm text-neutral-400">
                      {t("deviceApi.noResult")}
                    </div>
                  )}
                </div>
              )}

              {/* Cookies Tab */}
              {responseTab === "cookies" && (
                <div>
                  {response?.cookies && response.cookies.length > 0 ? (
                    <div className="divide-y divide-neutral-100 dark:divide-neutral-800">
                      {response.cookies.map((c, i) => (
                        <div key={i} className="px-3 py-2">
                          <p className="font-mono text-xs font-medium text-neutral-700 dark:text-neutral-300">
                            {c.name}
                          </p>
                          <p className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400 break-all">
                            {c.value}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex h-full items-center justify-center py-8 text-sm text-neutral-400">
                      {t("deviceApi.noResult")}
                    </div>
                  )}
                </div>
              )}

              {/* 压力测试 Tab */}
              {responseTab === "stress" && (
                <div className="p-3">
                  {stressResult?.error ? (
                    <p className="text-xs text-red-500">{stressResult.error}</p>
                  ) : stressResult ? (
                    <div className="space-y-3">
                      <div className="grid grid-cols-3 gap-2">
                        <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                          <p className="text-[10px] text-neutral-500 dark:text-neutral-400">
                            {t("deviceApi.qps")}
                          </p>
                          <p className="mt-1 text-lg font-bold text-emerald-600 dark:text-emerald-400">
                            {stressResult.qps?.toFixed?.(1) ?? stressResult.qps ?? "-"}
                          </p>
                        </div>
                        <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                          <p className="text-[10px] text-neutral-500 dark:text-neutral-400">
                            {t("deviceApi.successRate")}
                          </p>
                          <p className="mt-1 text-lg font-bold text-blue-600 dark:text-blue-400">
                            {stressResult.success_rate != null
                              ? `${(stressResult.success_rate * 100).toFixed(1)}%`
                              : "-"}
                          </p>
                        </div>
                        <div className="rounded-xl bg-neutral-50 p-3 dark:bg-neutral-900">
                          <p className="text-[10px] text-neutral-500 dark:text-neutral-400">
                            {t("deviceApi.avgRespTime")}
                          </p>
                          <p className="mt-1 text-lg font-bold text-amber-600 dark:text-amber-400">
                            {stressResult.avg_time != null
                              ? `${stressResult.avg_time.toFixed?.(0) ?? stressResult.avg_time} ms`
                              : "-"}
                          </p>
                        </div>
                      </div>

                      {stressResult.distribution && (
                        <div>
                          <p className="mb-2 text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
                            {t("deviceApi.respDistribution")}
                          </p>
                          <div className="space-y-1">
                            {Object.entries(stressResult.distribution).map(([range, count], i) => {
                              const total = Object.values(stressResult.distribution).reduce((a, b) => a + b, 0);
                              const pct = total > 0 ? (count / total) * 100 : 0;
                              return (
                                <div key={i} className="flex items-center gap-2">
                                  <span className="w-20 text-[10px] text-neutral-500 dark:text-neutral-400">
                                    {range}
                                  </span>
                                  <div className="flex-1 h-3 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-700">
                                    <div
                                      className="h-full bg-gradient-to-r from-emerald-400 to-blue-500 transition-all duration-500"
                                      style={{ width: `${pct}%` }}
                                    />
                                  </div>
                                  <span className="w-12 text-right text-[10px] font-mono text-neutral-500 dark:text-neutral-400">
                                    {count}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : stressRunning ? (
                    <div className="flex flex-col items-center justify-center py-8">
                      <span className="h-8 w-8 animate-spin rounded-full border-2 border-neutral-300 border-t-blue-500" />
                      <p className="mt-3 text-xs text-neutral-500 dark:text-neutral-400">
                        {t("deviceApi.running")}
                      </p>
                    </div>
                  ) : (
                    <div className="py-8 text-center text-sm text-neutral-400">
                      {t("deviceApi.noResult")}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 压力测试配置面板 */}
      {showStressPanel && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
          onClick={() => setShowStressPanel(false)}
        >
          <div
            className="card w-[360px] max-w-[calc(100vw-32px)] p-5"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <IconBolt size={18} className="text-amber-500" />
                <h3 className="text-sm font-semibold">{t("deviceApi.stressTest")}</h3>
              </div>
              <button
                onClick={() => setShowStressPanel(false)}
                className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white"
              >
                <IconX size={18} />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-xs text-neutral-500 dark:text-neutral-400">
                  {t("deviceApi.concurrent")}
                </label>
                <input
                  className="field h-9 w-full font-mono text-sm"
                  type="number"
                  value={stressConcurrent}
                  onChange={(e) => setStressConcurrent(e.target.value)}
                  min="1"
                  max="1000"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-neutral-500 dark:text-neutral-400">
                  {t("deviceApi.duration")}
                </label>
                <input
                  className="field h-9 w-full font-mono text-sm"
                  type="number"
                  value={stressDuration}
                  onChange={(e) => setStressDuration(e.target.value)}
                  min="1"
                  max="300"
                />
              </div>

              <button
                onClick={runStressTest}
                disabled={stressRunning || protocol !== "http"}
                className="pill pill-hover w-full justify-center"
              >
                {stressRunning ? (
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
                ) : (
                  <IconPlay size={14} />
                )}
                {stressRunning ? t("deviceApi.running") : t("deviceApi.startTest")}
              </button>

              {protocol !== "http" && (
                <p className="text-[11px] text-amber-500 text-center">
                  Stress test supports HTTP protocol only
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
