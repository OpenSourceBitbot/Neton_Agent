import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useLang } from "../../i18n.js";
import PillSwitch from "../PillSwitch.jsx";
import { IconPlay, IconPause, IconGlobe } from "../Icons.jsx";

/**
 * 网络爬虫工具
 * 支持 BFS/DFS 爬取、死链接检测、网站地图生成
 */
export default function WebCrawler({ onClose }) {
  const { t } = useLang();
  const [startUrl, setStartUrl] = useState("");
  const [maxPages, setMaxPages] = useState("50");
  const [maxDepth, setMaxDepth] = useState("3");
  const [mode, setMode] = useState("bfs"); // bfs, dfs
  const [delayMs, setDelayMs] = useState("500");
  const [respectRobots, setRespectRobots] = useState(true);
  const [crawling, setCrawling] = useState(false);
  const [activeTab, setActiveTab] = useState("pages"); // pages, deadlinks, sitemap
  const [error, setError] = useState("");

  // 爬取状态
  const [progress, setProgress] = useState(0);
  const [stats, setStats] = useState({
    crawled: 0,
    success: 0,
    failed: 0,
    elapsed: 0,
  });
  const [pages, setPages] = useState([]);
  const [deadLinks, setDeadLinks] = useState([]);
  const [sitemap, setSitemap] = useState(null);
  const [checkingDeadLinks, setCheckingDeadLinks] = useState(false);
  const [generatingSitemap, setGeneratingSitemap] = useState(false);

  const startTimeRef = useRef(null);
  const timerRef = useRef(null);
  const unlistenRef = useRef(null);

  const tabs = [
    { key: "pages", label: t("netsec.wcPages") },
    { key: "deadlinks", label: t("netsec.wcDeadLinks") },
    { key: "sitemap", label: t("netsec.wcSitemap") },
  ];

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (unlistenRef.current) unlistenRef.current();
    };
  }, []);

  const startCrawl = async () => {
    if (!startUrl.trim()) return;
    setCrawling(true);
    setError("");
    setProgress(0);
    setStats({ crawled: 0, success: 0, failed: 0, elapsed: 0 });
    setPages([]);
    setDeadLinks([]);
    setSitemap(null);
    startTimeRef.current = Date.now();

    // 启动计时器
    timerRef.current = setInterval(() => {
      if (startTimeRef.current) {
        setStats((prev) => ({
          ...prev,
          elapsed: Math.floor((Date.now() - startTimeRef.current) / 1000),
        }));
      }
    }, 1000);

    // 监听爬取进度事件
    try {
      unlistenRef.current = await listen("crawl_progress", (e) => {
        const data = e.payload;
        const max = parseInt(maxPages) || 50;
        const current = data.crawled || 0;
        setProgress(Math.min(Math.round((current / max) * 100), 100));
        setStats((prev) => ({
          ...prev,
          crawled: data.crawled ?? prev.crawled,
          success: data.success ?? prev.success,
          failed: data.failed ?? prev.failed,
        }));
        if (data.page) {
          setPages((prev) => [...prev, data.page]);
        }
        if (data.done) {
          finishCrawl();
        }
      });
    } catch (e) {
      // 事件监听失败不影响主流程
    }

    try {
      const res = await invoke("crawl_start", {
        startUrl: startUrl.trim(),
        maxPages: parseInt(maxPages) || 50,
        maxDepth: parseInt(maxDepth) || 3,
        mode,
        delayMs: parseInt(delayMs) || 500,
        respectRobots,
      });
      if (res && res.pages) {
        setPages(res.pages);
      }
      if (res && res.stats) {
        setStats((prev) => ({ ...prev, ...res.stats }));
      }
      setProgress(100);
      finishCrawl();
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
      finishCrawl();
    }
  };

  const finishCrawl = () => {
    setCrawling(false);
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (unlistenRef.current) {
      unlistenRef.current();
      unlistenRef.current = null;
    }
  };

  const stopCrawl = async () => {
    try {
      await invoke("crawl_stop");
    } catch (e) {
      // 忽略停止错误
    }
    finishCrawl();
  };

  const checkDeadLinks = async () => {
    if (!startUrl.trim()) return;
    setCheckingDeadLinks(true);
    setError("");
    try {
      const res = await invoke("crawl_check_dead_links", {
        url: startUrl.trim(),
        maxPages: parseInt(maxPages) || 50,
      });
      setDeadLinks(res?.dead_links || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setCheckingDeadLinks(false);
    }
  };

  const generateSitemap = async () => {
    if (!startUrl.trim()) return;
    setGeneratingSitemap(true);
    setError("");
    try {
      const res = await invoke("crawl_get_sitemap", {
        url: startUrl.trim(),
        maxPages: parseInt(maxPages) || 50,
      });
      setSitemap(res?.sitemap || null);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setGeneratingSitemap(false);
    }
  };

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  // 渲染网站结构树
  const renderTree = (node, depth = 0) => {
    if (!node) return null;
    return (
      <div key={node.url || node.path} style={{ paddingLeft: depth * 16 }}>
        <div className="flex items-center gap-2 py-1">
          <span className="text-neutral-400">
            {node.children && node.children.length > 0 ? "▸" : "•"}
          </span>
          <span className="font-mono text-xs break-all text-neutral-700 dark:text-neutral-300">
            {node.title || node.path || node.url}
          </span>
          {node.status && (
            <span className={`chip text-[10px] ${
              node.status < 400 ? "text-emerald-600 dark:text-emerald-400" : "text-red-500"
            }`}>
              {node.status}
            </span>
          )}
        </div>
        {node.children && node.children.length > 0 && (
          <div>
            {node.children.map((child, i) => renderTree(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconGlobe size={20} />
          <h3 className="text-base font-semibold">{t("netsec.webCrawler")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* 起始 URL */}
      <div className="mb-3">
        <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
          {t("netsec.wcStartUrl")}
        </label>
        <input
          className="field w-full font-mono"
          value={startUrl}
          onChange={(e) => setStartUrl(e.target.value)}
          placeholder="https://example.com"
        />
      </div>

      {/* 爬取配置 */}
      <div className="mb-3 grid grid-cols-2 gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.wcMaxPages")}
          </label>
          <input
            className="field w-full font-mono"
            value={maxPages}
            onChange={(e) => setMaxPages(e.target.value)}
            inputMode="numeric"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.wcMaxDepth")}
          </label>
          <input
            className="field w-full font-mono"
            value={maxDepth}
            onChange={(e) => setMaxDepth(e.target.value)}
            inputMode="numeric"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.wcCrawlMode")}
          </label>
          <select className="field w-full" value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="bfs">BFS</option>
            <option value="dfs">DFS</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.wcDelayMs")}
          </label>
          <input
            className="field w-full font-mono"
            value={delayMs}
            onChange={(e) => setDelayMs(e.target.value)}
            inputMode="numeric"
          />
        </div>
        <div className="col-span-2 flex items-center justify-between rounded-xl border border-neutral-200 px-3 py-2 dark:border-neutral-800">
          <span className="text-xs text-neutral-600 dark:text-neutral-400">
            {t("netsec.wcRespectRobots")}
          </span>
          <PillSwitch checked={respectRobots} onChange={setRespectRobots} size="sm" />
        </div>
      </div>

      {/* 开始/停止按钮 */}
      <div className="mb-3 flex gap-2">
        <button
          onClick={crawling ? stopCrawl : startCrawl}
          disabled={!startUrl.trim()}
          className={`pill pill-hover flex-1 justify-center ${
            crawling ? "bg-red-500 text-white hover:bg-red-600" : ""
          }`}
        >
          {crawling ? (
            <>
              <IconPause size={14} />
              {t("netsec.wcStop")}
            </>
          ) : (
            <>
              <IconPlay size={14} />
              {t("netsec.wcStartCrawl")}
            </>
          )}
        </button>
      </div>

      {/* 进度条 */}
      {(crawling || progress > 0) && (
        <div className="mb-3">
          <div className="mb-1 flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400">
            <span>{t("netsec.progress")}</span>
            <span>{progress}%</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
            <div
              className="h-full rounded-full bg-emerald-500 transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* 统计面板 */}
      {(crawling || pages.length > 0) && (
        <div className="mb-3 grid grid-cols-4 gap-2">
          <div className="rounded-xl bg-neutral-50 p-2 text-center dark:bg-neutral-900">
            <p className="text-lg font-semibold text-neutral-900 dark:text-white">{stats.crawled}</p>
            <p className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("netsec.wcCrawled")}</p>
          </div>
          <div className="rounded-xl bg-neutral-50 p-2 text-center dark:bg-neutral-900">
            <p className="text-lg font-semibold text-emerald-600 dark:text-emerald-400">{stats.success}</p>
            <p className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("common.success")}</p>
          </div>
          <div className="rounded-xl bg-neutral-50 p-2 text-center dark:bg-neutral-900">
            <p className="text-lg font-semibold text-red-500">{stats.failed}</p>
            <p className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("common.failed")}</p>
          </div>
          <div className="rounded-xl bg-neutral-50 p-2 text-center dark:bg-neutral-900">
            <p className="text-lg font-semibold font-mono text-neutral-900 dark:text-white">
              {formatTime(stats.elapsed)}
            </p>
            <p className="text-[10px] text-neutral-500 dark:text-neutral-400">{t("netsec.wcElapsed")}</p>
          </div>
        </div>
      )}

      {/* Tab 切换 */}
      <div className="mb-3 flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
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
        {/* 已爬取页面列表 */}
        {activeTab === "pages" && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-neutral-50 dark:bg-neutral-900">
              <tr>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.waTitle")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.status")}</th>
                <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">{t("netsec.waPageSize")}</th>
              </tr>
            </thead>
            <tbody>
              {pages.length > 0 ? (
                pages.map((p, i) => (
                  <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                    <td className="px-3 py-2">
                      <p className="font-medium truncate max-w-[200px]" title={p.title || p.url}>
                        {p.title || "-"}
                      </p>
                      <p className="font-mono text-[10px] text-neutral-500 dark:text-neutral-400 truncate max-w-[200px]" title={p.url}>
                        {p.url}
                      </p>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`chip ${
                        p.status && p.status < 400
                          ? "text-emerald-600 dark:text-emerald-400"
                          : "text-red-500"
                      }`}>
                        {p.status || "-"}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-neutral-500 dark:text-neutral-400">
                      {p.size || "-"}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={3} className="px-3 py-8 text-center text-neutral-400">
                    {crawling ? t("netsec.wcCrawling") : t("netsec.noResult")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}

        {/* 死链接列表 */}
        {activeTab === "deadlinks" && (
          <div className="p-3">
            <button
              onClick={checkDeadLinks}
              disabled={checkingDeadLinks || !startUrl.trim()}
              className="pill pill-hover mb-3 w-full justify-center"
            >
              {checkingDeadLinks ? (
                <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
              ) : (
                <IconPlay size={14} />
              )}
              {t("netsec.wcCheckDeadLinks")}
            </button>
            {deadLinks.length > 0 ? (
              <div className="space-y-2">
                {deadLinks.map((link, i) => (
                  <div key={i} className="rounded-xl border border-red-200 bg-red-50 p-3 dark:border-red-900/50 dark:bg-red-900/20">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs break-all pr-2">{link.url}</span>
                      <span className="chip text-[10px] text-red-500 shrink-0">
                        {link.status || t("netsec.wcUnreachable")}
                      </span>
                    </div>
                    {link.referer && (
                      <p className="mt-1 text-[11px] text-neutral-500 dark:text-neutral-400">
                        {t("netsec.wcReferer")}: {link.referer}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {checkingDeadLinks ? t("netsec.wcChecking") : t("netsec.noResult")}
              </div>
            )}
          </div>
        )}

        {/* 网站结构树 */}
        {activeTab === "sitemap" && (
          <div className="p-3">
            <button
              onClick={generateSitemap}
              disabled={generatingSitemap || !startUrl.trim()}
              className="pill pill-hover mb-3 w-full justify-center"
            >
              {generatingSitemap ? (
                <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
              ) : (
                <IconPlay size={14} />
              )}
              {t("netsec.wcGenerateSitemap")}
            </button>
            {sitemap ? (
              <div className="max-h-80 overflow-auto rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                {renderTree(sitemap)}
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-neutral-400">
                {generatingSitemap ? t("netsec.wcGenerating") : t("netsec.noResult")}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
