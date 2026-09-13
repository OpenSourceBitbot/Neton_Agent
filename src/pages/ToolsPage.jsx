import { useState } from "react";
import { useLang } from "../i18n.js";
import PortScanner from "../components/netsec/PortScanner.jsx";
import ArpScanner from "../components/netsec/ArpScanner.jsx";
import PasswordCracker from "../components/netsec/PasswordCracker.jsx";
import WeakPassword from "../components/netsec/WeakPassword.jsx";
import SqlInjection from "../components/netsec/SqlInjection.jsx";
import CveSearch from "../components/netsec/CveSearch.jsx";
import CaptchaRecog from "../components/netsec/CaptchaRecog.jsx";
import DomainAnalysis from "../components/netsec/DomainAnalysis.jsx";
import TopologyTool from "../components/netsec/TopologyTool.jsx";
import NatAnalyzer from "../components/netsec/NatAnalyzer.jsx";
import VirusScanner from "../components/netsec/VirusScanner.jsx";
import VirtualBrowser from "../components/netsec/VirtualBrowser.jsx";
import WebAnalyzer from "../components/netsec/WebAnalyzer.jsx";
import WebCrawler from "../components/netsec/WebCrawler.jsx";
import SiteAnalyzer from "../components/netsec/SiteAnalyzer.jsx";
import DeviceApi from "../components/netsec/DeviceApi.jsx";
import VulnScanner from "../components/netsec/VulnScanner.jsx";
import PacketCapture from "../components/netsec/PacketCapture.jsx";
import HashCrypto from "../components/netsec/HashCrypto.jsx";
import FirewallDns from "../components/netsec/FirewallDns.jsx";
import {
  IconShield,
  IconPlay,
  IconTarget,
  IconServer,
  IconGlobe,
  IconCode,
  IconImage,
  IconTerminal,
} from "../components/Icons.jsx";

// 工具分类与工具定义
const CATEGORIES = [
  {
    key: "network",
    labelKey: "netsec.catNetwork",
    icon: IconTarget,
    tools: [
      {
        key: "port_scanner",
        nameKey: "netsec.portScanner",
        descKey: "netsec.portScannerDesc",
        icon: IconTarget,
        component: PortScanner,
      },
      {
        key: "arp_scanner",
        nameKey: "netsec.arpScanner",
        descKey: "netsec.arpScannerDesc",
        icon: IconServer,
        component: ArpScanner,
      },
      {
        key: "topology",
        nameKey: "netsec.topologyAnalyzer",
        descKey: "netsec.topologyDesc",
        icon: IconGlobe,
        component: TopologyTool,
      },
      {
        key: "nat_analyzer",
        nameKey: "netsec.natAnalyzer",
        descKey: "netsec.natDesc",
        icon: IconShield,
        component: NatAnalyzer,
      },
    ],
  },
  {
    key: "password",
    labelKey: "netsec.catPassword",
    icon: IconShield,
    tools: [
      {
        key: "password_cracker",
        nameKey: "netsec.passwordCracker",
        descKey: "netsec.passwordCrackerDesc",
        icon: IconTerminal,
        component: PasswordCracker,
      },
      {
        key: "weak_password",
        nameKey: "netsec.weakPassword",
        descKey: "netsec.weakPasswordDesc",
        icon: IconShield,
        component: WeakPassword,
      },
    ],
  },
  {
    key: "vuln",
    labelKey: "netsec.catVuln",
    icon: IconCode,
    tools: [
      {
        key: "sql_injection",
        nameKey: "netsec.sqlInjection",
        descKey: "netsec.sqlInjectionDesc",
        icon: IconCode,
        component: SqlInjection,
      },
      {
        key: "cve_search",
        nameKey: "netsec.cveSearch",
        descKey: "netsec.cveSearchDesc",
        icon: IconShield,
        component: CveSearch,
      },
      {
        key: "vuln_scanner",
        nameKey: "vulnScanner.title",
        descKey: "vulnScanner.titleDesc",
        icon: IconShield,
        component: VulnScanner,
      },
    ],
  },
  {
    key: "domain",
    labelKey: "netsec.catDomain",
    icon: IconGlobe,
    tools: [
      {
        key: "domain_analysis",
        nameKey: "netsec.domainAnalysis",
        descKey: "netsec.domainAnalysisDesc",
        icon: IconGlobe,
        component: DomainAnalysis,
      },
    ],
  },
  {
    key: "visual",
    labelKey: "netsec.catVisual",
    icon: IconImage,
    tools: [
      {
        key: "captcha_recog",
        nameKey: "netsec.captchaRecog",
        descKey: "netsec.captchaRecogDesc",
        icon: IconImage,
        component: CaptchaRecog,
      },
      {
        key: "virtual_browser",
        nameKey: "netsec.virtualBrowser",
        descKey: "netsec.virtualBrowserDesc",
        icon: IconGlobe,
        component: VirtualBrowser,
      },
    ],
  },
  {
    key: "virus",
    labelKey: "netsec.catVirus",
    icon: IconShield,
    tools: [
      {
        key: "virus_scanner",
        nameKey: "netsec.virusScanner",
        descKey: "netsec.virusScannerDesc",
        icon: IconShield,
        component: VirusScanner,
      },
    ],
  },
  {
    key: "web",
    labelKey: "netsec.catWeb",
    icon: IconGlobe,
    tools: [
      {
        key: "web_analyzer",
        nameKey: "netsec.webAnalyzer",
        descKey: "netsec.webAnalyzerDesc",
        icon: IconGlobe,
        component: WebAnalyzer,
      },
      {
        key: "web_crawler",
        nameKey: "netsec.webCrawler",
        descKey: "netsec.webCrawlerDesc",
        icon: IconGlobe,
        component: WebCrawler,
      },
    ],
  },
  {
    key: "siteinfo",
    labelKey: "netsec.catSiteInfo",
    icon: IconShield,
    tools: [
      {
        key: "site_analyzer",
        nameKey: "siteAnalyzer.siteAnalyzer",
        descKey: "siteAnalyzer.siteAnalyzerDesc",
        icon: IconShield,
        component: SiteAnalyzer,
      },
    ],
  },
  {
    key: "device",
    labelKey: "netsec.catDevice",
    icon: IconServer,
    tools: [
      {
        key: "device_api",
        nameKey: "deviceApi.deviceApi",
        descKey: "deviceApi.deviceApiDesc",
        icon: IconServer,
        component: DeviceApi,
      },
    ],
  },
  {
    key: "packet",
    labelKey: "netsec.catPacket",
    icon: IconTerminal,
    tools: [
      {
        key: "packet_capture",
        nameKey: "packetCapture.title",
        descKey: "packetCapture.titleDesc",
        icon: IconTerminal,
        component: PacketCapture,
      },
    ],
  },
  {
    key: "crypto",
    labelKey: "netsec.catCrypto",
    icon: IconShield,
    tools: [
      {
        key: "hash_crypto",
        nameKey: "hashCrypto.title",
        descKey: "hashCrypto.titleDesc",
        icon: IconShield,
        component: HashCrypto,
      },
    ],
  },
  {
    key: "firewallDns",
    labelKey: "netsec.catFirewallDns",
    icon: IconShield,
    tools: [
      {
        key: "firewall_dns",
        nameKey: "firewallDns.title",
        descKey: "firewallDns.titleDesc",
        icon: IconShield,
        component: FirewallDns,
      },
    ],
  },
];

// 工具卡片组件
function ToolCard({ tool, onLaunch, t }) {
  const Icon = tool.icon;
  return (
    <div className="card group flex flex-col gap-3 transition-all duration-200 hover:shadow-card-hover">
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">
          <Icon size={20} />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold">{t(tool.nameKey)}</h3>
          <p className="mt-0.5 line-clamp-2 text-xs text-neutral-500 dark:text-neutral-400">
            {t(tool.descKey)}
          </p>
        </div>
      </div>
      <button
        onClick={() => onLaunch(tool)}
        className="pill pill-hover w-full justify-center"
      >
        <IconPlay size={14} />
        {t("netsec.launchTool")}
      </button>
    </div>
  );
}

/**
 * 网络安全工具中心页面
 */
export default function ToolsPage() {
  const { t } = useLang();
  const [activeTool, setActiveTool] = useState(null);

  const launchTool = (tool) => {
    setActiveTool(tool);
  };

  const closeTool = () => {
    setActiveTool(null);
  };

  return (
    <div className="flex h-full flex-col">
      {/* 头部标题 */}
      <div className="mb-6 flex items-center gap-3">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-neutral-900 text-white dark:bg-white dark:text-neutral-900">
          <IconShield size={24} />
        </div>
        <div>
          <h1 className="text-xl font-bold">{t("netsec.toolsCenter")}</h1>
          <p className="text-sm text-neutral-500 dark:text-neutral-400">
            {t("netsec.toolsCenterDesc")}
          </p>
        </div>
      </div>

      {/* 分类与工具卡片 */}
      <div className="flex-1 overflow-auto space-y-8">
        {CATEGORIES.map((cat) => {
          const CatIcon = cat.icon;
          return (
            <section key={cat.key}>
              <div className="mb-3 flex items-center gap-2">
                <CatIcon size={18} className="text-neutral-600 dark:text-neutral-400" />
                <h2 className="text-sm font-semibold">{t(cat.labelKey)}</h2>
                <span className="chip text-[10px]">{cat.tools.length}</span>
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {cat.tools.map((tool) => (
                  <ToolCard key={tool.key} tool={tool} onLaunch={launchTool} t={t} />
                ))}
              </div>
            </section>
          );
        })}
      </div>

      {/* 工具面板模态框 */}
      {activeTool && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
          onClick={closeTool}
        >
          <div
            className="card max-h-[85vh] w-[720px] max-w-[calc(100vw-32px)] overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="h-[70vh] overflow-auto p-5">
              {activeTool.component && (
                <activeTool.component onClose={closeTool} />
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
