import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconPlay, IconCopy, IconFile } from "../Icons.jsx";

/**
 * 哈希破解与编码转换工具
 * 包含哈希计算、哈希破解、编解码、密码学工具
 */
export default function HashCrypto({ onClose }) {
  const { t } = useLang();
  const [activeTab, setActiveTab] = useState("hash");
  const [error, setError] = useState("");

  // ─── Tab 1: 哈希计算 ───
  const [hashInput, setHashInput] = useState("");
  const [selectedAlgos, setSelectedAlgos] = useState(["MD5", "SHA256"]);
  const [hmacKey, setHmacKey] = useState("");
  const [hashResults, setHashResults] = useState([]);
  const [hashComputing, setHashComputing] = useState(false);
  const [copiedAlgo, setCopiedAlgo] = useState("");

  const allAlgos = ["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "CRC32", "HMAC-SHA256"];

  const toggleAlgo = (algo) => {
    if (selectedAlgos.includes(algo)) {
      setSelectedAlgos(selectedAlgos.filter((a) => a !== algo));
    } else {
      setSelectedAlgos([...selectedAlgos, algo]);
    }
  };

  const computeHash = async () => {
    if (!hashInput.trim() || selectedAlgos.length === 0) return;
    setHashComputing(true);
    setError("");
    setHashResults([]);
    try {
      const res = await invoke("hash_compute_all", {
        text: hashInput,
        algorithms: selectedAlgos,
        hmacKey: hmacKey.trim() || null,
      });
      setHashResults(res?.results || []);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setHashComputing(false);
    }
  };

  const copyHash = async (algo, value) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedAlgo(algo);
      setTimeout(() => setCopiedAlgo(""), 1500);
    } catch (e) {
      // ignore
    }
  };

  // ─── Tab 2: 哈希破解 ───
  const [crackHash, setCrackHash] = useState("");
  const [crackType, setCrackType] = useState("auto");
  const [crackMode, setCrackMode] = useState("dict");
  const [dictPath, setDictPath] = useState("");
  const [maxLength, setMaxLength] = useState("6");
  const [charset, setCharset] = useState({ digits: true, lower: true, upper: false, special: false });
  const [cracking, setCracking] = useState(false);
  const [crackResult, setCrackResult] = useState(null);

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

  const toggleCharset = (key) => {
    setCharset({ ...charset, [key]: !charset[key] });
  };

  const startCrack = async () => {
    if (!crackHash.trim()) return;
    setCracking(true);
    setError("");
    setCrackResult(null);
    try {
      const charsetStr = [
        charset.digits ? "0123456789" : "",
        charset.lower ? "abcdefghijklmnopqrstuvwxyz" : "",
        charset.upper ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "",
        charset.special ? "!@#$%^&*()_+-=[]{}|;:,.<>?" : "",
      ].join("");

      const res = await invoke("hash_crack", {
        hash: crackHash.trim(),
        hashType: crackType,
        mode: crackMode,
        dictPath: crackMode === "dict" ? dictPath.trim() : null,
        maxLength: crackMode === "brute" ? parseInt(maxLength) || 6 : 0,
        charset: crackMode === "brute" ? charsetStr : null,
      });
      setCrackResult(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setCracking(false);
    }
  };

  // ─── Tab 3: 编码/解码 ───
  const [codeInput, setCodeInput] = useState("");
  const [codeFormat, setCodeFormat] = useState("base64");
  const [decodeMode, setDecodeMode] = useState(false);
  const [caesarShift, setCaesarShift] = useState("3");
  const [codeResult, setCodeResult] = useState("");
  const [codeRunning, setCodeRunning] = useState(false);

  const codeFormats = [
    { key: "base64", label: "Base64" },
    { key: "base32", label: "Base32" },
    { key: "base58", label: "Base58" },
    { key: "url", label: "URL 编码" },
    { key: "hex", label: "Hex" },
    { key: "html", label: "HTML 实体" },
    { key: "unicode", label: "Unicode" },
    { key: "rot13", label: "ROT13" },
    { key: "caesar", label: "凯撒密码" },
    { key: "morse", label: "摩斯电码" },
    { key: "ascii", label: "ASCII" },
    { key: "binary", label: "Binary" },
    { key: "octal", label: "Octal" },
  ];

  const runEncodeDecode = async () => {
    if (!codeInput.trim()) return;
    setCodeRunning(true);
    setError("");
    try {
      const res = await invoke("encode_decode", {
        input: codeInput,
        format: codeFormat,
        decode: decodeMode,
        shift: codeFormat === "caesar" ? parseInt(caesarShift) || 3 : 0,
      });
      setCodeResult(res?.output || "");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setCodeRunning(false);
    }
  };

  const copyCodeResult = async () => {
    if (!codeResult) return;
    try {
      await navigator.clipboard.writeText(codeResult);
    } catch (e) {
      // ignore
    }
  };

  // ─── Tab 4: 密码学工具 ───
  const [cryptoSubTab, setCryptoSubTab] = useState("aes");

  // AES
  const [aesText, setAesText] = useState("");
  const [aesKey, setAesKey] = useState("");
  const [aesMode, setAesMode] = useState("cbc");
  const [aesResult, setAesResult] = useState("");
  const [aesRunning, setAesRunning] = useState(false);

  const runAes = async (encrypt) => {
    if (!aesText.trim() || !aesKey.trim()) return;
    setAesRunning(true);
    setError("");
    try {
      const fn = encrypt ? "crypto_aes_encrypt" : "crypto_aes_decrypt";
      const res = await invoke(fn, {
        text: aesText,
        key: aesKey,
        mode: aesMode,
      });
      setAesResult(res?.result || "");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setAesRunning(false);
    }
  };

  // XOR
  const [xorText, setXorText] = useState("");
  const [xorKey, setXorKey] = useState("");
  const [xorResult, setXorResult] = useState("");

  const runXor = async () => {
    if (!xorText.trim() || !xorKey.trim()) return;
    try {
      const res = await invoke("crypto_xor", { text: xorText, key: xorKey });
      setXorResult(res?.result || "");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  // 随机数
  const [randLength, setRandLength] = useState("16");
  const [randCharset, setRandCharset] = useState({ digits: true, lower: true, upper: true, special: false });
  const [randResult, setRandResult] = useState("");

  const runRandom = async () => {
    try {
      const cs = [
        randCharset.digits ? "digits" : "",
        randCharset.lower ? "lower" : "",
        randCharset.upper ? "upper" : "",
        randCharset.special ? "special" : "",
      ].filter(Boolean).join(",");
      const res = await invoke("crypto_random", {
        length: parseInt(randLength) || 16,
        charset: cs,
      });
      setRandResult(res?.result || "");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  // UUID
  const [uuidVersion, setUuidVersion] = useState("v4");
  const [uuidResult, setUuidResult] = useState("");

  const runUuid = async () => {
    try {
      const res = await invoke("crypto_uuid", { version: uuidVersion });
      setUuidResult(res?.result || "");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  // 文件格式识别
  const [filePath, setFilePath] = useState("");
  const [fileFormatResult, setFileFormatResult] = useState(null);

  const selectFile = async () => {
    try {
      const path = await invoke("open_file_dialog", { filters: null });
      if (path) {
        setFilePath(path);
        identifyFile(path);
      }
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const identifyFile = async (path) => {
    try {
      const res = await invoke("file_identify_format", { filePath: path });
      setFileFormatResult(res);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const mainTabs = [
    { key: "hash", label: t("hashCrypto.tabHashCompute") },
    { key: "crack", label: t("hashCrypto.tabHashCrack") },
    { key: "code", label: t("hashCrypto.tabEncodeDecode") },
    { key: "crypto", label: t("hashCrypto.tabCryptoTools") },
  ];

  const cryptoSubTabs = [
    { key: "aes", label: "AES" },
    { key: "xor", label: "XOR" },
    { key: "random", label: t("hashCrypto.random") },
    { key: "uuid", label: "UUID" },
    { key: "filefmt", label: t("hashCrypto.fileIdentify") },
  ];

  return (
    <div className="flex h-full flex-col">
      {/* 标题栏 */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <h3 className="text-base font-semibold">{t("hashCrypto.title")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      {/* 主 Tab 切换 */}
      <div className="mb-3 flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
        {mainTabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => { setActiveTab(tab.key); setError(""); }}
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
      <div className="flex-1 overflow-auto">
        {/* ─── Tab 1: 哈希计算 ─── */}
        {activeTab === "hash" && (
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                {t("hashCrypto.inputText")}
              </label>
              <textarea
                className="field w-full font-mono text-xs min-h-[80px] resize-none"
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                placeholder={t("hashCrypto.inputPlaceholder")}
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                {t("hashCrypto.algorithms")}
              </label>
              <div className="flex flex-wrap gap-1.5">
                {allAlgos.map((algo) => (
                  <button
                    key={algo}
                    onClick={() => toggleAlgo(algo)}
                    className={`rounded-full px-2.5 py-1 text-[11px] font-medium transition-colors ${
                      selectedAlgos.includes(algo)
                        ? "bg-neutral-900 text-white dark:bg-white dark:text-neutral-900"
                        : "bg-neutral-100 text-neutral-600 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-700"
                    }`}
                  >
                    {algo}
                  </button>
                ))}
              </div>
            </div>

            {selectedAlgos.some((a) => a.startsWith("HMAC")) && (
              <div>
                <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                  HMAC {t("hashCrypto.hmacKey")}
                </label>
                <input
                  className="field w-full font-mono text-xs"
                  value={hmacKey}
                  onChange={(e) => setHmacKey(e.target.value)}
                  type="password"
                  placeholder={t("hashCrypto.hmacKeyHint")}
                />
              </div>
            )}

            <button
              onClick={computeHash}
              disabled={hashComputing || !hashInput.trim() || selectedAlgos.length === 0}
              className="pill pill-hover w-full justify-center"
            >
              {hashComputing ? (
                <>
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
                  {t("netsec.calculating")}
                </>
              ) : (
                <>
                  <IconPlay size={14} />
                  {t("hashCrypto.compute")}
                </>
              )}
            </button>

            {hashResults.length > 0 && (
              <div className="rounded-2xl border border-neutral-200 dark:border-neutral-800">
                <table className="w-full text-left text-xs">
                  <thead className="bg-neutral-50 dark:bg-neutral-900">
                    <tr>
                      <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400 w-28">
                        {t("hashCrypto.algorithm")}
                      </th>
                      <th className="px-3 py-2 font-medium text-neutral-600 dark:text-neutral-400">
                        {t("hashCrypto.hashValue")}
                      </th>
                      <th className="px-3 py-2 w-16"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {hashResults.map((r, i) => (
                      <tr key={i} className="border-t border-neutral-100 dark:border-neutral-800">
                        <td className="px-3 py-2 font-medium">{r.algorithm}</td>
                        <td className="px-3 py-2 font-mono text-[11px] break-all text-neutral-700 dark:text-neutral-300">
                          {r.hash}
                        </td>
                        <td className="px-3 py-2">
                          <button
                            onClick={() => copyHash(r.algorithm, r.hash)}
                            className="pill pill-outline pill-hover text-[10px]"
                          >
                            <IconCopy size={10} />
                            {copiedAlgo === r.algorithm ? t("common.copied") : t("common.copy")}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ─── Tab 2: 哈希破解 ─── */}
        {activeTab === "crack" && (
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                {t("hashCrypto.hashValue")}
              </label>
              <input
                className="field w-full font-mono text-xs"
                value={crackHash}
                onChange={(e) => setCrackHash(e.target.value)}
                placeholder="e10adc3949ba59abbe56e057f20f883e"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                  {t("hashCrypto.hashType")}
                </label>
                <select className="field w-full text-xs" value={crackType} onChange={(e) => setCrackType(e.target.value)}>
                  <option value="auto">{t("netsec.autoDetect")}</option>
                  <option value="md5">MD5</option>
                  <option value="sha1">SHA1</option>
                  <option value="sha256">SHA256</option>
                  <option value="ntlm">NTLM</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                  {t("hashCrypto.crackMode")}
                </label>
                <select className="field w-full text-xs" value={crackMode} onChange={(e) => setCrackMode(e.target.value)}>
                  <option value="dict">{t("hashCrypto.dictAttack")}</option>
                  <option value="brute">{t("hashCrypto.bruteForce")}</option>
                </select>
              </div>
            </div>

            {crackMode === "dict" && (
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
                  <button onClick={selectDictFile} className="pill pill-outline pill-hover text-xs">
                    <IconFile size={14} />
                    {t("common.select")}
                  </button>
                </div>
              </div>
            )}

            {crackMode === "brute" && (
              <>
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.maxLength")}
                  </label>
                  <input
                    className="field w-full font-mono text-xs"
                    value={maxLength}
                    onChange={(e) => setMaxLength(e.target.value)}
                    inputMode="numeric"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.charset")}
                  </label>
                  <div className="flex flex-wrap gap-1.5">
                    {[
                      { key: "digits", label: t("hashCrypto.csDigits") },
                      { key: "lower", label: t("hashCrypto.csLower") },
                      { key: "upper", label: t("hashCrypto.csUpper") },
                      { key: "special", label: t("hashCrypto.csSpecial") },
                    ].map((c) => (
                      <button
                        key={c.key}
                        onClick={() => toggleCharset(c.key)}
                        className={`rounded-full px-2.5 py-1 text-[11px] font-medium transition-colors ${
                          charset[c.key]
                            ? "bg-neutral-900 text-white dark:bg-white dark:text-neutral-900"
                            : "bg-neutral-100 text-neutral-600 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-700"
                        }`}
                      >
                        {c.label}
                      </button>
                    ))}
                  </div>
                </div>
              </>
            )}

            <button
              onClick={startCrack}
              disabled={cracking || !crackHash.trim() || (crackMode === "dict" && !dictPath.trim())}
              className="pill pill-hover w-full justify-center"
            >
              {cracking ? (
                <>
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
                  {t("common.running")}
                </>
              ) : (
                <>
                  <IconPlay size={14} />
                  {t("hashCrypto.startCrack")}
                </>
              )}
            </button>

            {crackResult && (
              <div className="rounded-2xl border border-neutral-200 p-3 dark:border-neutral-800">
                <div className="mb-2 flex items-center gap-2">
                  <span className={`chip ${crackResult.found ? "text-emerald-600 dark:text-emerald-400" : "text-amber-600 dark:text-amber-400"}`}>
                    {crackResult.found ? t("netsec.cracked") : t("netsec.notFound")}
                  </span>
                </div>
                <div className="space-y-1 font-mono text-xs">
                  {crackResult.found && (
                    <p>
                      <span className="text-neutral-500 dark:text-neutral-400">{t("hashCrypto.plaintext")}:</span>{" "}
                      <span className="font-semibold">{crackResult.plaintext}</span>
                    </p>
                  )}
                  <p>
                    <span className="text-neutral-500 dark:text-neutral-400">{t("hashCrypto.attempts")}:</span>{" "}
                    {crackResult.attempts?.toLocaleString() || 0}
                  </p>
                  <p>
                    <span className="text-neutral-500 dark:text-neutral-400">{t("hashCrypto.elapsed")}:</span>{" "}
                    {crackResult.elapsed || "0s"}
                  </p>
                  {crackResult.speed && (
                    <p>
                      <span className="text-neutral-500 dark:text-neutral-400">{t("hashCrypto.speed")}:</span>{" "}
                      {crackResult.speed}
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ─── Tab 3: 编码/解码 ─── */}
        {activeTab === "code" && (
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                {t("hashCrypto.inputText")}
              </label>
              <textarea
                className="field w-full font-mono text-xs min-h-[80px] resize-none"
                value={codeInput}
                onChange={(e) => setCodeInput(e.target.value)}
                placeholder={t("hashCrypto.inputPlaceholder")}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                  {t("hashCrypto.encodeFormat")}
                </label>
                <select className="field w-full text-xs" value={codeFormat} onChange={(e) => setCodeFormat(e.target.value)}>
                  {codeFormats.map((f) => (
                    <option key={f.key} value={f.key}>{f.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                  {t("hashCrypto.mode")}
                </label>
                <div className="flex gap-1 rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
                  <button
                    onClick={() => setDecodeMode(false)}
                    className={`flex-1 rounded-full px-2 py-1.5 text-[11px] font-medium transition-colors ${
                      !decodeMode
                        ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                        : "text-neutral-500 dark:text-neutral-400"
                    }`}
                  >
                    {t("hashCrypto.encode")}
                  </button>
                  <button
                    onClick={() => setDecodeMode(true)}
                    className={`flex-1 rounded-full px-2 py-1.5 text-[11px] font-medium transition-colors ${
                      decodeMode
                        ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                        : "text-neutral-500 dark:text-neutral-400"
                    }`}
                  >
                    {t("hashCrypto.decode")}
                  </button>
                </div>
              </div>
            </div>

            {codeFormat === "caesar" && (
              <div>
                <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                  {t("hashCrypto.caesarShift")}
                </label>
                <input
                  className="field w-full font-mono text-xs"
                  value={caesarShift}
                  onChange={(e) => setCaesarShift(e.target.value)}
                  inputMode="numeric"
                />
              </div>
            )}

            <button
              onClick={runEncodeDecode}
              disabled={codeRunning || !codeInput.trim()}
              className="pill pill-hover w-full justify-center"
            >
              {codeRunning ? (
                <>
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
                  {t("common.running")}
                </>
              ) : (
                <>
                  <IconPlay size={14} />
                  {t("hashCrypto.convert")}
                </>
              )}
            </button>

            {codeResult && (
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <label className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.result")}
                  </label>
                  <button onClick={copyCodeResult} className="pill pill-outline pill-hover text-[10px]">
                    <IconCopy size={10} />
                    {t("common.copy")}
                  </button>
                </div>
                <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-2 font-mono text-xs break-all dark:border-neutral-800 dark:bg-neutral-900">
                  {codeResult}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ─── Tab 4: 密码学工具 ─── */}
        {activeTab === "crypto" && (
          <div className="space-y-3">
            {/* 子 Tab */}
            <div className="flex gap-1 overflow-x-auto rounded-full bg-neutral-100 p-1 dark:bg-neutral-800">
              {cryptoSubTabs.map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setCryptoSubTab(tab.key)}
                  className={`whitespace-nowrap rounded-full px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    cryptoSubTab === tab.key
                      ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white"
                      : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-white"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* AES */}
            {cryptoSubTab === "aes" && (
              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.aesText")}
                  </label>
                  <textarea
                    className="field w-full font-mono text-xs min-h-[60px] resize-none"
                    value={aesText}
                    onChange={(e) => setAesText(e.target.value)}
                    placeholder={decodeMode ? t("hashCrypto.ciphertextHint") : t("hashCrypto.plaintextHint")}
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("hashCrypto.aesKey")}
                    </label>
                    <input
                      className="field w-full font-mono text-xs"
                      value={aesKey}
                      onChange={(e) => setAesKey(e.target.value)}
                      type="password"
                      placeholder="16/24/32 字节密钥"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      {t("hashCrypto.aesMode")}
                    </label>
                    <select className="field w-full text-xs" value={aesMode} onChange={(e) => setAesMode(e.target.value)}>
                      <option value="cbc">CBC</option>
                      <option value="ecb">ECB</option>
                    </select>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => runAes(true)}
                    disabled={aesRunning || !aesText.trim() || !aesKey.trim()}
                    className="pill pill-hover flex-1 justify-center"
                  >
                    <IconPlay size={14} />
                    {t("hashCrypto.encrypt")}
                  </button>
                  <button
                    onClick={() => runAes(false)}
                    disabled={aesRunning || !aesText.trim() || !aesKey.trim()}
                    className="pill pill-outline pill-hover flex-1 justify-center"
                  >
                    <IconPlay size={14} />
                    {t("hashCrypto.decrypt")}
                  </button>
                </div>
                {aesResult && (
                  <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-2 font-mono text-xs break-all dark:border-neutral-800 dark:bg-neutral-900">
                    {aesResult}
                  </div>
                )}
              </div>
            )}

            {/* XOR */}
            {cryptoSubTab === "xor" && (
              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.plaintext")}
                  </label>
                  <input
                    className="field w-full font-mono text-xs"
                    value={xorText}
                    onChange={(e) => setXorText(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.xorKey")}
                  </label>
                  <input
                    className="field w-full font-mono text-xs"
                    value={xorKey}
                    onChange={(e) => setXorKey(e.target.value)}
                  />
                </div>
                <button
                  onClick={runXor}
                  disabled={!xorText.trim() || !xorKey.trim()}
                  className="pill pill-hover w-full justify-center"
                >
                  <IconPlay size={14} />
                  {t("hashCrypto.compute")}
                </button>
                {xorResult && (
                  <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-2 font-mono text-xs break-all dark:border-neutral-800 dark:bg-neutral-900">
                    {xorResult}
                  </div>
                )}
              </div>
            )}

            {/* 随机数生成 */}
            {cryptoSubTab === "random" && (
              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.randLength")}
                  </label>
                  <input
                    className="field w-full font-mono text-xs"
                    value={randLength}
                    onChange={(e) => setRandLength(e.target.value)}
                    inputMode="numeric"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.charset")}
                  </label>
                  <div className="flex flex-wrap gap-1.5">
                    {[
                      { key: "digits", label: t("hashCrypto.csDigits") },
                      { key: "lower", label: t("hashCrypto.csLower") },
                      { key: "upper", label: t("hashCrypto.csUpper") },
                      { key: "special", label: t("hashCrypto.csSpecial") },
                    ].map((c) => (
                      <button
                        key={c.key}
                        onClick={() => setRandCharset({ ...randCharset, [c.key]: !randCharset[c.key] })}
                        className={`rounded-full px-2.5 py-1 text-[11px] font-medium transition-colors ${
                          randCharset[c.key]
                            ? "bg-neutral-900 text-white dark:bg-white dark:text-neutral-900"
                            : "bg-neutral-100 text-neutral-600 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-700"
                        }`}
                      >
                        {c.label}
                      </button>
                    ))}
                  </div>
                </div>
                <button
                  onClick={runRandom}
                  disabled={!Object.values(randCharset).some(Boolean)}
                  className="pill pill-hover w-full justify-center"
                >
                  <IconPlay size={14} />
                  {t("hashCrypto.generate")}
                </button>
                {randResult && (
                  <div className="flex items-center gap-2 rounded-xl border border-neutral-200 bg-neutral-50 p-2 dark:border-neutral-800 dark:bg-neutral-900">
                    <code className="flex-1 font-mono text-xs break-all">{randResult}</code>
                    <button onClick={() => navigator.clipboard.writeText(randResult)} className="pill pill-outline pill-hover text-[10px]">
                      <IconCopy size={10} />
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* UUID */}
            {cryptoSubTab === "uuid" && (
              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                    {t("hashCrypto.uuidVersion")}
                  </label>
                  <select className="field w-full text-xs" value={uuidVersion} onChange={(e) => setUuidVersion(e.target.value)}>
                    <option value="v1">v1 (时间戳)</option>
                    <option value="v4">v4 (随机)</option>
                    <option value="v5">v5 (SHA-1)</option>
                  </select>
                </div>
                <button onClick={runUuid} className="pill pill-hover w-full justify-center">
                  <IconPlay size={14} />
                  {t("hashCrypto.generate")}
                </button>
                {uuidResult && (
                  <div className="flex items-center gap-2 rounded-xl border border-neutral-200 bg-neutral-50 p-2 dark:border-neutral-800 dark:bg-neutral-900">
                    <code className="flex-1 font-mono text-xs break-all">{uuidResult}</code>
                    <button onClick={() => navigator.clipboard.writeText(uuidResult)} className="pill pill-outline pill-hover text-[10px]">
                      <IconCopy size={10} />
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* 文件格式识别 */}
            {cryptoSubTab === "filefmt" && (
              <div className="space-y-3">
                <div>
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
                    <button onClick={selectFile} className="pill pill-outline pill-hover text-xs">
                      <IconFile size={14} />
                      {t("common.select")}
                    </button>
                  </div>
                </div>
                {fileFormatResult && (
                  <div className="rounded-xl border border-neutral-200 p-3 dark:border-neutral-800">
                    <div className="space-y-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-neutral-500 dark:text-neutral-400">{t("hashCrypto.fileFormat")}</span>
                        <span className="font-medium">{fileFormatResult.format || "-"}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-neutral-500 dark:text-neutral-400">{t("hashCrypto.mimeType")}</span>
                        <span className="font-mono">{fileFormatResult.mime || "-"}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-neutral-500 dark:text-neutral-400">{t("hashCrypto.fileExt")}</span>
                        <span className="font-mono">{fileFormatResult.extension || "-"}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-neutral-500 dark:text-neutral-400">{t("netsec.fileSize")}</span>
                        <span className="font-mono">{fileFormatResult.size || "-"}</span>
                      </div>
                      {fileFormatResult.description && (
                        <div className="pt-1 border-t border-neutral-100 dark:border-neutral-800">
                          <p className="text-neutral-500 dark:text-neutral-400">{t("hashCrypto.description")}</p>
                          <p className="mt-1 text-neutral-700 dark:text-neutral-300">{fileFormatResult.description}</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
