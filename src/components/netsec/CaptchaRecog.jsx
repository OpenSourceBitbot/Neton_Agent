import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLang } from "../../i18n.js";
import { IconImage, IconUpload } from "../Icons.jsx";

/**
 * 验证码识别工具
 * 支持图片上传和URL方式识别验证码
 */
export default function CaptchaRecog({ onClose }) {
  const { t } = useLang();
  const [imageUrl, setImageUrl] = useState("");
  const [imageData, setImageData] = useState("");
  const [recognizing, setRecognizing] = useState(false);
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [captchaType, setCaptchaType] = useState("auto");

  const selectImageFile = async () => {
    try {
      const data = await invoke("open_image_dialog");
      if (data) {
        setImageData(data);
        setImageUrl("");
        setResult("");
      }
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    }
  };

  const recognizeFromUrl = async () => {
    if (!imageUrl.trim()) return;
    setRecognizing(true);
    setError("");
    setResult("");
    try {
      const res = await invoke("captcha_recognize_url", {
        url: imageUrl.trim(),
        type: captchaType,
      });
      setResult(res?.text || "");
      setImageData(res?.image_data || "");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setRecognizing(false);
    }
  };

  const recognizeFromFile = async () => {
    if (!imageData) return;
    setRecognizing(true);
    setError("");
    setResult("");
    try {
      const res = await invoke("captcha_recognize", {
        imageData,
        type: captchaType,
      });
      setResult(res?.text || "");
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setRecognizing(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <circle cx="9" cy="9" r="2" />
            <path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.captchaRecog")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <div className="mb-4 space-y-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.captchaType")}
          </label>
          <select className="field w-full" value={captchaType} onChange={(e) => setCaptchaType(e.target.value)}>
            <option value="auto">{t("netsec.autoDetect")}</option>
            <option value="char">{t("netsec.charCaptcha")}</option>
            <option value="math">{t("netsec.mathCaptcha")}</option>
            <option value="slide">{t("netsec.slideCaptcha")}</option>
            <option value="click">{t("netsec.clickCaptcha")}</option>
          </select>
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
            {t("netsec.imageUrl")}
          </label>
          <div className="flex gap-2">
            <input
              className="field flex-1 font-mono text-xs"
              value={imageUrl}
              onChange={(e) => setImageUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && recognizeFromUrl()}
              placeholder="https://example.com/captcha.jpg"
            />
            <button
              onClick={recognizeFromUrl}
              disabled={recognizing || !imageUrl.trim()}
              className="pill pill-outline pill-hover"
            >
              {t("netsec.recognize")}
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-800" />
          <span className="text-[11px] text-neutral-400">{t("common.or")}</span>
          <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-800" />
        </div>

        <button
          onClick={selectImageFile}
          className="w-full rounded-2xl border-2 border-dashed border-neutral-300 p-6 text-center transition-colors hover:border-neutral-400 dark:border-neutral-700 dark:hover:border-neutral-600"
        >
          <IconUpload size={24} className="mx-auto mb-2 text-neutral-400" />
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            {t("netsec.uploadImage")}
          </p>
          <p className="mt-1 text-xs text-neutral-400">{t("netsec.supportFormats")}</p>
        </button>

        {imageData && (
          <div className="rounded-2xl border border-neutral-200 p-3 dark:border-neutral-800">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
                {t("netsec.preview")}
              </span>
              <button
                onClick={recognizeFromFile}
                disabled={recognizing}
                className="pill pill-hover text-xs"
              >
                {recognizing ? t("common.running") : t("netsec.recognize")}
              </button>
            </div>
            <img
              src={imageData}
              alt="captcha"
              className="mx-auto max-h-24 rounded-lg"
            />
          </div>
        )}
      </div>

      {error && <p className="mb-2 text-xs text-red-500">{error}</p>}

      {/* 识别结果 */}
      {result && (
        <div className="rounded-2xl border border-emerald-200 bg-emerald-50/50 p-4 dark:border-emerald-900/30 dark:bg-emerald-950/20">
          <p className="mb-2 text-xs font-medium text-emerald-700 dark:text-emerald-400">
            {t("netsec.recogResult")}
          </p>
          <p className="font-mono text-lg font-bold text-emerald-700 dark:text-emerald-300 tracking-wider">
            {result}
          </p>
        </div>
      )}
    </div>
  );
}
