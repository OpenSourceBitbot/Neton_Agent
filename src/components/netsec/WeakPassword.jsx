import { useState, useMemo } from "react";
import { useLang } from "../../i18n.js";

/**
 * 弱口令分析工具
 * 检测密码强度并给出改进建议
 */
export default function WeakPassword({ onClose }) {
  const { t } = useLang();
  const [password, setPassword] = useState("");

  const analysis = useMemo(() => {
    if (!password) {
      return { score: 0, level: "", issues: [], suggestions: [] };
    }

    const issues = [];
    const suggestions = [];
    let score = 0;

    // 长度检查
    if (password.length < 6) {
      issues.push(t("netsec.pwdTooShort"));
      suggestions.push(t("netsec.pwdSuggestLength"));
    } else if (password.length >= 8) {
      score += 20;
    } else {
      score += 10;
    }

    if (password.length >= 12) score += 10;
    if (password.length >= 16) score += 10;

    // 小写字母
    if (/[a-z]/.test(password)) {
      score += 15;
    } else {
      issues.push(t("netsec.pwdNoLower"));
      suggestions.push(t("netsec.pwdSuggestLower"));
    }

    // 大写字母
    if (/[A-Z]/.test(password)) {
      score += 15;
    } else {
      issues.push(t("netsec.pwdNoUpper"));
      suggestions.push(t("netsec.pwdSuggestUpper"));
    }

    // 数字
    if (/[0-9]/.test(password)) {
      score += 15;
    } else {
      issues.push(t("netsec.pwdNoDigit"));
      suggestions.push(t("netsec.pwdSuggestDigit"));
    }

    // 特殊字符
    if (/[^a-zA-Z0-9]/.test(password)) {
      score += 15;
    } else {
      issues.push(t("netsec.pwdNoSpecial"));
      suggestions.push(t("netsec.pwdSuggestSpecial"));
    }

    // 常见弱密码检测
    const weakPasswords = ["password", "123456", "12345678", "qwerty", "abc123", "admin", "letmein", "welcome", "monkey", "dragon"];
    if (weakPasswords.includes(password.toLowerCase())) {
      score = Math.min(score, 10);
      issues.push(t("netsec.pwdCommonWeak"));
      suggestions.push(t("netsec.pwdSuggestUnique"));
    }

    // 重复字符检测
    if (/(.)\1{2,}/.test(password)) {
      score -= 10;
      issues.push(t("netsec.pwdRepeatChars"));
    }

    // 连续字母/数字
    if (/(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
      score -= 10;
      issues.push(t("netsec.pwdSequential"));
    }

    score = Math.max(0, Math.min(100, score));

    let level = "";
    let levelColor = "";
    if (score < 30) {
      level = t("netsec.pwdWeak");
      levelColor = "text-red-500";
    } else if (score < 50) {
      level = t("netsec.pwdFair");
      levelColor = "text-orange-500";
    } else if (score < 70) {
      level = t("netsec.pwdGood");
      levelColor = "text-yellow-500";
    } else if (score < 90) {
      level = t("netsec.pwdStrong");
      levelColor = "text-lime-500";
    } else {
      level = t("netsec.pwdVeryStrong");
      levelColor = "text-emerald-500";
    }

    return { score, level, levelColor, issues, suggestions };
  }, [password, t]);

  return (
    <div className="flex h-full flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
          <h3 className="text-base font-semibold">{t("netsec.weakPassword")}</h3>
        </div>
        <button onClick={onClose} className="text-neutral-400 hover:text-neutral-700 dark:hover:text-white">
          ✕
        </button>
      </div>

      <div className="mb-4">
        <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
          {t("netsec.enterPassword")}
        </label>
        <input
          type="password"
          className="field w-full font-mono"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={t("netsec.passwordPlaceholder")}
        />
      </div>

      {/* 强度评分 */}
      {password && (
        <div className="mb-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
              {t("netsec.strengthScore")}
            </span>
            <span className={`text-sm font-bold ${analysis.levelColor}`}>
              {analysis.level} ({analysis.score}/100)
            </span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                analysis.score < 30 ? "bg-red-500" :
                analysis.score < 50 ? "bg-orange-500" :
                analysis.score < 70 ? "bg-yellow-500" :
                analysis.score < 90 ? "bg-lime-500" : "bg-emerald-500"
              }`}
              style={{ width: `${analysis.score}%` }}
            />
          </div>
        </div>
      )}

      {/* 检测结果 */}
      <div className="flex-1 overflow-auto space-y-4">
        {password && analysis.issues.length > 0 && (
          <div className="rounded-2xl border border-red-200 bg-red-50/50 p-3 dark:border-red-900/30 dark:bg-red-950/20">
            <h4 className="mb-2 text-xs font-semibold text-red-600 dark:text-red-400">
              {t("netsec.issuesFound")} ({analysis.issues.length})
            </h4>
            <ul className="space-y-1">
              {analysis.issues.map((issue, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-red-700 dark:text-red-300">
                  <span className="text-red-500">•</span>
                  {issue}
                </li>
              ))}
            </ul>
          </div>
        )}

        {password && analysis.suggestions.length > 0 && (
          <div className="rounded-2xl border border-neutral-200 p-3 dark:border-neutral-800">
            <h4 className="mb-2 text-xs font-semibold text-neutral-600 dark:text-neutral-400">
              {t("netsec.suggestions")}
            </h4>
            <ul className="space-y-1">
              {analysis.suggestions.map((s, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-neutral-600 dark:text-neutral-400">
                  <span className="text-emerald-500">✓</span>
                  {s}
                </li>
              ))}
            </ul>
          </div>
        )}

        {!password && (
          <div className="flex h-full items-center justify-center text-sm text-neutral-400">
            {t("netsec.enterToAnalyze")}
          </div>
        )}
      </div>
    </div>
  );
}
