// yxpil · NETON
//! 弱口令分析工具
//! 提供常见弱密码库检测和密码强度评估功能

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// 密码强度等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordStrength {
    VeryWeak = 0,
    Weak = 1,
    Fair = 2,
    Good = 3,
    Strong = 4,
    VeryStrong = 5,
}

impl PasswordStrength {
    pub fn to_label(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "非常弱",
            PasswordStrength::Weak => "弱",
            PasswordStrength::Fair => "一般",
            PasswordStrength::Good => "良好",
            PasswordStrength::Strong => "强",
            PasswordStrength::VeryStrong => "非常强",
        }
    }

    pub fn to_score(&self) -> u8 {
        *self as u8
    }
}

/// 密码分析详情
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordAnalysis {
    pub password: String,
    pub is_weak: bool,
    pub strength: PasswordStrength,
    pub score: u8,
    pub length: usize,
    pub has_uppercase: bool,
    pub has_lowercase: bool,
    pub has_digits: bool,
    pub has_special: bool,
    pub is_common_password: bool,
    pub has_repeated_chars: bool,
    pub has_sequential_chars: bool,
    pub suggestions: Vec<String>,
}

/// 弱密码批量检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakPasswordBatchResult {
    pub total_count: usize,
    pub weak_count: usize,
    pub weak_passwords: Vec<PasswordAnalysis>,
    pub strong_count: usize,
}

/// 获取内置弱密码库
pub fn get_weak_password_dictionary() -> HashSet<&'static str> {
    let passwords = vec![
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "abc123", "football", "monkey",
        "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890", "michael",
        "654321", "superman", "1qaz2wsx", "7777777", "121212",
        "000000", "qazwsx", "123qwe", "killer", "trustno1",
        "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
        "buster", "soccer", "harley", "batman", "andrew",
        "tigger", "sunshine", "iloveyou", "2000", "charlie",
        "robert", "thomas", "hockey", "ranger", "daniel",
        "starwars", "klaster", "112233", "george", "computer",
        "michelle", "jessica", "pepper", "1111", "zxcvbn",
        "555555", "11111111", "131313", "freedom", "777777",
        "passw0rd", "hello", "chicken", "access", "6969",
        "101010", "123654", "matrix", "zzzzzz", "password1",
        "999999", "qwerty123", "123abc", "a123456", "123456a",
        "1q2w3e4r", "q1w2e3r4", "1234qwer", "qwer1234", "asdf1234",
        "admin", "admin123", "root", "toor", "password123",
        "welcome", "welcome1", "welcome123", "test", "test123",
        "guest", "guest123", "default", "default123", "changeme",
    ];
    passwords.into_iter().collect()
}

/// 检查密码是否为常见弱密码
pub fn is_common_password(password: &str) -> bool {
    let dict = get_weak_password_dictionary();
    dict.contains(password)
        || dict.contains(password.to_lowercase().as_str())
}

/// 检测是否有重复字符模式
fn has_repeated_chars(password: &str) -> bool {
    if password.len() < 3 {
        return false;
    }
    let chars: Vec<char> = password.chars().collect();
    // 检查连续3个相同字符
    for i in 0..chars.len().saturating_sub(2) {
        if chars[i] == chars[i + 1] && chars[i + 1] == chars[i + 2] {
            return true;
        }
    }
    // 检查重复模式如 "ababab"
    if password.len() >= 6 {
        for pat_len in 2..=3 {
            if password.len() >= pat_len * 3 {
                let pat = &password[..pat_len];
                let mut all_match = true;
                for chunk in 1..3 {
                    let start = chunk * pat_len;
                    if &password[start..start + pat_len] != pat {
                        all_match = false;
                        break;
                    }
                }
                if all_match {
                    return true;
                }
            }
        }
    }
    false
}

/// 检测是否有连续字符
fn has_sequential_chars(password: &str) -> bool {
    if password.len() < 4 {
        return false;
    }
    let chars: Vec<char> = password.chars().collect();
    let mut forward = 0;
    let mut backward = 0;

    for i in 1..chars.len() {
        if chars[i] as i32 == chars[i - 1] as i32 + 1 {
            forward += 1;
            if forward >= 3 {
                return true;
            }
        } else {
            forward = 0;
        }
        if chars[i] as i32 == chars[i - 1] as i32 - 1 {
            backward += 1;
            if backward >= 3 {
                return true;
            }
        } else {
            backward = 0;
        }
    }
    false
}

/// 评估密码强度
pub fn analyze_password(password: String) -> Result<String, String> {
    let length = password.len();
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digits = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    let is_common = is_common_password(&password);
    let repeated = has_repeated_chars(&password);
    let sequential = has_sequential_chars(&password);

    let mut score: i32 = 0;

    // 长度评分
    score += match length {
        0..=4 => -5,
        5..=6 => 0,
        7..=8 => 5,
        9..=12 => 10,
        13..=16 => 15,
        _ => 20,
    };

    // 字符多样性评分
    if has_uppercase {
        score += 5;
    }
    if has_lowercase {
        score += 5;
    }
    if has_digits {
        score += 5;
    }
    if has_special {
        score += 10;
    }

    // 惩罚项
    if is_common {
        score -= 25;
    }
    if repeated {
        score -= 10;
    }
    if sequential {
        score -= 10;
    }
    if length > 0 && has_digits && !has_lowercase && !has_uppercase && !has_special {
        score -= 10; // 纯数字
    }
    if length > 0 && has_lowercase && !has_uppercase && !has_digits && !has_special {
        score -= 5; // 纯小写字母
    }

    // 映射到强度等级
    let strength = match score {
        i32::MIN..=0 => PasswordStrength::VeryWeak,
        1..=10 => PasswordStrength::Weak,
        11..=20 => PasswordStrength::Fair,
        21..=30 => PasswordStrength::Good,
        31..=40 => PasswordStrength::Strong,
        _ => PasswordStrength::VeryStrong,
    };

    let is_weak = matches!(
        strength,
        PasswordStrength::VeryWeak | PasswordStrength::Weak
    );

    let mut suggestions = Vec::new();

    if length < 8 {
        suggestions.push("密码长度建议至少8位".to_string());
    }
    if !has_uppercase {
        suggestions.push("建议添加大写字母".to_string());
    }
    if !has_lowercase {
        suggestions.push("建议添加小写字母".to_string());
    }
    if !has_digits {
        suggestions.push("建议添加数字".to_string());
    }
    if !has_special {
        suggestions.push("建议添加特殊字符".to_string());
    }
    if is_common {
        suggestions.push("此密码在常见弱密码库中，请更换".to_string());
    }
    if repeated {
        suggestions.push("避免使用重复字符模式".to_string());
    }
    if sequential {
        suggestions.push("避免使用连续字符序列".to_string());
    }
    if suggestions.is_empty() {
        suggestions.push("密码强度良好，继续保持".to_string());
    }

    let analysis = PasswordAnalysis {
        password: password.clone(),
        is_weak,
        strength,
        score: strength.to_score(),
        length,
        has_uppercase,
        has_lowercase,
        has_digits,
        has_special,
        is_common_password: is_common,
        has_repeated_chars: repeated,
        has_sequential_chars: sequential,
        suggestions,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(analysis, "密码分析完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}

/// 批量检测弱密码
pub fn check_weak_passwords(passwords: Vec<String>) -> Result<String, String> {
    let mut weak_passwords = Vec::new();
    let mut strong_count = 0;

    for password in &passwords {
        let result_str = analyze_password(password.clone())?;
        let analysis: crate::netsec::ToolResult<PasswordAnalysis> =
            serde_json::from_str(&result_str).map_err(|e| e.to_string())?;

        if let Some(data) = analysis.data {
            if data.is_weak {
                weak_passwords.push(data);
            } else {
                strong_count += 1;
            }
        }
    }

    let result = WeakPasswordBatchResult {
        total_count: passwords.len(),
        weak_count: weak_passwords.len(),
        weak_passwords,
        strong_count,
    };

    serde_json::to_string(&crate::netsec::ToolResult::ok(result, "批量检测完成"))
        .map_err(|e| format!("序列化失败: {}", e))
}
