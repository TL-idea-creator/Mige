//! 随机密码生成与强度评估（规则与鸿蒙版 `crypto/PasswordGen.ets` 一致）。

use rand::Rng;

use crate::types::PasswordRule;

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/~";
/// 易混淆字符：大写 I、小写 l、数字 1、大写 O、数字 0、小写 o
const AMBIGUOUS: &str = "Il1O0o";

fn filter_chars(source: &str, exclude: &str) -> String {
    source.chars().filter(|c| !exclude.contains(*c)).collect()
}

/// 从字符池中等概率取一个字符（拒绝采样，消除取模偏差）
fn pick_random(pool: &[char]) -> char {
    let len = pool.len() as u32;
    let limit = 256 - (256 % len);
    let mut rng = rand::thread_rng();
    loop {
        let value = rng.gen_range(0..256u32);
        if value < limit {
            return pool[(value % len) as usize];
        }
    }
}

/// 统计当前规则下可选字符总量
pub fn available_char_count(rule: &PasswordRule) -> usize {
    let mut pool = String::new();
    if rule.upper {
        pool.push_str(UPPER);
    }
    if rule.lower {
        pool.push_str(LOWER);
    }
    if rule.digits {
        pool.push_str(DIGITS);
    }
    if rule.symbols {
        pool.push_str(SYMBOLS);
    }
    if rule.exclude_ambiguous {
        pool = filter_chars(&pool, AMBIGUOUS);
    }
    pool.chars().count()
}

/// 按规则生成密码：每个启用的字符类别至少出现一次，其余从合并字符池中取，最后洗牌
pub fn generate(rule: &PasswordRule) -> String {
    let exclude = if rule.exclude_ambiguous { AMBIGUOUS } else { "" };
    let mut groups: Vec<Vec<char>> = Vec::new();

    let candidates: [(&str, bool); 4] = [
        (UPPER, rule.upper),
        (LOWER, rule.lower),
        (DIGITS, rule.digits),
        (SYMBOLS, rule.symbols),
    ];
    for (chars, enabled) in candidates {
        if !enabled {
            continue;
        }
        let filtered: Vec<char> = filter_chars(chars, exclude).chars().collect();
        if !filtered.is_empty() {
            groups.push(filtered);
        }
    }
    if groups.is_empty() {
        return String::new();
    }

    let pool: Vec<char> = groups.iter().flatten().copied().collect();
    let target_len = rule.length.max(groups.len());

    let mut result: Vec<char> = Vec::with_capacity(target_len);
    // 先保证每个类别至少一个
    for group in &groups {
        result.push(pick_random(group));
    }
    while result.len() < target_len {
        result.push(pick_random(&pool));
    }

    // Fisher–Yates 洗牌，打散类别位置
    let mut rng = rand::thread_rng();
    for i in (1..result.len()).rev() {
        let j = rng.gen_range(0..=i);
        result.swap(i, j);
    }
    result.into_iter().collect()
}

/// 粗略强度评估：0 空 / 1 很弱 / 2 较弱 / 3 较强 / 4 很强
pub fn strength(password: &str) -> u32 {
    if password.is_empty() {
        return 0;
    }
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 30;
    }
    if pool == 0 {
        return 0;
    }
    let entropy = password.chars().count() as f64 * (pool as f64).log2();
    if entropy < 30.0 {
        1
    } else if entropy < 50.0 {
        2
    } else if entropy < 70.0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(length: usize) -> PasswordRule {
        PasswordRule { length, ..Default::default() }
    }

    #[test]
    fn length_respected() {
        for len in [8usize, 12, 16, 32, 64] {
            assert_eq!(generate(&rule(len)).chars().count(), len);
        }
    }

    #[test]
    fn every_class_present() {
        for _ in 0..30 {
            let pwd = generate(&rule(8));
            assert!(pwd.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pwd.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pwd.chars().any(|c| c.is_ascii_digit()));
            assert!(pwd.chars().any(|c| !c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn exclude_ambiguous() {
        let r = PasswordRule { length: 32, exclude_ambiguous: true, ..Default::default() };
        for _ in 0..30 {
            let pwd = generate(&r);
            for ch in ['I', 'l', '1', 'O', '0', 'o'] {
                assert!(!pwd.contains(ch), "不应包含易混淆字符 {ch}");
            }
        }
    }

    #[test]
    fn no_class_returns_empty() {
        let r = PasswordRule { upper: false, lower: false, digits: false, symbols: false, ..Default::default() };
        assert!(generate(&r).is_empty());
    }

    #[test]
    fn candidate_count() {
        assert_eq!(available_char_count(&rule(16)), 26 + 26 + 10 + 25);
        let r = PasswordRule { exclude_ambiguous: true, ..Default::default() };
        assert_eq!(available_char_count(&r), 26 + 26 + 10 + 25 - 6);
    }

    #[test]
    fn strength_scale() {
        assert_eq!(strength(""), 0);
        assert_eq!(strength("abc"), 1);
        assert_eq!(strength("Abc12345"), 2);
        assert!(strength("aB3$kL9#mN2@qR5%") >= 3);
    }
}
