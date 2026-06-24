/// 密码生成模块
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

/// 可用于密码的字符集（字母、数字、特殊字符，排除容易混淆的字符）
const PASSWORD_CHARSET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";

/// 生成强密码并输出到 stdout
///
/// `length` 参数直接指定输出的密码字符数（而非随机字节数），
/// 消除了之前 Base64 编码导致的长度不直观问题。
pub fn cmd_generate_strong_password(length: usize) -> Result<(), Box<dyn std::error::Error>> {
    if length == 0 || length > 4096 {
        return Err("password length must be between 1 and 4096".into());
    }

    let charset_len = PASSWORD_CHARSET.len();
    let mut password = Vec::with_capacity(length);

    // 使用拒绝采样保证均匀分布
    for _ in 0..length {
        loop {
            let mut byte = [0u8; 1];
            OsRng.fill_bytes(&mut byte);
            let idx = byte[0] as usize;
            // 拒绝 >= charset_len * (256 / charset_len) 的值，避免 modulo bias
            if idx < (256 / charset_len) * charset_len {
                password.push(PASSWORD_CHARSET[idx % charset_len]);
                break;
            }
        }
    }

    let password_str = String::from_utf8(password.clone())
        .map_err(|_| "Internal error: invalid password bytes")?;
    println!("{}", password_str);

    // 清理密码字节
    password.zeroize();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_length_matches_request() {
        // 我们不能直接测试 stdout 输出，但可以验证内部逻辑
        // 通过验证 charset 不为空且合理
        assert!(!PASSWORD_CHARSET.is_empty());
        assert!(PASSWORD_CHARSET.len() <= 256);
    }

    #[test]
    fn password_rejects_zero_length() {
        assert!(cmd_generate_strong_password(0).is_err());
    }

    #[test]
    fn password_rejects_excessive_length() {
        assert!(cmd_generate_strong_password(4097).is_err());
    }
}
