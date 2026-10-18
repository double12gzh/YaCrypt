/// 密码生成模块
use crate::error::CryptError;
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// 可用于密码的字符集（字母、数字、特殊字符，排除容易混淆的字符）
const PASSWORD_CHARSET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";

/// 生成指定字符长度的强密码（使用拒绝采样保证均匀分布，返回 Zeroizing<String>）
pub fn generate_strong_password(length: usize) -> Result<Zeroizing<String>, CryptError> {
    if length == 0 || length > 4096 {
        return Err(CryptError::Key("password length must be between 1 and 4096".into()));
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

    match String::from_utf8(password) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err(CryptError::Crypto("Internal error: invalid password bytes".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_length_matches_request() {
        assert!(!PASSWORD_CHARSET.is_empty());
        assert!(PASSWORD_CHARSET.len() <= 256);
        let pw = generate_strong_password(32).unwrap();
        assert_eq!(pw.len(), 32);
    }

    #[test]
    fn password_rejects_zero_length() {
        assert!(generate_strong_password(0).is_err());
    }

    #[test]
    fn password_rejects_excessive_length() {
        assert!(generate_strong_password(4097).is_err());
    }
}
