/// 统一错误类型模块
use std::fmt;
use std::io;

/// 应用级错误类型，替代 `Box<dyn Error>` 和裸 `String`
#[derive(Debug)]
pub enum CryptError {
    /// IO 操作错误（文件读写、权限等）
    Io(io::Error),
    /// 加密/解密操作错误
    Crypto(String),
    /// 文件格式解析错误（blob、pubenc 格式不正确）
    Format(String),
    /// 密钥相关错误（长度、编码、派生等）
    Key(String),
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptError::Io(e) => write!(f, "IO error: {}", e),
            CryptError::Crypto(s) => write!(f, "Crypto error: {}", s),
            CryptError::Format(s) => write!(f, "Format error: {}", s),
            CryptError::Key(s) => write!(f, "Key error: {}", s),
        }
    }
}

impl std::error::Error for CryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CryptError {
    fn from(e: io::Error) -> Self {
        CryptError::Io(e)
    }
}

impl From<String> for CryptError {
    fn from(s: String) -> Self {
        CryptError::Crypto(s)
    }
}

impl From<&str> for CryptError {
    fn from(s: &str) -> Self {
        CryptError::Crypto(s.to_string())
    }
}
