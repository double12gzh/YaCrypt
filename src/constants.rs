/// 常量定义
pub const MAGIC: &[u8; 6] = b"SGPGv1"; // magic + version marker
pub const DEFAULT_ARGON_M_COST_KIB: u32 = 1 << 16; // 65536 KiB = 64 MiB
pub const DEFAULT_ARGON_T_COST: u32 = 2;
pub const DEFAULT_ARGON_P_COST: u32 = 1;
pub const SALT_LEN: usize = 16;
pub const XNONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const MIN_PASSWORD_LENGTH: usize = 12;
pub const MAX_PASSWORD_LENGTH: usize = 1024;
pub const PUBENC_MAGIC: &[u8; 5] = b"SCFv1"; // pubenc file magic + version
pub const PUBENC_FLAG_HAS_SIGNATURE: u8 = 0x01;
pub const MAX_ARGON_M_COST_KIB: u32 = 1 << 22; // 4 GiB max, prevents OOM from malicious blobs
pub const MAX_ARGON_T_COST: u32 = 100;
pub const MAX_ARGON_P_COST: u32 = 16;
