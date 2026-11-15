/// 常量定义
pub const MAGIC: &[u8; 6] = b"SGPGv1"; // magic + version 1 marker
pub const MAGIC_V2: &[u8; 6] = b"SGPGv2"; // magic + version 2 marker (length-hiding padded symmetric container)
pub const DEFAULT_ARGON_M_COST_KIB: u32 = 1 << 16; // 65536 KiB = 64 MiB
pub const DEFAULT_ARGON_T_COST: u32 = 2;
pub const DEFAULT_ARGON_P_COST: u32 = 1;
pub const SALT_LEN: usize = 16;
pub const XNONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const MIN_PASSWORD_LENGTH: usize = 12;
pub const MAX_PASSWORD_LENGTH: usize = 1024;
pub const PUBENC_MAGIC: &[u8; 5] = b"SCFv1"; // pubenc v1 file magic + version
pub const PUBENC_V2_MAGIC: &[u8; 5] = b"SCFv2"; // pubenc v2 file magic (encrypted inner signature + length-hiding padding)
pub const PUBENC_FLAG_HAS_SIGNATURE: u8 = 0x01;
pub const PUBENC_V2_INNER_VERSION: u8 = 0x02;
pub const SGPG_V2_INNER_VERSION: u8 = 0x02;
// SECURITY INVARIANT (YC-010): Do NOT shrink padding bounds or revert default encryption to SCFv1/SGPGv1.
pub const PADDING_MIN_FLOOR_BYTES: usize = 1024;
pub const PADDING_MIN_JITTER_BYTES: usize = 64;
pub const PADDING_MAX_JITTER_CAP_BYTES: usize = 4 * 1024 * 1024;
pub const MIN_ARGON_M_COST_KIB: u32 = 256; // 256 KiB minimum allowed
pub const MAX_ARGON_M_COST_KIB: u32 = 1 << 18; // 256 MiB max, prevents OOM/DoS from malicious blobs
pub const MAX_ARGON_T_COST: u32 = 16;
pub const MAX_ARGON_P_COST: u32 = 16;
