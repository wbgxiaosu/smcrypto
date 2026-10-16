// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html

name = "wbgxiaosu/smcrypto"

version = "0.3.0"

readme = "README.mbt.md"

repository = "https://github.com/wbgxiaosu/smcrypto"

license = "Apache-2.0"

keywords = [
  "sm3",
  "sm4",
  "chinese-national-cryptography",
  "hash",
  "cipher",
  "hmac",
  "kdf",
  "gcm",
  "aead",
  "pbkdf2",
]

preferred_target = "wasm-gc"

description = "国密算法库：SM3 密码杂凑（GB/T 32905-2016）与 SM4 分组密码（GB/T 32907-2016），含 ECB/CBC/CTR/GCM、HMAC-SM3、SM3-KDF、PBKDF2-HMAC-SM3，纯 MoonBit 零依赖、国标向量与 RFC 8998 对拍 / Pure-MoonBit Chinese national cryptography: SM3 hash and SM4 block cipher with ECB/CBC/CTR/GCM, HMAC, KDF and PBKDF2, zero-dependency, RFC 8998 cross-validated"
