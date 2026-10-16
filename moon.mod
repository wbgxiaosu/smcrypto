// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html

name = "wbgxiaosu/smcrypto"

version = "0.4.0"

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
  "toolsfx",
]

preferred_target = "wasm-gc"

description = "基于 2d5rrr333/toolsfx-moonbit 的国密工程化扩展：RFC 8998 符合的 SM4-GCM 认证加密、SM4 CTR、HMAC-SM3（RFC 2104）、PBKDF2-HMAC-SM3（RFC 8018），核心 SM3/SM4/SM2 原语委托 toolsfx-moonbit / Engineering-grade GM extension for toolsfx-moonbit: RFC 8998-conformant SM4-GCM, CTR, HMAC-SM3 and PBKDF2-HMAC-SM3"

import {
  "2d5rrr333/toolsfx-moonbit@0.3.0",
}
