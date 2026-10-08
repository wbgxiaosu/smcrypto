// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html

name = "wbgxiaosu/smcrypto"

version = "0.2.0"

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
]

preferred_target = "wasm-gc"

description = "国密算法库：SM3 密码杂凑（GB/T 32905-2016）与 SM4 分组密码（GB/T 32907-2016），纯 MoonBit 实现、零依赖、国标向量对拍 / Pure-MoonBit Chinese national cryptography: SM3 hash and SM4 block cipher with standard test vectors"
