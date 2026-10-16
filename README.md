# wbgxiaosu/smcrypto

**MoonBit 国密算法库：SM3 密码杂凑 + SM4 分组密码（ECB/CBC/CTR/GCM）+ HMAC + KDF + PBKDF2，纯 MoonBit 实现，零依赖。**

Chinese national cryptography (GM/T 国密) for MoonBit: SM3 hash and SM4 block cipher with authenticated encryption. Pure MoonBit, zero dependencies.

## 算法与标准

| 算法 | 标准 | 说明 |
|------|------|------|
| SM3 | GB/T 32905-2016 | 256 位密码杂凑（哈希）算法，流式 API 支持 |
| SM4 | GB/T 32907-2016 | 128 位分组密码，ECB / CBC / CTR / GCM 工作模式，PKCS7 填充 |
| SM4-GCM | NIST SP 800-38D | 认证加密，16 字节标签，以 RFC 8998 官方向量对拍 |
| HMAC-SM3 | RFC 2104 结构 | 基于 SM3 的消息认证码 |
| SM3-KDF | GB/T 32918.3-2016 5.4.2 | SM2/SM9 密钥派生函数 |
| PBKDF2-HMAC-SM3 | RFC 8018 | 口令基密钥派生 |

所有实现均已通过**国标附录标准测试向量**验证，并与独立的 Python `gmssl` 实现做了 51 条 SM3 向量、24 组 SM4 向量的**交叉对拍**（含 UTF-8 中文消息、填充边界长度 55/56/57/63/64/65 字节、随机分片流式输入）；SM4-GCM 通过 **IETF RFC 8998 附录 A.1 官方向量**对拍；PBKDF2-HMAC-SM3 与 Python 基准实现交叉对拍。

> 与生态的关系：mooncakes 上已有 `2d5rrr333/toolsfx-moonbit`（ToolsFx 移植，含 SM2/SM3/SM4 等大而全的工具箱）。本项目为**按国标文本独立编写的原创实现**（非移植、非 fork、未复用其代码），定位为聚焦 SM3/SM4 的轻量底座：零依赖、SM4 轮函数合成 T 表优化、流式 API、RFC 8998 对拍，并在 v0.3.0 补齐 GCM 与 PBKDF2-HMAC-SM3。两者可并存选用。

## 快速开始

```bash
moon add wbgxiaosu/smcrypto
```

### SM3 摘要

```moonbit
// 一次性计算
let hex = @smcrypto.sm3_hex_digest(b"abc")
// "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"（国标示例 1）

// 流式计算（大消息分段吸收）
let h = @sm3.Sm3::new()
h.update(part1)
h.update(part2)
let digest : Bytes = h.finalize()
```

### SM4 加解密

```moonbit
let key = @hexutil.decode("0123456789abcdeffedcba9876543210").unwrap()
let iv  = @hexutil.decode("000102030405060708090a0b0c0d0e0f").unwrap()
let pt  = @utf8.encode("攻击开始于黎明！")

// CBC 模式
let ct = @smcrypto.sm4_encrypt_cbc(key, iv, pt).unwrap()
let back = @smcrypto.sm4_decrypt_cbc(key, iv, ct).unwrap()
assert_eq(back, pt)

// 单块操作
let c = @smcrypto.sm4_new(key).unwrap()
let ct1 : Bytes = c.encrypt_block(std_block)
```

### SM4-GCM 认证加密

```moonbit
let iv  = @hexutil.decode("00001234567800000000ABCD").unwrap()
let aad = @utf8.encode("header:v1")
let (ct, tag) = @smcrypto.sm4_encrypt_gcm(key, iv, pt, aad).unwrap()
// 解密：标签不符返回 Err(AuthenticationFailed)
let back = @smcrypto.sm4_decrypt_gcm(key, iv, ct, tag, aad).unwrap()
```

### PBKDF2-HMAC-SM3 口令派生

```moonbit
let dk : Bytes = @smcrypto.sm3_pbkdf2(b"password", b"salt", 4096, 32)
```

## API 一览

### 根包 `@smcrypto`（便捷再导出）

| 函数 | 说明 |
|------|------|
| `sm3_digest(data : Bytes) -> Bytes` | SM3 摘要（32 字节） |
| `sm3_hex_digest(data : Bytes) -> String` | SM3 摘要（64 位十六进制串） |
| `sm4_new(key : Bytes) -> Result[Sm4, Sm4Error]` | 创建 SM4 密码器（密钥必须 16 字节） |
| `sm4_encrypt_ecb(key, pt) / sm4_decrypt_ecb(key, ct)` | ECB 模式（PKCS7） |
| `sm4_encrypt_cbc(key, iv, pt) / sm4_decrypt_cbc(key, iv, ct)` | CBC 模式（PKCS7） |
| `sm4_encrypt_ctr(key, ctr, pt) / sm4_decrypt_ctr(key, ctr, ct)` | CTR 模式（无填充，输出等长） |
| `sm4_encrypt_gcm(key, iv, pt, aad) -> (ct, tag)` | GCM 认证加密（16 字节标签） |
| `sm4_decrypt_gcm(key, iv, ct, tag, aad)` | GCM 认证解密（标签不符报 `AuthenticationFailed`） |
| `sm3_hmac(key, message) -> Bytes` | HMAC-SM3 消息认证码 |
| `sm3_kdf(z : Bytes, klen : Int) -> Bytes` | SM3 密钥派生函数 |
| `sm3_pbkdf2(password, salt, iterations, dklen) -> Bytes` | PBKDF2-HMAC-SM3 口令派生 |

### 子包

- `sm3/`：`Sm3::new / update / finalize / reset`、`digest`、`hex_digest`、`hmac`、`kdf`、`pbkdf2`
- `sm4/`：`Sm4::new / encrypt_block / decrypt_block`、`encrypt_ecb / decrypt_ecb / encrypt_cbc / decrypt_cbc / encrypt_ctr / decrypt_ctr / encrypt_gcm / decrypt_gcm`、`Sm4Error`
- `hexutil/`：十六进制 `encode / decode`（供密钥、IV 与结果的可读化处理）

## 可复现验证

```bash
git clone https://github.com/wbgxiaosu/smcrypto
cd smcrypto
moon check   # 零警告
moon test    # 30 组测试 / 国标向量 + 51 条 SM3、24 组 SM4 交叉对拍 + RFC 8998 官方向量
moon run cmd/main   # 演示：国标向量对拍 + RFC 8998 GCM 对拍 + PBKDF2
```

演示输出末尾为 SM4 国标单块向量与 RFC 8998 GCM 官方向量对拍：

```
国标单块向量    = 681edf34d206965e86b3e94f536e4246
国标期望        = 681edf34d206965e86b3e94f536e4246
RFC 8998 密文   = 17f399f08c67d5ee19d0dc9969c4bb7d…a56834cbcf98c397b4024a2691233b8d
RFC 8998 期望   = 17f399f08c67d5ee19d0dc9969c4bb7d…a56834cbcf98c397b4024a2691233b8d
RFC 8998 标签   = 83de3541e4c2b58177e065a9bf7b62ec
RFC 8998 期望   = 83de3541e4c2b58177e065a9bf7b62ec
```

### 测试向量来源与复现

1. `gen/vectors.json`：以 Python `gmssl` 库为基准生成（该库实现先通过 GB/T 32905-2016 / 32907-2016 国标标准向量校验，见 `gen/gen_*.py`）。
2. `sm3/sm3_vectors_test.mbt`、`sm4/sm4_vectors_test.mbt`：由 `gen/gen_sm3_tests.py`、`gen/gen_sm4_tests.py` 自动生成的 MoonBit 测试。
3. SM4-GCM：直接采用 **IETF RFC 8998 附录 A.1 官方测试向量**（SM4-GCM for TLS 1.3），密文与认证标签逐字节对拍，另含篡改检测用例。
4. PBKDF2-HMAC-SM3：以 Python `gmssl` SM3 + 手写 RFC 2104/8018 结构的独立基准实现生成（`gen/pbkdf2_vectors.json`），覆盖迭代 1/2/1000/4096/80000、跨派生块、长密钥预哈希、截断输出等场景。
5. 三种输入方式交叉验证：一次性计算、随机分片流式输入、逐字节流式输入，结果一致。

## 设计说明

- **纯 MoonBit、零第三方依赖**：仅依赖 `moonbitlang/core`；`wasm-gc` / `js` / `native` 三后端均可构建。
- **流式 API**：`Sm3` 支持任意长度分段 `update`，内部 64 字节缓冲自动处理填充边界。
- **合成 T 表**：SM4 轮函数将 S 盒替换与线性变换合并为单次查表（8 张 256 项 32 位表），合并正确性先经 2 万随机字的数学等价验证再生成代码。
- **健壮的错误类型**：`Sm4Error` / `HexError` 为代数数据类型，`derive(Eq, Debug)` 并提供中文可读 `to_string`；密钥/IV 长度、密文长度、PKCS7 填充合法性全部显式校验。
- **安全边界声明**：SM3 消息长度计数为 32 位字节计数，超过约 512 MiB 的消息长度域会失真（wasm-gc 场景下不构成实际限制）；本库面向协议互联与教学研究，未做侧信道防护，不建议直接用于生产密钥材料场景。

## License

Apache-2.0
