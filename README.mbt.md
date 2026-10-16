# wbgxiaosu/smcrypto

基于 [2d5rrr333/toolsfx-moonbit](https://github.com/2d5rrr333/toolsfx-moonbit) v0.3.0 的国密工程化扩展：RFC 8998 符合的 SM4-GCM 认证加密、SM4 CTR、HMAC-SM3、PBKDF2-HMAC-SM3。

核心国密原语（SM3 杂凑、SM4 单块与 ECB/CBC、SM3-KDF）委托上游 toolsfx-moonbit（ISC License，已通过 GB/T 32905/32907 国标向量）；本项目专注上游未覆盖或不符合标准的部分。

## 安装

```bash
moon add wbgxiaosu/smcrypto
```

## 能力清单

| 能力 | 来源 | 验证 |
|------|------|------|
| SM3 摘要（一次性/流式） | 委托上游 | 国标向量 + 51 条 gmssl 交叉对拍 |
| SM4 ECB/CBC（PKCS7） | 委托上游 | 国标向量 + 24 组交叉对拍 + 往返测试 |
| SM3-KDF（GB/T 32918.3 5.4.2） | 委托上游 | 国标向量 |
| SM4 CTR | 本项目实现 | 往返测试 + 交叉对拍 |
| SM4-GCM（SP 800-38D） | 本项目实现 | RFC 8998 附录 A.1 密文+标签逐字节对拍 + 篡改检测 |
| HMAC-SM3（RFC 2104） | 本项目新增 | RFC 2104 结构向量 + 篡改检测 |
| PBKDF2-HMAC-SM3（RFC 8018） | 本项目新增 | 独立 Python 基准交叉对拍（迭代 1~80000、跨块、长密钥、截断） |

## 为什么 GCM 是本项目实现的

以上游 `sm4_gcm_encrypt` 对 RFC 8998 附录 A.1 官方向量实测：按 `[key, iv, plaintext, aad]` 语义调用时密文输出仅 20 字节（输入 64 字节）；按其内部校验唯一接受的 `[key, iv, aad, plaintext]` 序调用，标签为 `09976f85...`，与 RFC 8998 规定的 `83de3541e4c2b58177e065a9bf7b62ec` 不一致。本项目 GCM 在上游 SM4 单块原语之上实现完整 SP 800-38D 流程，密文与标签均与 RFC 8998 逐字节一致。

## 快速上手

```moonbit nocheck
// GCM 认证加密（16 字节标签，支持任意长度 IV 与 AAD）
let (ct, tag) = @smcrypto.sm4_encrypt_gcm(key, iv, plaintext, aad).unwrap()
// 解密自动校验标签，篡改返回 AuthenticationFailed
let pt = @smcrypto.sm4_decrypt_gcm(key, iv, ct, tag, aad).unwrap()

// HMAC-SM3 / PBKDF2-HMAC-SM3
let mac = @smcrypto.sm3_hmac(key, message)
let dk  = @smcrypto.sm3_pbkdf2(b"password", b"salt", 4096, 32)

// SM3 / SM4 ECB、CBC、CTR、KDF 亦可经根包直接使用
let hex = @smcrypto.sm3_hex_digest(b"abc")   // 国标示例 1
```

## 可复现验证

```bash
moon check        # 零警告
moon test         # 30 组测试（含 RFC 8998、国标、gmssl 交叉对拍）
moon run cmd/main # 演示全流程
```

测试向量来源：RFC 8998 附录 A（GCM）、GB/T 32905/32907 附录（核心向量）、`gen/vectors.json` 与 `gen/pbkdf2_vectors.json`（Python gmssl 基准生成，脚本见 `gen/gen_*.py`）。

## 交付边界

不包含 SM2/SM9（上游已提供完整实现）；不做侧信道防护；不封装协议层。

## License

Apache-2.0（本项目）；上游 toolsfx-moonbit 为 ISC License。
