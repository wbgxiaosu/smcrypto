# wbgxiaosu/smcrypto

**基于 [2d5rrr333/toolsfx-moonbit](https://github.com/2d5rrr333/toolsfx-moonbit) 的国密工程化扩展：RFC 8998 符合的 SM4-GCM 认证加密、SM4 CTR、HMAC-SM3、PBKDF2-HMAC-SM3。**

An engineering-grade GM (Chinese national cryptography) extension for toolsfx-moonbit: RFC 8998-conformant SM4-GCM, SM4 CTR, HMAC-SM3 and PBKDF2-HMAC-SM3.

## 与上游的关系

本项目构建于 `2d5rrr333/toolsfx-moonbit` v0.3.0（ISC License）之上：SM3 杂凑、SM4 单块加解密与 ECB/CBC 模式、SM3-KDF 等**核心国密原语直接委托上游实现**（上游已通过 GB/T 32905/32907 国标向量），本项目专注补齐上游未覆盖或不符合标准的部分：

| 能力 | 状态 | 说明 |
|------|------|------|
| SM3 摘要（一次性/流式） | 委托上游 | `@sm.sm3` / `Sm3` 流式 |
| SM4 ECB/CBC（PKCS7） | 委托上游 | `@sm.sm4_ecb_*` / `sm4_cbc_*` |
| SM3-KDF（GB/T 32918.3 5.4.2） | 委托上游 | `@sm.sm2_kdf`（国标向量对拍通过） |
| SM4 CTR | 本项目实现 | 128 位大端计数器整块进位，基于上游单块原语 |
| **SM4-GCM** | **本项目实现** | 上游 GCM 无法通过 RFC 8998 对拍（见下文实测），本项目提供符合 RFC 8998 附录 A.1 的实现 |
| HMAC-SM3 | 本项目新增 | RFC 2104 结构，上游无此能力 |
| PBKDF2-HMAC-SM3 | 本项目新增 | RFC 8018，上游无此能力 |

### 为什么 GCM 要重写：对上游的实测

以上游 `sm4_gcm_encrypt` 对 RFC 8998 附录 A.1 官方向量（K=0123456789ABCDEFFEDCBA9876543210，IV=00001234567800000000ABCD）实测：

- 按 `[key, iv, plaintext, aad]` 语义调用：密文输出仅 20 字节（输入 64 字节），长度即错误；
- 按 `[key, iv, aad, plaintext]` 调用（其内部校验唯一接受的参数序）：密文长度正确但**认证标签为 `09976f85...`，与 RFC 8998 规定的 `83de3541e4c2b58177e065a9bf7b62ec` 不一致**，密文亦不符。

本项目的 GCM 在上游 SM4 单块原语之上实现完整 SP 800-38D 流程（GHASH GF(2^128)、J0 派生、任意长度 IV/AAD、流式边界补零），密文与标签均与 RFC 8998 逐字节一致，并含篡改检测测试。复现：`moon test`（`sm4/gcm_test.mbt`）或 `moon run cmd/main`。

## 快速开始

```bash
moon add wbgxiaosu/smcrypto
```

### SM3 摘要与 HMAC

```moonbit
let digest : Bytes = @smcrypto.sm3_digest(b"abc")
let mac : Bytes = @smcrypto.sm3_hmac(b"secret-key", b"message")
// 流式
let h = @smcrypto.@sm3.Sm3::new()
h.update(b"part1"); h.update(b"part2")
let d : Bytes = h.finalize()
```

### SM4 工作模式

```moonbit
let key = @hexutil.decode("0123456789abcdeffedcba9876543210").unwrap()
// ECB / CBC（PKCS7 填充）
let ct = @smcrypto.sm4_encrypt_cbc(key, iv, plaintext).unwrap()
// CTR（密文等长）
let ct = @smcrypto.sm4_encrypt_ctr(key, counter, plaintext).unwrap()
// GCM 认证加密（RFC 8998 对拍，16 字节标签，支持任意长度 IV 与 AAD）
let (ct, tag) = @smcrypto.sm4_encrypt_gcm(key, iv, plaintext, aad).unwrap()
// 解密自动校验标签，篡改返回 AuthenticationFailed
let pt = @smcrypto.sm4_decrypt_gcm(key, iv, ct, tag, aad).unwrap()
```

### PBKDF2 口令派生

```moonbit
let dk = @smcrypto.sm3_pbkdf2(b"password", b"salt", 4096, 32)
```

## 可复现验证

```bash
git clone https://github.com/wbgxiaosu/smcrypto
cd smcrypto
moon check        # 零警告
moon test         # 30 组测试
moon run cmd/main # 演示：国标向量 + RFC 8998 对拍 + HMAC 篡改检测
```

### 测试构成与来源

1. **委托层回归**：SM3 国标向量、SM4 国标单块向量、51 条 gmssl 交叉对拍向量（`gen/vectors.json`，由 `gen/gen_*.py` 生成）——验证核心委托链路正确；
2. **KDF**：GB/T 32918.3-2016 国标向量（验证上游 `sm2_kdf` 委托）；
3. **SM4-GCM**：RFC 8998 附录 A.1 官方向量（密文+标签逐字节）+ 篡改检测；
4. **PBKDF2-HMAC-SM3**：与独立 Python 基准（gmssl）交叉对拍，迭代 1~80000、跨块、长密钥预哈希、截断输出（`gen/pbkdf2_vectors.json`）。

## 交付边界

本项目不包含 SM2/SM9（上游已提供完整 SM2 签名/加密/DER）；不做侧信道防护（wasm 目标下威胁模型不同）；不封装 TLS 等协议层。上游 toolsfx-moonbit 与本项目均以 ISC/Apache-2.0 开源，可独立或组合使用。

## License

Apache-2.0。上游 2d5rrr333/toolsfx-moonbit 为 ISC License。
