# wbgxiaosu/smcrypto

国密算法库（SM3 + SM4，含 GCM 认证加密、HMAC、KDF、PBKDF2），纯 MoonBit 实现、零依赖。

## 安装

```bash
moon add wbgxiaosu/smcrypto
```

## SM3 密码杂凑（GB/T 32905-2016）

```moonbit nocheck
// 一次性计算（返回十六进制串）
let hex : String = @smcrypto.sm3_hex_digest(b"abc")
// = "66c7f0f4..."（国标示例 1）

// 流式计算
let h = @sm3.Sm3::new()
h.update(part1)
h.update(part2)
let digest : Bytes = h.finalize()  // 32 字节
```

## SM4 分组密码（GB/T 32907-2016）

```moonbit nocheck
let key = @hexutil.decode("0123456789abcdeffedcba9876543210").unwrap()
let iv  = @hexutil.decode("000102030405060708090a0b0c0d0e0f").unwrap()
let pt  = @utf8.encode("攻击开始于黎明！")

let ct   = @smcrypto.sm4_encrypt_cbc(key, iv, pt).unwrap()
let back = @smcrypto.sm4_decrypt_cbc(key, iv, ct).unwrap()
assert_eq(back, pt)
```

另有 ECB 模式（`sm4_encrypt_ecb` / `sm4_decrypt_ecb`，PKCS7 填充）、CTR 计数器模式（`sm4_encrypt_ctr` / `sm4_decrypt_ctr`，无填充输出等长）与单块操作（`Sm4::new` + `encrypt_block` / `decrypt_block`）。

## SM4-GCM 认证加密（NIST SP 800-38D）

```moonbit nocheck
let gcm_iv = @hexutil.decode("00001234567800000000ABCD").unwrap()
let aad    = @utf8.encode("header:v1")   // 附加认证数据，可为空
let (ct, tag) = @smcrypto.sm4_encrypt_gcm(key, gcm_iv, pt, aad).unwrap()
// 解密：标签不符返回 Err(Sm4Error::AuthenticationFailed)
let back = @smcrypto.sm4_decrypt_gcm(key, gcm_iv, ct, tag, aad).unwrap()
```

## HMAC-SM3、SM3-KDF 与 PBKDF2

```moonbit nocheck
// 消息认证码（RFC 2104 结构）
///|
let mac : Bytes = @smcrypto.sm3_hmac(key, message)

// 密钥派生（GB/T 32918.3-2016 5.4.2，SM2/SM9 使用）

///|
let derived : Bytes = @smcrypto.sm3_kdf(shared_secret, 32)

// 口令基密钥派生（RFC 8018）

///|
let dk : Bytes = @smcrypto.sm3_pbkdf2(b"password", b"salt", 4096, 32)
```

## 验证

- 国标标准测试向量全通过（SM3 示例 1/2、SM4 标准示例）
- 与 Python `gmssl` 交叉对拍：51 条 SM3 向量、24 组 SM4 向量
- SM4-GCM 以 **IETF RFC 8998 附录 A.1 官方向量**逐字节对拍（密文 + 认证标签 + 篡改检测）
- PBKDF2-HMAC-SM3 与 Python 独立基准实现交叉对拍（`gen/pbkdf2_vectors.json`）
- `wasm-gc` / `js` / `native` 三后端测试一致

### 测试向量来源与复现

1. `gen/vectors.json`：以 Python `gmssl` 库为基准生成（该库实现先通过 GB/T 32905-2016 / 32907-2016 国标标准向量校验，生成脚本见仓库 `gen/gen_*.py`）。
2. `sm3/sm3_vectors_test.mbt`、`sm4/sm4_vectors_test.mbt`：由 `gen/gen_sm3_tests.py`、`gen/gen_sm4_tests.py` 自动生成的 MoonBit 测试，文件头部注明来源。
3. SM4-GCM：直接采用 IETF RFC 8998 官方测试向量（IETF 标准文档可自由引用）。
4. PBKDF2-HMAC-SM3：以 Python `gmssl` SM3 + 手写 RFC 2104 / RFC 8018 结构的独立基准生成（`gen/pbkdf2_vectors.json`）。
5. 三种输入方式交叉验证：一次性计算、随机分片流式输入、逐字节流式输入，结果一致。

```bash
moon check   # 零警告
moon test    # 30 组测试
moon run cmd/main   # 可复现演示（含 RFC 8998 对拍）
```

## 与生态中其他国密库的关系

mooncakes 上另有 `2d5rrr333/toolsfx-moonbit`（ToolsFx 桌面工具的 MoonBit 移植，覆盖 SM2/SM3/SM4 及编码、古典密码等）。本项目为按国标文本独立编写的原创实现（非移植、非 fork），定位为聚焦 SM3/SM4 的轻量底座：零依赖、SM4 合成 T 表性能优化、流式 API、RFC 8998 对拍，并提供 GCM 认证加密与 PBKDF2-HMAC-SM3。两个项目可按需并存选用。

## License

Apache-2.0
