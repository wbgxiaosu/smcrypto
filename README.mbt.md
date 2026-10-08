# wbgxiaosu/smcrypto

国密算法库（SM3 + SM4），纯 MoonBit 实现、零依赖。

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

另有 ECB 模式（`sm4_encrypt_ecb` / `sm4_decrypt_ecb`，PKCS7 填充）与单块操作（`Sm4::new` + `encrypt_block` / `decrypt_block`）。

## 验证

- 国标标准测试向量全通过（SM3 示例 1/2、SM4 标准示例）
- 与 Python `gmssl` 交叉对拍：51 条 SM3 向量、24 组 SM4 向量
- `wasm-gc` / `js` / `native` 三后端测试一致

```bash
moon check   # 零警告
moon test    # 14 组测试
moon run cmd/main   # 可复现演示
```

## License

Apache-2.0
