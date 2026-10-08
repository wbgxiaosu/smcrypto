# MoonBit 十月黑客松项目申报书（草稿）

> 提交方式：由本人在报名问卷中填写/粘贴。以下按问卷常见字段组织。

## 项目名称

smcrypto —— MoonBit 国密算法基础库（SM3 + SM4）

## 一句话简介

为 MoonBit 生态提供符合国标 GB/T 32905-2016 / GB/T 32907-2016 的 SM3 密码杂凑与 SM4 分组密码算法库，纯 MoonBit 实现、零第三方依赖、三后端（wasm-gc / js / native）测试一致，国标标准向量与独立实现交叉对拍全部通过。

## 项目定位（可复用基础设施）

- **不是应用，是基础库**：供其他 MoonBit 项目 `moon add` 直接复用，为上层应用（安全通信、文件完整性校验、协议实现、区块链与数据签名工具）提供密码学原语。
- **国产化题材与大赛定位高度契合**：国密算法（SM 系列）是国家商用密码标准，是国产基础软件栈的关键组件。用国产编程语言 MoonBit 实现国密算法，是"国产语言 × 国 密码标准"的自然结合。
- **生态查重结论**：截至申报时，GitHub 与 mooncakes.io 上无任何 MoonBit 实现的 SM3/SM4（已逐项检索 `sm3`/`sm4`/`guomi`/`cipher`/`crypto` 等关键词，现有通用密码学库 mooncrypt、crypto.mbt 均未覆盖国密系列），本项目为 MoonBit 生态首个国密算法库。

## 功能清单

| 模块 | 能力 |
|------|------|
| `sm3/` | 256 位密码杂凑：一次性 `digest` / `hex_digest`，流式 `Sm3::new/update/finalize/reset`（任意分段、字节级流式一致） |
| `sm4/` | 128 位分组密码：密钥扩展、单块 `encrypt_block/decrypt_block`、ECB / CBC 工作模式、PKCS7 填充 |
| `hexutil/` | 十六进制编解码（密钥、IV、摘要的可读化与互转） |
| `cmd/main/` | 可复现演示：国标向量对拍 + 中英文消息加解密 roundtrip + 错误处理展示 |

## 正确性验证（硬指标）

1. **国标标准向量**：SM3 附录 A 示例 1（"abc"）、示例 2（"abcd"×16）；SM4 标准示例（密钥=明文=0123456789abcdeffedcba9876543210 → 密文 681edf34d206965e86b3e94f536e4246）全部通过。
2. **独立实现交叉对拍**：以 Python `gmssl` 库为基准（该基准先通过国标向量校验），生成 51 条 SM3 向量（含空消息、55/56/57/63/64/65 字节填充边界、UTF-8 中文、0-700 字节随机消息）与 24 组 SM4 向量（3 组密钥 × 8 组随机长度明文 × 随机 IV，ECB+CBC 加解密），全部一致。
3. **三种输入模式一致性**：一次性计算、随机分片流式、逐字节流式，结果完全一致。
4. **三后端一致性**：wasm-gc、js、native 三个后端 `moon test` 全部通过（CI 双 job 验证）。

## 工程质量

- `moon check` 零警告（含 moonc 0.10.14 全部新检查项：无弃用语法、无 implicit 提升方法）
- 14 组测试用例（底层断言 200+ 次），覆盖算法正确性、边界填充、错误分支、roundtrip
- GitHub Actions CI：`moon check` + `moon build` + `moon test`，另设 multi-backend job 覆盖 js / native
- 生成式测试基建：`gen/` 目录提供向量提取与测试代码生成脚本，测试可复现、可扩展
- 完整中文文档：README（含 API 表、验证方法、设计说明与安全边界声明）

## 开源合规

- License：Apache-2.0
- 零依赖：仅依赖 moonbitlang/core，无第三方代码，无许可证冲突
- 常量数据来源：SM3 IV、SM4 S 盒/FK/CK 均来自国标文本，不涉及第三方版权数据

## 赛期计划

- 赛期内完成：核心算法全部功能、交叉验证基建、CI 三后端覆盖、mooncakes 发布（v0.1.x）
- 可选增强（时间允许时）：SM3 HMAC 构造、SM4 CTR 模式、SM3-based KDF
- 发布渠道：mooncakes.io（`moon publish`）+ GitHub Releases

## 仓库与发布

- GitHub：https://github.com/wbgxiaosu/smcrypto
- mooncakes：https://mooncakes.io/docs/#/wbgxiaosu/smcrypto （验收前确保最新版已 `moon publish`）
