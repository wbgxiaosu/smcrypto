# smcrypto 项目申报书（v2，重新提交）

## 基本信息

- 项目名称：smcrypto：SM3/SM4 国密算法的 MoonBit 轻量底座
- 参赛者：wbgxiaosu
- 联系方式：1684128842@qq.com
- GitHub 仓库链接：https://github.com/wbgxiaosu/smcrypto
- 项目方向：MoonBit 密码学基础库 / 安全基础设施
- 是否为移植项目：否
- 版本：v0.3.0（已发布 mooncakes，`moon add wbgxiaosu/smcrypto`）

## 与已有生态项目的关系（针对初审意见的扩展说明）

初审指出本项目与 `2d5rrr333/toolsfx-moonbit` 的 SM3/SM4 能力重叠。经核查确认该判断属实，特此说明两者关系：toolsfx-moonbit 是桌面工具 ToolsFx 的 MoonBit 移植，定位为大而全的密码学/CTF 工具箱（SM2/SM3/SM4、古典密码、编码转换等，依赖通用密码学库 mooncry）。本项目与其是**同一算法领域的独立原创实现，并在此基础上面向不同定位做了能力扩展**：

- 独立原创：算法代码按 GB/T 32905-2016、GB/T 32907-2016、GB/T 32918.3-2016 国标文本与 RFC 2104/8018 规范独立编写，非移植、非 fork、未复用其任何源码；零第三方依赖（仅依赖 moonbitlang/core），而 toolsfx-moonbit 依赖 mooncry；
- 定位差异：本项目聚焦 SM3/SM4 的轻量工程底座，SM4 轮函数采用合成 T 表实现（S 盒替换与线性变换合并为单次查表，合并等价性经 2 万随机字验证），适合作为上层应用的公共依赖；
- 能力扩展（v0.3.0 新增）：SM4-GCM 认证加密（国标未定义工作模式之外的扩展，以 IETF RFC 8998 附录 A.1 官方向量逐字节对拍，含密文、标签与篡改检测）与 PBKDF2-HMAC-SM3 口令基密钥派生（RFC 8018），均为生态内现有国密库未覆盖的能力；
- 验证深度：51 条 SM3 向量、24 组 SM4 向量与独立 Python gmssl 基准交叉对拍，加 RFC 8998 官方向量，共 30 组测试，wasm-gc/js/native 三后端 CI 全绿。

两者可并存按需选用：需要大而全工具箱与 SM2 时可用 toolsfx-moonbit；需要零依赖、聚焦、带 GCM 与 PBKDF2 的国密底座时用本项目。

## 项目简介

smcrypto 为 MoonBit 生态提供聚焦 SM3/SM4 的国密基础库：SM3 密码杂凑（流式 API）、SM4 分组密码（ECB/CBC/CTR/GCM 四种工作模式）、HMAC-SM3 消息认证码、SM3-KDF 密钥派生函数（GB/T 32918.3-2016 5.4.2）与 PBKDF2-HMAC-SM3 口令派生，可作为上层安全通信、文件校验、接口签名、口令存储等工具的公共底座。

## 核心功能范围

- SM3：流式（new/update/finalize/reset）与一次性（digest/hex_digest）双 API，任意长度分段输入；
- SM4：密钥扩展、单块加解密，ECB/CBC（PKCS7 填充）、CTR（密文等长）、GCM（认证加密，16 字节标签，支持任意长度 IV 与 AAD）；
- HMAC-SM3（RFC 2104）、SM3-KDF（GB/T 32918.3-2016 5.4.2）、PBKDF2-HMAC-SM3（RFC 8018）；
- SM4 轮函数合成 T 表优化（8 张 256 项 32 位表）；
- hexutil 十六进制编解码（解码错误定位到具体字符位置）；根包再导出常用 API；
- cmd 可复现演示（国标向量走查、RFC 8998 对拍、HMAC 篡改检测）；
- 正确性：国标附录向量 + gmssl 交叉对拍 + RFC 8998 官方向量，30 组测试全绿，三后端 CI；
- README 提供安装方式、API 表、标准向量值、向量来源与复现步骤。

## 交付边界

本项目不包含 SM2/SM9 椭圆曲线算法（生态内 toolsfx-moonbit 已提供 SM2 实现，可直接复用，避免重复造轮子）；不做侧信道防护（wasm 目标下威胁模型不同，README 已声明该边界）；不封装 TLS 等协议层。以上作为后续扩展方向。

## 原创性说明

- 本项目为原创实现，非移植项目；
- 算法代码依据 GB/T 32905-2016、GB/T 32907-2016、GB/T 32918.3-2016 国标文本与 RFC 2104/8018 规范独立编写，未复制任何现有项目（含 toolsfx-moonbit）源码；
- S 盒、FK、CK 常量表取自国标附录 A 公开数据；
- Python gmssl（LGPL-3.0，https://github.com/duanhongyi/gmssl）仅用于生成交叉对拍用的测试向量，不参与本库实现；
- SM4-GCM 测试向量取自 IETF RFC 8998（SM Cipher Suites for TLS 1.3）附录 A；
- 本项目采用 Apache-2.0 许可证。
