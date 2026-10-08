# smcrypto 项目申报书

## 基本信息

- 项目名称：smcrypto：国密算法（SM3/SM4）的 MoonBit 实现
- 参赛者：wbgxiaosu
- 联系方式：1684128842@qq.com
- GitHub 仓库链接：https://github.com/wbgxiaosu/smcrypto
- 项目方向：MoonBit 密码学基础库 / 安全基础设施
- 是否为移植项目：否

## 项目简介

smcrypto 为 MoonBit 生态补齐国密商用密码算法，当前实现了 SM3 密码杂凑（GB/T 32905-2016）与 SM4 分组密码（GB/T 32907-2016），并在此基础上提供 HMAC-SM3 消息认证码、SM3-KDF 密钥派生函数（GB/T 32918.3-2016 5.4.2）以及 SM4 的 ECB/CBC/CTR 三种工作模式。项目面向需要在 MoonBit 中做数据完整性校验、消息认证、对称加解密或密钥派生的库作者、工具开发者和应用开发者，可作为上层安全通信、文件校验、接口签名等工具的公共底座。

申报前已对 mooncakes.io 全站和 GitHub 上 sm3、sm4、guomi、cipher、crypto 等关键词进行检索，确认 MoonBit 生态此前没有国密算法实现，mooncrypt、crypto.mbt 等通用密码学库也不包含 SM 系列。本项目为原创实现，算法代码按国标文本与 RFC 2104 规范独立编写，纯 MoonBit 实现、仅依赖 moonbitlang/core，在 wasm-gc、js、native 三个后端上行为一致，已发布至 mooncakes（`moon add wbgxiaosu/smcrypto`）。

## 核心功能范围

- 提供 SM3 杂凑实现，支持流式计算（new/update/finalize/reset）与一次性摘要（digest/hex_digest），可处理任意长度分段输入；
- 提供 HMAC-SM3 消息认证码，遵循 RFC 2104 结构，超长密钥按规范预哈希；
- 提供 SM3-KDF 密钥派生函数，与 SM2 加密、密钥交换规范中使用的 KDF 一致，可作为 SM2/SM9 移植的基础；
- 提供 SM4 密钥扩展、单块加解密，以及 ECB/CBC（PKCS7 填充）和 CTR（无填充、密文等长）工作模式；
- SM4 轮函数采用合成 T 表实现，将 S 盒替换与线性变换合并为单次查表，合并等价性先经 2 万随机字验证再生成代码；
- 提供 hexutil 十六进制编解码，解码错误可定位到具体字符位置；
- 根包再导出常用 API，`moon add` 后单个包即可完成常用操作；
- 提供 cmd 演示程序，覆盖全部公开原语，包括国标向量走查与 HMAC 篡改检测示例；
- 正确性经国标附录标准向量验证，并与 Python gmssl 实现交叉对拍（51 条 SM3 向量、24 组 SM4 向量），共 25 组测试保持全绿；
- 提供 README（安装方式、API 表、标准向量值、复现步骤）与 GitHub Actions CI，在三个后端上执行 check/build/test。

## 交付边界

本项目不包含 SM2/SM9 椭圆曲线算法（工作量数倍于本库，适合作为独立项目申报）；不做侧信道防护（wasm 目标下威胁模型不同，README 中已声明该边界）；不封装 TLS 等协议层。以上作为后续扩展方向。

## 原创性说明

- 本项目为原创实现，非移植项目；
- 算法代码依据 GB/T 32905-2016、GB/T 32907-2016、GB/T 32918.3-2016 国标文本与 RFC 2104 规范独立编写，未复制任何现有项目源码；
- S 盒、FK、CK 常量表取自国标附录 A 公开数据；
- Python gmssl（LGPL-3.0，https://github.com/duanhongyi/gmssl）仅用于生成交叉对拍用的测试向量，不参与本库实现；
- 本项目采用 Apache-2.0 许可证。
