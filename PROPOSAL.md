# 项目申报书

**1. 项目名称**

smcrypto —— 基于 toolsfx-moonbit 的国密工程化扩展（RFC 8998 合规 GCM、HMAC-SM3、PBKDF2）

**2. 项目简介**

这个项目源于我对 mooncakes 生态国密库的调研与实测。生态里已有 2d5rrr333/toolsfx-moonbit（ToolsFx 的 MoonBit 移植，ISC 许可）提供 SM2/SM3/SM4 核心能力，我以它为上游做工程化扩展，专补三块它没有做好的事：一是**认证加密**——我用 RFC 8998 附录 A.1 官方向量实测其 sm4_gcm_encrypt，发现无论按哪种参数序调用，密文长度或认证标签都与标准不符（自然语义下密文只有 20 字节，另一种序下标签不匹配），于是我在它的 SM4 单块原语之上实现了一个完整通过 RFC 8998 逐字节对拍的 GCM；二是**口令学基建**——补上它没有的 HMAC-SM3（RFC 2104）和 PBKDF2-HMAC-SM3（RFC 8018）；三是把国标向量、gmssl 交叉对拍、RFC 8998 对拍沉淀成 30 组可一键复跑的测试。已发布 mooncakes.io（wbgxiaosu/smcrypto v0.4.0，依赖 2d5rrr333/toolsfx-moonbit@0.3.0）。

**3. 项目方向与通用性**

方向是密码学工程库，定位为上游 toolsfx-moonbit 的"符合性+扩展层"：上游管算法内核，本项目管工程可用性——认证加密、口令派生、统一的错误处理与流式 API。所有需要国密认证加密或口令存储的 MoonBit 应用（安全通信、文件加密、登录系统）都可以复用这一层，而不必每个应用自己拿分组原语拼 GCM——拼错 GHASH 位约定或计数器进位是这类实现最常见的出错方式，RFC 8998 向量就是为此准备的验收线。

**4. 预期使用场景**

- 接口签名与消息防篡改：后端服务间通行的 HMAC-SHA256 方案在国内合规场景需换成 HMAC-SM3，本库提供 RFC 2104 结构的 HMAC-SM3，测试含篡改检测演示，可直接用于网关签名、Webhook 校验。
- 口令存储与密钥派生：登录系统不能明文存口令，PBKDF2-HMAC-SM3（RFC 8018）支持可调迭代次数与输出长度，与独立 Python 基准交叉对拍（迭代 1~80000、跨块、长密钥预哈希、截断输出）。
- 文件与传输的认证加密：SM4-GCM 一次完成加密与完整性校验，16 字节标签篡改即失败，已用 RFC 8998 官方向量逐字节对拍，适用于文件加密存储与轻量安全信道——这也是上游现有 GCM 无法保证的。

三个场景复用同一个经验证的扩展层。

**5. 拟实现的核心功能**

在上游 SM4 单块原语之上的 SM4-GCM（GHASH GF(2^128)、J0 派生、任意长度 IV/AAD、流式边界补零，RFC 8998 附录 A.1 密文与标签逐字节一致）与 SM4 CTR（128 位大端计数器整块进位）；HMAC-SM3 与 PBKDF2-HMAC-SM3；对上游 ECB/CBC/KDF 的委托封装与统一错误约定；根包 API 再导出与 hexutil 编解码。正确性以三层验证兜底：RFC 8998 官方向量、国标向量、与独立 Python gmssl 基准的交叉对拍，共 30 组测试，wasm-gc/js/native 三后端 CI 全绿。

**6. 项目性质**

本项目为**基于已有生态项目 2d5rrr333/toolsfx-moonbit 的扩展**（其 moon.mod 与 README 均声明 ISC 许可，允许任意使用），非移植项目：核心 SM3/SM4/SM2 原语直接依赖上游（moon.mod 声明 `2d5rrr333/toolsfx-moonbit@0.3.0`），本项目代码不重复实现国标算法本体，只做工作模式、口令学扩展与符合性验证。选择扩展而非另起炉灶的理由：GCM 属于工作模式层，本就应共享同一套分组原语；上游的 SM4 单块与 KDF 均通过国标向量，作为依赖是可靠的；而它的 GCM 与 RFC 8998 不符且缺少 HMAC/PBKDF2，恰好构成明确的扩展空间。扩展过程中发现的上游 GCM 问题已记录实测证据（README 附复现步骤）。

**7. 参考项目说明**

上游依赖：2d5rrr333/toolsfx-moonbit，https://github.com/2d5rrr333/toolsfx-moonbit ，ISC License（mooncakes: 2d5rrr333/toolsfx-moonbit@0.3.0）。开发中另参考两类公开资料：IETF RFC 8998 的 SM4-GCM 测试向量；Python gmssl（LGPL-3.0，https://github.com/duanhongyi/gmssl ，仅用于生成交叉对拍测试向量，不参与本库实现）。

**8. GitHub 仓库链接**

https://github.com/wbgxiaosu/smcrypto （master 分支有效提交按功能拆分）

目前核心功能已完成：30 组测试全部通过、moon check 零警告、CI 三后端全绿，已发布 mooncakes.io（https://mooncakes.io/docs/#/wbgxiaosu/smcrypto/ ，v0.4.0）。README 提供上游委托关系表、GCM 重写的实测依据与完整复现步骤（`moon test` 即可复跑全部对拍）。
