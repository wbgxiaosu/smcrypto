# 项目申报书

**1. 项目名称**

smcrypto —— MoonBit 国密算法基础库（SM3/SM4）

**2. 项目简介**

这个选题来自一次生态调研：我翻了一遍 mooncakes.io，发现 Base64、JSON、压缩这类编码工具都有，但作为国内支付、政务、工控场景刚需的国密算法，生态里只有一个桌面工具 ToolsFx 的移植版顺带覆盖（toolsfx-moonbit，依赖通用密码学库 mooncry），没有零依赖、可单独引入的轻量实现。参考 Java 的 BouncyCastle、Go 的 tjfoc/gmsm 都是独立基础库的做法，我把 SM3/SM4 做成了纯 MoonBit 的国密底座：SM3 密码杂凑（GB/T 32905-2016）、SM4 分组密码（GB/T 32907-2016）四种工作模式（ECB/CBC/CTR/GCM），外加 HMAC-SM3、SM3-KDF（GB/T 32918.3-2016 5.4.2）与 PBKDF2-HMAC-SM3 口令派生。已发布 mooncakes.io（wbgxiaosu/smcrypto v0.3.0），一行依赖即可使用。

**3. 项目方向与通用性**

方向是密码学基础库，定位为可复用的纯计算组件，不绑定任何界面、协议与运行方式，只提供"给我输入，还你正确结果"的算法能力。它在生态里的角色类似 Go 生态的 gmsm——所有需要国密能力的 MoonBit 应用（签名工具、口令管理、安全通信）复用同一个经过标准向量验证的内核，而不是各自照着国标文本重写一遍并在轮函数上犯不同的错。实现上零第三方依赖（仅 moonbitlang/core），可编译到 wasm-gc / js / native 全后端。

**4. 预期使用场景**

- 接口签名与消息防篡改：后端服务间通行的 HMAC-SHA256 方案在国内合规场景需换成 HMAC-SM3，本库提供 RFC 2104 结构的 HMAC-SM3，测试含篡改检测演示，可直接用于网关签名、Webhook 校验。
- 口令存储与密钥派生：登录系统不能明文存口令，PBKDF2-HMAC-SM3（RFC 8018）支持可调迭代次数与输出长度，配合 SM3-KDF 覆盖 SM2 密钥协商场景的派生需求（GB/T 32918.3 5.4.2）。
- 文件与传输的认证加密：SM4-GCM（SP 800-38D）一次完成加密与完整性校验，16 字节标签篡改即失败，已用 IETF RFC 8998 附录 A 官方向量逐字节对拍，适用于文件加密存储与轻量安全信道。

三个场景复用同一套 SM3/SM4 内核，这正是基础库的意义所在。

**5. 拟实现的核心功能**

SM3 流式（new/update/finalize/reset）与一次性双 API；SM4 密钥扩展、单块加解密及 ECB/CBC（PKCS7 填充）/CTR/GCM 四种模式，轮函数采用合成 T 表实现（S 盒与线性变换合并为单次查表，等价性经两万随机字验证）；HMAC-SM3、SM3-KDF、PBKDF2-HMAC-SM3；hexutil 十六进制编解码与根包 API 再导出。正确性以三层验证兜底：国标附录向量、51+24 条与独立 Python gmssl 基准的交叉对拍、RFC 8998 官方向量，共 30 组测试，三后端 CI 全绿。

**6. 项目性质**

原创项目，算法代码全部按国标与 RFC 文本从零编写，未复用任何现有项目源码。需要说明的是：生态内已有 toolsfx-moonbit 覆盖 SM2/SM3/SM4（ToolsFx 的移植版），按章程 4.1 要求说明两者关系——本项目与其是同一算法领域的独立实现，且在其未覆盖的方向上做了扩展（SM4-GCM、PBKDF2-HMAC-SM3 均为该库没有的能力）。选择独立建设而非在其上扩展的理由：它是面向 CTF 场景的大而全工具箱移植，依赖 mooncry 且自 8 月底起未再更新，不适合作为上层应用的公共依赖底座；两者定位不同、可并存按需选用。

**7. 移植项目说明**

不适用（非移植项目）。开发中仅参考三类公开资料：国标附录 A 的 S 盒/FK/CK 常量表、RFC 8998 的 SM4-GCM 测试向量、Python gmssl（LGPL-3.0，仅用于生成对拍用测试向量，不参与实现）。

**8. GitHub 仓库链接**

https://github.com/wbgxiaosu/smcrypto （master 分支 18 条有效提交，按功能拆分）

目前核心功能已完成：30 组测试全部通过、moon check 零警告、CI 三后端全绿，已发布 mooncakes.io（https://mooncakes.io/docs/#/wbgxiaosu/smcrypto/）。README 提供完整 API 表、标准向量值、向量来源与复现步骤（`moon test` 即可复跑全部对拍）。
