// SM3 密码杂凑算法 —— 适配层
// 核心实现委托给 2d5rrr333/toolsfx-moonbit/sm（ISC License，
// 上游按 GB/T 32905-2016 实现并通过国标向量）。
// 本包保留稳定的流式 API（new/update/finalize/reset），
// 并在其上提供上游没有的 HMAC-SM3 与 PBKDF2-HMAC-SM3。

///|
/// SM3 流式哈希器（适配上游流式实现）。
pub struct Sm3 {
  /// 上游流式哈希器实例
  mut inner : @sm.Sm3
}

///|
/// 新建一个 SM3 哈希器，处于初始状态。
pub fn Sm3::new() -> Sm3 {
  { inner: @sm.Sm3::new(), }
}

///|
/// 重置哈希器到初始状态，可复用计算下一条消息。
pub fn Sm3::reset(self : Sm3) -> Unit {
  self.inner = @sm.Sm3::new()
}

///|
/// 吸收一段消息。可多次调用，顺序即消息顺序。
pub fn Sm3::update(self : Sm3, data : Bytes) -> Unit {
  self.inner.update(data)
}

///|
/// 结束哈希并输出 32 字节摘要。
pub fn Sm3::finalize(self : Sm3) -> Bytes {
  self.inner.finalize()
}

///|
/// 一次性计算消息 `data` 的 SM3 摘要，返回 32 字节。
pub fn digest(data : Bytes) -> Bytes {
  @sm.sm3(data)
}

///|
/// 一次性计算消息 `data` 的 SM3 摘要，返回小写十六进制字符串（64 字符）。
pub fn hex_digest(data : Bytes) -> String {
  @hexutil.encode(digest(data))
}
