// SM3 密钥派生函数（KDF）—— 适配层
// 依据：GB/T 32918.3-2016《信息安全技术 SM2 椭圆曲线公钥密码算法 第 3 部分：
// 密钥交换协议》5.4.2。核心计算委托上游 @sm.sm2_kdf（同一国标实现，
// 已通过国标向量对拍），本包提供统一的错误约定（klen <= 0 返回空字节串）。

///|
/// SM3 密钥派生函数：`KDF(Z, klen)`。
/// 计数器 ct 从 1 开始逐块拼接 SM3(Z || ct_be32)，截取前 `klen` 字节。
/// `klen <= 0` 返回空字节串。
pub fn kdf(z : Bytes, klen : Int) -> Bytes {
  if klen <= 0 {
    return Bytes::from_array(FixedArray::make(0, b'\x00'))
  }
  @sm.sm2_kdf(z, klen)
}
