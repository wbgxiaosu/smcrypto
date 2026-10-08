// SM3 密钥派生函数（KDF）
// 依据：GB/T 32918.3-2016《信息安全技术 SM2 椭圆曲线公钥密码算法 第 3 部分：
// 密钥交换协议》5.4.2。SM2/SM9 密钥协商与 SM2 加密均使用该 KDF，
// 输入共享秘密比特串 Z 与密钥长度 klen（字节），输出密钥数据比特串。

///|
/// SM3 密钥派生函数：`KDF(Z, klen)`。
/// 计数器 ct 从 1 开始，对 `SM3(Z || ct_be32)` 逐块拼接，
/// 截取前 `klen` 字节作为输出。`klen <= 0` 返回空字节串。
pub fn kdf(z : Bytes, klen : Int) -> Bytes {
  if klen <= 0 {
    return Bytes::from_array(FixedArray::make(0, b'\x00'))
  }
  let out : FixedArray[Byte] = FixedArray::make(klen, b'\x00')
  let mut filled = 0
  let mut ct : Int = 1
  while filled < klen {
    let h = Sm3::new()
    h.update(z)
    // ct 的 4 字节大端编码
    let cbe : FixedArray[Byte] = FixedArray::make(4, b'\x00')
    cbe[0] = ((ct >> 24) & 0xff).to_byte()
    cbe[1] = ((ct >> 16) & 0xff).to_byte()
    cbe[2] = ((ct >> 8) & 0xff).to_byte()
    cbe[3] = (ct & 0xff).to_byte()
    h.update(Bytes::from_array(cbe))
    let d = h.finalize()
    let n = if klen - filled < 32 { klen - filled } else { 32 }
    for i in 0..<n {
      out[filled + i] = d[i]
    }
    filled = filled + n
    ct = ct + 1
  }
  Bytes::from_array(out)
}
