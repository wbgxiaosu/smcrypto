// HMAC-SM3 消息认证码
// 结构遵循 RFC 2104（HMAC: Keyed-Hashing for Message Authentication），
// 底层杂凑使用 SM3（GB/T 32905-2016），分组长度 64 字节。

///|
/// HMAC 分组长度（与 SM3 压缩块一致）。
let hmac_block_size : Int = 64

///|
/// 计算 HMAC-SM3：`mac = H(opad_key || H(ipad_key || message))`。
/// 密钥长度任意；超过 64 字节时先对密钥本身做一次 SM3。
pub fn hmac(key : Bytes, message : Bytes) -> Bytes {
  // 第 1 步：整理密钥到 64 字节
  let k : FixedArray[Byte] = FixedArray::make(hmac_block_size, b'\x00')
  if key.length() > hmac_block_size {
    let kh = digest(key)
    for i in 0..<32 {
      k[i] = kh[i]
    }
  } else {
    for i in 0..<key.length() {
      k[i] = key[i]
    }
  }
  // 第 2 步：ipad/opad 异或
  let inner : FixedArray[Byte] = FixedArray::make(hmac_block_size, b'\x00')
  let outer : FixedArray[Byte] = FixedArray::make(hmac_block_size, b'\x00')
  for i in 0..<hmac_block_size {
    inner[i] = (k[i].to_int() ^ 0x36).to_byte()
    outer[i] = (k[i].to_int() ^ 0x5c).to_byte()
  }
  // 第 3 步：内层 H(ipad || message)
  let h = Sm3::new()
  h.update(Bytes::from_array(inner))
  h.update(message)
  let inner_digest = h.finalize()
  // 第 4 步：外层 H(opad || inner)
  let h2 = Sm3::new()
  h2.update(Bytes::from_array(outer))
  h2.update(inner_digest)
  h2.finalize()
}
