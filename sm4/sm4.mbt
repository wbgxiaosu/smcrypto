// SM4 分组密码算法
// 依据：GB/T 32907-2016《信息安全技术 SM4 分组密码算法》
// 纯 MoonBit 实现，零依赖。提供 128 位分组加解密、
// 密钥扩展、ECB/CBC 工作模式与 PKCS7 填充。

///|
/// SM4 相关错误类型。
pub(all) enum Sm4Error {
  /// 密钥长度不是 16 字节，实际为 `Int` 字节
  InvalidKeyLength(Int)
  /// IV 长度不是 16 字节，实际为 `Int` 字节
  InvalidIvLength(Int)
  /// 密文长度不是 16 的整数倍
  InvalidCiphertextLength(Int)
  /// 密文 PKCS7 填充不合法
  InvalidPadding
} derive(Eq, Debug)

///|
pub extend Sm4Error with Eq::{not_equal, equal}

///|
pub extend Sm4Error with @moonbitlang/core/debug.Debug::{to_repr}

///|
/// 将错误转换为可读字符串。
pub fn Sm4Error::to_string(self : Sm4Error) -> String {
  match self {
    InvalidKeyLength(n) =>
      "sm4: 密钥长度必须为 16 字节，实际 \{n} 字节"
    InvalidIvLength(n) =>
      "sm4: IV 长度必须为 16 字节，实际 \{n} 字节"
    InvalidCiphertextLength(n) =>
      "sm4: 密文长度必须为 16 的整数倍，实际 \{n} 字节"
    InvalidPadding => "sm4: PKCS7 填充不合法"
  }
}

///|
/// 加密轮合成变换 T：按字节查合成表（S 盒替换 + 线性变换 L 已合并）。
fn t_round(x : UInt) -> UInt {
  sm4_te0[((x >> 24) & 0xffU).reinterpret_as_int()] ^
  sm4_te3[((x >> 16) & 0xffU).reinterpret_as_int()] ^
  sm4_te2[((x >> 8) & 0xffU).reinterpret_as_int()] ^
  sm4_te1[(x & 0xffU).reinterpret_as_int()]
}

///|
/// 密钥扩展合成变换 T'：按字节查合成表（S 盒替换 + 线性变换 L' 已合并）。
fn t_key(x : UInt) -> UInt {
  sm4_td0[((x >> 24) & 0xffU).reinterpret_as_int()] ^
  sm4_td3[((x >> 16) & 0xffU).reinterpret_as_int()] ^
  sm4_td2[((x >> 8) & 0xffU).reinterpret_as_int()] ^
  sm4_td1[(x & 0xffU).reinterpret_as_int()]
}

///|
/// SM4 密码器：保存 32 个轮密钥，可反复加解密数据块。
pub struct Sm4 {
  /// 轮密钥（加密序；解密时倒序使用）
  rk : FixedArray[UInt]
}

///|
/// 从 16 字节密钥创建 SM4 密码器。密钥长度错误时返回 [InvalidKeyLength]。
pub fn Sm4::new(key : Bytes) -> Result[Sm4, Sm4Error] {
  if key.length() != 16 {
    return Err(InvalidKeyLength(key.length()))
  }
  let mk : FixedArray[UInt] = FixedArray::make(4, 0U)
  for i in 0..<4 {
    mk[i] = ((key[i * 4].to_int() << 24) |
    (key[i * 4 + 1].to_int() << 16) |
    (key[i * 4 + 2].to_int() << 8) |
    key[i * 4 + 3].to_int()).reinterpret_as_uint()
  }
  // 密钥扩展：K[i+4] = K[i] ^ T'(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i])
  let rk : FixedArray[UInt] = FixedArray::make(32, 0U)
  let mut k0 = mk[0] ^ sm4_fk[0]
  let mut k1 = mk[1] ^ sm4_fk[1]
  let mut k2 = mk[2] ^ sm4_fk[2]
  let mut k3 = mk[3] ^ sm4_fk[3]
  for i in 0..<32 {
    let nk = k0 ^ t_key(k1 ^ k2 ^ k3 ^ sm4_ck[i])
    rk[i] = nk
    k0 = k1
    k1 = k2
    k2 = k3
    k3 = nk
  }
  Ok({ rk, })
}

///|
/// 32 轮迭代核心。`keys` 为本轮使用的轮密钥序列。
fn Sm4::crypt_block(self : Sm4, block : Bytes, reverse : Bool) -> Bytes {
  let mut x0 = ((block[0].to_int() << 24) |
  (block[1].to_int() << 16) |
  (block[2].to_int() << 8) |
  block[3].to_int()).reinterpret_as_uint()
  let mut x1 = ((block[4].to_int() << 24) |
  (block[5].to_int() << 16) |
  (block[6].to_int() << 8) |
  block[7].to_int()).reinterpret_as_uint()
  let mut x2 = ((block[8].to_int() << 24) |
  (block[9].to_int() << 16) |
  (block[10].to_int() << 8) |
  block[11].to_int()).reinterpret_as_uint()
  let mut x3 = ((block[12].to_int() << 24) |
  (block[13].to_int() << 16) |
  (block[14].to_int() << 8) |
  block[15].to_int()).reinterpret_as_uint()
  for i in 0..<32 {
    let rk = if reverse { self.rk[31 - i] } else { self.rk[i] }
    let xn = x0 ^ t_round(x1 ^ x2 ^ x3 ^ rk)
    x0 = x1
    x1 = x2
    x2 = x3
    x3 = xn
  }
  // 输出为反序：X35 X34 X33 X32
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let words = [x3, x2, x1, x0]
  for i in 0..<4 {
    let w = words[i]
    out[i * 4] = ((w >> 24) & 0xffU).reinterpret_as_int().to_byte()
    out[i * 4 + 1] = ((w >> 16) & 0xffU).reinterpret_as_int().to_byte()
    out[i * 4 + 2] = ((w >> 8) & 0xffU).reinterpret_as_int().to_byte()
    out[i * 4 + 3] = (w & 0xffU).reinterpret_as_int().to_byte()
  }
  Bytes::from_array(out)
}

///|
/// 加密一个 16 字节块。
pub fn Sm4::encrypt_block(self : Sm4, block : Bytes) -> Bytes {
  self.crypt_block(block, false)
}

///|
/// 解密一个 16 字节块。
pub fn Sm4::decrypt_block(self : Sm4, block : Bytes) -> Bytes {
  self.crypt_block(block, true)
}

///|
/// PKCS7 填充：追加 `16 - len % 16` 个值为该数的字节（恒追加 1..16 字节）。
fn pkcs7_pad(data : Bytes) -> Bytes {
  let pad = 16 - data.length() % 16
  let out : FixedArray[Byte] = FixedArray::make(data.length() + pad, b'\x00')
  for i in 0..<data.length() {
    out[i] = data[i]
  }
  for i in 0..<pad {
    out[data.length() + i] = pad.to_byte()
  }
  Bytes::from_array(out)
}

///|
/// PKCS7 去填充。填充不合法时返回 [InvalidPadding]。
fn pkcs7_unpad(data : Bytes) -> Result[Bytes, Sm4Error] {
  let n = data.length()
  let pad = data[n - 1].to_int()
  if pad < 1 || pad > 16 || pad > n {
    return Err(InvalidPadding)
  }
  for i in 0..<pad {
    if data[n - 1 - i].to_int() != pad {
      return Err(InvalidPadding)
    }
  }
  Ok(data[0:n - pad].to_owned())
}

///|
/// 校验密钥长度并创建密码器（内部便捷函数）。
fn sm4_of(key : Bytes) -> Result[Sm4, Sm4Error] {
  Sm4::new(key)
}

///|
/// ECB 模式加密（含 PKCS7 填充）。
pub fn encrypt_ecb(key : Bytes, plaintext : Bytes) -> Result[Bytes, Sm4Error] {
  let c = match sm4_of(key) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  let padded = pkcs7_pad(plaintext)
  let out : FixedArray[Byte] = FixedArray::make(padded.length(), b'\x00')
  let mut off = 0
  while off < padded.length() {
    let ct = c.encrypt_block(padded[off:off + 16].to_owned())
    for i in 0..<16 {
      out[off + i] = ct[i]
    }
    off = off + 16
  }
  Ok(Bytes::from_array(out))
}

///|
/// ECB 模式解密（去 PKCS7 填充）。
pub fn decrypt_ecb(key : Bytes, ciphertext : Bytes) -> Result[Bytes, Sm4Error] {
  let c = match sm4_of(key) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  if ciphertext.length() == 0 || ciphertext.length() % 16 != 0 {
    return Err(InvalidCiphertextLength(ciphertext.length()))
  }
  let out : FixedArray[Byte] = FixedArray::make(ciphertext.length(), b'\x00')
  let mut off = 0
  while off < ciphertext.length() {
    let pt = c.decrypt_block(ciphertext[off:off + 16].to_owned())
    for i in 0..<16 {
      out[off + i] = pt[i]
    }
    off = off + 16
  }
  pkcs7_unpad(Bytes::from_array(out))
}

///|
/// CBC 模式加密（含 PKCS7 填充）。`iv` 必须为 16 字节。
pub fn encrypt_cbc(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
) -> Result[Bytes, Sm4Error] {
  if iv.length() != 16 {
    return Err(InvalidIvLength(iv.length()))
  }
  let c = match sm4_of(key) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  let padded = pkcs7_pad(plaintext)
  let out : FixedArray[Byte] = FixedArray::make(padded.length(), b'\x00')
  let prev : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    prev[i] = iv[i]
  }
  let mut off = 0
  while off < padded.length() {
    let xored : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for i in 0..<16 {
      xored[i] = (padded[off + i].to_int() ^ prev[i].to_int()).to_byte()
    }
    let ct = c.encrypt_block(Bytes::from_array(xored))
    for i in 0..<16 {
      out[off + i] = ct[i]
      prev[i] = ct[i]
    }
    off = off + 16
  }
  Ok(Bytes::from_array(out))
}

///|
/// CBC 模式解密（去 PKCS7 填充）。`iv` 必须为 16 字节。
pub fn decrypt_cbc(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
) -> Result[Bytes, Sm4Error] {
  if iv.length() != 16 {
    return Err(InvalidIvLength(iv.length()))
  }
  let c = match sm4_of(key) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  if ciphertext.length() == 0 || ciphertext.length() % 16 != 0 {
    return Err(InvalidCiphertextLength(ciphertext.length()))
  }
  let out : FixedArray[Byte] = FixedArray::make(ciphertext.length(), b'\x00')
  let prev : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    prev[i] = iv[i]
  }
  let mut off = 0
  while off < ciphertext.length() {
    let pt = c.decrypt_block(ciphertext[off:off + 16].to_owned())
    for i in 0..<16 {
      out[off + i] = (pt[i].to_int() ^ prev[i].to_int()).to_byte()
      prev[i] = ciphertext[off + i]
    }
    off = off + 16
  }
  pkcs7_unpad(Bytes::from_array(out))
}
