// SM4 GCM 认证加密模式（Galois/Counter Mode）
// 依据：GB/T 32907-2016 分组密码 + NIST SP 800-38D 定义的 GCM 工作方式，
// 并以 RFC 8998（SM4-GCM for TLS 1.3）附录 A 测试向量对拍。
// GHASH 使用 GF(2^128) 上的乘法，约减多项式 R = 0xe1 || 0^120。
// 当前实现固定输出 16 字节（128 位）认证标签，支持任意长度 IV。

///|
/// GF(2^128) 乘法（MSB 在前的位序约定，SP 800-38D）。
fn gcm_gf_mul(x : FixedArray[Byte], y : FixedArray[Byte]) -> FixedArray[Byte] {
  let z : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let v : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    v[i] = y[i]
  }
  for i in 0..<128 {
    let bit = (x[i / 8].to_int() >> (7 - i % 8)) & 1
    if bit == 1 {
      for j in 0..<16 {
        z[j] = (z[j].to_int() ^ v[j].to_int()).to_byte()
      }
    }
    let lsb = (v[15].to_int() & 1) == 1
    // v 整体右移 1 位
    let mut j = 15
    while j >= 1 {
      v[j] = ((v[j].to_int() >> 1) | ((v[j - 1].to_int() & 1) << 7)).to_byte()
      j = j - 1
    }
    v[0] = (v[0].to_int() >> 1).to_byte()
    if lsb {
      v[0] = (v[0].to_int() ^ 0xe1).to_byte()
    }
  }
  z
}

///|
/// 流式 GHASH：按 16 字节块累积 `y = GHASH_H(data)`，支持任意长度分段输入。
priv struct GHash {
  h : FixedArray[Byte]
  mut y : FixedArray[Byte]
  buf : FixedArray[Byte]
  mut buf_len : Int
}

///|
fn GHash::new(h : FixedArray[Byte]) -> GHash {
  {
    h,
    y: FixedArray::make(16, b'\x00'),
    buf: FixedArray::make(16, b'\x00'),
    buf_len: 0,
  }
}

///|
/// 对一个 16 字节块做 y = (y ^ block) * H。
fn GHash::absorb_block(self : GHash, block : FixedArray[Byte]) -> Unit {
  for j in 0..<16 {
    self.y[j] = (self.y[j].to_int() ^ block[j].to_int()).to_byte()
  }
  self.y = gcm_gf_mul(self.y, self.h)
}

///|
/// 喂入任意长度的数据，内部缓存不足一块的部分。
fn GHash::update(self : GHash, data : Bytes) -> Unit {
  let mut off = 0
  if self.buf_len > 0 {
    let space = 16 - self.buf_len
    let to_copy = if data.length() < space { data.length() } else { space }
    for i in 0..<to_copy {
      self.buf[self.buf_len + i] = data[i]
    }
    self.buf_len = self.buf_len + to_copy
    off = to_copy
    if self.buf_len == 16 {
      self.absorb_block(self.buf)
      self.buf_len = 0
    }
  }
  while data.length() - off >= 16 {
    let block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for i in 0..<16 {
      block[i] = data[off + i]
    }
    self.absorb_block(block)
    off = off + 16
  }
  if data.length() - off > 0 {
    let n = data.length() - off
    for i in 0..<n {
      self.buf[i] = data[off + i]
    }
    self.buf_len = n
  }
}

///|
/// 把尾部不足一块的部分补零后吸收（对应规范中 AAD / 密文各自的 0 填充）。
fn GHash::flush(self : GHash) -> Unit {
  if self.buf_len > 0 {
    for i in self.buf_len..<16 {
      self.buf[i] = b'\x00'
    }
    self.absorb_block(self.buf)
    self.buf_len = 0
  }
}

///|
/// 8 字节大端位长编码。注意 MoonBit 的 Int 移位量超过 31 会回绕，
/// 因此高 4 字节直接置零、只用 ≤24 的移位量写低 4 字节。
fn gcm_len64(nbits : Int, out : FixedArray[Byte], offset : Int) -> Unit {
  for i in 0..<4 {
    out[offset + i] = b'\x00'
  }
  for i in 0..<4 {
    out[offset + 4 + i] = ((nbits >> (24 - i * 8)) & 0xff).to_byte()
  }
}

///|
/// 由 IV 派生预计数器 J0（SP 800-38D 8.1.1）：
/// 12 字节 IV 时 `J0 = IV || 0^31 || 1`；其他长度经 GHASH_H 计算。
fn gcm_j0(h : FixedArray[Byte], iv : Bytes) -> FixedArray[Byte] {
  if iv.length() == 12 {
    let j0 : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for i in 0..<12 {
      j0[i] = iv[i]
    }
    j0[15] = b'\x01'
    j0
  } else {
    let g = GHash::new(h)
    g.update(iv)
    g.flush()
    // 长度块固定 16 字节：8 字节零 + 64 位 IV 位长
    let tail : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    gcm_len64(iv.length() * 8, tail, 8)
    g.absorb_block(tail)
    g.y
  }
}

///|
/// GCM 计数器递增：仅最后 4 字节按 32 位大端加一（mod 2^32）。
fn gcm_inc32(cbe : FixedArray[Byte]) -> Unit {
  let mut i = 15
  while i >= 12 {
    let v = cbe[i].to_int() + 1
    if v <= 0xff {
      cbe[i] = v.to_byte()
      return
    }
    cbe[i] = 0
    i = i - 1
  }
}

///|
/// GCM 核心的 CTR 输出：从 inc32(J0) 开始生成密钥流并异或。
fn gcm_ctr_xor(
  c : Sm4,
  j0 : FixedArray[Byte],
  data : Bytes,
) -> FixedArray[Byte] {
  let cb : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    cb[i] = j0[i]
  }
  gcm_inc32(cb)
  let out : FixedArray[Byte] = FixedArray::make(data.length(), b'\x00')
  let mut off = 0
  while off < data.length() {
    let ks = c.encrypt_block(Bytes::from_array(cb))
    let n = if data.length() - off < 16 { data.length() - off } else { 16 }
    for i in 0..<n {
      out[off + i] = (data[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
    gcm_inc32(cb)
    off = off + n
  }
  out
}

///|
/// 计算 GCM 认证标签：`T = E(K, J0) XOR GHASH_H(pad(A) || pad(C) || 长度块)`。
/// AAD 与密文各自补零到 16 字节边界，最后吸收一个
/// `[len(A)_64 || len(C)_64]` 长度块（SP 800-38D 7.1）。
fn gcm_tag(
  c : Sm4,
  h : FixedArray[Byte],
  j0 : FixedArray[Byte],
  aad : Bytes,
  ciphertext : Bytes,
) -> FixedArray[Byte] {
  let g = GHash::new(h)
  g.update(aad)
  g.flush()
  g.update(ciphertext)
  g.flush()
  let tail : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  gcm_len64(aad.length() * 8, tail, 0)
  gcm_len64(ciphertext.length() * 8, tail, 8)
  g.absorb_block(tail)
  let ekj0 = c.encrypt_block(Bytes::from_array(j0))
  let t : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    t[i] = (g.y[i].to_int() ^ ekj0[i].to_int()).to_byte()
  }
  t
}

///|
/// 常数时间标签比较（长度不同直接失败）。
fn gcm_tag_eq(a : FixedArray[Byte], b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<a.length() {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
/// GCM 认证加密。返回 `(密文, 16 字节认证标签)`，密文与明文等长。
/// `aad` 为附加认证数据（不加密但参与认证），可为空。
pub fn encrypt_gcm(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
  aad : Bytes,
) -> Result[(Bytes, Bytes), Sm4Error] {
  let c = match sm4_of(key) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  if iv.length() == 0 {
    return Err(InvalidIvLength(0))
  }
  let h = gcm_h(c)
  let j0 = gcm_j0(h, iv)
  let ct = gcm_ctr_xor(c, j0, plaintext)
  let tag = gcm_tag(c, h, j0, aad, Bytes::from_array(ct))
  Ok((Bytes::from_array(ct), Bytes::from_array(tag)))
}

///|
/// GCM 认证解密：先校验 16 字节标签，不匹配返回 [AuthenticationFailed]，
/// 校验通过后输出与密文等长的明文。
pub fn decrypt_gcm(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
  aad : Bytes,
) -> Result[Bytes, Sm4Error] {
  let c = match sm4_of(key) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  if iv.length() == 0 {
    return Err(InvalidIvLength(0))
  }
  if tag.length() != 16 {
    return Err(InvalidIvLength(tag.length()))
  }
  let h = gcm_h(c)
  let j0 = gcm_j0(h, iv)
  let expected = gcm_tag(c, h, j0, aad, ciphertext)
  if !gcm_tag_eq(expected, tag) {
    return Err(AuthenticationFailed)
  }
  Ok(Bytes::from_array(gcm_ctr_xor(c, j0, ciphertext)))
}

///|
/// 由加密轮密钥派生 GHASH 子密钥 H = E(K, 0^128)。
fn gcm_h(c : Sm4) -> FixedArray[Byte] {
  let zero : Bytes = Bytes::from_array(FixedArray::make(16, b'\x00'))
  let b = c.encrypt_block(zero)
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    out[i] = b[i]
  }
  out
}
