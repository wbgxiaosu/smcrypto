// SM3 密码杂凑算法
// 依据：GB/T 32905-2016《信息安全技术 SM3 密码杂凑算法》
// 纯 MoonBit 实现，零依赖，输出 256 位（32 字节）摘要。

///|
/// SM3 初始链接变量（国标 5.3.2）。
let sm3_iv : FixedArray[UInt] = {
  let iv : FixedArray[UInt] = FixedArray::make(8, 0U)
  iv[0] = 0x7380166fU
  iv[1] = 0x4914b2b9U
  iv[2] = 0x172442d7U
  iv[3] = 0xda8a0600U
  iv[4] = 0xa96f30bcU
  iv[5] = 0x163138aaU
  iv[6] = 0xe38dee4dU
  iv[7] = 0xb0fb0e4eU
  iv
}

///|
/// 32 位循环左移。
fn rotl(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
/// 布尔置换 P0(x) = x ^ (x <<< 9) ^ (x <<< 17)（国标 5.1）。
fn p0(x : UInt) -> UInt {
  x ^ rotl(x, 9) ^ rotl(x, 17)
}

///|
/// 布尔置换 P1(x) = x ^ (x <<< 15) ^ (x <<< 23)（国标 5.1）。
fn p1(x : UInt) -> UInt {
  x ^ rotl(x, 15) ^ rotl(x, 23)
}

///|
/// SM3 流式哈希器：多次 `update` 吸收消息，`finalize` 输出摘要。
pub struct Sm3 {
  /// 8 个 32 位链接变量
  v : FixedArray[UInt]
  /// 未压缩的消息尾部缓冲（最多 64 字节）
  buf : FixedArray[Byte]
  /// buf 中的有效字节数
  mut buflen : Int
  /// 已处理的消息总字节数（模 2^32）
  mut total : UInt
}

///|
/// 新建一个 SM3 哈希器，处于初始状态。
pub fn Sm3::new() -> Sm3 {
  let v : FixedArray[UInt] = FixedArray::make(8, 0U)
  for i in 0..<8 {
    v[i] = sm3_iv[i]
  }
  { v, buf: FixedArray::make(64, b'\x00'), buflen: 0, total: 0U, }
}

///|
/// 重置哈希器到初始状态，可复用计算下一条消息。
pub fn Sm3::reset(self : Sm3) -> Unit {
  for i in 0..<8 {
    self.v[i] = sm3_iv[i]
  }
  self.buflen = 0
  self.total = 0U
}

///|
/// 吸收一段消息。可多次调用，顺序即消息顺序。
pub fn Sm3::update(self : Sm3, data : Bytes) -> Unit {
  self.total = self.total + data.length().reinterpret_as_uint()
  let mut i = 0
  // 先把旧缓冲填满并压缩
  while self.buflen < 64 && i < data.length() {
    self.buf[self.buflen] = data[i]
    self.buflen = self.buflen + 1
    i = i + 1
  }
  if self.buflen == 64 {
    sm3_compress(self.v, self.buf)
    self.buflen = 0
  }
  // 整块直接压缩
  while data.length() - i >= 64 {
    let block : FixedArray[Byte] = FixedArray::make(64, b'\x00')
    for j in 0..<64 {
      block[j] = data[i + j]
    }
    sm3_compress(self.v, block)
    i = i + 64
  }
  // 剩余字节进缓冲
  while i < data.length() {
    self.buf[self.buflen] = data[i]
    self.buflen = self.buflen + 1
    i = i + 1
  }
}

///|
/// 把 64 位大端比特长度写入块的末 8 字节。
fn put_bit_len(b : FixedArray[Byte], hi : UInt, lo : UInt) -> Unit {
  b[56] = ((hi >> 24) & 0xffU).reinterpret_as_int().to_byte()
  b[57] = ((hi >> 16) & 0xffU).reinterpret_as_int().to_byte()
  b[58] = ((hi >> 8) & 0xffU).reinterpret_as_int().to_byte()
  b[59] = (hi & 0xffU).reinterpret_as_int().to_byte()
  b[60] = ((lo >> 24) & 0xffU).reinterpret_as_int().to_byte()
  b[61] = ((lo >> 16) & 0xffU).reinterpret_as_int().to_byte()
  b[62] = ((lo >> 8) & 0xffU).reinterpret_as_int().to_byte()
  b[63] = (lo & 0xffU).reinterpret_as_int().to_byte()
}

///|
/// 结束哈希并输出 32 字节摘要。
pub fn Sm3::finalize(self : Sm3) -> Bytes {
  let bit_lo : UInt = self.total << 3
  let bit_hi : UInt = self.total >> 29
  // 填充块：原缓冲 + 0x80 + 零填充
  let b1 : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i in 0..<self.buflen {
    b1[i] = self.buf[i]
  }
  b1[self.buflen] = b'\x80'
  if self.buflen < 56 {
    // 长度可以放进同一块
    put_bit_len(b1, bit_hi, bit_lo)
    sm3_compress(self.v, b1)
  } else {
    // 0x80 已越过本块 56 字节界：本块只填 0x80，长度另起一块
    sm3_compress(self.v, b1)
    let b2 : FixedArray[Byte] = FixedArray::make(64, b'\x00')
    put_bit_len(b2, bit_hi, bit_lo)
    sm3_compress(self.v, b2)
  }
  // 输出 8 个大端字
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i in 0..<8 {
    let w = self.v[i]
    out[i * 4] = ((w >> 24) & 0xffU).reinterpret_as_int().to_byte()
    out[i * 4 + 1] = ((w >> 16) & 0xffU).reinterpret_as_int().to_byte()
    out[i * 4 + 2] = ((w >> 8) & 0xffU).reinterpret_as_int().to_byte()
    out[i * 4 + 3] = (w & 0xffU).reinterpret_as_int().to_byte()
  }
  Bytes::from_array(out)
}

///|
/// SM3 压缩函数：把一个 64 字节块压缩进链接变量 v（国标 5.3.1）。
fn sm3_compress(v : FixedArray[UInt], block : FixedArray[Byte]) -> Unit {
  // 消息扩展：w[0..68)
  let w : FixedArray[UInt] = FixedArray::make(68, 0U)
  let wp : FixedArray[UInt] = FixedArray::make(64, 0U)
  for j in 0..<16 {
    w[j] = ((block[j * 4].to_int() << 24) |
    (block[j * 4 + 1].to_int() << 16) |
    (block[j * 4 + 2].to_int() << 8) |
    block[j * 4 + 3].to_int()).reinterpret_as_uint()
  }
  for j in 16..<68 {
    w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^
      rotl(w[j - 13], 7) ^
      w[j - 6]
  }
  for j in 0..<64 {
    wp[j] = w[j] ^ w[j + 4]
  }
  // 64 轮迭代
  let mut a = v[0]
  let mut b = v[1]
  let mut c = v[2]
  let mut d = v[3]
  let mut e = v[4]
  let mut f = v[5]
  let mut g = v[6]
  let mut h = v[7]
  for j in 0..<64 {
    let t : UInt = if j < 16 { 0x79cc4519U } else { 0x7a879d8aU }
    let ss1 = rotl(rotl(a, 12) + e + rotl(t, j % 32), 7)
    let ss2 = ss1 ^ rotl(a, 12)
    let tt1 = (if j < 16 { a ^ b ^ c } else { (a & b) | (a & c) | (b & c) }) +
      d +
      ss2 +
      wp[j]
    let tt2 = (if j < 16 {
        e ^ f ^ g
      } else {
        (e & f) | ((e ^ 0xffffffffU) & g)
      }) +
      h +
      ss1 +
      w[j]
    d = c
    c = rotl(b, 9)
    b = a
    a = tt1
    h = g
    g = rotl(f, 19)
    f = e
    e = p0(tt2)
  }
  v[0] = v[0] ^ a
  v[1] = v[1] ^ b
  v[2] = v[2] ^ c
  v[3] = v[3] ^ d
  v[4] = v[4] ^ e
  v[5] = v[5] ^ f
  v[6] = v[6] ^ g
  v[7] = v[7] ^ h
}

///|
/// 一次性计算消息 `data` 的 SM3 摘要，返回 32 字节。
pub fn digest(data : Bytes) -> Bytes {
  let h = Sm3::new()
  h.update(data)
  h.finalize()
}

///|
/// 一次性计算消息 `data` 的 SM3 摘要，返回小写十六进制字符串（64 字符）。
pub fn hex_digest(data : Bytes) -> String {
  @hexutil.encode(digest(data))
}
