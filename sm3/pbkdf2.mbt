// PBKDF2 口令基密钥派生（基于 HMAC-SM3）
// 依据：RFC 8018（PKCS #5 v2.1）5.2 定义的 PBKDF2 结构，
// 伪随机函数 PRF 取 HMAC-SM3（hLen = 32，分组长度 64 字节）。

///|
/// PBKDF2-HMAC-SM3：由口令与盐派生 `dklen` 字节密钥。
/// `iterations` 为迭代次数（RFC 8018 要求至少 1），
/// `iterations <= 0` 或 `dklen <= 0` 返回空字节串。
pub fn pbkdf2(
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dklen : Int,
) -> Bytes {
  if iterations <= 0 || dklen <= 0 {
    return Bytes::from_array(FixedArray::make(0, b'\x00'))
  }
  let out : FixedArray[Byte] = FixedArray::make(dklen, b'\x00')
  let mut filled = 0
  let mut block_index : Int = 1
  while filled < dklen {
    // U1 = PRF(P, S || INT(i))，INT(i) 为 4 字节大端块序号
    let seed : FixedArray[Byte] = FixedArray::make(salt.length() + 4, b'\x00')
    for i in 0..<salt.length() {
      seed[i] = salt[i]
    }
    seed[salt.length()] = ((block_index >> 24) & 0xff).to_byte()
    seed[salt.length() + 1] = ((block_index >> 16) & 0xff).to_byte()
    seed[salt.length() + 2] = ((block_index >> 8) & 0xff).to_byte()
    seed[salt.length() + 3] = (block_index & 0xff).to_byte()
    let mut u = hmac(password, Bytes::from_array(seed))
    // T = U1 ^ U2 ^ ... ^ Uc
    let t : FixedArray[Byte] = FixedArray::make(32, b'\x00')
    for i in 0..<32 {
      t[i] = u[i]
    }
    for _j in 1..<iterations {
      u = hmac(password, u)
      for i in 0..<32 {
        t[i] = (t[i].to_int() ^ u[i].to_int()).to_byte()
      }
    }
    let n = if dklen - filled < 32 { dklen - filled } else { 32 }
    for i in 0..<n {
      out[filled + i] = t[i]
    }
    filled = filled + n
    block_index = block_index + 1
  }
  Bytes::from_array(out)
}
