// SM4 CTR 计数器模式
// 依据 GB/T 32907-2016 分组密码 + NIST SP 800-38A 定义的 CTR 工作方式：
// 计数器为 16 字节大端整数，逐块加一（整块进位，全 1 回绕到 0），
// 密钥流 = ECB(counter)，密文 = 明文 XOR 密钥流（无填充，长度与明文一致）。

///|
/// 把 16 字节计数器按 128 位大端整数加一（全 1 回绕到全 0）。
fn ctr_increment(cbe : FixedArray[Byte]) -> Unit {
  let mut i = 15
  while i >= 0 {
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
/// CTR 模式加密。`counter` 为 16 字节初始计数器，输出长度与明文一致。
/// CTR 加解密是同一变换（XOR 密钥流），`decrypt_ctr` 复用本函数。
pub fn encrypt_ctr(
  key : Bytes,
  counter : Bytes,
  plaintext : Bytes,
) -> Result[Bytes, Sm4Error] {
  if counter.length() != 16 {
    return Err(InvalidIvLength(counter.length()))
  }
  let c = match sm4_of(key) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  let ctrbuf : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    ctrbuf[i] = counter[i]
  }
  let out : FixedArray[Byte] = FixedArray::make(plaintext.length(), b'\x00')
  let mut off = 0
  while off < plaintext.length() {
    let ks = c.encrypt_block(Bytes::from_array(ctrbuf))
    let n = if plaintext.length() - off < 16 {
      plaintext.length() - off
    } else {
      16
    }
    for i in 0..<n {
      out[off + i] = (plaintext[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
    ctr_increment(ctrbuf)
    off = off + n
  }
  Ok(Bytes::from_array(out))
}

///|
/// CTR 模式解密。CTR 模式下解密与加密为同一变换。
pub fn decrypt_ctr(
  key : Bytes,
  counter : Bytes,
  ciphertext : Bytes,
) -> Result[Bytes, Sm4Error] {
  encrypt_ctr(key, counter, ciphertext)
}
