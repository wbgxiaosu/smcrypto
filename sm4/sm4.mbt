// SM4 分组密码算法 —— 适配层
// 核心单块加解密委托给 2d5rrr333/toolsfx-moonbit/sm（ISC License，
// 上游按 GB/T 32907-2016 实现并通过国标向量）。
// 本包在上游原语之上提供工作模式：ECB/CBC 委托上游（含 PKCS7 填充）；
// CTR 与 GCM 由本项目实现——其中 GCM 为 RFC 8998 附录 A.1
// 官方向量逐字节对拍的符合性实现（上游 GCM 无法通过该对拍，见 README）。

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
  /// GCM 认证标签校验失败（密文、标签或 AAD 被篡改）
  AuthenticationFailed
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
    AuthenticationFailed => "sm4: GCM 认证标签校验失败"
  }
}

///|
/// SM4 密码器：保存已校验的 16 字节密钥，可反复加解密数据块。
pub struct Sm4 {
  /// 16 字节密钥（创建时已校验）
  key : Bytes
}

///|
/// 从 16 字节密钥创建 SM4 密码器。密钥长度错误时返回 [InvalidKeyLength]。
pub fn Sm4::new(key : Bytes) -> Result[Sm4, Sm4Error] {
  if key.length() != 16 {
    return Err(InvalidKeyLength(key.length()))
  }
  Ok({ key, })
}

///|
/// 加密一个 16 字节块。调用契约：`block` 为 16 字节、密钥已校验，
/// 此时上游单块加密不会失败；违反契约视为程序错误。
pub fn Sm4::encrypt_block(self : Sm4, block : Bytes) -> Bytes {
  @sm.sm4_encrypt_block(self.key, block) catch {
    _ =>
      abort(
        "sm4: 上游单块加密失败（契约：16 字节块 + 已校验密钥）",
      )
  }
}

///|
/// 解密一个 16 字节块。调用契约同 [Sm4::encrypt_block]。
pub fn Sm4::decrypt_block(self : Sm4, block : Bytes) -> Bytes {
  @sm.sm4_decrypt_block(self.key, block) catch {
    _ =>
      abort(
        "sm4: 上游单块解密失败（契约：16 字节块 + 已校验密钥）",
      )
  }
}

///|
/// 校验密钥长度并创建密码器（内部便捷函数）。
fn sm4_of(key : Bytes) -> Result[Sm4, Sm4Error] {
  Sm4::new(key)
}

///|
/// ECB 模式加密（含 PKCS7 填充，委托上游实现）。
pub fn encrypt_ecb(key : Bytes, plaintext : Bytes) -> Result[Bytes, Sm4Error] {
  if key.length() != 16 {
    return Err(InvalidKeyLength(key.length()))
  }
  Ok(@sm.sm4_ecb_encrypt(key, plaintext)) catch {
    _ => Err(InvalidKeyLength(key.length()))
  }
}

///|
/// ECB 模式解密（去 PKCS7 填充，委托上游实现）。
pub fn decrypt_ecb(key : Bytes, ciphertext : Bytes) -> Result[Bytes, Sm4Error] {
  if key.length() != 16 {
    return Err(InvalidKeyLength(key.length()))
  }
  if ciphertext.length() == 0 || ciphertext.length() % 16 != 0 {
    return Err(InvalidCiphertextLength(ciphertext.length()))
  }
  Ok(@sm.sm4_ecb_decrypt(key, ciphertext)) catch {
    // 长度已预检，上游报错只可能是填充不合法
    _ => Err(InvalidPadding)
  }
}

///|
/// CBC 模式加密（含 PKCS7 填充，委托上游实现）。`iv` 必须为 16 字节。
pub fn encrypt_cbc(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
) -> Result[Bytes, Sm4Error] {
  if key.length() != 16 {
    return Err(InvalidKeyLength(key.length()))
  }
  if iv.length() != 16 {
    return Err(InvalidIvLength(iv.length()))
  }
  Ok(@sm.sm4_cbc_encrypt(key, iv, plaintext)) catch {
    _ => Err(InvalidKeyLength(key.length()))
  }
}

///|
/// CBC 模式解密（去 PKCS7 填充，委托上游实现）。`iv` 必须为 16 字节。
pub fn decrypt_cbc(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
) -> Result[Bytes, Sm4Error] {
  if key.length() != 16 {
    return Err(InvalidKeyLength(key.length()))
  }
  if iv.length() != 16 {
    return Err(InvalidIvLength(iv.length()))
  }
  if ciphertext.length() == 0 || ciphertext.length() % 16 != 0 {
    return Err(InvalidCiphertextLength(ciphertext.length()))
  }
  Ok(@sm.sm4_cbc_decrypt(key, iv, ciphertext)) catch {
    // 长度已预检，上游报错只可能是填充不合法
    _ => Err(InvalidPadding)
  }
}
