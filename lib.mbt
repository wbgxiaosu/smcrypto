// 根包便捷再导出：让使用者 `moon add wbgxiaosu/smcrypto` 后
// 直接通过 @smcrypto 使用最常用的函数，无需关心子包结构。

///|
/// 计算 SM3 摘要，返回 32 字节。
pub fn sm3_digest(data : Bytes) -> Bytes {
  @sm3.digest(data)
}

///|
/// 计算 SM3 摘要，返回小写十六进制字符串。
pub fn sm3_hex_digest(data : Bytes) -> String {
  @sm3.hex_digest(data)
}

///|
/// 从 16 字节密钥创建 SM4 密码器。
pub fn sm4_new(key : Bytes) -> Result[@sm4.Sm4, @sm4.Sm4Error] {
  @sm4.Sm4::new(key)
}

///|
/// SM4 ECB 模式加密（含 PKCS7 填充）。
pub fn sm4_encrypt_ecb(
  key : Bytes,
  plaintext : Bytes,
) -> Result[Bytes, @sm4.Sm4Error] {
  @sm4.encrypt_ecb(key, plaintext)
}

///|
/// SM4 ECB 模式解密（去 PKCS7 填充）。
pub fn sm4_decrypt_ecb(
  key : Bytes,
  ciphertext : Bytes,
) -> Result[Bytes, @sm4.Sm4Error] {
  @sm4.decrypt_ecb(key, ciphertext)
}

///|
/// SM4 CBC 模式加密（含 PKCS7 填充）。
pub fn sm4_encrypt_cbc(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
) -> Result[Bytes, @sm4.Sm4Error] {
  @sm4.encrypt_cbc(key, iv, plaintext)
}

///|
/// SM4 CBC 模式解密（去 PKCS7 填充）。
pub fn sm4_decrypt_cbc(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
) -> Result[Bytes, @sm4.Sm4Error] {
  @sm4.decrypt_cbc(key, iv, ciphertext)
}
