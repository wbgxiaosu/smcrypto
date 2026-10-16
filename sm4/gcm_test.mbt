// SM4 GCM 模式测试
// 向量来源：RFC 8998（ShangMi (SM) Cipher Suites for TLS 1.3）
// 附录 A.1 SM4-GCM 官方测试向量，IETF 标准文档可自由引用。

///|
test "sm4-gcm RFC 8998 A.1 official vector" {
  let key = sm4_hex_bytes("0123456789ABCDEFFEDCBA9876543210")
  let iv = sm4_hex_bytes("00001234567800000000ABCD")
  // 64 字节明文：16A 16B 16C 16D 16E 16F 16E 16A
  let pt = sm4_hex_bytes(
    "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd" +
    "eeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
  )
  let aad = sm4_hex_bytes("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
  let (ct, tag) = @sm4.encrypt_gcm(key, iv, pt, aad).unwrap()
  assert_eq(
    ctr_bytes_hex(ct),
    "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735" +
    "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d",
    msg="rfc8998 ciphertext",
  )
  assert_eq(
    ctr_bytes_hex(tag),
    "83de3541e4c2b58177e065a9bf7b62ec",
    msg="rfc8998 tag",
  )
}

///|
test "sm4-gcm rfc8998 decrypt and tamper detection" {
  let key = sm4_hex_bytes("0123456789ABCDEFFEDCBA9876543210")
  let iv = sm4_hex_bytes("00001234567800000000ABCD")
  let ct = sm4_hex_bytes(
    "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735" +
    "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d",
  )
  let tag = sm4_hex_bytes("83DE3541E4C2B58177E065A9BF7B62EC")
  let aad = sm4_hex_bytes("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
  let pt_expect = sm4_hex_bytes(
    "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd" +
    "eeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
  )
  // 正常解密还原明文
  let pt = @sm4.decrypt_gcm(key, iv, ct, tag, aad).unwrap()
  assert_eq(ctr_bytes_hex(pt), ctr_bytes_hex(pt_expect), msg="rfc8998 decrypt")
  // 密文被篡改 1 位 -> 认证失败
  let bad_ct = sm4_hex_bytes(
    "17f399f08c67d5ee19d0dc9969c4bb7e5fd46fd3756489069157b282bb200735" +
    "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d",
  )
  assert_eq(
    @sm4.decrypt_gcm(key, iv, bad_ct, tag, aad) is Err(AuthenticationFailed),
    true,
    msg="tampered ciphertext rejected",
  )
  // 标签被篡改 -> 认证失败
  let bad_tag = sm4_hex_bytes("83DE3541E4C2B58177E065A9BF7B62ED")
  assert_eq(
    @sm4.decrypt_gcm(key, iv, ct, bad_tag, aad) is Err(AuthenticationFailed),
    true,
    msg="tampered tag rejected",
  )
  // AAD 被篡改 -> 认证失败
  let bad_aad = sm4_hex_bytes("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD3")
  assert_eq(
    @sm4.decrypt_gcm(key, iv, ct, tag, bad_aad) is Err(AuthenticationFailed),
    true,
    msg="tampered aad rejected",
  )
}

///|
test "sm4-gcm roundtrip and edge cases" {
  let key = sm4_hex_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = sm4_hex_bytes("cafef00dbaadf00dcafef00d")
  // 非整块长度（35 字节）与空 AAD
  let pt : FixedArray[Byte] = FixedArray::make(35, b'\x00')
  for i in 0..<35 {
    pt[i] = ((i * 17 + 3) % 256).to_byte()
  }
  let (ct, tag) = @sm4.encrypt_gcm(
    key,
    iv,
    Bytes::from_array(pt),
    Bytes::from_array(FixedArray::make(0, b'\x00')),
  ).unwrap()
  assert_eq(ct.length(), 35, msg="gcm keeps length")
  assert_eq(tag.length(), 16, msg="gcm tag is 16 bytes")
  let back = @sm4.decrypt_gcm(
    key,
    iv,
    ct,
    tag,
    Bytes::from_array(FixedArray::make(0, b'\x00')),
  ).unwrap()
  assert_eq(
    ctr_bytes_hex(back),
    ctr_bytes_hex(Bytes::from_array(pt)),
    msg="gcm roundtrip",
  )
  // 空明文仍产生有效标签
  let (ct0, tag0) = @sm4.encrypt_gcm(key, iv, b"", b"aad only").unwrap()
  assert_eq(ct0.length(), 0, msg="empty plaintext")
  assert_eq(
    @sm4.decrypt_gcm(key, iv, ct0, tag0, b"aad only") is Ok(_),
    true,
    msg="empty plaintext roundtrip",
  )
  // 非 12 字节 IV 走 GHASH 派生 J0 路径
  let iv8 = sm4_hex_bytes("0011223344556677")
  let (ct8, tag8) = @sm4.encrypt_gcm(key, iv8, b"iv path", b"").unwrap()
  assert_eq(
    @sm4.decrypt_gcm(key, iv8, ct8, tag8, b"") is Ok(_),
    true,
    msg="non-96bit iv roundtrip",
  )
  // 空 IV 被拒绝
  assert_eq(
    @sm4.encrypt_gcm(key, b"", b"x", b"") is Err(_),
    true,
    msg="empty iv rejected",
  )
  // 标签长度错误被拒绝
  assert_eq(
    @sm4.decrypt_gcm(key, iv, ct, b"short", b"") is Err(_),
    true,
    msg="bad tag length rejected",
  )
}
