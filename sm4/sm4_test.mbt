// SM4 黑盒测试：国标核心向量（GB/T 32907-2016 附录 A）
// 标准示例：密钥 = 明文 = 0123456789abcdeffedcba9876543210
//           密文 = 681edf34d206965e86b3e94f536e4246

///|
/// 十六进制转字节（测试辅助，与本包其他测试文件共享）。
fn sm4_hex_bytes(s : String) -> Bytes {
  let n = s.length()
  let out : FixedArray[Byte] = FixedArray::make(n / 2, b'\x00')
  for i in 0..<n {
    let c = s[i].to_int()
    let v = if c >= '0'.to_int() && c <= '9'.to_int() {
      c - '0'.to_int()
    } else if c >= 'a'.to_int() && c <= 'f'.to_int() {
      c - 'a'.to_int() + 10
    } else if c >= 'A'.to_int() && c <= 'f'.to_int() {
      c - 'A'.to_int() + 10
    } else {
      abort("bad hex")
    }
    if i % 2 == 0 {
      out[i / 2] = (v << 4).to_byte()
    } else {
      out[i / 2] = (out[i / 2].to_int() | v).to_byte()
    }
  }
  Bytes::from_array(out)
}

///|
fn sm4_bytes_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i in 0..<b.length() {
    let v = b[i].to_int()
    sb.write_char(digits[v >> 4].to_int().unsafe_to_char())
    sb.write_char(digits[v & 0x0f].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
test "sm4 gb standard vector (block)" {
  let key = sm4_hex_bytes("0123456789abcdeffedcba9876543210")
  let pt = sm4_hex_bytes("0123456789abcdeffedcba9876543210")
  let c = @sm4.Sm4::new(key).unwrap()
  let ct = c.encrypt_block(pt)
  assert_eq(
    sm4_bytes_hex(ct),
    "681edf34d206965e86b3e94f536e4246",
    msg="gb standard encryption",
  )
  let back = c.decrypt_block(ct)
  assert_eq(
    sm4_bytes_hex(back),
    "0123456789abcdeffedcba9876543210",
    msg="gb standard decryption",
  )
}

///|
test "sm4 ecb roundtrip various lengths" {
  let key = sm4_hex_bytes("0123456789abcdeffedcba9876543210")
  for n in [0, 1, 15, 16, 17, 31, 32, 100] {
    let pt : FixedArray[Byte] = FixedArray::make(n, b'\x00')
    for i in 0..<n {
      pt[i] = ((i * 7 + 3) % 256).to_byte()
    }
    let data = Bytes::from_array(pt)
    let ct = @sm4.encrypt_ecb(key, data).unwrap()
    assert_eq(
      (ct.length() - 1) / 16 * 16,
      ct.length() - 16,
      msg="ciphertext aligned",
    )
    let back = @sm4.decrypt_ecb(key, ct).unwrap()
    assert_eq(
      sm4_bytes_hex(back),
      sm4_bytes_hex(data),
      msg="ecb roundtrip n=\{n}",
    )
  }
}

///|
test "sm4 cbc roundtrip and chaining" {
  let key = sm4_hex_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = sm4_hex_bytes("000102030405060708090a0b0c0d0e0f")
  let pt = sm4_hex_bytes("6bc1bee22e409f96e93d7e117393172a")
  let ct = @sm4.encrypt_cbc(key, iv, pt).unwrap()
  let back = @sm4.decrypt_cbc(key, iv, ct).unwrap()
  assert_eq(sm4_bytes_hex(back), sm4_bytes_hex(pt), msg="cbc roundtrip")
  // CBC 与 ECB 密文应不同（相同明文块在 CBC 下被 IV 遮蔽）
  let ct_ecb = @sm4.encrypt_ecb(key, pt).unwrap()
  assert_false(
    sm4_bytes_hex(ct) == sm4_bytes_hex(ct_ecb),
    msg="cbc differs from ecb",
  )
}

///|
test "sm4 error cases" {
  let key = sm4_hex_bytes("0123456789abcdeffedcba9876543210")
  // 密钥长度错误
  let bad = @sm4.Sm4::new(sm4_hex_bytes("00"))
  assert_eq(bad is Err(_), true, msg="1-byte key rejected")
  match bad {
    Err(e) => assert_eq(e, InvalidKeyLength(1), msg="error payload")
    Ok(_) => fail("expected error")
  }
  // IV 长度错误
  assert_eq(
    @sm4.encrypt_cbc(key, sm4_hex_bytes("0001"), b"x"),
    Err(InvalidIvLength(2)),
  )
  // 密文长度错误
  assert_eq(
    @sm4.decrypt_ecb(key, sm4_hex_bytes("0000")),
    Err(InvalidCiphertextLength(2)),
  )
  // 全零密钥块解密不 panic
  let zero_block = sm4_hex_bytes("00000000000000000000000000000000")
  let _ = @sm4.decrypt_ecb(key, zero_block)
}

///|
test "sm4 cbc decrypts with wrong iv gives different plaintext" {
  let key = sm4_hex_bytes("0123456789abcdeffedcba9876543210")
  let iv1 = sm4_hex_bytes("000102030405060708090a0b0c0d0e0f")
  let iv2 = sm4_hex_bytes("ff0102030405060708090a0b0c0d0e0f")
  let pt = b"attack at dawn!!"
  let ct = @sm4.encrypt_cbc(key, iv1, pt).unwrap()
  let back1 = @sm4.decrypt_cbc(key, iv1, ct).unwrap()
  let back2 = @sm4.decrypt_cbc(key, iv2, ct).unwrap()
  assert_eq(back1, pt, msg="correct iv recovers plaintext")
  assert_false(back1 == back2, msg="wrong iv changes plaintext")
}
