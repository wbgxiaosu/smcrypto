// 可复现演示：SM3 与 SM4 全流程
// 运行：moon run cmd/main

///|
fn main {
  println("=== SM3 密码杂凑 (GB/T 32905-2016) ===")
  let abc : Bytes = b"abc"
  println("SM3(\"abc\")      = \{@smcrypto.sm3_hex_digest(abc)}")
  println(
    "国标示例 1 期望 = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
  let cn = @utf8.encode("国密算法，安全可靠")
  println("SM3(中文消息)   = \{@smcrypto.sm3_hex_digest(cn)}")
  println("")
  println("=== SM4 分组密码 (GB/T 32907-2016) ===")
  let key = @hexutil.decode("0123456789abcdeffedcba9876543210").unwrap()
  let pt = @utf8.encode("攻击开始于黎明！Attack at dawn!")
  let c = @smcrypto.sm4_new(key).unwrap()
  // ECB
  let ct_ecb = @smcrypto.sm4_encrypt_ecb(key, pt).unwrap()
  let back_ecb = @smcrypto.sm4_decrypt_ecb(key, ct_ecb).unwrap()
  println("明文            = \{@hexutil.encode(pt)}")
  println("ECB 密文        = \{@hexutil.encode(ct_ecb)}")
  println("ECB 解密还原    = \{@hexutil.encode(back_ecb)}")
  println("ECB 还原正确    = \{back_ecb == pt}")
  // CBC
  let iv = @hexutil.decode("000102030405060708090a0b0c0d0e0f").unwrap()
  let ct_cbc = @smcrypto.sm4_encrypt_cbc(key, iv, pt).unwrap()
  let back_cbc = @smcrypto.sm4_decrypt_cbc(key, iv, ct_cbc).unwrap()
  println("CBC 密文        = \{@hexutil.encode(ct_cbc)}")
  println("CBC 解密还原    = \{@hexutil.encode(back_cbc)}")
  println("CBC 还原正确    = \{back_cbc == pt}")
  // 单块国标向量
  let std_pt = @hexutil.decode("0123456789abcdeffedcba9876543210").unwrap()
  let std_ct = c.encrypt_block(std_pt)
  println("")
  println("国标单块向量    = \{@hexutil.encode(std_ct)}")
  println("国标期望        = 681edf34d206965e86b3e94f536e4246")
  println("")
  println("=== HMAC-SM3 消息认证 ===")
  let mac = @smcrypto.sm3_hmac(key, pt)
  println("HMAC-SM3        = \{@hexutil.encode(mac)}")
  // 篡改一个字节后校验失败
  let tampered : FixedArray[Byte] = FixedArray::make(pt.length(), b'\x00')
  for i in 0..<pt.length() {
    tampered[i] = pt[i]
  }
  tampered[0] = (tampered[0].to_int() ^ 0x01).to_byte()
  let mac2 = @smcrypto.sm3_hmac(key, Bytes::from_array(tampered))
  println("篡改后校验通过  = \{mac == mac2}")
  println("")
  println("=== SM3-KDF 密钥派生 (GB/T 32918.3-2016) ===")
  let shared = @hexutil.decode("000102030405060708090a0b0c0d0e0f").unwrap()
  println("KDF(Z, 32)      = \{@hexutil.encode(@smcrypto.sm3_kdf(shared, 32))}")
  println(
    "KDF(Z, 32) 期望 = 36f913884de844fce7bc7958fc2a3dd004f6992a3dd76a7fc2e287f2bd58a8dd",
  )
  println("")
  println("=== 错误处理 ===")
  let bad_key = @hexutil.decode("000102030405060708090a0b0c0d0e").unwrap()
  match @smcrypto.sm4_new(bad_key) {
    Err(e) => println("15 字节密钥 -> \{e.to_string()}")
    Ok(_) => println("意外通过")
  }
}
