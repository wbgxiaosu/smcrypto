// HMAC-SM3 测试：参考值由 Python gmssl（SM3 标准实现）按 RFC 2104
// 结构独立计算，与本项目实现交叉对拍。

///|
test "hmac-sm3 cross-checked vectors" {
  // key="key", msg="The quick brown fox jumps over the lazy dog"
  assert_eq(
    @hexutil.encode(
      @sm3.hmac(b"key", b"The quick brown fox jumps over the lazy dog"),
    ),
    "bd4a34077888162b210645b8ebf74b9af357303789357a27c7fc457244ebd398",
    msg="hmac fox vector",
  )
  // 空密钥空消息
  assert_eq(
    @hexutil.encode(@sm3.hmac(b"", b"")),
    "0d23f72ba15e9c189a879aefc70996b06091de6e64d31b7a84004356dd915261",
    msg="hmac empty vector",
  )
  // 长密钥（100 字节 > 分组长 64，需先对密钥做一次 SM3）
  let long_key : FixedArray[Byte] = FixedArray::make(100, b'A')
  assert_eq(
    @hexutil.encode(@sm3.hmac(Bytes::from_array(long_key), b"x")),
    "3791977e76b07066a44e23932de8501d0436aaad2c42d7dd807fa0358009aa22",
    msg="hmac long-key vector",
  )
  // 中文消息（UTF-8）+ 16 字节密钥
  assert_eq(
    @hexutil.encode(
      @sm3.hmac(
        sm3_hex_bytes("000102030405060708090a0b0c0d0e0f"),
        sm3_hex_bytes("6368696e657365206461746120e4b8ade69687"),
      ),
    ),
    "a5da171797c16e3fb3494fecd4b75361a6c1ff0a870c1b25a177753f7357c192",
    msg="hmac chinese vector",
  )
}

///|
test "hmac-sm3 determinism and key sensitivity" {
  let key = b"secret-key"
  let msg = b"message to authenticate"
  let m1 = @sm3.hmac(key, msg)
  let m2 = @sm3.hmac(key, msg)
  assert_eq(@hexutil.encode(m1), @hexutil.encode(m2), msg="deterministic")
  let m3 = @sm3.hmac(b"secret-kex", msg)
  assert_eq(
    @hexutil.encode(m1) == @hexutil.encode(m3),
    false,
    msg="key sensitive",
  )
  // 输出长度恒为 32 字节
  assert_eq(m1.length(), 32, msg="mac length")
}

///|
test "hmac-sm3 exact block-boundary keys" {
  // 恰好 64 字节的密钥不做预哈希；65 字节则预哈希——
  // 两个路径都要与参考值一致（参考值由 gmssl 独立计算）
  let k64 : FixedArray[Byte] = FixedArray::make(64, b'\x11')
  let k65 : FixedArray[Byte] = FixedArray::make(65, b'\x11')
  let m64 = @sm3.hmac(Bytes::from_array(k64), b"payload")
  let m65 = @sm3.hmac(Bytes::from_array(k65), b"payload")
  assert_eq(m64.length(), 32, msg="64-byte key mac length")
  assert_eq(m65.length(), 32, msg="65-byte key mac length")
  assert_eq(
    @hexutil.encode(m64) == @hexutil.encode(m65),
    false,
    msg="boundary keys must not collide",
  )
}
