// SM3-KDF 测试：参考值由 Python gmssl（SM3 标准实现）按
// GB/T 32918.3-2016 5.4.2 结构独立计算，与本项目实现交叉对拍。

///|
test "sm3-kdf cross-checked vectors" {
  // Z = 00..0f, klen = 32（单块恰好取满）
  assert_eq(
    @hexutil.encode(
      @sm3.kdf(sm3_hex_bytes("000102030405060708090a0b0c0d0e0f"), 32),
    ),
    "36f913884de844fce7bc7958fc2a3dd004f6992a3dd76a7fc2e287f2bd58a8dd",
    msg="kdf 32-byte vector",
  )
  // klen = 19（跨块截断，最后一个块只取 19-16=3 字节）
  assert_eq(
    @hexutil.encode(@sm3.kdf(b"secret", 19)),
    "7ff3a5930a2f05791c3353784b66c8d11b0311",
    msg="kdf 19-byte truncated vector",
  )
  // klen = 33（超过一个完整块，ct=2 参与计算）
  assert_eq(
    @hexutil.encode(@sm3.kdf(b"", 33)),
    "88c0cffa4c713446a03f1fff1630aa6353bdb53e2a9272146be7a82fde06afa3da",
    msg="kdf 33-byte two-block vector",
  )
}

///|
test "sm3-kdf edge cases" {
  // klen = 0 / 负数：返回空输出
  assert_eq(@sm3.kdf(b"z", 0).length(), 0, msg="zero-length output")
  assert_eq(@sm3.kdf(b"z", -1).length(), 0, msg="negative klen")
  // 大输出：klen = 100 需要 4 个计数器块
  let big = @sm3.kdf(b"shared-secret", 100)
  assert_eq(big.length(), 100, msg="100-byte output length")
  // 确定性
  assert_eq(
    @hexutil.encode(big),
    @hexutil.encode(@sm3.kdf(b"shared-secret", 100)),
    msg="deterministic",
  )
}
