// SM4 CTR 模式测试：参考值由 Python gmssl（SM4 标准实现）+
// 手写 SP 800-38A CTR 结构独立计算，与本项目实现交叉对拍。

///|
/// 字节串转小写十六进制（测试辅助）。
fn ctr_bytes_hex(data : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i in 0..<data.length() {
    let v = data[i].to_int()
    sb.write_char(digits[v >> 4].to_int().unsafe_to_char())
    sb.write_char(digits[v & 0x0f].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
test "sm4-ctr cross-checked vectors" {
  let key = sm4_hex_bytes("0123456789abcdeffedcba9876543210")
  let ctr1 = sm4_hex_bytes("00000000000000000000000000000001")
  // 43 字节明文（2 个整块 + 11 字节尾块）
  assert_eq(
    ctr_bytes_hex(
      @sm4.encrypt_ctr(
        key, ctr1, b"The quick brown fox jumps over the lazy dog",
      ).unwrap(),
    ),
    "1a313ed04e56d47359bbcd24f79ff6ccd57c142424e0255d3c45411f2a5561b9c9403239ea749e72ff92c0",
    msg="ctr fox vector",
  )
  // 空明文输出空
  assert_eq(
    @sm4.encrypt_ctr(key, ctr1, b"").unwrap().length(),
    0,
    msg="ctr empty",
  )
  // 计数器全 1 进位回绕（ffffffff... + 2 块进位），33 字节明文 0x41
  let ctr_max = sm4_hex_bytes("ffffffffffffffffffffffffffffffff")
  let rollover = @sm4.encrypt_ctr(
    key,
    ctr_max,
    sm4_hex_bytes(
      "414141414141414141414141414141414141414141414141414141414141414141",
    ),
  ).unwrap()
  assert_eq(
    ctr_bytes_hex(rollover),
    "2950ee3f483225a6c7ba048f1cdb21b16736b52a4880638dd61472511a95e36b0f",
    msg="ctr counter rollover",
  )
}

///|
test "sm4-ctr roundtrip and error cases" {
  let key = sm4_hex_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let ctr = sm4_hex_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
  let pt : FixedArray[Byte] = FixedArray::make(37, b'\x00')
  for i in 0..<37 {
    pt[i] = ((i * 31 + 7) % 256).to_byte()
  }
  let ct = @sm4.encrypt_ctr(key, ctr, Bytes::from_array(pt)).unwrap()
  // CTR 密文长度 == 明文长度（无填充）
  assert_eq(ct.length(), 37, msg="ctr keeps length")
  // 解密还原
  let back = @sm4.decrypt_ctr(key, ctr, ct).unwrap()
  assert_eq(
    ctr_bytes_hex(back),
    ctr_bytes_hex(Bytes::from_array(pt)),
    msg="roundtrip",
  )
  // 计数器长度错误
  assert_eq(
    @sm4.encrypt_ctr(key, sm4_hex_bytes("0001"), b"x") is Err(_),
    true,
    msg="bad counter length rejected",
  )
}
