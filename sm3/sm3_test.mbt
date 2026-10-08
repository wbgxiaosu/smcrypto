// SM3 黑盒测试：国标核心向量（GB/T 32905-2016 附录 A）
// 示例 1：消息 "abc"
// 示例 2：消息 "abcd" 重复 16 次（64 字节）
// 空消息摘要另与 Python gmssl 实现交叉验证核对。

///|
test "sm3 gb standard vector 1 (abc)" {
  let d = @sm3.hex_digest(b"abc")
  assert_eq(
    d, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
}

///|
test "sm3 gb standard vector 2 (abcd x16)" {
  let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
  let d = @sm3.hex_digest(msg)
  assert_eq(
    d, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
  )
}

///|
test "sm3 empty message" {
  let d = @sm3.hex_digest(b"")
  assert_eq(
    d, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
  )
}

///|
test "sm3 hexutil roundtrip" {
  let data = b"\x00\xff\x7f\x80\x12\x34"
  let hex = @hexutil.encode(data)
  assert_eq(hex, "00ff7f801234")
  let back = @hexutil.decode(hex).unwrap()
  assert_eq(back, data)
}
