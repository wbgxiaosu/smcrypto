// hexutil 边界行为测试。

///|
test "hex roundtrip for all byte values" {
  // 全部 256 个字节值的编解码往返
  let all : FixedArray[Byte] = FixedArray::make(256, b'\x00')
  for i in 0..<256 {
    all[i] = i.to_byte()
  }
  let data = Bytes::from_array(all)
  assert_eq(@hexutil.decode(@hexutil.encode(data)).unwrap(), data, msg="full-range roundtrip")
}

///|
test "hex encode output format" {
  assert_eq(@hexutil.encode(Bytes::from_array(FixedArray::make(0, b'\x00'))), "", msg="empty input")
  assert_eq(@hexutil.encode(b"\x00\xff\x10"), "00ff10", msg="mixed bytes")
  // 输出恒为小写
  assert_eq(@hexutil.encode(b"\xab\xcd\xef"), "abcdef", msg="lowercase output")
}

///|
test "hex decode error positions" {
  // 奇数长度
  assert_eq(@hexutil.decode("abc") is Err(InvalidLength), true, msg="odd length rejected")
  // 非法字符：定位到具体位置
  assert_eq(
    @hexutil.decode("00zz") is Err(InvalidCharacter(2)),
    true,
    msg="bad char at index 2",
  )
  assert_eq(
    @hexutil.decode("0g00") is Err(InvalidCharacter(1)),
    true,
    msg="bad char at index 1",
  )
  // 空串合法，产出空字节串
  let empty = @hexutil.decode("").unwrap()
  assert_eq(empty.length(), 0, msg="empty string decodes to empty bytes")
}

///|
test "hex decode case insensitivity" {
  // 大写、小写、混合大小写解码结果一致
  assert_eq(
    @hexutil.decode("0123456789ABCDEF").unwrap(),
    @hexutil.decode("0123456789abcdef").unwrap(),
    msg="upper vs lower",
  )
  assert_eq(
    @hexutil.decode("01aBcD").unwrap(),
    @hexutil.decode("01ABcd").unwrap(),
    msg="mixed case",
  )
}
