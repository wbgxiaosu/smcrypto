// PBKDF2-HMAC-SM3 测试：参考值由 Python gmssl（SM3 国标实现）+
// 手写 RFC 2104 HMAC / RFC 8018 PBKDF2 结构独立计算，与本项目实现交叉对拍。
// 生成脚本与向量另存于仓库 gen/ 目录。

///|
test "pbkdf2-hmac-sm3 cross-checked vectors" {
  // 基础用例：password/salt
  assert_eq(
    @hexutil.encode(@sm3.pbkdf2(b"password", b"salt", 1, 32)),
    "4612f922a1fdcefaf4312fc6f8f3322b489cbf24f2ea361b44c2bd8fa2c6dcb0",
    msg="pbkdf2 iter=1",
  )
  assert_eq(
    @hexutil.encode(@sm3.pbkdf2(b"password", b"salt", 2, 32)),
    "fee723a2bc966e11dffb66133f4e8df577383c78ade30e3298edbd3e54ed85b7",
    msg="pbkdf2 iter=2",
  )
  assert_eq(
    @hexutil.encode(@sm3.pbkdf2(b"password", b"salt", 4096, 32)),
    "b6e8f2074c87432b78f62e5ced980fdff89e86af2f693dab1638e2b3683045dd",
    msg="pbkdf2 iter=4096",
  )
  // 跨两个派生块（dklen 64 > hLen 32），前 32 字节应与上一条一致
  assert_eq(
    @hexutil.encode(@sm3.pbkdf2(b"password", b"salt", 4096, 64)),
    "b6e8f2074c87432b78f62e5ced980fdff89e86af2f693dab1638e2b3683045dd" +
    "844438500eead50cb3e11a74db6bb2df4cc402ec6986ad3a46163e3b9647fea4",
    msg="pbkdf2 multi-block",
  )
  // 高迭代次数
  assert_eq(
    @hexutil.encode(
      @sm3.pbkdf2(b"PasswordSecret", b"NaCl-project SodiumChloride", 80000, 32),
    ),
    "f91fbfb56e7de3e910cc9f12ae13745e1e8c8c53f4c7d0bebc0e890565223063",
    msg="pbkdf2 iter=80000",
  )
  // 长密钥（80 字节 > 64，需先预哈希）+ 非 32 倍数输出长度
  let long_pw = Bytes::from_array(FixedArray::make(80, b'\xff'))
  let salt3_arr : FixedArray[Byte] = FixedArray::make(3, b'\x00')
  salt3_arr[0] = b'\x01'
  salt3_arr[1] = b'\x02'
  salt3_arr[2] = b'\x03'
  let salt3 = Bytes::from_array(salt3_arr)
  assert_eq(
    @hexutil.encode(@sm3.pbkdf2(long_pw, salt3, 1000, 48)),
    "233519cdc5babc1f7a79309ccd6b6b80b185386728e227c1c91a52d3099c5a13" +
    "4ac0277cba68a43e0e1675902442a2c7",
    msg="pbkdf2 long-key 48B",
  )
}

///|
test "pbkdf2 edge cases" {
  // 空口令、空盐仍可派生（与 Python 基准对拍）
  assert_eq(
    @hexutil.encode(@sm3.pbkdf2(b"", b"", 1, 32)),
    "311c191a8c3676b7b0e5ab0b9e1a7b66da1eb58f798d2ccb08de8ab50385e96c",
    msg="pbkdf2 empty inputs",
  )
  // 非法参数返回空
  assert_eq(@sm3.pbkdf2(b"pw", b"salt", 0, 32).length(), 0, msg="iter=0 empty")
  assert_eq(@sm3.pbkdf2(b"pw", b"salt", 10, 0).length(), 0, msg="dklen=0 empty")
  // dklen 非 32 倍数：截断最后一块
  let part = @sm3.pbkdf2(b"password", b"salt", 1, 10)
  assert_eq(part.length(), 10, msg="truncated length")
  assert_eq(
    @hexutil.encode(part),
    "4612f922a1fdcefaf431",
    msg="truncated prefix",
  )
}
