///|
/// 十六进制编码错误类型。
pub(all) enum HexError {
  /// 输入长度为奇数（每个字节需要两个十六进制字符）
  InvalidLength
  /// 第 `Int` 个字符不是合法的十六进制字符
  InvalidCharacter(Int)
} derive(Eq, Debug)

///|
pub extend HexError with Eq::{not_equal, equal}

///|
pub extend HexError with @moonbitlang/core/debug.Debug::{to_repr}

///|
/// 将错误转换为可读字符串。
pub fn HexError::to_string(self : HexError) -> String {
  match self {
    InvalidLength => "hex: 输入长度必须为偶数"
    InvalidCharacter(i) =>
      "hex: 第 \{i} 个字符不是合法的十六进制字符"
  }
}

///|
/// 小写十六进制字符表。
let hex_digits : String = "0123456789abcdef"

///|
/// 将字节串编码为小写十六进制字符串。
pub fn encode(data : Bytes) -> String {
  let sb = StringBuilder()
  for i in 0..<data.length() {
    let b = data[i].to_int()
    sb.write_char(hex_digits[b >> 4].to_int().unsafe_to_char())
    sb.write_char(hex_digits[b & 0x0f].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
/// 十六进制字符数值。失败返回 -1。
fn hex_val(v : Int) -> Int {
  if v >= '0'.to_int() && v <= '9'.to_int() {
    v - '0'.to_int()
  } else if v >= 'a'.to_int() && v <= 'f'.to_int() {
    v - 'a'.to_int() + 10
  } else if v >= 'A'.to_int() && v <= 'F'.to_int() {
    v - 'A'.to_int() + 10
  } else {
    -1
  }
}

///|
/// 将十六进制字符串解码为字节串。失败时返回 [HexError]。
pub fn decode(s : String) -> Result[Bytes, HexError] {
  let n = s.length()
  if n % 2 != 0 {
    return Err(InvalidLength)
  }
  let out : FixedArray[Byte] = FixedArray::make(n / 2, b'\x00')
  for i in 0..<n {
    let v = hex_val(s[i].to_int())
    if v < 0 {
      return Err(InvalidCharacter(i))
    }
    if i % 2 == 0 {
      out[i / 2] = (v << 4).to_byte()
    } else {
      out[i / 2] = (out[i / 2].to_int() | v).to_byte()
    }
  }
  Ok(Bytes::from_array(out))
}
