# 生成 sm4 全量向量测试（数据来自 gen/vectors.json，与 Python gmssl 交叉验证）
import json

vec = json.load(open(r"C:\Users\16841\WorkBuddy\2026-09-17-21-36-22\smcrypto\gen\vectors.json", encoding="utf-8"))
cases = vec["sm4_cases"]

lines = []
lines.append("// 本文件由 gen/gen_sm4_tests.py 自动生成")
lines.append("// 测试向量来源：Python gmssl 库（其实现已通过 GB/T 32907-2016 国标向量验证）")
lines.append("// 共 %d 条向量：3 组密钥 x 8 组随机明文（16/17/31/32/48/100 字节）与随机 IV" % len(cases))
lines.append("")
lines.append("///|")
lines.append("let sm4_vector_cases : Array[(String, String, String, String, String)] = [")
for c in cases:
    lines.append('  ("%s", "%s", "%s", "%s", "%s"),' % (c["key"], c["pt"], c["iv"], c["ecb"], c["cbc"]))
lines.append("]")
lines.append("")
lines.append("///|")
lines.append('test "sm4 all cross-verified vectors (ecb + cbc)" {')
lines.append("  for i, case in sm4_vector_cases {")
lines.append("    let (key_hex, pt_hex, iv_hex, ecb_hex, cbc_hex) = case")
lines.append("    let key = sm4_hex_bytes(key_hex)")
lines.append("    let pt = sm4_hex_bytes(pt_hex)")
lines.append("    let iv = sm4_hex_bytes(iv_hex)")
lines.append("    // ECB")
lines.append("    let ecb_ct = @sm4.encrypt_ecb(key, pt).unwrap()")
lines.append("    assert_eq(sm4_bytes_hex(ecb_ct), ecb_hex, msg=\"ecb #\\{i}\")")
lines.append("    assert_eq(sm4_bytes_hex(@sm4.decrypt_ecb(key, ecb_ct).unwrap()), pt_hex, msg=\"ecb roundtrip #\\{i}\")")
lines.append("    // CBC")
lines.append("    let cbc_ct = @sm4.encrypt_cbc(key, iv, pt).unwrap()")
lines.append("    assert_eq(sm4_bytes_hex(cbc_ct), cbc_hex, msg=\"cbc #\\{i}\")")
lines.append("    assert_eq(sm4_bytes_hex(@sm4.decrypt_cbc(key, iv, cbc_ct).unwrap()), pt_hex, msg=\"cbc roundtrip #\\{i}\")")
lines.append("  }")
lines.append("}")
lines.append("")

out = r"C:\Users\16841\WorkBuddy\2026-09-17-21-36-22\smcrypto\sm4\sm4_vectors_test.mbt"
open(out, "w", encoding="utf-8", newline="\n").write("\n".join(lines))
print("written", out, len(cases), "vectors")
