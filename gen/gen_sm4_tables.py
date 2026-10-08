# 生成 sm4 常量表（S盒/FK/CK），数据来自 gen/vectors.json（提取自 gmssl，已过国标向量验证）
import json

vec = json.load(open(r"C:\Users\16841\WorkBuddy\2026-09-17-21-36-22\smcrypto\gen\vectors.json", encoding="utf-8"))
sbox = [int(x, 16) for x in vec["sbox"]]
fk = [int(x, 16) for x in vec["fk"]]
ck = [int(x, 16) for x in vec["ck"]]

lines = []
lines.append("// 本文件由 gen/gen_sm4_tables.py 自动生成")
lines.append("// SM4 S 盒与系统参数/固定参数，来源：GB/T 32907-2016 附录 A")
lines.append("// （与 Python gmssl 库内置表逐字节一致，其实现已通过国标标准向量验证）")
lines.append("")
lines.append("///|")
lines.append("let sm4_sbox : FixedArray[Byte] = [")
for i in range(0, 256, 16):
    row = ", ".join("0x%02x" % b for b in sbox[i:i+16])
    lines.append("  %s," % row)
lines.append("]")
lines.append("")
lines.append("///|")
lines.append("let sm4_fk : FixedArray[UInt] = [")
lines.append("  " + ", ".join("0x%08xU" % x for x in fk))
lines.append("]")
lines.append("")
lines.append("///|")
lines.append("let sm4_ck : FixedArray[UInt] = [")
for i in range(0, 32, 4):
    row = ", ".join("0x%08xU" % x for x in ck[i:i+4])
    lines.append("  %s," % row)
lines.append("]")
lines.append("")

out = r"C:\Users\16841\WorkBuddy\2026-09-17-21-36-22\smcrypto\sm4\tables.mbt"
open(out, "w", encoding="utf-8", newline="\n").write("\n".join(lines))
print("written", out)
