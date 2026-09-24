#!/usr/bin/env python3
# gen_web.py — 把 web 资源编成 C 字节数组头, 嵌入 dylib。
# 零运行时依赖、免转义: 前端正常写 web/index.html, make 时自动生成本头。
# 用法:
#   python3 tools/gen_web.py web/index.html src/server/web_index_html.h
#   python3 tools/gen_web.py web/wechat-follow.png src/server/web_wechat_png.h kDHWeChatPNG
import os
import re
import sys


def main():
    if len(sys.argv) not in (3, 4):
        print("用法: gen_web.py <input> <output.h> [symbol]", file=sys.stderr)
        sys.exit(2)
    src, dst = sys.argv[1], sys.argv[2]
    symbol = sys.argv[3] if len(sys.argv) == 4 else "kDHIndexHTML"
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
        print("非法 symbol: %s" % symbol, file=sys.stderr)
        sys.exit(2)
    data = open(src, "rb").read()
    guard = re.sub(r"[^A-Z0-9]+", "_", os.path.basename(dst).upper()).strip("_") + "_"
    src_name = os.path.basename(src)
    out = []
    out.append("// AUTO-GENERATED from %s by tools/gen_web.py — 请勿手改, 改源文件后 make 自动重生成。" % src_name)
    out.append("#ifndef %s" % guard)
    out.append("#define %s" % guard)
    out.append("static const unsigned char %s[] = {" % symbol)
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        out.append("  " + "".join("0x%02x," % b for b in chunk))
    out.append("};")
    out.append("static const unsigned int %s_len = %d;" % (symbol, len(data)))
    out.append("#endif // %s" % guard)
    open(dst, "w").write("\n".join(out) + "\n")
    print("generated %s (%d bytes)" % (dst, len(data)))


if __name__ == "__main__":
    main()
