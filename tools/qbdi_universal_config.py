"""Merge matching static QBDI configs, enabling pointer authentication only for arm64e."""
from pathlib import Path
import re
import sys


def merge(arm64, arm64e):
    off = "/* #undef QBDI_PTRAUTH */"
    if arm64.count(off) != 1:
        raise ValueError("arm64 config must disable QBDI_PTRAUTH")
    enabled = re.compile(r"^#define QBDI_PTRAUTH[ \t]+[^\s]+[ \t]*$", re.M)
    if len(enabled.findall(arm64e)) != 1:
        raise ValueError("arm64e config must enable QBDI_PTRAUTH")
    normalized = enabled.sub(off, arm64e)
    if normalized != arm64:
        raise ValueError("QBDI static configs differ beyond pointer authentication")
    if "#define QBDI_ARCH_AARCH64 1" not in arm64 or "#define QBDI_EXPORT_SYM" in arm64:
        raise ValueError("expected static AARCH64 configurations")
    return arm64.replace(off, "#if defined(__arm64e__)\n#define QBDI_PTRAUTH 1\n#endif")


if __name__ == "__main__":
    a, b, output = map(Path, sys.argv[1:])
    output.write_text(merge(a.read_text(), b.read_text()), encoding="utf8")
