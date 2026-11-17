"""Check optimized iOS ARC output never retains borrowed dispatch arguments.

Compile dh_flow_sources.m with -O2 -fobjc-arc -S -emit-llvm for each iOS arch,
then pass the .ll paths. A system disposal caller may supply a source whose
external refs already reached zero: retaining that input traps in libdispatch.
The association value has independent ownership and must still be retained.
"""
import argparse
import re
from pathlib import Path


def verify(path):
    text = path.read_text(encoding="utf8")
    checks = {"wrap_source_cancel": [0], "wrap_target": [0, 1], "wrap_source_create": [3],
              "wrap_event": [0], "wrap_cancel": [0], "wrap_registration": [0],
              "wrap_event_f": [0], "wrap_cancel_f": [0], "wrap_registration_f": [0]}
    for name, indices in checks.items():
        match = re.search(r"^define[^\n]* @" + name + r"\(([^\n]*)\)[^\n]*\{\n(.*?)^\}", text, re.M | re.S)
        assert match, (path.name, "missing optimized wrapper", name)
        params, body = match.groups()
        arguments = re.findall(r"(?:ptr|i\d+)[^,%\n]* (%[\w.]+)", params)
        for index in indices:
            value = arguments[index]
            pattern = r"@(?:llvm\.objc\.(?:retain(?:Block)?|release)|objc_(?:retain|release)|_?os_object_retain)\(ptr(?: [a-z_]+)* " + re.escape(value) + r"\)"
            assert not re.search(pattern, body), (path.name, name, "borrowed input retained/released", index)
    print("PASS", path.name, "nine optimized wrappers preserve borrowed dispatch inputs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("llvm_ir", nargs="+", type=Path)
    for filename in parser.parse_args().llvm_ir:
        verify(filename)
