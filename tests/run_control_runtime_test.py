import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
for mode in ("full", "prepared", "breakpoint", "breakpoint-prepared"):
    with tempfile.TemporaryDirectory(prefix="idh-native-control-") as directory:
        executable=Path(sys.argv[1]).resolve()
        result=subprocess.run([str(executable), mode],env={**os.environ, "DH_LOG_DIR": directory},
                              capture_output=True,text=True,timeout=45)
        saved=executable.parent/"control-test-results";saved.mkdir(exist_ok=True)
        (saved/f"{mode}.json").write_text(result.stdout,encoding="utf8")
        (saved/f"{mode}.stderr.txt").write_text(result.stderr,encoding="utf8")
        if result.returncode:
            print(result.stdout[-8000:]);print(result.stderr[-4000:]);result.check_returncode()
        report=json.loads(result.stdout)
        if not report.get("ok"):raise AssertionError(report.get("error","owned native control fixture failed"))
    print(f"PASS original native control fixture: {mode}", flush=True)
