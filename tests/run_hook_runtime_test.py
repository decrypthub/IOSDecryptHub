"""在独立日志目录运行真实原生 Hook 与跨进程 journal 回归。"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="idh-hook-runtime-") as directory:
        env = {**os.environ, "DH_LOG_DIR": directory}
        first = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=40)
        print(first.stdout)
        assert first.returncode == 0, first.stderr
        generation = json.loads(first.stdout.strip().splitlines()[-1])["generation"]
        second = subprocess.run([binary, "--restore", generation], env=env, capture_output=True, text=True, timeout=20)
        print(second.stdout)
        assert second.returncode == 0, second.stderr


if __name__ == "__main__":
    main()
