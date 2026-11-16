import os
from pathlib import Path
import subprocess
import sys
import tempfile
with tempfile.TemporaryDirectory(prefix="idh-unwind-") as directory:
    environment={**os.environ,"DH_LOG_DIR":directory}
    subprocess.run([str(Path(sys.argv[1]).resolve())],env=environment,check=True)
