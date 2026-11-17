import json
from pathlib import Path
import signal
import subprocess
import sys
binary=Path(sys.argv[1]).resolve();saved=binary.parent/'control-test-results';saved.mkdir(exist_ok=True)
for mode in ['default64','state64','identity64','default32','state32','identity32','thread-conflict','unhandled']:
 result=subprocess.run([str(binary),mode],capture_output=True,text=True,timeout=15)
 (saved/('forward-'+mode+'.json')).write_text(json.dumps({'exit':result.returncode,'output':result.stdout,'stderr':result.stderr}),encoding='utf8')
 if mode=='unhandled':
  if result.returncode!=-signal.SIGTRAP:raise AssertionError(('original unknown trap behavior changed',result.returncode,result.stderr))
 else:
  if result.returncode:raise AssertionError((mode,result.returncode,result.stdout,result.stderr))
  if not json.loads(result.stdout)['ok']:raise AssertionError(mode)
 print('PASS owned Mach routing:',mode,flush=True)
