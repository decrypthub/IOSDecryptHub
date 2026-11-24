"""Generate the SDK's checked Mach exception demultiplexer with private names."""
import argparse
from pathlib import Path
import re
import subprocess
p=argparse.ArgumentParser();p.add_argument('--sdk',default='macosx');p.add_argument('--prefix',default='dh_control');p.add_argument('--output',default='build/control-mig');p.add_argument('--protocol',choices=['mach_exc','exc'],default='mach_exc');a=p.parse_args()
if not re.fullmatch(r'[a-z_][a-z0-9_]*',a.prefix):raise ValueError('invalid symbol prefix')
out=Path(a.output);out.mkdir(parents=True,exist_ok=True)
sdk=subprocess.check_output(['xcrun','--sdk',a.sdk,'--show-sdk-path'],text=True).strip()
source=out/(a.prefix+'_mach.c');header=out/(a.prefix+'_mach.h')
client=out/(a.prefix+'_mach_client.h');user=out/(a.prefix+'_mach_client.c')
subprocess.run(['xcrun','mig','-arch','arm64','-isysroot',sdk,'-server',str(source),'-sheader',str(header),'-user',str(user),'-header',str(client),str(Path(sdk)/('usr/include/mach/'+a.protocol+'.defs'))],check=True)
names={a.protocol+'_server':a.prefix+'_mach_server',a.protocol+'_server_routine':a.prefix+'_mach_server_routine',a.protocol+'_subsystem':a.prefix+'_mach_subsystem'}
names['catch_'+a.protocol+'_subsystem']=a.prefix+'_catch_'+a.protocol+'_subsystem'
for kind in ['raise','raise_state','raise_state_identity']:
 original=('catch_mach_exception_' if a.protocol=='mach_exc' else 'catch_exception_')+kind
 names[original]=a.prefix+'_'+original
for kind in ['raise','raise_state','raise_state_identity']:
 original=('mach_exception_' if a.protocol=='mach_exc' else 'exception_')+kind
 names[original]=a.prefix+'_'+original
for path in [source,header,client,user]:
 text=path.read_text();text=re.sub(r'\b('+'|'.join(map(re.escape,names))+r')\b',lambda m:names[m[0]],text)
 with path.open('w',encoding='utf8',newline='\n') as f: f.write(text)
if a.protocol=='mach_exc':
 narrowHeader=out/(a.prefix+'_exc_client.h');narrowUser=out/(a.prefix+'_exc_client.c')
 subprocess.run(['xcrun','mig','-arch','arm64','-isysroot',sdk,'-server','/dev/null','-sheader','/dev/null','-user',str(narrowUser),'-header',str(narrowHeader),str(Path(sdk)/'usr/include/mach/exc.defs')],check=True)
 for path in [narrowHeader,narrowUser]:
  text=path.read_text();text=re.sub(r'\b(exception_raise(?:_state(?:_identity)?)?)\b',lambda m:a.prefix+'_'+m[0],text)
  with path.open('w',encoding='utf8',newline='\n') as f: f.write(text)
