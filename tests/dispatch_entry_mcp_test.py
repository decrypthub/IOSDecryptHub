"""Native private-callout evidence and mutation isolation on an explicit endpoint."""
import argparse
import json
from pathlib import Path
import unittest
import urllib.request


def rpc(name, arguments=None):
    body=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':arguments or {}}}).encode()
    request=urllib.request.Request(ENDPOINT+'/api/mcp',data=body,headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=40) as response:result=json.load(response)['result']
    if result.get('isError'):return False,result
    data=result.get('structuredContent')
    if data is None:data=json.loads(next(x['text'] for x in result['content'] if x['type']=='text'))
    return True,data


class DispatchEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ok,c=rpc('get_capabilities');assert ok
        cls.generation=c['processGeneration']

    def test_a_native_evidence_has_distinct_real_deliveries(self):
        evidence=json.loads(Path(FIXTURE).read_text(encoding='utf8'))
        if 'structuredContent' in evidence:evidence=evidence['structuredContent']
        self.assertTrue(evidence['ok']);self.assertEqual(len(evidence['passed']),4)
        rows=evidence['tasks'];self.assertEqual(len(rows),2)
        self.assertEqual(len({r['asyncTaskId'] for r in rows}),2)
        for row in rows:
            self.assertTrue(row['asyncTaskId'].startswith(self.generation+':async:'))
            self.assertEqual(row['state'],'completed')
            self.assertEqual(row['edge'],'observed-callback-entry; registration-unobserved')
            self.assertFalse(row['registrationId']);self.assertFalse(row['asyncSubmittedByCallId'])
            self.assertLessEqual(int(row['startedNs']),int(row['finishedNs']))
        observed=evidence['observations'];self.assertEqual(len(observed),4)
        self.assertFalse(observed[0]['task']);self.assertFalse(observed[3]['task'])
        self.assertEqual(len({o['context'] for o in observed}),1)
        self.assertEqual({observed[1]['task'],observed[2]['task']},{r['asyncTaskId'] for r in rows})

    def test_b_typed_target_is_owned(self):
        ok,state=rpc('get_dispatch_entry_state');self.assertTrue(ok)
        self.assertTrue(state['ready']);self.assertFalse(state['enabled']);self.assertTrue(state['retainedUntilRestart'])
        self.assertEqual(state['probeMismatches'],0)
        ok,result=rpc('hook_inline',{'addr':state['targetIdentity']['address'],'process_generation':self.generation,'label':'conflicting-private-entry','abi':{'arguments':['pointer','pointer'],'return':'void'},'capture_return':False})
        self.assertFalse(ok,result)

    def test_c_bad_mutations_preserve_state(self):
        _,before=rpc('get_dispatch_entry_state')
        for args in [{'enabled':True},{'process_generation':'stale','enabled':True},{'process_generation':self.generation,'enabled':1},{'process_generation':self.generation,'enabled':'true'},{'process_generation':self.generation}]:
            ok,result=rpc('configure_dispatch_entry',args);self.assertFalse(ok,result)
        ok,result=rpc('run_dispatch_entry_selftest',{'process_generation':'stale'});self.assertFalse(ok,result)
        _,after=rpc('get_dispatch_entry_state')
        for key in ['ready','enabled','attempted','retainedUntilRestart','targetIdentity','probeMismatches']:self.assertEqual(before[key],after[key])

    def test_d_selftest_cannot_replace_an_async_window(self):
        ok,arm=rpc('configure_async_capture',{'process_generation':self.generation,'enabled':True,'capture_roots':False,'max_tasks':3,'max_ms':10000});self.assertTrue(ok)
        try:
            ok,test=rpc('run_dispatch_entry_selftest',{'process_generation':self.generation});self.assertTrue(ok);self.assertFalse(test['ok'])
            _,state=rpc('get_flow_state')
            for key in ['windowStartedNs','windowDeadlineNs','rootAPIInclude','maxRecords']:self.assertEqual(arm['state'][key],state[key])
        finally:rpc('configure_async_capture',{'process_generation':self.generation,'enabled':False})

    def test_e_private_switch_does_not_change_async_window(self):
        ok,arm=rpc('configure_async_capture',{'process_generation':self.generation,'enabled':True,'capture_roots':False,'root_api_include':['libdispatch.client-callout'],'max_tasks':3,'max_ms':10000});self.assertTrue(ok)
        try:
            for on in [True,False]:
                ok,state=rpc('configure_dispatch_entry',{'process_generation':self.generation,'enabled':on});self.assertTrue(ok);self.assertEqual(bool(state['state']['enabled']),on)
                _,flow=rpc('get_flow_state')
                for key in ['windowStartedNs','windowDeadlineNs','rootAPIInclude']:self.assertEqual(flow[key],arm['state'][key])
        finally:
            rpc('configure_dispatch_entry',{'process_generation':self.generation,'enabled':False})
            rpc('configure_async_capture',{'process_generation':self.generation,'enabled':False})


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--endpoint',required=True);parser.add_argument('--fixture',required=True);args=parser.parse_args()
    ENDPOINT=args.endpoint.rstrip('/');FIXTURE=args.fixture
    unittest.main(argv=['dispatch_entry_mcp_test.py'],verbosity=2)
