"""Read completed IDH-owned flow fixtures and reject invalid requests on an explicit device."""
import argparse,json,unittest
from urllib.request import Request,urlopen
class FlowTests(unittest.TestCase):
    endpoint=''
    aborted=''
    def raw(self,name,args=None):
        body=json.dumps({'jsonrpc':'2.0','id':name,'method':'tools/call','params':{'name':name,'arguments':args or {}}}).encode()
        with urlopen(Request(self.endpoint.rstrip('/')+'/api/mcp',body,{'Content-Type':'application/json'}),timeout=40) as response:return json.load(response)['result']
    def call(self,name,args=None):
        r=self.raw(name,args);self.assertFalse(r.get('isError'),r);return r.get('structuredContent') or json.loads(r['content'][0]['text'])
    def test_aborted_is_not_normal_return(self):
        r=self.call('get_call',{'call_id':self.aborted,'limit':100})
        self.assertEqual(r['status'],'aborted');self.assertFalse(r['retainedPair']);self.assertIsNone(r['leaveSeq']);self.assertIsNotNone(r['abortedSeq'])
        end=next(e for e in r['events'] if e.get('callId')==self.aborted and e['phase']=='aborted')
        self.assertFalse(end['payload']['returnValue']['available'])
    def test_observed_task_edges_and_exact_event_filter(self):
        r=self.call('get_async_tasks',{'limit':128});tasks=r['tasks'];self.assertGreaterEqual(len(tasks),10)
        ids={t['asyncTaskId'] for t in tasks};self.assertEqual(len(ids),len(tasks))
        self.assertTrue(any(t['asyncParentTaskId'] for t in tasks));self.assertTrue(all(not t['asyncParentTaskId'] or t['asyncParentTaskId'] in ids for t in tasks))
        self.assertTrue(all(t.get('callbackIdentity',{}).get('imageUUID') for t in tasks));unresolved=[t for t in tasks if t['state']=='unresolved'];self.assertEqual(len(unresolved),2);self.assertEqual({t['terminalReason'] for t in unresolved},{'block-reused-before-observed-start','block-executed-outside-calibrated-async-invoker'});self.assertTrue(all(t['startedNs']=='0' and t['executionThreadId']==0 for t in unresolved));self.assertTrue(all(t['state']=='completed' for t in tasks if t not in unresolved));self.assertFalse(r['state']['enabled']);self.assertEqual(r['state']['pendingOrRunning'],0)
        first=tasks[0]['asyncTaskId'];events=self.call('query_events',{'async_task_id':first,'limit':50})['events']
        self.assertTrue(events);self.assertTrue(all(e.get('asyncTaskId')==first for e in events))
    def test_invalid_rejected_without_mutation(self):
        g=self.call('get_capabilities')['processGeneration'];before=self.call('get_flow_state');hooks=self.call('list_hooks')
        base={'process_generation':g,'enabled':True,'max_tasks':8,'max_ms':1000}
        for bad in [{'enabled':1},{'enabled':'true'},{'capture_roots':1},{'max_tasks':0},{'max_tasks':257},{'max_ms':0},{'max_ms':60001},{'max_ms':True},{'max_tasks':1.5},{'process_generation':'old'},{'queue_exclude':None},{'queue_exclude':['x']*9},{'queue_exclude':['']},{'queue_exclude':['a\x00b']},{'queue_exclude':['a'*128]},{'root_queue_include':None},{'root_queue_include':['x']*9},{'root_queue_include':['']},{'root_queue_include':['a\x00b']},{'root_queue_include':['a'*128]},{'root_queue_include':['汉'*43]},{'root_queue_include':'network'},{'root_api_include':None},{'root_api_include':['x']*9},{'root_api_include':['']},{'root_api_include':['a\x00b']},{'root_api_include':['a'*128]},{'root_api_include':['汉'*43]},{'root_api_include':'source'}]:
            with self.subTest(bad=bad):self.assertTrue(self.raw('configure_async_capture',{**base,**bad}).get('isError'))
        self.assertTrue(self.raw('configure_async_capture',{'process_generation':g}).get('isError'))
        for symbol in ['dispatch_async','dispatch_block_create','dispatch_block_create_with_qos_class','dispatch_group_notify','dispatch_group_notify_f','dispatch_block_notify']:self.assertTrue(self.raw('hook_import',{'symbol':symbol,'process_generation':g}).get('isError'))
        for bad in [{'limit':0},{'limit':129},{'offset':1025},{'offset':True},{'task_id':'old:async:1'}]:
            with self.subTest(bad=bad):self.assertTrue(self.raw('get_async_tasks',bad).get('isError'))
        self.assertEqual(hooks,self.call('list_hooks'));self.assertEqual(before,self.call('get_flow_state'))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--endpoint',required=True);p.add_argument('--aborted-call-id',required=True);a=p.parse_args()
    FlowTests.endpoint=a.endpoint;FlowTests.aborted=a.aborted_call_id;unittest.main(argv=[__file__],verbosity=2)
