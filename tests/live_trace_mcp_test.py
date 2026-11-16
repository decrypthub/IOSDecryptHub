"""显式授权设备的 live 读取和拒绝路径；不执行任何业务函数。"""
import argparse
import json
import unittest
from urllib.request import Request,urlopen

class LiveTraceTests(unittest.TestCase):
    endpoint=""
    trace_id=""
    def raw(self,name,args=None):
        body=json.dumps({"jsonrpc":"2.0","id":name,"method":"tools/call","params":{"name":name,"arguments":args or {}}}).encode()
        with urlopen(Request(self.endpoint.rstrip('/')+'/api/mcp',body,{"Content-Type":"application/json"}),timeout=40) as response:
            return json.load(response)["result"]
    def call(self,name,args=None):
        result=self.raw(name,args);self.assertFalse(result.get("isError"),result)
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])
    def test_actual_capabilities(self):
        c=self.call("get_capabilities")
        self.assertTrue(c["capabilities"]["trace_live"])
        self.assertTrue(c["capabilities"]["native_stack_unwind"])
        self.assertEqual(c["stackUnwind"]["maxFrames"],256)
        self.assertEqual(c["liveTrace"]["budgetAction"],"stop recording; continue original")
    def test_reject_before_state_change(self):
        generation=self.call("get_capabilities")["processGeneration"]
        before=self.call("list_hooks")
        base={"process_generation":generation,"slot":0,"normal_return":True}
        bad=[{"normal_return":False},{"normal_return":1},{"normal_return":"true"},
             {"slot":True},{"slot":-1},{"slot":256},{"slot":2**32},
             {"max_insns":0},{"max_insns":8193},{"max_insns":2**32+1},
             {"max_ms":0},{"max_ms":10001},{"max_ms":True},
             {"process_generation":"old-generation"}]
        for patch in bad:
            with self.subTest(patch=patch):self.assertTrue(self.raw("trace_live_arm",{**base,**patch}).get("isError"))
        self.assertTrue(self.raw("trace_live_cancel",{"trace_id":self.trace_id,"process_generation":"old-generation"}).get("isError"))
        self.assertEqual(before,self.call("list_hooks"))
    def test_immutable_paged_real_context(self):
        first=self.call("trace_live_read",{"trace_id":self.trace_id,"limit":2})
        again=self.call("trace_live_read",{"trace_id":self.trace_id,"limit":2})
        self.assertEqual(first,again)
        self.assertEqual(first["state"],"completed")
        self.assertTrue(first["callCompleted"])
        self.assertFalse(first["syntheticCall"])
        self.assertFalse(first["inputPointerSubstitution"])
        self.assertEqual(len(first["entry"]["q0_q31"]),32)
        self.assertEqual(len(first["instructions"][0]["x0_x30"]),31)
        self.assertEqual(len(first["instructions"][0]["q0_q31"]),32)
        for patch in [{"offset":-1},{"limit":0},{"limit":257},{"limit":True},{"offset":1.5}]:
            with self.subTest(patch=patch):self.assertTrue(self.raw("trace_live_read",{"trace_id":self.trace_id,**patch}).get("isError"))

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint",required=True)
    parser.add_argument("--trace-id",required=True,help="run_live_selftest 返回的当前进程内已完成自有 trace")
    args=parser.parse_args();LiveTraceTests.endpoint=args.endpoint;LiveTraceTests.trace_id=args.trace_id
    unittest.main(argv=[__file__],verbosity=2)
