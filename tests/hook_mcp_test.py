"""P0 MCP 边界回归；必须显式指定已授权 endpoint，不自动连接设备。

不调用业务方法、不安装有效 Hook。--call-id 可验证已采集的嵌套调用。
"""
import argparse
import json
import unittest
import uuid
from urllib.request import Request, urlopen


class HookMCPTests(unittest.TestCase):
    endpoint = ""
    call_id = ""

    @classmethod
    def setUpClass(cls):
        if not cls.endpoint:
            raise unittest.SkipTest("需要显式 --endpoint 指定已授权设备")

    def raw(self, name, arguments):
        body = json.dumps({"jsonrpc": "2.0", "id": name, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}}).encode()
        with urlopen(Request(self.endpoint.rstrip("/") + "/api/mcp", body,
                             {"Content-Type": "application/json"}), timeout=20) as response:
            return json.load(response)["result"]

    def call(self, name, arguments=None):
        result = self.raw(name, arguments or {})
        self.assertFalse(result.get("isError"), result)
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    def stable_hooks(self):
        def stable(item):
            if isinstance(item, dict):
                return {k: stable(v) for k, v in item.items() if k not in {"hits", "inFlight"}}
            if isinstance(item, list):
                return [stable(v) for v in item]
            return item
        return stable(self.call("list_hooks"))

    def test_rejection_before_mutation(self):
        generation = self.call("get_capabilities")["processGeneration"]
        before = self.stable_hooks()
        base = {"class": "IDHABIProbe", "selector": "inner:", "process_generation": generation}
        cases = [
            ("hook_method", {**base, "process_generation": str(uuid.uuid4())}),
            ("unhook", {"slot": 0}),
            ("hook_method", {**base, "classMethod": None}),
            ("hook_method", {**base, "capture_return": True}),
            ("hook_method", {**base, "capture_after": True, "post_abi": "fixed-nonvariadic"}),
            ("hook_method", {**base, "capture_ret_multi": "x2:8", "post_abi": "fixed-nonvariadic"}),
            ("hook_method", {**base, "capture_multi": "x0:8193"}),
            ("hook_import", {"symbol": "getpid", "process_generation": generation, "capture_return": True}),
            ("hook_import", {"symbol": "getpid", "process_generation": generation, "capture_return": True,
                             "abi": {"arguments": ["double"], "return": "i32"}}),
        ]
        for name, arguments in cases:
            with self.subTest(tool=name, arguments=arguments):
                self.assertTrue(self.raw(name, arguments).get("isError"))
        self.assertEqual(self.stable_hooks(), before)

    def test_retained_call_and_budgets(self):
        if not self.call_id:
            self.skipTest("需要 --call-id 指定已保留的配对嵌套调用")
        full = self.call("get_call", {"call_id": self.call_id, "limit": 200})
        self.assertTrue(full["retainedPair"])
        self.assertGreater(full["matched"], 2)
        short = self.call("get_call", {"call_id": self.call_id, "limit": 1})
        self.assertTrue(short["resultTruncated"])
        self.assertEqual(len(short["events"]), 1)
        for field, value in (("limit", []), ("max_blob_bytes", None), ("include_children", "yes")):
            with self.subTest(field=field):
                self.assertTrue(self.raw("get_call", {"call_id": self.call_id, field: value}).get("isError"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--call-id", default="")
    args = parser.parse_args()
    HookMCPTests.endpoint = args.endpoint
    HookMCPTests.call_id = args.call_id
    unittest.main(argv=[__file__], verbosity=2)
