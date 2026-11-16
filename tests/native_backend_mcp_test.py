"""显式授权 endpoint 的原生后端回归；仅回放无副作用的 getpid，不安装 Hook。"""
import argparse
import json
import unittest
from urllib.request import Request, urlopen


class NativeBackendTests(unittest.TestCase):
    endpoint = ""

    @classmethod
    def setUpClass(cls):
        if not cls.endpoint:
            raise unittest.SkipTest("需要显式 --endpoint 指定授权设备")

    def raw(self, name, arguments):
        body = json.dumps({"jsonrpc": "2.0", "id": name, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}}).encode()
        with urlopen(Request(self.endpoint.rstrip("/") + "/api/mcp", body,
                             {"Content-Type": "application/json"}), timeout=30) as response:
            return json.load(response)["result"]

    def call(self, name, arguments=None):
        result = self.raw(name, arguments or {})
        self.assertFalse(result.get("isError"), result)
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    def test_actual_backends(self):
        result = self.call("get_capabilities")
        self.assertTrue(result["capabilities"]["hook_inline"])
        self.assertTrue(result["capabilities"]["trace_function"])
        self.assertEqual(result["backends"], {"inline": "dobby", "trace": "qbdi"})

    def test_invalid_replay_rejected_before_execution(self):
        generation = self.call("get_capabilities")["processGeneration"]
        base = {"symbol": "getpid", "args": [0], "process_generation": generation}
        bad = [
            {"args": [0] * 9}, {"addr": "0x1", "symbol": ""},
            {"buffers": None}, {"buffers": [{"arg": 0, "hex": "z0"}]},
            {"buffers": [{"arg": 0, "hex": "0"}]},
            {"buffers": [{"arg": True, "hex": "00"}]},
            {"buffers": [{"arg": 1, "hex": "00"}]},
            {"buffers": [{"arg": 0, "hex": "00"}, {"arg": 0, "hex": "00"}]},
            {"buffers": [{"arg": 0, "hex": "00" * 8193}]},
            {"args": [0] * 5, "buffers": [{"arg": i, "hex": "00" * 8192} for i in range(5)]},
        ]
        for patch in bad:
            with self.subTest(patch=str(patch)[:100]):
                self.assertTrue(self.raw("trace_function", {**base, **patch}).get("isError"))
        self.assertEqual(self.call("get_capabilities")["processGeneration"], generation)

    def test_resolved_function_pointer(self):
        capability = self.call("get_capabilities")
        result = self.call("trace_function", {"symbol": "getpid", "args": [], "max_insns": 512,
                                               "max_ms": 5000, "process_generation": capability["processGeneration"]})
        self.assertTrue(result["call_ok"])
        self.assertTrue(result["retval_valid"])
        self.assertEqual(result["stop_reason"], "completed")
        self.assertGreater(result["count"], 0)
        self.assertEqual(int(result["retval"], 16), capability["process"]["pid"])
        self.assertEqual(result["pointerAuthentication"], capability["arch"] == "arm64e")
        self.assertEqual(result["executionMode"], "replay")
        self.assertFalse(result["contextComplete"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    NativeBackendTests.endpoint = parser.parse_args().endpoint
    unittest.main(argv=[__file__], verbosity=2)
