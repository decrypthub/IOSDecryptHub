"""只读 MCP 回归：分支目标、ObjC 查询分页与实际后端能力。

python tests/analysis_mcp_test.py --endpoint http://<test-device>:8088 --expect-inline true
不执行目标字节，不安装 Hook，不读取目标请求或密钥。
"""
import argparse
import json
import unittest
from urllib.request import Request, urlopen


class AnalysisMCPTests(unittest.TestCase):
    endpoint = ""
    expect_inline = None
    method_class = None
    method_selector = None
    analysis_image = None
    analysis_selector = None
    paging_address = None

    @classmethod
    def setUpClass(cls):
        if not cls.endpoint:
            raise unittest.SkipTest("需要显式 --endpoint 指定已授权的测试设备；普通离线测试不连接手机")

    def call(self, name, arguments=None):
        body = json.dumps({"jsonrpc": "2.0", "id": name, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments or {}}}).encode()
        req = Request(self.endpoint.rstrip("/") + "/api/mcp", body,
                      {"Content-Type": "application/json", "Accept": "application/json"})
        with urlopen(req, timeout=15) as response:
            result = json.load(response)["result"]
        self.assertFalse(result.get("isError"), result.get("content"))
        if "structuredContent" in result:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])

    def test_arm64_branch_targets(self):
        # 机器码包含两个立即数的位测试分支，必须返回地址而非位编号。
        base = 0x100000000
        cases = [
            ("b", "02000014", base + 8),
            ("bl", "feffff97", base - 8),
            ("b.eq", "40000054", base + 8),
            ("cbz", "400000b4", base + 8),
            ("cbnz", "400000b5", base + 8),
            ("tbz-bit0", "e0010036", base + 60),
            ("tbz-bit13", "e0016836", base + 60),
            ("tbnz-bit13", "e0016837", base + 60),
            ("br", "00001fd6", None),
            ("blr", "00003fd6", None),
            ("ret", "c0035fd6", None),
            ("add", "00040091", None),
        ]
        for name, code, target in cases:
            with self.subTest(instruction=name):
                result = self.call("disassemble", {"bytes": code, "address": hex(base), "arch": "arm64"})
                self.assertEqual(result["count"], 1)
                row = result["instructions"][0]
                if target is None:
                    self.assertNotIn("target", row)
                else:
                    self.assertEqual(int(row["target"], 16), target)

    def test_objc_filters_and_pagination(self):
        args = {"class": "NSJSONSerialization", "method_type": "class", "limit": 200}
        whole = self.call("find_objc_methods", args)
        self.assertGreaterEqual(whole["total"], 2)
        for offset in (0, 1):
            with self.subTest(offset=offset):
                page = self.call("find_objc_methods", {**args, "offset": offset, "limit": 1})
                self.assertEqual(page["total"], whole["total"])
                self.assertEqual(page["methods"], whole["methods"][offset:offset + 1])
        for match, query in (("exact", "dataWithJSONObject:options:error:"), ("prefix", "dataWithJSONObject:"), ("contains", "JSONObject")):
            with self.subTest(match=match):
                result = self.call("find_objc_methods", {**args, "selector": query, "match": match})
                self.assertGreater(result["total"], 0)
                for method in result["methods"]:
                    selector = method["selector"]
                    self.assertTrue(selector == query if match == "exact" else selector.startswith(query) if match == "prefix" else query in selector)

    def test_backend_capabilities(self):
        result = self.call("get_capabilities")
        caps = result["capabilities"]
        self.assertIn("hook_import", result["dynamicHookTools"])
        self.assertIn("hook_method", result["dynamicHookTools"])
        self.assertEqual("hook_inline" in result["dynamicHookTools"], caps["hook_inline"])
        self.assertEqual(result["backends"]["inline"] == "dobby", caps["hook_inline"])
        self.assertEqual(result["backends"]["trace"] == "qbdi", caps["trace_function"])
        if self.expect_inline is not None:
            self.assertEqual(caps["hook_inline"], self.expect_inline)
            self.assertEqual(caps["trace_function"], self.expect_inline)

    def test_method_function_boundary_and_executable_ranges(self):
        if not self.method_class or not self.method_selector:
            self.skipTest("未提供用于归属验证的测试方法")
        rows = self.call("find_objc_methods", {"class": self.method_class, "selector": self.method_selector, "match": "exact"})["methods"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        address = int(row["current_imp"], 16)
        info = self.call("symbolicate", {"address": hex(address + 4)})
        self.assertEqual(info["confidence"], "high")
        self.assertEqual(int(info["function_start"], 16), address)
        disasm = self.call("disassemble_function", {"address": hex(address + 4), "max_bytes": 64})
        self.assertEqual(int(disasm["resolved_start"], 16), address)
        # 现有协议将「下一个函数入口近似出的末尾」标 medium；函数起点单独由
        # symbolicate 的 high 信号确认。64B 页必须保留完整边界与截断标记。
        self.assertEqual(disasm["boundary_source"], "lc_function_starts")
        self.assertEqual(disasm["boundary_confidence"], "medium")
        self.assertGreater(int(disasm["resolved_end"], 16), address)
        name = row["class_image"].rsplit("/", 1)[-1]
        images = self.call("list_loaded_images", {"query": name, "include_system": False})["images"]
        self.assertEqual(len(images), 1)
        self.assertTrue(images[0]["executable_ranges_complete"])
        self.assertTrue(any(int(r["start"], 16) <= address < int(r["end"], 16) for r in images[0]["executable_ranges"]))

    def test_selector_references(self):
        if not self.analysis_image or not self.analysis_selector:
            self.skipTest("未提供用于交叉引用验证的测试镜像/selector")
        result = self.call("find_selector_refs", {"image": self.analysis_image, "selector": self.analysis_selector, "match": "exact", "scan_size": 8 * 1024 * 1024})
        self.assertTrue(result["scan"]["coverage_complete"])
        self.assertGreater(result["count"], 0)

    def test_function_pagination(self):
        if not self.paging_address:
            self.skipTest("未提供用于长函数分页验证的地址")
        first = self.call("disassemble_function", {"address": self.paging_address, "max_bytes": 65536})
        self.assertEqual(first["count"], 1024)
        self.assertTrue(first["truncated"])
        self.assertGreater(first["next_byte_offset"], 0)
        second = self.call("disassemble_function", {"address": self.paging_address,
                           "byte_offset": first["next_byte_offset"], "max_bytes": 64})
        self.assertEqual(second["resolved_start"], first["resolved_start"])
        self.assertEqual(second["resolved_end"], first["resolved_end"])
        self.assertEqual(second["decode_start"], first["next_address"])
        self.assertEqual(second["instructions"][0]["address"], first["next_address"])
        self.assertNotEqual(second["instructions"][0]["address"], first["instructions"][0]["address"])
        size = first["function_size"]
        last = self.call("disassemble_function", {"address": self.paging_address,
                         "byte_offset": ((size - 1) // 4) * 4, "max_bytes": 64})
        self.assertFalse(last["truncated"])
        self.assertIsNone(last["next_byte_offset"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--expect-inline", choices=("true", "false"))
    parser.add_argument("--method-class")
    parser.add_argument("--method-selector")
    parser.add_argument("--analysis-image")
    parser.add_argument("--analysis-selector")
    parser.add_argument("--paging-address", help="已知超过 1024 条指令的 ARM64 函数")
    args = parser.parse_args()
    AnalysisMCPTests.endpoint = args.endpoint
    AnalysisMCPTests.expect_inline = None if args.expect_inline is None else args.expect_inline == "true"
    AnalysisMCPTests.method_class = args.method_class
    AnalysisMCPTests.method_selector = args.method_selector
    AnalysisMCPTests.analysis_image = args.analysis_image
    AnalysisMCPTests.analysis_selector = args.analysis_selector
    AnalysisMCPTests.paging_address = args.paging_address
    unittest.main(argv=[__file__], verbosity=2)
