"""Read owned flow diagnostics and verify bounded, non-mutating MCP pagination."""
import argparse
import json
import unittest
from urllib.request import Request, urlopen


class FlowDiagnosticTests(unittest.TestCase):
    endpoint = ""

    def raw(self, name, args=None):
        body = json.dumps({"jsonrpc": "2.0", "id": name, "method": "tools/call",
                           "params": {"name": name, "arguments": args or {}}}).encode()
        with urlopen(Request(self.endpoint.rstrip("/") + "/api/mcp", body,
                             {"Content-Type": "application/json"}), timeout=40) as response:
            return json.load(response)["result"]

    def call(self, name, args=None):
        result = self.raw(name, args)
        self.assertFalse(result.get("isError"), result)
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    def test_owned_boundary_evidence_and_paging(self):
        state = self.call("get_flow_state")
        self.assertFalse(state["enabled"], "disable capture after the owned flow selftest first")
        self.assertGreater(state["verifiedPartialBoundaries"], 0)
        self.assertEqual(sum(state["unverifiedReasonCounts"].values()), state["unverifiedBoundaries"])
        rows, offset, total = [], 0, None
        while True:
            page = self.call("get_flow_diagnostics", {"offset": offset, "limit": 4})
            self.assertLessEqual(len(page["records"]), 4)
            self.assertLessEqual(page["retained"], 16)
            self.assertEqual(int(page["total"]), int(page["overwritten"]) + page["retained"])
            if total is None:
                total = page["total"]
            self.assertEqual(page["total"], total, "diagnostic ring changed while reading")
            rows.extend(page["records"])
            if page["nextOffset"] is None:
                self.assertEqual(len(rows), page["retained"])
                break
            self.assertGreater(page["nextOffset"], offset)
            offset = page["nextOffset"]
        self.assertTrue(rows, "run the owned flow selftest to create an uncertain boundary")
        ids = [int(row["id"]) for row in rows]
        self.assertEqual(ids, sorted(set(ids)))
        for row in rows:
            self.assertIn(row["reason"], state["unverifiedReasonCounts"])
            self.assertEqual(row["association"], "suppressed; candidate identity is diagnostic only")
            stack = row["stack"]
            self.assertLessEqual(len(stack["frames"]), 256)
            self.assertEqual(stack["symbolication"], "resolved-on-reader-thread")
            termination = stack["termination"]
            self.assertIsInstance(termination["stepResult"], int)
            for key in ("pc", "sp", "fp", "procedureStart", "procedureEnd",
                        "threadStackLow", "threadStackHigh"):
                self.assertGreaterEqual(int(termination[key], 16), 0)
        self.assertEqual(self.call("get_flow_diagnostics", {"offset": 16, "limit": 1})["records"], [])

    def test_bad_pages_rejected_without_state_or_hook_changes(self):
        before = self.call("get_flow_state")
        hooks = self.call("list_hooks")
        for bad in ({"offset": -1}, {"offset": 17}, {"offset": True}, {"offset": 0.5},
                    {"offset": "0"}, {"offset": None}, {"limit": 0}, {"limit": 5},
                    {"limit": False}, {"limit": 1.5}, {"limit": "1"}, {"limit": None}):
            with self.subTest(bad=bad):
                self.assertTrue(self.raw("get_flow_diagnostics", bad).get("isError"))
        self.assertEqual(before, self.call("get_flow_state"))
        self.assertEqual(hooks, self.call("list_hooks"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    options = parser.parse_args()
    FlowDiagnosticTests.endpoint = options.endpoint
    unittest.main(argv=[__file__], verbosity=2)
