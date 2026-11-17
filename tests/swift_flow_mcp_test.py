"""Verify actual compiler/runtime fixture evidence and the live bounded reader."""
import argparse
import json
from pathlib import Path
import unittest
import source_flow_mcp_test as transport


class SwiftFlowTests(unittest.TestCase):
    endpoint = ""
    fixture = None
    raw = transport.SourceFlowTests.raw
    call = transport.SourceFlowTests.call

    def tasks(self):
        rows, offset = [], 0
        while True:
            page = self.call("get_swift_tasks", {"offset": offset, "limit": 16})
            self.assertLessEqual(len(page["tasks"]), 16)
            rows.extend(page["tasks"])
            if page["nextOffset"] is None:
                self.assertEqual(len(rows), page["total"])
                return rows
            self.assertGreater(page["nextOffset"], offset)
            offset = page["nextOffset"]

    def test_a_real_runtime_language_and_lifetime_evidence(self):
        f = self.fixture
        self.assertTrue(f["ok"], f)
        p = f["proof"]
        for key in ("languageAndRuntime", "pendingAfterDisable", "budgetPreservesOriginalWork",
                    "fastOriginalResultsAndLifetimes"):
            self.assertTrue(p[key], key)
        self.assertEqual((p["compilerGeneratedTasksPerRun"], p["fastTasks"], p["failures"]), (7, 65, 0))
        self.assertEqual(f["state"]["processGeneration"], self.call("get_capabilities")["processGeneration"])
        roles = p["languageRoles"]
        self.assertEqual(len({r["swiftTaskId"] for r in roles}), 7)
        self.assertTrue(roles[1]["observedAcrossNativeThreads"])
        self.assertNotEqual(roles[1]["firstObservedThreadId"], roles[1]["lastObservedThreadId"])
        self.assertEqual([r["lastOwnedTaskLocalValue"] for r in roles], [0, 0x4848, 0, 0x4848, 0, 0x4848, 0x4848])
        owned = [r for r in self.tasks() if r["fixture"]]
        self.assertEqual(len(owned), 81)
        self.assertEqual(sum(r["completionHadSwiftError"] for r in owned), 4)
        for r in owned:
            self.assertTrue(r["identityValidated"] and r["initialEnqueueWitness"])
            self.assertEqual(r["state"], "completed")
            self.assertTrue(r["completionConfirmedByOriginalJobReturn"])
            self.assertLessEqual(int(r["creationInvocationNs"]), int(r["completionObservedNs"]))

    def test_b_readers_are_bounded_and_read_only(self):
        before = self.call("get_swift_state")
        rows = self.tasks()
        self.assertEqual(len(rows), len({r["swiftTaskId"] for r in rows}))
        self.assertLessEqual(len(rows), 512)
        self.assertEqual(self.call("get_swift_tasks", {"offset": 512, "limit": 1})["tasks"], [])
        self.assertEqual(before, self.call("get_swift_state"))

    def test_c_event_lifetimes_and_exact_task_filter(self):
        events, after = [], 0
        while True:
            page = self.call("get_swift_events", {"after_seq": after, "limit": 64})
            self.assertLessEqual(len(page["events"]), 64)
            events.extend(page["events"])
            if page["nextAfterSeq"] is None:
                break
            self.assertGreater(page["nextAfterSeq"], after)
            after = page["nextAfterSeq"]
        self.assertTrue(events)
        seqs = [e["schedulerSeq"] for e in events]
        self.assertEqual(seqs, sorted(set(seqs)))
        groups = {}
        for e in events:
            self.assertEqual(e["sequenceScope"], "swift-scheduler-ring")
            self.assertLessEqual(int(e["monotonicNs"]), int(e["recordedNs"]))
            if e["swiftTaskId"]:
                groups.setdefault(e["swiftTaskId"], set()).add(e["phase"])
        complete = [token for token, phases in groups.items()
                    if "create-return-observed" in phases and "completion-confirmed" in phases and
                    ({"runtime-completion-entry", "completion-recovered"} & phases)]
        self.assertGreaterEqual(len(complete), 3)
        for token in complete[-3:]:
            page = self.call("get_swift_events", {"swift_task_id": token, "limit": 64})
            self.assertTrue(page["events"])
            self.assertTrue(all(e["swiftTaskId"] == token for e in page["events"]))

    def test_d_bad_arguments_do_not_run_work(self):
        before = self.call("get_swift_state")
        for tool, arguments in (("get_swift_tasks", {"offset": True}),
                                ("get_swift_tasks", {"limit": 17}),
                                ("get_swift_events", {"after_seq": -1}),
                                ("get_swift_events", {"limit": 65}),
                                ("get_swift_events", {"swift_task_id": "old-generation:swift:1"}),
                                ("run_swift_selftest", {"process_generation": "old-generation"}),
                                ("configure_swift_capture", {"process_generation": "old-generation", "enabled": True})):
            with self.subTest(tool=tool, arguments=arguments):
                self.assertTrue(self.raw(tool, arguments).get("isError"))
        self.assertEqual(before, self.call("get_swift_state"))

    def test_e_active_window_is_not_replaced_by_selftest(self):
        generation = self.call("get_capabilities")["processGeneration"]
        try:
            self.call("configure_swift_capture", {"process_generation": generation, "enabled": True,
                                                 "max_tasks": 1, "max_ms": 30000})
            before = self.call("get_swift_state")
            result = self.call("run_swift_selftest", {"process_generation": generation})
            self.assertFalse(result["ok"])
            after = self.call("get_swift_state")
            for key in ("windowStartedNs", "deadlineNs", "windowLimit", "enabled"):
                self.assertEqual(before[key], after[key], key)
        finally:
            self.call("configure_swift_capture", {"process_generation": generation, "enabled": False})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    SwiftFlowTests.endpoint = args.endpoint
    data = json.loads(args.fixture.read_text(encoding="utf8"))
    SwiftFlowTests.fixture = data.get("structuredContent", data)
    unittest.main(argv=[__file__], verbosity=2)
