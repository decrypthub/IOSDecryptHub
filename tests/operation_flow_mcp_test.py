"""Verify real operation fixture evidence and scheduler ownership on one device."""
import argparse
import json
from pathlib import Path
import unittest
import source_flow_mcp_test as transport


class OperationFlowTests(unittest.TestCase):
    endpoint = ""
    fixture = None
    raw = transport.SourceFlowTests.raw
    call = transport.SourceFlowTests.call

    def test_actual_callback_and_lifecycle_evidence(self):
        f = self.fixture
        self.assertTrue(f["pass"], f)
        self.assertEqual(len(f["passed"]), 10)
        self.assertEqual(f["state"]["processGeneration"], self.call("get_capabilities")["processGeneration"])
        pending, cancelled = f["asyncPendingAfterStartReturn"], f["asyncPendingAfterCancel"]
        self.assertTrue(pending["startReturned"] and pending["isExecuting"])
        self.assertFalse(pending["isFinished"])
        self.assertTrue(cancelled["isCancelled"])
        self.assertFalse(cancelled["isFinished"])
        workers = f["dependencyAndWorkerObservations"]
        self.assertEqual(len({r["taskId"] for r in workers}), 3)
        self.assertTrue(all(r["taskId"] for r in workers))
        self.assertTrue(f["customStartObservations"][0]["taskId"])
        self.assertEqual(f["directBlockObservations"][0]["taskId"], "")
        self.assertEqual(len(f["directBlockObservations"]), 2)
        state = self.call("get_operation_state")
        self.assertTrue(state["ready"] and state["blockInvokersReady"])
        self.assertEqual((state["bindingCapacity"], state["executionMethodCapacity"], state["blockCapacity"]), (64, 32, 128))
        tasks = f["taskEvidence"]["tasks"]
        self.assertTrue(any(t["api"] == "NSOperation.main" and t["state"] == "completed" for t in tasks))
        self.assertTrue(any(t["api"] == "NSOperation.start" and t["state"] == "completed" for t in tasks))
        self.assertTrue(any(t["terminalReason"] == "operation-block-outside-calibrated-execution" and t["state"] == "unresolved" and not t["executionThreadId"] for t in tasks))

    def test_bad_generation_does_not_run_owned_work(self):
        self.call("get_operation_state")  # Reconcile completed fixture objects before comparing counters.
        before, hooks = self.call("get_flow_state"), self.call("list_hooks")
        operations = self.call("get_operation_state")
        for value in (None, True, 1, "", "old-generation"):
            with self.subTest(value=value):
                self.assertTrue(self.raw("run_operation_selftest", {"process_generation": value}).get("isError"))
        self.assertEqual(before, self.call("get_flow_state"))
        self.assertEqual(hooks, self.call("list_hooks"))
        self.assertEqual(operations["bindingsCreated"], self.call("get_operation_state")["bindingsCreated"])

    def test_active_window_is_not_overwritten_by_selftest(self):
        generation = self.call("get_capabilities")["processGeneration"]
        try:
            configured = self.call("configure_async_capture", {"process_generation": generation, "enabled": True,
                                   "capture_roots": False, "max_tasks": 1, "max_ms": 10000,
                                   "root_queue_include": ["__IDH_no_match__"]})
            self.assertTrue(configured["ok"])
            before = self.call("get_flow_state")
            result = self.call("run_operation_selftest", {"process_generation": generation})
            self.assertFalse(result["pass"])
            self.assertIn("inactive", result["error"])
            after = self.call("get_flow_state")
            # App submissions continue while this window is active. Their miss/
            # skipped counters may increase, but the refused fixture must not
            # replace configuration, allocate tasks or alter lifecycle state.
            for key in ("installed", "enabled", "captureRoots", "rootQueueInclude", "rootAPIInclude",
                        "rootCallbackInclude", "queueExclude", "retained", "windowAccepted", "maxRecords",
                        "maxPending", "maxDepth", "windowStartedNs", "windowDeadlineNs", "windowStopReason",
                        "pendingOrRunning", "abandonedCalls", "guardOverflows", "specialBindingsCreated",
                        "retainedRegistrations", "windowRegistrations"):
                self.assertEqual(before[key], after[key], key)
        finally:
            self.call("configure_async_capture", {"process_generation": generation, "enabled": False})

    def test_typed_method_targets_reject_dynamic_overwrites(self):
        generation = self.call("get_capabilities")["processGeneration"]
        before, hooks = self.call("get_flow_state"), self.call("list_hooks")
        for cls, selector, class_method in (("NSOperationQueue", "addOperation:", False),
                ("NSOperationQueue", "addOperations:waitUntilFinished:", False),
                ("NSOperationQueue", "addOperationWithBlock:", False),
                ("NSBlockOperation", "blockOperationWithBlock:", True),
                ("NSBlockOperation", "addExecutionBlock:", False), ("IDHOperationSync", "main", False)):
            with self.subTest(cls=cls, selector=selector):
                result = self.raw("hook_method", {"process_generation": generation, "class": cls,
                                  "selector": selector, "classMethod": class_method, "capture_return": False})
                self.assertTrue(result.get("isError"), result)
                self.assertIn("already", str(result).lower())
        self.assertEqual(before, self.call("get_flow_state"))
        self.assertEqual(hooks, self.call("list_hooks"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    OperationFlowTests.endpoint = args.endpoint
    OperationFlowTests.fixture = json.loads(args.fixture.read_text(encoding="utf8"))
    unittest.main(argv=[__file__], verbosity=2)
