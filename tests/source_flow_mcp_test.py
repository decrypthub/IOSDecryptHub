"""Verify owned source fixtures, registration/delivery separation and MCP bounds."""
import argparse
import json
import unittest
from urllib.request import Request, urlopen


class SourceFlowTests(unittest.TestCase):
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

    def test_registration_is_separate_from_each_real_delivery(self):
        state = self.call("get_flow_state")
        self.assertFalse(state["enabled"], "run the owned flow selftest first, then disable capture")
        self.assertLessEqual(state["retainedRegistrations"], state["maxRegistrations"])
        rows, offset = [], 0
        while True:
            page = self.call("get_async_registrations", {"offset": offset, "limit": 8})
            self.assertLessEqual(len(page["registrations"]), 8)
            self.assertEqual(page["maxRecords"], 128)
            rows.extend(page["registrations"])
            if page["nextOffset"] is None:
                self.assertEqual(len(rows), page["retained"])
                break
            self.assertGreater(page["nextOffset"], offset)
            offset = page["nextOffset"]
        by_id = {row["registrationId"]: row for row in rows}
        self.assertEqual(len(by_id), len(rows))
        self.assertGreaterEqual(len(rows), 20, "owned source fixtures have not completed")
        self.assertTrue(any(row["capturedInvocations"] == 2 for row in rows))
        self.assertTrue(any(not row["active"] and row["observedInvocations"] == 0 and
                            row["terminalReason"].startswith("source-handler-") for row in rows))
        self.assertTrue(any(row["queueAtRegistration"] != row["currentKnownQueue"] for row in rows))
        tasks = self.call("get_async_tasks", {"limit": 128})["tasks"]
        deliveries = [task for task in tasks if task.get("registrationId")]
        self.assertGreaterEqual(len(deliveries), 20)
        for task in deliveries:
            registration = by_id[task["registrationId"]]
            self.assertEqual(task["edge"], "registered-handler-to-callback")
            self.assertEqual(task["api"], registration["api"])
            self.assertEqual(task["state"], "completed")
            self.assertLessEqual(int(task["submittedNs"]), int(task["deliveryObservedNs"]))
            self.assertLessEqual(int(task["deliveryObservedNs"]), int(task["startedNs"]))
            self.assertEqual(task["asyncSubmittedByCallId"], registration["registeredByCallId"])
        for task in deliveries[:3]:
            with self.subTest(delivery=task["asyncTaskId"]):
                events = self.call("query_events", {"async_task_id": task["asyncTaskId"],
                                                   "kind": "async-task", "phase": "delivery", "limit": 5})["events"]
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["asyncRegistrationId"], task["registrationId"])
                detail = self.call("get_event", {"seq": events[0]["seq"]})
                self.assertEqual(detail["payload"]["registrationId"], task["registrationId"])
                self.assertEqual(detail["payload"]["edge"], "registered-handler-to-callback")
                self.assertEqual(self.call("query_events", {"async_task_id": task["asyncTaskId"],
                                                           "phase": "submit", "limit": 5})["events"], [])
        for row in rows:
            observed = [task for task in deliveries if task["registrationId"] == row["registrationId"]]
            self.assertEqual(row["capturedInvocations"], len(observed))
            self.assertGreaterEqual(row["observedInvocations"], row["capturedInvocations"])
            self.assertTrue(row["callbackIdentity"].get("imageUUID"))
            self.assertEqual(row["registrationStack"]["symbolication"], "resolved-on-reader-thread")
        self.assertEqual(self.call("get_async_registrations", {"offset": 128, "limit": 1})["registrations"], [])

    def test_source_import_ownership_and_bad_pages_preserve_state(self):
        before = self.call("get_flow_state")
        hooks = self.call("list_hooks")
        generation = self.call("get_capabilities")["processGeneration"]
        for bad in ({"offset": -1}, {"offset": 129}, {"offset": True}, {"offset": 0.5},
                    {"offset": "0"}, {"offset": None}, {"limit": 0}, {"limit": 9},
                    {"limit": False}, {"limit": 1.5}, {"limit": "1"}, {"limit": None}):
            with self.subTest(bad=bad):
                self.assertTrue(self.raw("get_async_registrations", bad).get("isError"))
        for symbol in ("dispatch_source_create", "dispatch_source_set_event_handler",
                       "dispatch_source_set_event_handler_f", "dispatch_source_set_cancel_handler",
                       "dispatch_source_set_cancel_handler_f", "dispatch_source_set_registration_handler",
                       "dispatch_source_set_registration_handler_f", "dispatch_source_cancel",
                       "dispatch_set_target_queue"):
            with self.subTest(symbol=symbol):
                self.assertTrue(self.raw("hook_import", {"symbol": symbol, "process_generation": generation}).get("isError"))
        self.assertEqual(before, self.call("get_flow_state"))
        self.assertEqual(hooks, self.call("list_hooks"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    options = parser.parse_args()
    SourceFlowTests.endpoint = options.endpoint
    unittest.main(argv=[__file__], verbosity=2)
