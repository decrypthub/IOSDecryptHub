"""Verify timer fixtures, measured callback edges and typed adapter ownership."""
import argparse
import unittest

import source_flow_mcp_test as source


class TimerFlowTests(source.SourceFlowTests):
    def test_native_entry_is_calibrated_in_this_process(self):
        result = self.call("get_timer_state")
        capability = self.call("get_capabilities")
        self.assertEqual(result["processGeneration"], capability["processGeneration"])
        state = result["state"]
        self.assertTrue(state["nativeEntryReady"], state)
        self.assertTrue(state["factoriesReady"], state)
        self.assertEqual(state["nativeCalibrationEntries"], 2)
        self.assertEqual(state["nativeCalibrationMismatches"], 0)
        self.assertLessEqual(state["bindingsCreated"], state["maxBindings"])
        adapter = result["nativeAdapter"]
        self.assertTrue(adapter["ready"])
        self.assertTrue(adapter["patchRetainedUntilRestart"])
        self.assertEqual(adapter["signature"], "void(CFRunLoopTimerRef, void*)")
        identity = adapter["targetIdentity"]
        self.assertTrue(identity["imageUUID"])
        self.assertTrue(identity["image"].endswith("/Foundation"))
        resolved = self.call("resolve_symbol", {"symbol": "__NSFireTimer"})
        self.assertEqual(int(identity["address"], 16), int(resolved["address"], 16))

    def test_unregistered_entry_does_not_invent_registration_or_submit(self):
        tasks = self.call("get_async_tasks", {"limit": 128})["tasks"]
        entries = [row for row in tasks if row["api"] == "NSTimer.runloop-callback"]
        self.assertEqual(len(entries), 2, "run the owned flow selftest in a fresh process first")
        for row in entries:
            self.assertEqual(row["edge"], "observed-callback-entry; registration-unobserved")
            self.assertEqual(row["registrationId"], "")
            self.assertEqual(row["asyncSubmittedByCallId"], "")
            self.assertTrue(row["asyncEnteredByCallId"])
            self.assertEqual(row["queue"], "runloop:IDHFlowTimerMode")
            self.assertEqual(row["state"], "completed")
            events = self.call("query_events", {"async_task_id": row["asyncTaskId"],
                                               "kind": "async-task", "phase": "callback-entry", "limit": 5})["events"]
            self.assertEqual(len(events), 1)
            detail = self.call("get_event", {"seq": events[0]["seq"]})
            self.assertEqual(detail["payload"]["edge"], row["edge"])
            self.assertEqual(detail["payload"].get("registrationId", ""), "")
            for phase in ("submit", "delivery"):
                self.assertEqual(self.call("query_events", {"async_task_id": row["asyncTaskId"],
                                                           "phase": phase, "limit": 5})["events"], [])

    def test_factory_registration_repeat_delivery_and_manual_fire(self):
        tasks = self.call("get_async_tasks", {"limit": 128})["tasks"]
        registrations, offset = [], 0
        while True:
            page = self.call("get_async_registrations", {"offset": offset, "limit": 8})
            registrations.extend(page["registrations"])
            if page["nextOffset"] is None:
                break
            offset = page["nextOffset"]
        for api, mode in (("NSTimer.timerWithTimeInterval.target", "IDHFlowTimerMode"),
                          ("NSTimer.timerWithTimeInterval.block", "IDHFlowTimerMode"),
                          ("NSTimer.scheduledTimerWithTimeInterval.target", "kCFRunLoopDefaultMode"),
                          ("NSTimer.scheduledTimerWithTimeInterval.block", "kCFRunLoopDefaultMode")):
            with self.subTest(api=api):
                rows = [row for row in tasks if row["api"] == api]
                self.assertEqual(len(rows), 2)
                self.assertEqual(len({row["registrationId"] for row in rows}), 1)
                self.assertTrue(rows[0]["registrationId"])
                for row in rows:
                    self.assertEqual(row["edge"], "registered-handler-to-callback")
                    self.assertEqual(row["queue"], "runloop:" + mode)
                registered = [row for row in registrations if row["api"] == api]
                self.assertTrue(any(row["capturedInvocations"] == 2 for row in registered))
                expected = "NSTimer.block" if api.endswith(".block") else "[IDHFlowProbe timerTick:]"
                self.assertTrue(all(row["callbackLabel"] == expected for row in registered))
        # The separate synchronous manual-fire fixture registers its timer but
        # never enters the RunLoop callback and must have no async delivery.
        self.assertTrue(any(row["api"] == "NSTimer.timerWithTimeInterval.target" and
                            row["capturedInvocations"] == 0 for row in registrations))
        performs = [row for row in tasks if row["api"] == "CFRunLoopPerformBlock"]
        self.assertEqual(len(performs), 1)
        self.assertEqual(performs[0]["edge"], "observed-submit-to-execute")
        self.assertEqual(performs[0]["queue"], "runloop:IDHFlowTimerMode")

    def test_invalid_callback_filters_do_not_open_a_window(self):
        generation = self.call("get_capabilities")["processGeneration"]
        before = self.call("get_flow_state")
        for value in (None, True, 1, "target", [None], [1], [True], [""],
                      ["x\0y"], ["x" * 128], ["目标" * 43], ["x"] * 9):
            with self.subTest(value=value):
                result = self.raw("configure_async_capture", {"process_generation": generation,
                                                              "enabled": True, "root_callback_include": value})
                self.assertTrue(result.get("isError"), result)
        self.assertEqual(before, self.call("get_flow_state"))

    def test_typed_ownership_rejects_conflicting_mutations(self):
        generation = self.call("get_capabilities")["processGeneration"]
        hooks = self.call("list_hooks")
        before = self.call("get_flow_state")
        timer = self.call("get_timer_state")
        for symbol in ("CFRunLoopTimerCreate", "CFRunLoopTimerCreateWithHandler", "CFRunLoopTimerInvalidate",
                       "CFRunLoopAddTimer", "CFRunLoopRemoveTimer", "CFRunLoopPerformBlock"):
            with self.subTest(symbol=symbol):
                result = self.raw("hook_import", {"symbol": symbol, "process_generation": generation})
                self.assertTrue(result.get("isError"), result)
                self.assertIn("owned by bounded async capture", str(result).lower())
        for selector in ("timerWithTimeInterval:target:selector:userInfo:repeats:",
                         "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",
                         "timerWithTimeInterval:repeats:block:", "scheduledTimerWithTimeInterval:repeats:block:"):
            with self.subTest(selector=selector):
                result = self.raw("hook_method", {"class": "NSTimer", "selector": selector,
                                                  "classMethod": True, "capture_return": False,
                                                  "process_generation": generation})
                self.assertTrue(result.get("isError"), result)
                self.assertIn("already", str(result).lower())
        address = timer["nativeAdapter"]["targetIdentity"]["address"]
        result = self.raw("hook_inline", {"addr": address, "process_generation": generation})
        self.assertTrue(result.get("isError"), result)
        self.assertIn("typed adapter", str(result).lower())
        result = self.raw("trace_function", {"addr": address, "args": [], "max_insns": 64,
                                             "process_generation": generation})
        self.assertTrue(result.get("isError"), result)
        self.assertIn("patch", str(result).lower())
        self.assertEqual(hooks, self.call("list_hooks"))
        self.assertEqual(before, self.call("get_flow_state"))
        self.assertEqual(timer, self.call("get_timer_state"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    TimerFlowTests.endpoint = parser.parse_args().endpoint
    unittest.main(argv=[__file__], verbosity=2)
