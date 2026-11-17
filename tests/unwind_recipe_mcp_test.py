"""Verify owned real-CFI evidence and recipe MCP validation on an explicit device."""
import argparse
import json
import unittest
from pathlib import Path

import source_flow_mcp_test as transport


class UnwindRecipeTests(unittest.TestCase):
    endpoint = ""
    fixture = None
    raw = transport.SourceFlowTests.raw
    call = transport.SourceFlowTests.call

    def test_actual_missing_metadata_reaches_its_original_caller(self):
        evidence = self.fixture
        self.assertTrue(evidence["pass"], evidence)
        self.assertEqual(len(evidence["passed"]), 6)
        generation = self.call("get_capabilities")["processGeneration"]
        self.assertEqual(evidence["state"]["processGeneration"], generation)
        repaired = evidence["repaired"]
        self.assertTrue(repaired["complete"])
        self.assertEqual(repaired["error"], 0)
        self.assertEqual(repaired["recoveredSteps"], 1)
        self.assertEqual(evidence["baseline"]["recoveredSteps"], 0)
        self.assertEqual(evidence["disabled"]["recoveredSteps"], 0)
        repaired_rows = [r for r in repaired["frames"] if "unwindRecipeSlot" in r]
        self.assertEqual(len(repaired_rows), 1)
        self.assertEqual(repaired_rows[0]["unwindRecipeSlot"], evidence["recipeSlot"])
        self.assertEqual(repaired_rows[0]["unwindSource"], "validated-canonical-frame-recipe")
        parent = repaired["frames"][repaired["frames"].index(repaired_rows[0]) + 1]
        self.assertEqual(parent["pcSemantics"], "verified-saved-return-address-minus-4")
        self.assertEqual(int(parent["savedReturnAddress"], 16), int(parent["pc"], 16) + 4)
        state = self.call("get_unwind_state")
        self.assertTrue(state["backendAvailable"])
        self.assertEqual((state["maxRecipes"], state["maxInstructions"], state["maxFrameBytes"]), (32, 256, 512))

    def test_bad_requests_preserve_configuration(self):
        before = self.call("get_unwind_state")
        hooks = self.call("list_hooks")
        generation = before["processGeneration"]
        for address in (None, True, 1, 1.5, [], {}, "", "0x", "-1", "0x-1", "0x+4", "0x0", "0x1", "0x3",
                        "0xffffffffffffffff", "0x10000000000000000", "0x1234\0", " 0x1234", "0x1234 ", "0x汉"):
            with self.subTest(address=address):
                self.assertTrue(self.raw("register_unwind_recipe", {"process_generation": generation, "address": address}).get("isError"))
        for slot in (None, True, 0, -1, 33, 1.5, "1"):
            with self.subTest(slot=slot):
                self.assertTrue(self.raw("set_unwind_recipe_enabled", {"process_generation": generation, "recipe_slot": slot, "enabled": True}).get("isError"))
        for enabled in (None, 0, 1, "true", [], {}):
            with self.subTest(enabled=enabled):
                self.assertTrue(self.raw("set_unwind_recipe_enabled", {"process_generation": generation, "recipe_slot": self.fixture["recipeSlot"], "enabled": enabled}).get("isError"))
        for tool, arguments in (("register_unwind_recipe", {"address": "0x1000"}),
                                ("set_unwind_recipe_enabled", {"recipe_slot": 1, "enabled": True}), ("run_unwind_selftest", {})):
            self.assertTrue(self.raw(tool, {**arguments, "process_generation": "old"}).get("isError"))
        self.assertEqual(before, self.call("get_unwind_state"))
        self.assertEqual(hooks, self.call("list_hooks"))

    def test_disassembler_reports_actual_pre_and_post_writeback(self):
        state = self.call("get_unwind_state")
        own = next(r for r in state["recipes"] if r["recipeSlot"] == self.fixture["recipeSlot"])
        code = self.call("disassemble_function", {"address": own["start"], "max_bytes": 128})
        rows = code["instructions"]
        self.assertEqual(rows[0]["mnemonic"], "stp")
        self.assertTrue(rows[0]["writeback"])
        self.assertIn("sp", rows[0]["registers_written"])
        self.assertEqual(rows[1]["mnemonic"], "stp")
        self.assertFalse(rows[1]["writeback"])
        post = next(r for r in rows if r["mnemonic"] == "ldp" and r["writeback"])
        self.assertTrue(post["writeback"])
        self.assertIn("sp", post["registers_written"])

    def test_public_registration_is_idempotent_and_toggle_is_explicit(self):
        state = self.call("get_unwind_state")
        slot = self.fixture["recipeSlot"]
        own = next(r for r in state["recipes"] if r["recipeSlot"] == slot)
        self.assertFalse(own["enabled"])
        result = self.call("register_unwind_recipe", {"process_generation": state["processGeneration"], "address": own["start"]})
        self.assertTrue(result["alreadyRegistered"])
        self.assertFalse(result["enabled"])
        self.assertEqual(result["recipeSlot"], slot)
        self.assertEqual(state, self.call("get_unwind_state"))
        try:
            result = self.call("set_unwind_recipe_enabled", {"process_generation": state["processGeneration"], "recipe_slot": slot, "enabled": True})
            self.assertTrue(result["enabled"])
            now = self.call("get_unwind_state")
            self.assertTrue(next(r for r in now["recipes"] if r["recipeSlot"] == slot)["enabled"])
        finally:
            self.call("set_unwind_recipe_enabled", {"process_generation": state["processGeneration"], "recipe_slot": slot, "enabled": False})
        self.assertEqual(state, self.call("get_unwind_state"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--fixture", required=True, type=Path)
    options = parser.parse_args()
    UnwindRecipeTests.endpoint = options.endpoint
    UnwindRecipeTests.fixture = json.loads(options.fixture.read_text(encoding="utf8"))
    unittest.main(argv=[__file__], verbosity=2)
