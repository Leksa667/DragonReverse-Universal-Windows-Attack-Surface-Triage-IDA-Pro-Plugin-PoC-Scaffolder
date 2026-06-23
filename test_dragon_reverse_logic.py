from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
IDA_PLUGIN = ROOT / "ida_plugin"
sys.path.insert(0, str(IDA_PLUGIN))

import dragon_reverse_logic as logic


class FilenameProfileTests(unittest.TestCase):
    def test_matches_alias_and_marks_filename_only(self) -> None:
        profiles = {
            "zam64.sys": {
                "name": "zam64.sys / zamguard64.sys",
                "aliases": ["zamguard64.sys"],
                "primitives": ["process_kill"],
            }
        }
        hit = logic.match_filename_profile(r"C:\drivers\zamguard64.sys", profiles)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["profile_key"], "zam64.sys")
        self.assertEqual(hit["match_confidence"], "filename-only")


class ActionabilityTests(unittest.TestCase):
    def test_suppresses_copy_only_user_pointer_noise(self) -> None:
        ok, reason = logic.family_hit_actionable("method_neither_user_pointer", {"memmove"}, False, {"memmove"})
        self.assertFalse(ok)
        self.assertEqual(reason, "suppressed-copy-only-user-pointer-fp")

    def test_keeps_copy_with_user_length_context(self) -> None:
        ok, reason = logic.family_hit_actionable("unsafe_copy_length", {"memmove", "InputBufferLength"}, False, {"memmove", "InputBufferLength"})
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_suppresses_registry_open_without_write(self) -> None:
        ok, reason = logic.family_hit_actionable("registry_service_write", {"ZwOpenKey"}, False, {"ZwOpenKey"})
        self.assertFalse(ok)
        self.assertEqual(reason, "registry-open-only-not-write")


class CompoundCorrelationTests(unittest.TestCase):
    def test_adds_weak_device_memory_bundle(self) -> None:
        rows: list[dict] = []
        family_scores = {
            "weak_device_acl": {"score": 20, "functions": [{"ea": 1, "name": "setup", "score": 20, "roles": ["Device ACL / namespace exposure"]}], "evidence": {"IoCreateDevice"}, "roles": {"Device ACL / namespace exposure"}},
            "physmem_map": {"score": 45, "functions": [{"ea": 2, "name": "map", "score": 45, "roles": ["Physical memory mapper"]}], "evidence": {"MmMapIoSpace"}, "roles": {"Physical memory mapper"}},
        }
        logic.add_compound_correlations(rows, family_scores, {}, "")
        self.assertTrue(any(row["family"] == "weak_device_to_memory_primitive" for row in rows))
        self.assertTrue(any("confidence_reason" in row for row in rows))


if __name__ == "__main__":
    unittest.main()
