from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from dragon_reverse_shared import decode_ioctl_value, matching_signals, severity_from_score, signal_matches


def ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    return (device_type << 16) | (access << 14) | (function << 2) | method


class DecodeIoctlTests(unittest.TestCase):
    def test_accepts_file_device_unknown_method_neither(self) -> None:
        decoded = decode_ioctl_value(ctl_code(0x22, 0x800, 3, 0))
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["hex"], "0x00222003")
        self.assertEqual(decoded["method"], "METHOD_NEITHER")
        self.assertEqual(decoded["access"], "FILE_ANY_ACCESS")
        self.assertEqual(decoded["function_code"], 0x800)

    def test_accepts_vendor_defined_device_type(self) -> None:
        decoded = decode_ioctl_value(ctl_code(0x8086, 0x801, 3, 0))
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["device_type"], 0x8086)
        self.assertEqual(decoded["confidence"], "high")

    def test_rejects_common_false_positive_values(self) -> None:
        for value in (0, 0x00013F8B, 0x005E221B, 0x206B6444, 0x51EB851F):
            with self.subTest(value=value):
                self.assertIsNone(decode_ioctl_value(value))

    def test_rejects_low_function_codes(self) -> None:
        self.assertIsNone(decode_ioctl_value(ctl_code(0x22, 0x10, 0, 0)))


class ScoringAndSignalTests(unittest.TestCase):
    def test_severity_thresholds(self) -> None:
        self.assertEqual(severity_from_score(55), "Critical")
        self.assertEqual(severity_from_score(35), "High")
        self.assertEqual(severity_from_score(18), "Medium")
        self.assertEqual(severity_from_score(8), "Low")
        self.assertEqual(severity_from_score(7), "Info")

    def test_short_tokens_match_exactly(self) -> None:
        self.assertFalse(signal_matches("in", "InitializeObject"))
        self.assertFalse(signal_matches("pci", "SpecialCase"))
        self.assertTrue(signal_matches("in", "ntoskrnl!in"))

    def test_api_names_match_import_decorations(self) -> None:
        self.assertTrue(signal_matches("MmMapIoSpace", "ntoskrnl!MmMapIoSpace"))
        self.assertTrue(signal_matches("IoCreateDevice", "__imp_IoCreateDevice"))
        self.assertEqual(
            matching_signals(["MmMapIoSpace", "wrmsr"], {"ntoskrnl!MmMapIoSpace", "mov"}),
            ["MmMapIoSpace"],
        )


if __name__ == "__main__":
    unittest.main()
