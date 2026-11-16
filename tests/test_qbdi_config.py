import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("qbdi_config", ROOT / "tools/qbdi_universal_config.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
OFF = "/* #undef QBDI_PTRAUTH */"
ON = "#define QBDI_PTRAUTH ON"


class QBDIConfigTests(unittest.TestCase):
    def setUp(self):
        self.a = "#define QBDI_ARCH_AARCH64 1\n/* #undef QBDI_EXPORT_SYM */\n" + OFF + "\n\nend\n"
        self.b = self.a.replace(OFF, ON)

    def test_abi_specific_pointer_auth(self):
        merged = module.merge(self.a, self.b)
        self.assertIn("#if defined(__arm64e__)\n#define QBDI_PTRAUTH 1\n#endif\n\nend", merged)

    def test_wrong_slice_or_different_contract_rejected(self):
        for a, b in ((self.b, self.a), (self.a, self.a), (self.a, self.b.replace("end", "different")),
                     (self.a.replace("/* #undef QBDI_EXPORT_SYM */", "#define QBDI_EXPORT_SYM 1"),
                      self.b.replace("/* #undef QBDI_EXPORT_SYM */", "#define QBDI_EXPORT_SYM 1"))):
            with self.subTest(a=a, b=b), self.assertRaises(ValueError):
                module.merge(a, b)


if __name__ == "__main__":
    unittest.main()
