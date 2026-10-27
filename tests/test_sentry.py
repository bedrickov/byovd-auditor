import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts')))
from driver_sentry import get_loaded_drivers, audit_vulnerable_drivers

class TestDriverSentry(unittest.TestCase):
    def test_enumeration_returns_drivers(self):
        drivers = get_loaded_drivers()
        self.assertGreater(len(drivers), 10, "Should enumerate kernel drivers on Windows")
        # ntoskrnl.exe is always loaded as a kernel image
        names = [d["name"].lower() for d in drivers]
        self.assertTrue(any("ntoskrnl" in n or "kernel" in n or "win32k" in n for n in names))

    def test_audit_logic(self):
        mock_drivers = [
            {"name": "clean_driver.sys", "address": "0x1000"},
            {"name": "mhyprot2.sys", "address": "0x2000"}
        ]
        vuln = audit_vulnerable_drivers(mock_drivers)
        self.assertEqual(len(vuln), 1)
        self.assertEqual(vuln[0]["name"], "mhyprot2.sys")

if __name__ == '__main__':
    unittest.main()
