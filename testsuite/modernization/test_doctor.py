"""Tests that do not require the legacy Samba/Python 2 environment."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("doctor", ROOT / "script/doctor.py")
doctor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(doctor)


class DoctorTests(unittest.TestCase):
    @patch.object(doctor.shutil, "which", return_value=None)
    def test_missing_tools_do_not_attempt_subprocesses(self, _which):
        with patch.object(doctor, "run") as run:
            report = doctor.inspect()
        run.assert_not_called()
        self.assertEqual(report["samba_baseline"], "4.1.18")
        self.assertTrue(any(c["status"] == "unchecked" for c in report["checks"]))

    def inventory(self, python_version="3.13", samba_version="4.99.0"):
        def command(args):
            if "-c" in args:
                return 0, python_version
            return 0, ""
        with patch.object(doctor.shutil, "which", side_effect=lambda name: "/bin/" + name):
            with patch.object(doctor, "run", side_effect=command):
                with patch.object(doctor, "samba_version", return_value=samba_version):
                    return doctor.inspect()

    def test_samba_release_is_read_from_header_not_library_api_version(self):
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / "samba/version.h"
            header.parent.mkdir()
            header.write_text('#define SAMBA_VERSION_OFFICIAL_STRING "4.22.10"\n')
            with patch.object(doctor, "run", return_value=(0, directory)) as run:
                self.assertEqual(doctor.samba_version("pkg-config"), "4.22.10")
            run.assert_called_once_with(["pkg-config", "--variable=includedir", "samba-hostconfig"])

    def test_unknown_samba_release_is_not_guessed(self):
        with patch.object(doctor, "run", return_value=(1, "missing package")):
            self.assertIsNone(doctor.samba_version("pkg-config"))

    def test_nanomsg_legacy_metadata_is_supported(self):
        def command(args):
            return (1, "missing") if args[-1] == "nanomsg >= 0.5" else (0, "")
        with patch.object(doctor.shutil, "which", return_value="/bin/tool"):
            with patch.object(doctor, "run", side_effect=command):
                with patch.object(doctor, "samba_version", return_value=None):
                    report = doctor.inspect()
        check = next(c for c in report["checks"] if c["name"] == "nanomsg >= 0.5")
        self.assertEqual(check["status"], "ok")

    def test_old_python_and_different_samba_are_not_reported_ready(self):
        checks = {c["name"]: c for c in self.inventory("2.7")["checks"]}
        self.assertEqual(checks["Python runtime"]["status"], "incompatible")
        self.assertEqual(checks["Samba baseline"]["status"], "unverified")

    def test_legacy_baseline_is_discoverable(self):
        self.assertTrue(all(c["status"] == "ok" for c in
                            self.inventory("3.13", "4.1.18")["checks"]))

    def test_strict_exit_status(self):
        with patch.object(doctor, "inspect", return_value={"checks": [{"status": "missing"}]}):
            with patch("builtins.print"):
                self.assertEqual(doctor.main(["--json", "--strict"]), 1)
                self.assertEqual(doctor.main(["--json"]), 0)

    def test_timed_out_probe_is_a_diagnostic(self):
        with patch.object(doctor.subprocess, "run", side_effect=subprocess.TimeoutExpired("probe", 10)):
            code, detail = doctor.run(["probe"])
        self.assertEqual(code, 1)
        self.assertIn("timed out", detail)


if __name__ == "__main__":
    unittest.main()
