"""Provisioning command entry points must run with the Python 3 runtime."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class CommandLineTests(unittest.TestCase):
    def test_help_from_outside_the_source_directory(self):
        with tempfile.TemporaryDirectory(prefix='openchange-cli-test-') as directory:
            for name in ('openchange_provision', 'openchange_migrate',
                         'openchange_group', 'openchange_newuser',
                         'openchange_neworganization'):
                with self.subTest(command=name):
                    result = subprocess.run([sys.executable, str(ROOT / 'setup' / name), '--help'],
                                            cwd=directory, capture_output=True,
                                            text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('--help', result.stdout)
