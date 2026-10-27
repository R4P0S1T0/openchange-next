"""Exercise bootstrap failures and the real generated configure entry point."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openchange-bootstrap-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = os.environ.copy()

    def run_bootstrap(self):
        return subprocess.run(["sh", str(ROOT / "autogen.sh")], cwd=self.root,
                              env=self.env, capture_output=True, text=True, timeout=60)

    def fake_tool(self, name, version="2.72", status=0):
        tool = self.root / name
        tool.write_text(
            '#!/bin/sh\nif [ "$1" = "--version" ]; then\n'
            '  echo "tool (GNU) {}"\n  exit 0\nfi\nexit {}\n'.format(version, status)
        )
        tool.chmod(0o755)
        self.env[name.upper()] = str(tool)

    def test_missing_tool_fails_before_changing_generated_files(self):
        generated = self.root / "configure"
        generated.write_text("keep existing configure")
        self.env["AUTOCONF"] = str(self.root / "absent-autoconf")
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required tool not found", result.stderr)
        self.assertEqual(generated.read_text(), "keep existing configure")

    def test_old_autoconf_is_rejected(self):
        for name in ("autoconf", "autoheader", "aclocal"):
            self.fake_tool(name, version="2.56")
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("2.57 or later", result.stderr)

    def test_future_major_version_is_accepted(self):
        for name in ("autoconf", "autoheader", "aclocal"):
            self.fake_tool(name, version="3.0")
        self.assertEqual(self.run_bootstrap().returncode, 0)

    def test_generator_failure_propagates(self):
        for name in ("autoconf", "autoheader", "aclocal"):
            self.fake_tool(name, status=7 if name == "autoheader" else 0)
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 7)
        self.assertNotIn("Now run", result.stdout)

    @unittest.skipUnless(all(shutil.which(t) for t in
                             ("autoconf", "autoheader", "aclocal", "pkg-config", "cc")),
                         "requires Autoconf, aclocal, pkg-config and a C compiler")
    def test_real_configure_runs_without_automake_auxiliary_files(self):
        for name in ("configure.ac", "config.guess", "config.sub", "install-sh", "VERSION"):
            shutil.copy2(ROOT / name, self.root / name)
        # Remove host-specific overrides: this test exercises installed tools.
        for name in ("AUTOCONF", "AUTOHEADER", "ACLOCAL"):
            self.env.pop(name, None)
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("obsolete", result.stderr)
        result = subprocess.run(["sh", "./configure"], cwd=self.root, env=self.env,
                                capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        self.assertNotIn("cannot find required auxiliary files", output)
        self.assertIn("checking whether the C compiler works... yes", output)

        # Reach the real pkg-config nanomsg check with isolated prerequisite
        # metadata; neither a database daemon nor Samba is needed for this test.
        metadata = self.root / "pkgconfig"
        metadata.mkdir()
        for name, version in (("samba-hostconfig", "0.0.1"), ("nanomsg", "1.1.5")):
            (metadata / (name + ".pc")).write_text(
                "Name: {}\nDescription: bootstrap test fixture\nVersion: {}\n"
                "Libs:\nCflags:\n".format(name, version)
            )
        mysql_config = self.root / "mysql_config"
        mysql_config.write_text("#!/bin/sh\nexit 0\n")
        mysql_config.chmod(0o755)
        self.env["MYSQL_CONFIG"] = str(mysql_config)
        self.env["PKG_CONFIG_PATH"] = str(metadata)
        self.env["PKG_CONFIG_LIBDIR"] = str(metadata)
        result = subprocess.run(["sh", "./configure"], cwd=self.root, env=self.env,
                                capture_output=True, text=True, timeout=60)
        self.assertIn("checking for nanomsg >= 0.5... yes", result.stdout)


if __name__ == "__main__":
    unittest.main()
