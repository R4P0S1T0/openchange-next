"""Check version provenance and stable generation using disposable Git repositories."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("git"), "Git is required for version provenance tests")
class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="openchange-version ")
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "source with spaces"
        self.source.mkdir()
        self.output = self.source / "version header.h"
        self.env = os.environ.copy()
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
            self.env.pop(key, None)
        self.write_version()

    def write_version(self, nickname="Vulcan", snapshot="yes"):
        (self.source / "VERSION").write_text(
            f"OPENCHANGE_VERSION_IS_GIT_SNAPSHOT={snapshot}\n"
            f"OPENCHANGE_VERSION_RELEASE_NICKNAME={nickname}\n"
            "OPENCHANGE_VERSION_RELEASE_NUMBER=2.3\n"
        )

    def git(self, *args, cwd=None):
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Version test",
             "-c", "user.email=version@example.test", *args],
            cwd=cwd or self.source, env=self.env, check=True, text=True, capture_output=True,
        ).stdout.strip()

    def initialize_git(self):
        self.git("init", "-b", "main")
        self.git("add", "VERSION")
        self.git("commit", "-m", "Fixture")
        return self.git("rev-parse", "--short", "HEAD")

    def generate(self, source=None, output=None, cwd=None):
        destination = output or self.output
        subprocess.run(
            ["sh", str(ROOT / "script/mkversion.sh"), "VERSION", str(destination), "2.3", str(source or self.source)],
            cwd=cwd or self.temporary.name, env=self.env, check=True, capture_output=True, text=True,
        )
        return destination.read_text()

    def make_header(self, source):
        subprocess.run(
            ["make", "-f", str(ROOT / "Makefile"), "-o", "config.mk", "libmapi/version.h"],
            cwd=source, env=self.env, check=True, text=True, capture_output=True,
        )
        return source / "libmapi/version.h"

    def prepare_make(self, source):
        (source / "script").mkdir()
        shutil.copy2(ROOT / "script/mkversion.sh", source / "script/mkversion.sh")
        (source / "libmapi").mkdir()
        (source / "config.mk").write_text("PACKAGE_VERSION=2.3\ntop_builddir=.\n")

    def check_make_revision_update(self, source):
        self.prepare_make(source)
        header = self.make_header(source)
        old_time = 1_000_000_000_000_000_000
        git_dir = Path(self.git("rev-parse", "--absolute-git-dir", cwd=source))
        inputs = [source / "VERSION", source / "script/mkversion.sh", git_dir / "HEAD"]
        if source == self.source:
            inputs.append(git_dir / "refs/heads/main")
        for item in inputs:
            os.utime(item, ns=(old_time, old_time))
        os.utime(header, ns=(old_time + 1_000_000, old_time + 1_000_000))
        (source / "marker").write_text("new source revision")
        self.git("add", "marker", cwd=source)
        self.git("commit", "-m", "New revision", cwd=source)
        revision = self.git("rev-parse", "--short", "HEAD", cwd=source)
        self.make_header(source)
        self.assertIn(f'OPENCHANGE_VERSION_GIT_REVISION "{revision}"', header.read_text())
        result = subprocess.run(
            ["make", "-q", "-f", str(ROOT / "Makefile"), "-o", "config.mk", "libmapi/version.h"],
            cwd=source, env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("make"), "Make is required")
    def test_make_tracks_branch_head_and_stays_quiet_after_generation(self):
        self.initialize_git()
        self.check_make_revision_update(self.source)

    @unittest.skipUnless(shutil.which("make"), "Make is required")
    def test_make_tracks_detached_worktree_head(self):
        revision = self.initialize_git()
        worktree = Path(self.temporary.name) / "worktree"
        self.git("worktree", "add", "--detach", str(worktree), revision)
        self.check_make_revision_update(worktree)

    def test_source_revision_comes_from_source_checkout(self):
        revision = self.initialize_git()
        header = self.generate(cwd=ROOT)
        self.assertIn(f'OPENCHANGE_VERSION_GIT_REVISION "{revision}"', header)
        self.assertIn(f'"2.3-GIT-{revision} (Vulcan)"', header)

    def test_regeneration_preserves_timestamp_without_changes(self):
        self.initialize_git()
        first = self.generate()
        old_time = 1_000_000_000_000_000_000
        os.utime(self.output, ns=(old_time, old_time))
        self.assertEqual(self.generate(), first)
        self.assertEqual(self.output.stat().st_mtime_ns, old_time)

    def test_archive_inside_other_repository_has_no_parent_revision(self):
        self.initialize_git()
        archive = self.source / "archive"
        archive.mkdir()
        shutil.copyfile(self.source / "VERSION", archive / "VERSION")
        header = self.generate(source=archive)
        self.assertNotIn("OPENCHANGE_VERSION_GIT_REVISION", header)
        self.assertIn('"2.3 (Vulcan)"', header)

    def test_worktree_uses_its_own_head(self):
        revision = self.initialize_git()
        worktree = Path(self.temporary.name) / "worktree"
        self.git("worktree", "add", "--detach", str(worktree), revision)
        header = self.generate(source=worktree)
        self.assertIn(f'OPENCHANGE_VERSION_GIT_REVISION "{revision}"', header)

    def test_release_omits_git_and_escapes_strings(self):
        self.initialize_git()
        self.write_version(nickname='Name "quoted" \\ test', snapshot="no")
        header = self.generate()
        self.assertNotIn("OPENCHANGE_VERSION_GIT_REVISION", header)
        self.assertIn(r'Name \"quoted\" \\ test', header)

    def test_missing_version_does_not_replace_existing_header(self):
        self.output.write_text("keep")
        (self.source / "VERSION").unlink()
        with self.assertRaises(subprocess.CalledProcessError):
            self.generate()
        self.assertEqual(self.output.read_text(), "keep")
        self.assertFalse(list(self.source.glob("version header.h.tmp.*")))


if __name__ == "__main__":
    unittest.main()
