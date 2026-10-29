"""Staged install checker: reject incomplete or escaping artifacts before loading code."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('check_install', ROOT / 'script/check_install.py')
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class InstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='openchange-stage-test-')
        self.addCleanup(temporary.cleanup)
        self.stage = Path(temporary.name)
        self.prefix = self.stage / 'usr/local'
        self.library = self.prefix / 'lib'
        self.library.mkdir(parents=True)
        for name in checker.LIBRARIES:
            target = name.removesuffix('.0') + '.2.3'
            (self.library / target).write_bytes(b'library')
            (self.library / name).symlink_to(target)
        for name in checker.MODULES:
            (self.library / name).write_bytes(b'module')
        for name in checker.COMMANDS + checker.ADMIN:
            binary = self.prefix / 'bin' / name
            binary.parent.mkdir(exist_ok=True)
            binary.write_text('program')
        self.python = self.library / 'python3.13/site-packages/openchange'
        self.python.mkdir(parents=True)
        (self.python / 'provision.py').write_text('module')
        self.setup = self.prefix / 'share/setup'
        (self.setup / 'mapistore').mkdir(parents=True)
        (self.setup / 'mapistore/mapistore_namedprops.ldif').write_text('fixture')
        shutil.copytree(ROOT / 'setup/AD', self.setup / 'AD')
        (self.setup / 'openchangedb').mkdir()
        for source in (ROOT / 'setup/openchangedb').glob('oc_provision*'):
            shutil.copy2(source, self.setup / 'openchangedb' / source.name)

    def test_inventory_and_runtime_checks_use_installed_paths(self):
        def command(argv, **options):
            self.assertNotEqual(Path(options['cwd']), ROOT)
            self.assertNotEqual(Path(options['cwd']), self.stage)
            self.assertTrue(options['env']['PYTHONPATH'].startswith(str(self.python.parent)))
            self.assertTrue(options['env']['LD_LIBRARY_PATH'].startswith(str(self.library)))
            self.assertEqual(options['env']['PYTHONDONTWRITEBYTECODE'], '1')
            return subprocess.CompletedProcess(argv, 0, '', '')
        with patch.object(checker.subprocess, 'run', side_effect=command):
            report = checker.inspect(self.stage)
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['checks']), 2 + len(checker.COMMANDS + checker.ADMIN))
        rows = {r['path']: r for r in report['files']}
        self.assertIn('sha256', rows['usr/local/lib/libmapi.so.2.3'])
        self.assertEqual(rows['usr/local/lib/libmapi.so.0']['link'], 'libmapi.so.2.3')

    def rejected_before_execution(self, text):
        with patch.object(checker.subprocess, 'run') as command:
            report = checker.inspect(self.stage)
        command.assert_not_called()
        self.assertTrue(any(text in error for error in report['errors']), report['errors'])

    def test_missing_soname_link(self):
        (self.library / 'libmapi.so.0').unlink()
        self.rejected_before_execution('libmapi.so.0')

    def test_external_symlink(self):
        (self.prefix / 'escape').symlink_to('/etc/passwd')
        self.rejected_before_execution('escaping path')

    def test_broken_symlink(self):
        (self.prefix / 'broken').symlink_to('missing')
        self.rejected_before_execution('Broken')

    def test_duplicate_library(self):
        (self.prefix / 'libmapi.so.0').write_text('duplicate')
        self.rejected_before_execution('libmapi.so.0')

    def test_template_tampering_or_missing_data(self):
        (self.setup / 'AD/oc_provision_schema.ldif').write_text('wrong')
        (self.setup / 'AD/prefixMap.txt').unlink()
        self.rejected_before_execution('AD template')

    def test_fifo_is_not_opened_or_hashed(self):
        os.mkfifo(self.prefix / 'fifo')
        self.rejected_before_execution('Not a regular file')

    def test_failed_runtime_check_is_not_reported_as_success(self):
        with patch.object(checker.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'missing symbol')):
            report = checker.inspect(self.stage)
        self.assertTrue(report['errors'])
        self.assertEqual(report['checks'][0]['detail'], 'missing symbol')

    def test_system_root_is_rejected(self):
        with self.assertRaises(ValueError):
            checker.inspect('/')
