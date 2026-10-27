"""Python 3 provisioning against a disposable LDB, without an AD server."""

import contextlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import ldb
from samba import Ldb
from openchange import provision
from openchange.migration.directory import SetPostmansterSecondaryProxyAddressesEntry


class SchemaProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openchange-schema-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = Ldb(str(self.root / "schema.ldb"))
        self.db.add({'dn': 'DC=example', 'objectClass': 'domain', 'dc': 'example'})
        self.names = SimpleNamespace(**{name: 'example' for name in (
            'firstorg', 'firstorgdn', 'firstou', 'configdn', 'schemadn',
            'domaindn', 'domain', 'dnsdomain', 'netbiosname', 'hostname')})
        self.reporter = Mock()

    def apply_ldif(self, text, **kwargs):
        (self.root / "fixture.ldif").write_text(text, encoding="utf-8")
        with patch.object(provision, 'force_schemas_update'):
            with contextlib.redirect_stdout(io.StringIO()):
                provision.provision_schema(
                    self.db, lambda name: str(self.root / name), self.names,
                    self.reporter, 'fixture.ldif', 'test schema', **kwargs)

    def test_multiple_entries_and_unicode(self):
        self.apply_ldif('dn: CN=one,DC=example\nobjectClass: container\ncn: one\n\n'
                        'dn: CN=two,DC=example\nobjectClass: container\ncn: two\n'
                        'description: café ${FIRSTORG}\n')
        result = self.db.search(base='CN=two,DC=example', scope=ldb.SCOPE_BASE)
        self.assertEqual(result[0]['description'].text[0], 'café example')
        self.reporter.reportNextStep.assert_called_once_with('test schema')

    def test_existing_entries_can_be_ignored(self):
        text = 'dn: CN=one,DC=example\nobjectClass: container\ncn: one\n'
        self.apply_ldif(text)
        self.apply_ldif(text, ignore_already_exists=True)
        self.assertEqual(len(self.db.search(base='CN=one,DC=example', scope=ldb.SCOPE_BASE)), 1)

    def test_failed_import_rolls_back_prior_entries(self):
        text = 'dn: CN=one,DC=example\nobjectClass: container\ncn: one\n\n'
        with self.assertRaises(ldb.LdbError):
            self.apply_ldif(text + text)
        self.assertEqual(len(self.db.search(base='DC=example', expression='(cn=one)')), 0)

    def test_modify_mode(self):
        self.apply_ldif('dn: CN=one,DC=example\nobjectClass: container\ncn: one\n')
        self.apply_ldif('dn: CN=one,DC=example\nchangetype: modify\n'
                        'replace: description\ndescription: changed\n', modify_mode=True)
        result = self.db.search(base='CN=one,DC=example', scope=ldb.SCOPE_BASE)
        self.assertEqual(result[0]['description'].text[0], 'changed')

    def test_postmaster_migration_handles_ldb_bytes_and_can_rollback(self):
        self.db.add({'dn': 'CN=postmaster,DC=example', 'objectClass': 'container',
                     'cn': 'postmaster', 'proxyAddresses': [
                         'SMTP:postmaster@example.test', 'smtp:other@example.test']})
        kwargs = dict(lp=None, creds=None, names=SimpleNamespace(domaindn='DC=example'))
        with patch.object(provision, 'get_local_samdb', return_value=self.db):
            SetPostmansterSecondaryProxyAddressesEntry.apply(None, **kwargs)
            result = self.db.search(base='CN=postmaster,DC=example', scope=ldb.SCOPE_BASE)
            self.assertEqual(set(result[0]['proxyAddresses'].text),
                             {'smtp:postmaster@example.test', 'smtp:other@example.test'})
            SetPostmansterSecondaryProxyAddressesEntry.unapply(None, **kwargs)
        result = self.db.search(base='CN=postmaster,DC=example', scope=ldb.SCOPE_BASE)
        self.assertIn('SMTP:postmaster@example.test', result[0]['proxyAddresses'].text)
