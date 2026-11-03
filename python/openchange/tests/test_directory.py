#!/usr/bin/python3

# OpenChange directory generated from PostfixAdmin
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import tempfile
import unittest
from unittest import mock

import ldb

from openchange import directory
from openchange.directory import Mailbox

ORG = "First Organization"
OU = "Exchange Administrative Group (FYDIBOHF23SPDLT)"
ALICE = Mailbox("alice@example.invalid", "Alice Example", True)
BOB = Mailbox("bob@example.invalid", "Bob", False)


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.query = None

    def execute(self, query):
        self.query = query

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class FakeConnection:
    def __init__(self, rows):
        self.cur = FakeCursor(rows)

    def cursor(self):
        return self.cur


class DirectoryTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "directory.ldb")

    def tearDown(self):
        self.tmp.cleanup()

    def open(self):
        return ldb.Ldb("tdb://" + self.path, flags=ldb.FLG_RDONLY)

    def user(self, db, email):
        res = db.search(base="CN=Users,DC=openchange", scope=ldb.SCOPE_SUBTREE,
                        expression="(sAMAccountName=%s)" % ldb.binary_encode(email))
        self.assertEqual(len(res), 1)
        return res[0]

    def test_nickname_vector(self):
        self.assertEqual(directory.nickname("teste@lab.fitasonline.com.br"), "teste-ec0903c6")
        self.assertTrue(directory.nickname("A.B+x@Example.invalid").startswith("a.b_x-"))
        # Every UTF-8 byte outside [a-z0-9._-] becomes "_", like mapihttpd's Autodiscover.
        self.assertTrue(directory.nickname("jo\u00e3o@example.invalid").startswith("jo__o-"))

    def test_legacy_dn(self):
        self.assertEqual(directory.legacy_dn(ORG, OU, "alice@example.invalid"),
                         "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)"
                         "/cn=Recipients/cn=" + directory.nickname("alice@example.invalid"))

    def test_written_entries(self):
        directory.write_directory(self.path, ORG, OU, [ALICE, BOB])
        db = self.open()
        alice = self.user(db, "alice@example.invalid")
        self.assertEqual(str(alice["mail"]), "alice@example.invalid")
        self.assertEqual(str(alice["displayName"]), "Alice Example")
        self.assertEqual(str(alice["mailNickname"]), directory.nickname("alice@example.invalid"))
        self.assertEqual(str(alice["legacyExchangeDN"]), directory.legacy_dn(ORG, OU, "alice@example.invalid"))
        self.assertEqual(str(alice["proxyAddresses"]), "SMTP:alice@example.invalid")
        self.assertIn("user", [str(v) for v in alice["objectClass"]])
        self.assertEqual(str(alice["msExchRecipientTypeDetails"]), "6")
        self.assertEqual(str(alice["msExchRecipientDisplayType"]), "0")
        self.assertEqual(str(alice["msExchUserAccountControl"]), "0")
        self.assertEqual(str(self.user(db, "bob@example.invalid")["msExchUserAccountControl"]), "2")
        root = db.search(base="@ROOTDSE", scope=ldb.SCOPE_BASE)[0]
        self.assertEqual(str(root["defaultNamingContext"]), "DC=openchange")
        self.assertEqual(str(root["configurationNamingContext"]), "CN=Configuration,DC=openchange")
        org_dn = "CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=openchange"
        org = db.search(base=org_dn, scope=ldb.SCOPE_BASE)[0]
        self.assertIn("msExchOrganizationContainer", [str(v) for v in org["objectClass"]])
        group = db.search(base="CN=%s,CN=Administrative Groups,%s" % (OU, org_dn), scope=ldb.SCOPE_BASE)[0]
        self.assertIn("msExchAdminGroup", [str(v) for v in group["objectClass"]])
        self.assertEqual(str(group["msExchDefaultAdminGroup"]), "TRUE")

    def test_file_mode(self):
        # ldb's tdb backend opens O_RDWR even when asked for read-only: the service group needs write.
        directory.write_directory(self.path, ORG, OU, [ALICE])
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o660)

    def test_dn_special_addresses(self):
        # Legal mailbox addresses with DN special characters must not break the whole sync.
        odd = ["a+b=c@example.invalid", '"a,b;<c>"@example.invalid', "a\\b#c@example.invalid"]
        directory.write_directory(self.path, ORG, OU, [Mailbox(e, "", True) for e in odd] + [ALICE])
        db = self.open()
        for email in odd + ["alice@example.invalid"]:
            self.assertEqual(str(self.user(db, email)["sAMAccountName"]), email)

    def test_display_name_fallback(self):
        directory.write_directory(self.path, ORG, OU, [Mailbox("carol@example.invalid", "  ", True)])
        self.assertEqual(str(self.user(self.open(), "carol@example.invalid")["displayName"]), "carol@example.invalid")

    def test_search_is_case_insensitive(self):
        directory.write_directory(self.path, ORG, OU, [ALICE])
        dn = directory.legacy_dn(ORG, OU, "alice@example.invalid").upper()
        res = self.open().search(base="DC=openchange", scope=ldb.SCOPE_SUBTREE,
                                 expression="(legacyExchangeDN=%s)" % ldb.binary_encode(dn))
        self.assertEqual(len(res), 1)

    def test_inactive_domain_disables_account(self):
        conn = FakeConnection([("x@d.invalid", "", 0), ("y@d.invalid", "Y", 1)])
        self.assertEqual(directory.fetch_mailboxes(conn),
                         [Mailbox("x@d.invalid", "", False), Mailbox("y@d.invalid", "Y", True)])
        self.assertIn("d.active = 1", conn.cur.query)

    def test_failed_write_keeps_previous_file(self):
        directory.write_directory(self.path, ORG, OU, [ALICE])
        real = directory._populate

        def populate_then_fail(*args):
            real(*args)  # leaves a partially built temp file behind
            raise ldb.LdbError(1, "boom")
        with mock.patch.object(directory, "_populate", populate_then_fail):
            with self.assertRaises(ldb.LdbError):
                directory.write_directory(self.path, ORG, OU, [BOB])
        self.user(self.open(), "alice@example.invalid")
        self.assertEqual(os.listdir(self.tmp.name), ["directory.ldb"])


if __name__ == "__main__":
    unittest.main()
