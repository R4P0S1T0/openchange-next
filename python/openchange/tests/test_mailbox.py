#!/usr/bin/python

# OpenChange provisioning
# Copyright (C) Jelmer Vernooij <jelmer@openchange.org> 2009
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
#

from openchange.mailbox import NoSuchServer, OpenChangeDB, gen_mailbox_folder_fid
from openchange.provision import ProvisionNames
import os
import tempfile
import unittest


class OpenChangeDBTests(unittest.TestCase):
    """Tests for OpenChangeDB."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openchange-mailbox-test-")
        self.addCleanup(self.temp.cleanup)
        self.db = OpenChangeDB(os.path.join(self.temp.name, "openchange.ldb"))
        self.db.setup()
        self.names = ProvisionNames()
        self.names.firstorg = 'firstorg'
        self.names.firstou = 'firstou'
        self.names.ocserverdn = 'dc=myserver'
        self.names.netbiosname = 'myserver'

    def test_user_exists_no_server(self):
        self.assertRaises(NoSuchServer, self.db.lookup_mailbox_user,
                          "someserver", "foo")

    def test_server_lookup_doesnt_exist(self):
        self.assertRaises(NoSuchServer, self.db.lookup_server,
                          "nonexistantserver")

    def test_server_lookup(self):
        self.db.add_server(self.names)
        self.assertEqual(self.names.ocserverdn,
                          str(self.db.lookup_server(self.names.netbiosname)['dn']))

    def test_msg_globalcount_initial(self):
        self.db.add_server(self.names)
        self.assertEqual(1, self.db.get_message_GlobalCount(self.names.netbiosname))

    def test_set_msg_globalcount(self):
        self.db.add_server(self.names)
        self.db.set_message_GlobalCount(self.names.netbiosname, 42)
        self.assertEqual(42, self.db.get_message_GlobalCount(self.names.netbiosname))

    def test_msg_replicaid_initial(self):
        self.db.add_server(self.names)
        self.assertEqual(1, self.db.get_message_ReplicaID(self.names.netbiosname))


class MailboxFIDTests(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(0x7816000000012345, int(gen_mailbox_folder_fid(0x1678, 0x12345)))


class MysqlDatabaseNameTests(unittest.TestCase):
    """mysqlclient's escape_string returns bytes on Python 3; DDL must use the plain name."""

    def setUp(self):
        from openchange.mailbox import OpenChangeDBWithMysqlBackend

        class FakeDb:
            def escape_string(self, value):
                return value.encode() if isinstance(value, str) else value

            def select_db(self, name):
                pass

        self.db = OpenChangeDBWithMysqlBackend.__new__(OpenChangeDBWithMysqlBackend)
        self.db.db = FakeDb()
        self.db.db_name = "openchange"
        self.sql = []
        self.db._execute = lambda sql, params=(): self.sql.append(sql)

    def test_create_database_uses_plain_name(self):
        self.db._create_database()
        self.assertEqual(self.sql, ["DROP DATABASE IF EXISTS `openchange`", "CREATE DATABASE `openchange`"])

    def test_remove_uses_plain_name(self):
        self.db.remove()
        self.assertEqual(self.sql, ["DROP DATABASE `openchange`"])
