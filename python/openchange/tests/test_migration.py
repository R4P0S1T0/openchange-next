#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) Enrique J. Hernández <ejhernandez@zentyal.com> 2015
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
"""
OpenChangeDB migration framework functional tests.

SQL tests require an explicitly selected disposable endpoint via OPENCHANGE_TEST_MYSQL_SOCKET or OPENCHANGE_TEST_MYSQL_HOST.
"""
from datetime import datetime
import os
import MySQLdb
import unittest
import uuid


from openchange.migration import migration, Migration, MigrationManager


@unittest.skipUnless(os.environ.get('OPENCHANGE_TEST_MYSQL_SOCKET') or
                     os.environ.get('OPENCHANGE_TEST_MYSQL_HOST'),
                     'set OPENCHANGE_TEST_MYSQL_SOCKET or OPENCHANGE_TEST_MYSQL_HOST')
class MigrationDBTests(unittest.TestCase):
    """Tests for OpenChangeDB migration framework"""

    def setUp(self):
        original_migrations = MigrationManager.migrations
        self.builtin_migrations = original_migrations
        MigrationManager.migrations = {}
        self.addCleanup(setattr, MigrationManager, 'migrations', original_migrations)
        options = {
            'user': os.environ.get('OPENCHANGE_TEST_MYSQL_USER', 'root'),
            'charset': 'utf8mb4',
            'passwd': os.environ.get('OPENCHANGE_TEST_MYSQL_PASSWORD', ''),
        }
        if os.environ.get('OPENCHANGE_TEST_MYSQL_SOCKET'):
            options['unix_socket'] = os.environ['OPENCHANGE_TEST_MYSQL_SOCKET']
        else:
            options['host'] = os.environ['OPENCHANGE_TEST_MYSQL_HOST']
            options['port'] = int(os.environ.get('OPENCHANGE_TEST_MYSQL_PORT', '3306'))
        self.db = MySQLdb.connect(**options)
        self.addCleanup(self.db.close)
        self.db_name = 'openchange_test_' + uuid.uuid4().hex
        cur = self.db.cursor()
        cur.execute('CREATE DATABASE IF NOT EXISTS {}'.format(self.db_name))
        self.db.commit()
        cur.close()
        self.addCleanup(self.drop_database)
        self.app = 'test'

    def drop_database(self):
        cur = self.db.cursor()
        cur.execute('DROP DATABASE `{}`'.format(self.db_name))
        cur.close()

    def _register_do_nothing_migrations(self, app):
        # Register a do-nothing migration into app
        @migration(app, 1)
        class DoNothingMigration(Migration):

            @classmethod
            def apply(cls, cur, **kwargs):
                cur.execute('SELECT 1 FROM test_migrations')

            @classmethod
            def unapply(cls, cur):
                cur.execute('SELECT 2 FROM test_migrations')

        MigrationManager.add_migration(app, 2, DoNothingMigration)

    def test_setup(self):
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')
        self.assertIsNotNone(manager)
        cur = self.db.cursor()
        cur.execute('DESCRIBE test_migrations')
        row = cur.fetchone()
        self.assertIsNotNone(row)

    def test_invalid_table_names_are_rejected(self):
        for name in ('', 'bad`name', 'bad;name', 'x' * 65, b'migrations'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                MigrationManager(self.db, self.db_name, name)

    def test_reserved_table_name_is_quoted(self):
        manager = MigrationManager(self.db, self.db_name, 'select')
        self._register_do_nothing_migrations(self.app)
        manager.apply_version(self.app, 1)
        self.assertEqual(manager.version(self.app), 1)
        self.assertIsNotNone(manager.applied_migration(self.app, 1))
        self.assertIsNotNone(manager.list_migrations(self.app)[1]['applied'])
        manager.unapply_version(self.app, 1)
        self.assertIsNone(manager.version(self.app))

    def test_setup_does_not_treat_underscores_as_wildcards(self):
        MigrationManager(self.db, self.db_name, 'testXmigrations')
        MigrationManager(self.db, self.db_name, 'test_migrations')
        cur = self.db.cursor()
        cur.execute('DESCRIBE test_migrations')
        self.assertIsNotNone(cur.fetchone())

    def test_builtin_sql_schemas_upgrade_and_rollback(self):
        MigrationManager.migrations = self.builtin_migrations
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')
        for app in ('openchangedb', 'indexing', 'named_properties'):
            with self.subTest(app=app):
                self.assertTrue(manager.migrate(app))
                self.assertEqual(manager.version(app), max(manager.migrations[app]))
                self.assertFalse(manager.migrate(app))
                if app == 'named_properties':
                    cursor = self.db.cursor()
                    cursor.execute('SELECT COUNT(*) FROM named_properties')
                    self.assertGreater(cursor.fetchone()[0], 0)
                    cursor.close()
                self.assertTrue(manager.migrate(app, 0))
                self.assertIsNone(manager.version(app))

    def named_properties_manager(self, version):
        MigrationManager.migrations = self.builtin_migrations
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')
        manager.migrate('named_properties', version)
        return manager

    def test_named_properties_unicode_identity_and_uniqueness(self):
        manager = self.named_properties_manager(1)
        cur = self.db.cursor()
        # Reproduce the charset/collation of an existing version-2 installation.
        cur.execute("ALTER TABLE named_properties CONVERT TO CHARACTER SET utf8 COLLATE utf8_general_ci")
        guid = '00112233-4455-6677-8899-aabbccddeeff'
        cur.execute("INSERT INTO named_properties (type,propType,oleguid,mappedId,propId,propName) "
                    "VALUES (1,1,%s,40000,0,'existing')", (guid,))
        self.db.commit()
        # Mark the seed import complete without inserting its fixtures in this test.
        manager.apply_version('named_properties', 2)
        manager.migrate('named_properties')
        cur.execute("SHOW FULL COLUMNS FROM named_properties WHERE Field='propName'")
        self.assertEqual(cur.fetchone()[2], 'utf8mb4_bin')
        cur.execute("SHOW FULL COLUMNS FROM named_properties WHERE Field='oleguid'")
        self.assertEqual(cur.fetchone()[2], 'ascii_general_ci')
        cur.execute("SELECT propId FROM named_properties WHERE mappedId=40000")
        self.assertIsNone(cur.fetchone()[0])
        names = ('X-Foo', 'x-foo', 'cafe', 'café', 'emoji 😀')
        for offset, name in enumerate(names):
            cur.execute("INSERT INTO named_properties (type,propType,oleguid,mappedId,propName) "
                        "VALUES (1,1,%s,%s,%s)", (guid, 40001 + offset, name))
        for offset, name in enumerate(names):
            cur.execute("SELECT mappedId FROM named_properties WHERE type=1 AND oleguid=%s AND propName=%s",
                        (guid, name))
            self.assertEqual(cur.fetchall(), ((40001 + offset,),))
        cur.execute("INSERT INTO named_properties (type,propType,oleguid,mappedId,propId) "
                    "VALUES (0,1,%s,40010,42)", (guid,))
        for kind, mapped, lid, name in ((1,41000,None,'X-Foo'), (1,40001,None,'other'),
                                         (0,41000,42,None)):
            with self.subTest(kind=kind, mapped=mapped), self.assertRaises(MySQLdb.IntegrityError) as error:
                cur.execute("INSERT INTO named_properties (type,propType,oleguid,mappedId,propId,propName) "
                            "VALUES (%s,1,%s,%s,%s,%s)", (kind,guid,mapped,lid,name))
            self.assertEqual(error.exception.args[0], 1062)
        with self.assertRaises(MySQLdb.IntegrityError):
            cur.execute("INSERT INTO named_properties (type,propType,oleguid,mappedId,propName) "
                        "VALUES (1,1,%s,41002,'X-Foo')", (guid.upper(),))
        with self.assertRaises(MySQLdb.Error):
            cur.execute("INSERT INTO named_properties (type,propType,oleguid,mappedId,propId,propName) "
                        "VALUES (1,1,%s,41001,42,'invalid arm')", (guid,))
        self.db.commit()
        manager.migrate('named_properties', 2)
        cur.execute("SELECT propName FROM named_properties WHERE mappedId=40005")
        self.assertEqual(cur.fetchone()[0], 'emoji 😀')
        manager.migrate('named_properties', 3)
        self.assertEqual(manager.version('named_properties'), 3)

    def test_named_properties_migration_refuses_ambiguous_ids(self):
        manager = self.named_properties_manager(1)
        cur = self.db.cursor()
        guid = '00112233-4455-6677-8899-aabbccddeeff'
        for lid in (1,2):
            cur.execute("INSERT INTO named_properties (type,propType,oleguid,mappedId,propId) "
                        "VALUES (0,1,%s,40000,%s)", (guid,lid))
        self.db.commit()
        manager.apply_version('named_properties', 2)
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            manager.migrate('named_properties')
        self.assertEqual(manager.version('named_properties'), 2)
        cur.execute("SELECT mappedId,propId FROM named_properties ORDER BY propId")
        self.assertEqual(cur.fetchall(), ((40000,1),(40000,2)))
        cur.execute("SELECT IS_USED_LOCK(CONCAT('openchange:namedprops:',MD5(DATABASE())))")
        self.assertIsNone(cur.fetchone()[0])

    def test_named_properties_migration_refuses_duplicate_identities(self):
        manager = self.named_properties_manager(1)
        cur = self.db.cursor()
        manager.apply_version('named_properties', 2)
        for kind, lid, name in ((0,42,None), (1,0,'same')):
            with self.subTest(kind=kind):
                cur.execute('DELETE FROM named_properties')
                for mapped in (40000,40001):
                    cur.execute("INSERT INTO named_properties (type,propType,oleguid,mappedId,propId,propName) "
                                "VALUES (%s,1,'00112233-4455-6677-8899-aabbccddeeff',%s,%s,%s)",
                                (kind,mapped,lid,name))
                self.db.commit()
                with self.assertRaisesRegex(ValueError, 'Duplicate'):
                    manager.migrate('named_properties')
                self.assertEqual(manager.version('named_properties'), 2)
                cur.execute('SELECT mappedId,propId FROM named_properties ORDER BY mappedId')
                self.assertEqual(cur.fetchall(), ((40000,lid),(40001,lid)))

    def test_version(self):
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')
        self.assertIsNone(manager.version(self.app))

        manager.apply_version(self.app, 1)
        self.assertIsNotNone(manager.version(self.app))
        self.assertEqual(manager.version(self.app), 1)

        manager.apply_version(self.app, 3)
        self.assertEqual(manager.version(self.app), 3)

        manager.unapply_version(self.app, 3)
        self.assertEqual(manager.version(self.app), 1)

        manager.unapply_version(self.app, 1)
        self.assertIsNone(manager.version(self.app))

    def test_go_forward_and_backwards(self):
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')

        self._register_do_nothing_migrations(self.app)

        migrated = manager.migrate(self.app, target_version=1)
        self.assertTrue(migrated)
        self.assertEqual(manager.version(self.app), 1)
        self.assertLessEqual(manager.applied_migration(self.app, 1), datetime.now())

        migrated = manager.migrate(self.app)
        self.assertTrue(migrated)
        self.assertEqual(manager.version(self.app), 2)
        self.assertLessEqual(manager.applied_migration(self.app, 2), datetime.now())

        migrated = manager.migrate(self.app)
        self.assertFalse(migrated)

        migrated = manager.migrate(self.app, target_version=1)
        self.assertTrue(migrated)
        self.assertIsNone(manager.applied_migration(self.app, 2))

        migrated = manager.migrate(self.app)
        self.assertTrue(migrated)

        migrated = manager.migrate(self.app, target_version=0)
        self.assertTrue(migrated)
        self.assertIsNone(manager.version(self.app))
        self.assertIsNone(manager.applied_migration(self.app, 1))
        self.assertIsNone(manager.applied_migration(self.app, 2))

        migrated = manager.migrate(self.app, target_version=0)
        self.assertFalse(migrated)

        for v in list(manager.migrations):
            del manager.migrations[v]

    def test_fake_migrations(self):
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')

        self.assertFalse(manager.fake_migration('fake app', None))

        self._register_do_nothing_migrations(self.app)
        self.assertFalse(manager.fake_migration(self.app, None))

        self.assertTrue(manager.fake_migration(self.app, 3))
        self.assertEqual(manager.version(self.app), 2)

        self.assertFalse(manager.fake_migration(self.app, 2))

        self.assertTrue(manager.fake_migration(self.app, 1))
        self.assertEqual(manager.version(self.app), 1)

        for v in list(manager.migrations):
            del manager.migrations[v]

    def test_list_migrations(self):
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')

        self.assertEqual(len(manager.list_migrations(self.app).keys()), 0)
        self._register_do_nothing_migrations(self.app)

        self.assertEqual(len(manager.list_migrations(self.app).keys()), 2)
        self.assertTrue(all([m['applied'] is None for m in manager.list_migrations(self.app).values()]))
        self.assertTrue(all(['class' in m for m in manager.list_migrations(self.app).values()]))

        manager.migrate(self.app)
        for m in manager.list_migrations(self.app).values():
            self.assertTrue(m['applied'])
            self.assertTrue(len(m['class'].description))

        for v in list(manager.migrations):
            del manager.migrations[v]

    def test_multiapp(self):
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')

        new_app = 'wannadie'
        self._register_do_nothing_migrations(self.app)
        self._register_do_nothing_migrations(new_app)

        migrated = manager.migrate(self.app, target_version=1)
        self.assertTrue(migrated)

        migrated = manager.migrate(new_app)
        self.assertTrue(migrated)

        self.assertEqual(manager.version(self.app), 1)
        self.assertEqual(manager.version(new_app), 2)

        self.assertLessEqual(manager.applied_migration(self.app, 1), datetime.now())
        self.assertLessEqual(manager.applied_migration(new_app, 2), datetime.now())

        self.assertEqual(len(manager.list_migrations(self.app).keys()), 2)
        self.assertEqual(len(manager.list_migrations(new_app).keys()), 2)

        for v in list(manager.migrations):
            del manager.migrations[v]

    def test_apps(self):
        manager = MigrationManager(self.db, self.db_name, 'test_migrations')
        for v in list(manager.migrations):
            del manager.migrations[v]

        self.assertEqual(manager.apps(), [])
        self._register_do_nothing_migrations(self.app)
        self._register_do_nothing_migrations('la_cena')

        self.assertEqual(manager.apps(), ['la_cena', self.app])

        for v in list(manager.migrations):
            del manager.migrations[v]
