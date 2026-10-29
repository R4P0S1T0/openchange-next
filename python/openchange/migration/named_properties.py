#!/usr/bin/python
# -*- coding: utf-8 -*-

# Named properties DB schema and its migrations
# Copyright (C) Enrique J. Hernández Blasco <ejhernandez@zentyal.com> 2015
# Copyright (C) Jesús García Sáez <jgarcia@zentyal.com> 2015
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
Schema migration for Named Properties "app" with SQL based backend
"""
from __future__ import print_function
from MySQLdb import ProgrammingError
from openchange.migration import migration, Migration, mapistore_namedprops
import sys


@migration('named_properties', 1)
class InitialIndexingMigration(Migration):

    description = 'initial'

    @classmethod
    def apply(cls, cur, **kwargs):
        try:
            cur.execute('SELECT COUNT(*) FROM `named_properties`')
            return False
        except ProgrammingError as e:
            if e.args[0] != 1146:
                raise
            # Table does not exist, then migrate

        cur.execute("""CREATE TABLE IF NOT EXISTS `named_properties` (
                         `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                         `type` TINYINT(1) NOT NULL,
                         `propType` INT(10) unsigned NOT NULL,
                         `oleguid` VARCHAR(255) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                         `mappedId` INT(10) unsigned NOT NULL,
                         `propId` INT(10) unsigned DEFAULT NULL,
                         `propName` VARCHAR(255) DEFAULT NULL,
                         `oom` VARCHAR(255) DEFAULT NULL,
                         `canonical` VARCHAR(255) DEFAULT NULL,
                         PRIMARY KEY(`id`),
                         KEY `named_properties_nappedId` (`mappedId`),
                         KEY `named_properties_type_oleguid_propId` (`type`,`oleguid`,`propId`),
                         KEY `named_properties_type_oleguid_propName` (`type`,`oleguid`,`propName`)
                      ) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_bin""")

    @classmethod
    def unapply(cls, cur):
        cur.execute("DROP TABLE named_properties")


@migration('named_properties', 2)
class InitialDataMigration(Migration):

    description = 'import default named properties'

    @classmethod
    def apply(cls, cur, **kwargs):
        cur.execute("START TRANSACTION")
        try:
            for p in mapistore_namedprops.named_properties:
                cls._insert_named_property(cur, p)
            cur.execute("COMMIT")
        except Exception as e:
            print("Error inserting named properties, rollback", file=sys.stderr)
            cur.execute("ROLLBACK")
            raise

    @classmethod
    def _already_inserted(cls, cur, p):
        # Avoid duplicates in already running installations
        cur.execute("SELECT count(*) FROM named_properties "
                    "WHERE mappedId = %d AND propType = %d" %
                    (p['mappedId'], p['propType']))
        res = cur.fetchone()
        return int(res[0]) != 0

    @classmethod
    def _insert_named_property(cls, cur, p):
        mandatory_keys = ('type', 'propType', 'oleguid', 'mappedId')
        if any(key not in p for key in mandatory_keys):
            return
        if cls._already_inserted(cur, p):
            return
        fields = list(mandatory_keys)
        fields += [key for key in ('propId', 'propName', 'oom', 'canonical')
                   if key in p and not (key == 'propId' and p['type'] == 1)]
        cur.execute("INSERT INTO named_properties ({}) VALUES ({})".format(
            ','.join(fields), ','.join(['%s'] * len(fields))),
            tuple(p[key] for key in fields))

    @classmethod
    def unapply(cls, cur):
        cur.execute("DELETE FROM named_properties")


@migration('named_properties', 3)
class ExactNamesAndUniqueIdsMigration(Migration):

    description = 'UTF-8 names and unique named-property mappings'

    @classmethod
    def apply(cls, cur, **kwargs):
        cur.execute("SELECT GET_LOCK(CONCAT('openchange:namedprops:',MD5(DATABASE())),5)")
        if cur.fetchone()[0] != 1:
            raise RuntimeError('Cannot lock named properties for schema migration')
        try:
            # Never repair ambiguous mappings by renumbering stored property IDs.
            for columns, condition in (
                    ('mappedId', '1=1'),
                    ('type,LOWER(oleguid),propId', 'type=0'),
                    ('type,LOWER(oleguid),BINARY propName', 'type=1')):
                cur.execute("SELECT 1 FROM named_properties WHERE {} GROUP BY {} "
                            "HAVING COUNT(*)>1 LIMIT 1".format(condition, columns))
                if cur.fetchone():
                    raise ValueError('Duplicate named-property mappings; repair requires a mailbox-aware migration')
            cur.execute("SELECT 1 FROM named_properties WHERE type NOT IN (0,1) "
                        "OR mappedId<32768 OR mappedId>65534 "
                        "OR (type=0 AND (propId IS NULL OR propName IS NOT NULL)) "
                        "OR (type=1 AND (propName IS NULL OR COALESCE(propId,0)<>0)) LIMIT 1")
            if cur.fetchone():
                raise ValueError('Invalid named-property mappings; schema migration stopped')
            # Older seed generators used zero for the inactive numeric arm.
            cur.execute("UPDATE named_properties SET propId=NULL WHERE type=1 AND propId=0")
            cur.execute("""ALTER TABLE named_properties
                DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
                MODIFY oleguid VARCHAR(255) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                MODIFY propName VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
                MODIFY oom VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
                MODIFY canonical VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
                ADD UNIQUE KEY named_properties_unique_mappedId (mappedId),
                ADD UNIQUE KEY named_properties_unique_lid (type,oleguid,propId),
                ADD UNIQUE KEY named_properties_unique_name (type,oleguid,propName),
                ADD CONSTRAINT named_properties_valid_kind CHECK (
                    mappedId BETWEEN 32768 AND 65534 AND (
                    (type=0 AND propId IS NOT NULL AND propName IS NULL) OR
                    (type=1 AND propId IS NULL AND propName IS NOT NULL)))""")
        finally:
            cur.execute("SELECT RELEASE_LOCK(CONCAT('openchange:namedprops:',MD5(DATABASE())))")
            cur.fetchone()

    @classmethod
    def unapply(cls, cur):
        # Keep UTF-8 capability on rollback: utf8mb3 cannot preserve four-byte names.
        cur.execute("""ALTER TABLE named_properties
            DROP CONSTRAINT named_properties_valid_kind,
            DROP INDEX named_properties_unique_mappedId,
            DROP INDEX named_properties_unique_lid,
            DROP INDEX named_properties_unique_name""")
