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

"""Plain LDB directory for the MAPI server, generated from PostfixAdmin.

MariaDB stays the source of truth; this file is a read-only cache with the
attributes the EMSMDB/NSPI code queries. It is replaced atomically.
"""

import collections
import grp
import hashlib
import os
import re
import tempfile

import ldb

Mailbox = collections.namedtuple("Mailbox", "email name active")

BASE_DN = "DC=openchange"
USERS_DN = "CN=Users," + BASE_DN
CONFIG_DN = "CN=Configuration," + BASE_DN

QUERY = ("SELECT m.username, m.name, (m.active = 1 AND d.active = 1) "
         "FROM mailbox m JOIN domain d ON d.domain = m.domain")


def nickname(email):
    """mailNickname: readable local part plus a stable per-address hash."""
    email = email.lower()
    local = re.sub(rb"[^a-z0-9._-]", b"_", email.split("@", 1)[0].encode("utf-8")).decode("ascii")
    return "%s-%s" % (local, hashlib.sha256(email.encode("utf-8")).hexdigest()[:8])


def legacy_dn(org, ou, email):
    return "/o=%s/ou=%s/cn=Recipients/cn=%s" % (org, ou, nickname(email))


def fetch_mailboxes(conn):
    cur = conn.cursor()
    try:
        cur.execute(QUERY)
        return [Mailbox(email.lower(), name or "", bool(active)) for email, name, active in cur.fetchall()]
    finally:
        cur.close()


def _entry(db, dn, **attrs):
    msg = ldb.Message(ldb.Dn(db, dn))
    for name, value in attrs.items():
        msg[name] = ldb.MessageElement(value, ldb.FLAG_MOD_ADD, name)
    db.add(msg)


def _populate(db, org, ou, mailboxes):
    _entry(db, "@ATTRIBUTES", legacyExchangeDN="CASE_INSENSITIVE", sAMAccountName="CASE_INSENSITIVE",
           mail="CASE_INSENSITIVE", mailNickname="CASE_INSENSITIVE", cn="CASE_INSENSITIVE")
    _entry(db, "@INDEXLIST", **{"@IDXATTR": ["legacyExchangeDN", "sAMAccountName", "objectClass"]})
    _entry(db, "@ROOTDSE", defaultNamingContext=BASE_DN, configurationNamingContext=CONFIG_DN)
    org_dn = "CN=%s,CN=Microsoft Exchange,CN=Services,%s" % (org, CONFIG_DN)
    _entry(db, org_dn, objectClass=["top", "msExchOrganizationContainer"], cn=org)
    _entry(db, "CN=%s,CN=Administrative Groups,%s" % (ou, org_dn),
           objectClass=["top", "msExchAdminGroup"], cn=ou, msExchDefaultAdminGroup="TRUE")
    for box in mailboxes:
        _entry(db, "CN=%s,%s" % (ldb.binary_encode(box.email), USERS_DN),
               objectClass=["top", "person", "organizationalPerson", "user"],
               sAMAccountName=box.email, mail=box.email,
               displayName=box.name.strip() or box.email,
               mailNickname=nickname(box.email),
               legacyExchangeDN=legacy_dn(org, ou, box.email),
               proxyAddresses="SMTP:" + box.email,
               msExchUserAccountControl="0" if box.active else "2",
               msExchRecipientTypeDetails="6", msExchRecipientDisplayType="0")


def write_directory(path, org, ou, mailboxes):
    """Build the directory next to path, then rename it over path."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".directory-")
    os.close(fd)
    os.unlink(tmp)  # tdb must create the file itself
    try:
        db = ldb.Ldb("tdb://" + tmp)
        db.transaction_start()
        try:
            _populate(db, org, ou, mailboxes)
        except BaseException:
            db.transaction_cancel()
            raise
        db.transaction_commit()
        del db
        os.chmod(tmp, 0o640)
        try:
            os.chown(tmp, -1, grp.getgrnam("openchange").gr_gid)
        except (KeyError, PermissionError):
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
