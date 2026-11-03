#!/usr/bin/python3
"""Create the oc-emsmdb test openchangedb the way a SamDB-free deployment does (see doc/MAPIHTTP.md)."""
import sys

from openchange.mailbox import OpenChangeDB
from openchange.provision import ProvisionNames

names = ProvisionNames()
names.firstorg = "First Organization"
names.firstou = "Exchange Administrative Group (FYDIBOHF23SPDLT)"
names.netbiosname = "SERVER"
names.ocserverdn = "CN=SERVER,DC=example,DC=invalid"
names.ocfirstorgdn = "CN=%s,%s" % (names.firstorg, names.ocserverdn)
db = OpenChangeDB(sys.argv[1])
db.setup(names)
db.add_server(names)
db.add_public_folders(names)
