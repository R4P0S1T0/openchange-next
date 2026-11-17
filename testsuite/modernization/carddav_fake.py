#!/usr/bin/python3
"""A fake CardDAV server for the dav backend tests, shaped like SOGo (fixtures/dav/*.xml).

Usage: carddav_fake.py <port-file> <state-dir>
Serves http://127.0.0.1:<port>/dav/u/Contacts/ with Basic auth u/p, one book "personal".
The port goes to <port-file> once listening; <state-dir>/requests.log gets "METHOD path status".
Test controls (no auth): POST /_ctl/edit?path=P, /_ctl/delete?path=P (act as another client),
/_ctl/fail?code=N (every request answers N; 0 clears), /_ctl/slow?secs=S (delay every request),
/_ctl/serve?file=F (PROPFIND and REPORT answer 207 with the file F until serve?file= is empty),
/_ctl/invalidate_token (the next sync with a token gets 403 valid-sync-token; real SOGo
answers 207 with the full state instead).
A PUT with If-None-Match: * on an existing card answers 412 (RFC 4918); real SOGo ignores it and overwrites (204).
"""
import os
import re
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from xml.sax.saxutils import escape

HOME = "/dav/u/Contacts/"
AUTH = "Basic dTpw"  # u:p
lock = threading.Lock()
S = {"fail": 0, "slow": 0.0, "invalidate": False, "serve": "", "version": 0}
books = {"personal": {"name": "Personal", "items": {}, "counter": 1794920000, "changes": []}}


def bump(book, name, removed):
    book["counter"] += 1
    book["changes"].append((book["counter"], name, removed))


def split(path):
    """(book, name) from /dav/u/Contacts/<book>/<name>; name None for the book itself."""
    if not path.startswith(HOME):
        return None, None
    parts = path[len(HOME):].split("/")
    book = books.get(parts[0])
    return (parts[0], parts[1] if len(parts) > 1 and parts[1] else None)


def ms(inner, extra_ns=""):
    return ('<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:"%s>%s</D:multistatus>'
            % (extra_ns, inner))


def item_resp(book_key, name, etag, data=None):
    prop = ""
    if data is not None:
        prop += "<C:address-data>%s</C:address-data>" % escape(data)
    prop += "<D:getetag>&quot;%s&quot;</D:getetag>" % etag[1:-1]
    return ("<D:response><D:href>%s%s/%s</D:href><D:propstat><D:prop>%s</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>" % (HOME, book_key, name, prop))


def gone_resp(book_key, name):
    return ("<D:response><D:href>%s%s/%s</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>"
            % (HOME, book_key, name))


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body=b"", ctype="text/plain", etag=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        with open(os.path.join(self.server.state_dir, "requests.log"), "a") as f:
            f.write("%s %s %d\n" % (self.command, self.path, code))

    def xml(self, code, body):
        self.send(code, body, 'application/xml; charset="utf-8"')

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def handle_any(self):
        u = urlparse(self.path)
        data = self.body()
        if u.path.startswith("/_ctl/"):
            return self.ctl(u, parse_qs(u.query))
        if S["slow"]:
            time.sleep(S["slow"])
        if S["fail"]:
            return self.send(S["fail"])
        if self.headers.get("Authorization") != AUTH:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="fake"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with lock:
            self.dispatch(u.path, data)

    do_GET = do_PUT = do_DELETE = do_PROPFIND = do_REPORT = do_MKCOL = do_PROPPATCH = handle_any
    do_POST = handle_any

    def ctl(self, u, q):
        with lock:
            key, name = split(q.get("path", [""])[0])
            book = books.get(key)
            op = u.path[len("/_ctl/"):]
            if op in ("edit", "delete"):
                if not book or name not in book["items"]:
                    return self.send(404)
                if op == "edit":
                    S["version"] += 1
                    body = book["items"][name][0]
                    i = body.rfind("END:V")
                    body = body[:i] + "X-EDITED:%d\r\n" % S["version"] + body[i:] if i >= 0 else body + "X-EDITED:1\r\n"
                    book["items"][name] = (body, '"gcs%08d"' % S["version"])
                else:
                    del book["items"][name]
                bump(book, name, op == "delete")
            elif op == "fail":
                S["fail"] = int(q["code"][0])
            elif op == "slow":
                S["slow"] = float(q["secs"][0])
            elif op == "serve":
                S["serve"] = q.get("file", [""])[0]
            elif op == "invalidate_token":
                S["invalidate"] = True
            else:
                return self.send(404)
        self.send(200)

    def dispatch(self, path, data):
        m = self.command
        if S["serve"] and m in ("PROPFIND", "REPORT"):
            with open(S["serve"], "rb") as f:
                return self.xml(207, f.read())
        if m == "REPORT" and b"sync-collection" in data and self.headers.get("Depth") != "0":
            return self.send(400)  # RFC 6578: sync-collection is Depth 0
        key, name = split(path)
        book = books.get(key) if key else None
        if m == "PROPFIND" and path == HOME:
            return self.propfind()
        if not book:
            if m == "MKCOL" and key and name is None:
                return self.mkcol(key, data)
            return self.send(404)
        if name is None:
            if m == "REPORT":
                return self.report(key, book, data)
            if m == "PROPPATCH":
                mt = re.search(rb"<[^>]*displayname[^>]*>([^<]*)<", data)
                if not mt:
                    return self.send(400)
                book["name"] = mt.group(1).decode()
                return self.xml(207, ms("<D:response><D:href>%s%s/</D:href><D:propstat><D:prop><D:displayname/>"
                                        "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>" % (HOME, key)))
            if m == "DELETE":
                del books[key]
                return self.send(204)
            return self.send(405)
        item = book["items"].get(name)
        if m == "GET":
            return self.send(200, item[0], "text/x-vcard; charset=utf-8", item[1]) if item else self.send(404)
        if m == "DELETE":
            if not item:
                return self.send(404)
            im = self.headers.get("If-Match")
            if im and im != item[1]:
                return self.send(412)
            del book["items"][name]
            bump(book, name, True)
            return self.send(204)
        if m == "PUT":
            im, inm = self.headers.get("If-Match"), self.headers.get("If-None-Match")
            if (inm == "*" and item) or (im and (not item or im != item[1])):
                return self.send(412)
            S["version"] += 1
            etag = '"gcs%08d"' % S["version"]
            book["items"][name] = (data.decode(), etag)
            bump(book, name, False)
            return self.send(204 if item else 201, b"", "text/plain", etag)
        self.send(405)

    def propfind(self):
        out = ("<D:response><D:href>%s</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop>"
               "<D:resourcetype><D:collection/></D:resourcetype><D:displayname>Contacts</D:displayname></D:prop>"
               "</D:propstat></D:response>" % HOME)
        for k, b in books.items():
            out += ('<D:response><D:href>%s%s/</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop>'
                    '<D:resourcetype><D:collection/><addressbook xmlns="urn:ietf:params:xml:ns:carddav"/>'
                    '</D:resourcetype><D:displayname>%s</D:displayname><D:sync-token>%d</D:sync-token></D:prop>'
                    '</D:propstat></D:response>' % (HOME, k, escape(b["name"]), b["counter"]))
        self.xml(207, ms(out))

    def mkcol(self, key, data):
        mt = re.search(rb"<[^>]*displayname[^>]*>([^<]*)<", data)
        books[key] = {"name": mt.group(1).decode() if mt else key, "items": {}, "counter": 1794920000, "changes": []}
        self.send(201)

    def report(self, key, book, data):
        if b"sync-collection" in data:
            mt = re.search(rb"<[^>]*sync-token>([^<]*)<", data)
            tok = mt.group(1).decode().strip() if mt else ""
            if tok and S["invalidate"]:
                S["invalidate"] = False
                return self.xml(403, '<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:"><D:valid-sync-token/></D:error>')
            names = {}
            if tok.isdigit() and int(tok) <= book["counter"]:
                for c, n, removed in book["changes"]:
                    if c > int(tok):
                        names[n] = removed
            elif tok:  # SOGo: an unknown token is treated as 0 (everything since the start)
                for c, n, removed in book["changes"]:
                    names[n] = removed
            else:
                names = {n: False for n in book["items"]}
            out = ""
            for n, removed in names.items():
                if removed or n not in book["items"]:
                    out += gone_resp(key, n)
                else:
                    out += item_resp(key, n, book["items"][n][1])
            return self.xml(207, ms(out + "<D:sync-token>%d</D:sync-token>" % book["counter"]))
        if b"addressbook-multiget" in data:
            out = ""
            for h in re.findall(rb"<[^>]*href>([^<]*)<", data):
                _, n = split(h.decode())
                it = book["items"].get(n)
                out += item_resp(key, n, it[1], it[0]) if it else gone_resp(key, n)
            return self.xml(207, ms(out, ' xmlns:C="urn:ietf:params:xml:ns:carddav"'))
        self.send(501)


def main():
    port_file, state_dir = sys.argv[1:3]
    os.makedirs(state_dir, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    srv.state_dir = state_dir
    tmp = port_file + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(srv.server_address[1]))
    os.rename(tmp, port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
