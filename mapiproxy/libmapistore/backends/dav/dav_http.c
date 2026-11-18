/*
   CardDAV client for the dav mapistore backend (libcurl + expat)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <curl/curl.h>
#include <expat.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "dav_http.h"

#define DAV_MAX_BODY	(64u * 1024 * 1024)
#define DAV_MAX_TEXT	(32u * 1024 * 1024)
#define NS_DAV		"DAV: "
#define NS_CARD		"urn:ietf:params:xml:ns:carddav "

struct dav_http {
	CURL		*curl;
	char		*origin;	/* scheme://host[:port], no trailing slash */
	char		*base_path;
	const char	*user;
	const char	*password;	/* borrowed */
	char		*etag;		/* ETag header of the last request */
};

struct buf {
	char	*p;
	size_t	len;
};

static size_t on_body(char *data, size_t size, size_t nmemb, void *ud)
{
	struct buf *b = ud;
	size_t n = size * nmemb;
	char *np;

	if (n > DAV_MAX_BODY - b->len) return 0;
	np = realloc(b->p, b->len + n + 1);
	if (!np) return 0;
	memcpy(np + b->len, data, n);
	b->len += n;
	np[b->len] = '\0';
	b->p = np;
	return n;
}

static size_t on_header(char *data, size_t size, size_t nmemb, void *ud)
{
	struct dav_http *h = ud;
	size_t n = size * nmemb, a = 0, z;

	if (n > 5 && !strncasecmp(data, "etag:", 5)) {
		a = 5;
		while (a < n && (data[a] == ' ' || data[a] == '\t')) a++;
		z = n;
		while (z > a && (data[z - 1] == '\r' || data[z - 1] == '\n' || data[z - 1] == ' ')) z--;
		talloc_free(h->etag);
		h->etag = talloc_strndup(h, data + a, z - a);
	}
	return n;
}

static int dav_http_free(struct dav_http *h)
{
	if (h->curl) curl_easy_cleanup(h->curl);
	return 0;
}

struct dav_http *dav_http_new(TALLOC_CTX *mem_ctx, const char *base_url, const char *user, const char *password)
{
	static bool global_init;
	struct dav_http *h;
	const char *host, *path;

	if (!base_url || (strncmp(base_url, "http://", 7) && strncmp(base_url, "https://", 8))) return NULL;
	if (!global_init) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT)) return NULL;
		global_init = true;
	}
	h = talloc_zero(mem_ctx, struct dav_http);
	if (!h) return NULL;
	talloc_set_destructor(h, dav_http_free);
	host = strstr(base_url, "://") + 3;
	path = strchr(host, '/');
	h->origin = path ? talloc_strndup(h, base_url, path - base_url) : talloc_strdup(h, base_url);
	h->base_path = talloc_strdup(h, path ? path : "/");
	h->user = user;
	h->password = password;
	h->curl = curl_easy_init();
	if (!h->curl || !h->origin || !h->base_path) {
		talloc_free(h);
		return NULL;
	}
	return h;
}

static enum mapistore_error status_err(long st)
{
	if (st >= 200 && st < 300) return MAPISTORE_SUCCESS;
	switch (st) {
	case 401: case 403: return MAPISTORE_ERR_DENIED;
	case 404: return MAPISTORE_ERR_NOT_FOUND;
	case 405: case 409: return MAPISTORE_ERR_EXIST;
	case 412: return MAPISTORE_ERR_CONFLICT;
	}
	if (st >= 500) return MAPISTORE_ERR_CONN_REFUSED;
	return st >= 400 ? MAPISTORE_ERR_INVALID_DATA : MAPISTORE_ERR_NOT_AVAILABLE;
}

/* Path part of a server href, which may also arrive as an absolute URL. */
static const char *href_path(const char *href)
{
	const char *p;
	if (!strncmp(href, "http://", 7) || !strncmp(href, "https://", 8)) {
		p = strchr(strstr(href, "://") + 3, '/');
		return p ? p : "/";
	}
	return href;
}

static int hexval(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

char *dav_href_norm(TALLOC_CTX *mem_ctx, const char *href)
{
	const char *p = href_path(href);
	char *o = talloc_array(mem_ctx, char, strlen(p) + 1), *s;
	size_t n = 0, sl;
	int c;

	if (!o) return NULL;
	for (; *p; p++) {
		c = *p;
		if (c == '%' && hexval(p[1]) >= 0 && hexval(p[2]) >= 0) {
			c = hexval(p[1]) * 16 + hexval(p[2]);
			p += 2;
			if (c == 0) { talloc_free(o); return NULL; }
			if (c == '/' || c == '%') {
				n += sprintf(o + n, "%%%02X", c);
				continue;
			}
		}
		o[n++] = c;
	}
	while (n > 1 && o[n - 1] == '/') n--;
	o[n] = '\0';
	for (s = o; *s; s += sl) {
		while (*s == '/') s++;
		sl = strcspn(s, "/");
		if ((sl == 1 && s[0] == '.') || (sl == 2 && s[0] == '.' && s[1] == '.')) {
			talloc_free(o);
			return NULL;
		}
	}
	return o;
}

/* href (normalized) is a direct member of the collection `parent` (normalized). */
static bool is_member(const char *parent, const char *href)
{
	size_t pl = strcmp(parent, "/") ? strlen(parent) : 0;

	return href && !strncmp(href, parent, pl) && href[pl] == '/' && href[pl + 1] && !strchr(href + pl + 1, '/');
}

static bool header_safe(const char *s)
{
	return !s || !strpbrk(s, "\r\n");
}

/* One request. Only a transport failure is an error here; the caller maps the HTTP status. */
static enum mapistore_error dav_do(struct dav_http *h, const char *method, const char *href, const char *const *hdrs,
				   const char *body, long *status, struct buf *out)
{
	struct curl_slist *list = NULL;
	char *url;
	CURLcode rc;
	int i;

	out->p = NULL;
	out->len = 0;
	*status = 0;
	if (!href || href_path(href)[0] != '/') return MAPISTORE_ERR_INVALID_PARAMETER;
	url = talloc_asprintf(h, "%s%s", h->origin, href_path(href));
	if (!url) return MAPISTORE_ERR_NO_MEMORY;
	for (i = 0; hdrs && hdrs[i]; i++) {
		list = curl_slist_append(list, hdrs[i]);
		if (!list) { talloc_free(url); return MAPISTORE_ERR_NO_MEMORY; }
	}
	talloc_free(h->etag);
	h->etag = NULL;
	curl_easy_reset(h->curl);
	curl_easy_setopt(h->curl, CURLOPT_URL, url);
	curl_easy_setopt(h->curl, CURLOPT_NOSIGNAL, 1L);
	/* SOGo leaves VLIST lists out of listings for a client without a User-Agent. */
	curl_easy_setopt(h->curl, CURLOPT_USERAGENT, "openchange-mapistore-dav/" PACKAGE_VERSION);
#if LIBCURL_VERSION_NUM >= 0x075500
	curl_easy_setopt(h->curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
	curl_easy_setopt(h->curl, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
	curl_easy_setopt(h->curl, CURLOPT_CONNECTTIMEOUT, 5L);
	curl_easy_setopt(h->curl, CURLOPT_TIMEOUT, 15L);
	if (h->user) {
		curl_easy_setopt(h->curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
		curl_easy_setopt(h->curl, CURLOPT_USERNAME, h->user);
		curl_easy_setopt(h->curl, CURLOPT_PASSWORD, h->password ? h->password : "");
	}
	if (strcmp(method, "GET")) curl_easy_setopt(h->curl, CURLOPT_CUSTOMREQUEST, method);
	if (body) {
		curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(body));
	}
	curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION, on_body);
	curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, out);
	curl_easy_setopt(h->curl, CURLOPT_HEADERFUNCTION, on_header);
	curl_easy_setopt(h->curl, CURLOPT_HEADERDATA, h);
	rc = curl_easy_perform(h->curl);
	curl_slist_free_all(list);
	talloc_free(url);
	if (rc != CURLE_OK) {
		OC_DEBUG(3, "DAV backend: %s failed: %s\n", method, curl_easy_strerror(rc));
		free(out->p);
		out->p = NULL;
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	curl_easy_getinfo(h->curl, CURLINFO_RESPONSE_CODE, status);
	return MAPISTORE_SUCCESS;
}

/* ---- multistatus parsing ---- */

struct resp {
	char	*href, *etag, *displayname, *token, *data;
	bool	book, dir;
	int	status;
};

struct pst {
	XML_Parser	p;
	TALLOC_CTX	*mem;
	struct resp	*r;
	size_t		n;
	char		*token;		/* of the multistatus itself */
	struct resp	cur, ps;
	int		ps_status, bad;
	bool		in_resp, in_ps, in_rt, err;
	const char	*collect;	/* element whose text is gathered */
	char		*text;
	size_t		tlen;
};

static const char *const leaves[] = {
	NS_DAV "href", NS_DAV "status", NS_DAV "getetag", NS_DAV "displayname", NS_DAV "sync-token",
	NS_CARD "address-data", NULL
};

static void XMLCALL on_doctype(void *ud, const XML_Char *n, const XML_Char *s, const XML_Char *p, int i)
{
	struct pst *s2 = ud;
	s2->err = true;
	XML_StopParser(s2->p, XML_FALSE);
}

static void XMLCALL on_start(void *ud, const XML_Char *name, const XML_Char **attrs)
{
	struct pst *s = ud;
	int i;

	if (!strcmp(name, NS_DAV "response")) {
		memset(&s->cur, 0, sizeof s->cur);
		s->in_resp = true;
	} else if (!strcmp(name, NS_DAV "propstat")) {
		memset(&s->ps, 0, sizeof s->ps);
		s->ps_status = 0;
		s->in_ps = true;
	} else if (!strcmp(name, NS_DAV "resourcetype")) {
		s->in_rt = true;
	} else if (s->in_rt && !strcmp(name, NS_CARD "addressbook")) {
		s->ps.book = true;
	} else if (s->in_rt && !strcmp(name, NS_CARD "directory")) {
		s->ps.dir = true;
	} else if (!s->collect) {
		for (i = 0; leaves[i]; i++) {
			if (!strcmp(name, leaves[i])) {
				s->collect = leaves[i];
				s->tlen = 0;
				break;
			}
		}
	}
}

static void XMLCALL on_text(void *ud, const XML_Char *txt, int len)
{
	struct pst *s = ud;

	if (!s->collect) return;
	if (s->tlen + len > DAV_MAX_TEXT) {
		s->err = true;
		XML_StopParser(s->p, XML_FALSE);
		return;
	}
	s->text = talloc_realloc(s->mem, s->text, char, s->tlen + len + 1);
	if (!s->text) {
		s->err = true;
		XML_StopParser(s->p, XML_FALSE);
		return;
	}
	memcpy(s->text + s->tlen, txt, len);
	s->tlen += len;
}

static void leaf_done(struct pst *s, const char *name)
{
	char *v = talloc_strndup(s->mem, s->text ? s->text : "", s->tlen);
	int code = 0;

	if (!v) { s->err = true; return; }
	if (name == leaves[0]) {
		if (s->in_resp && !s->cur.href) s->cur.href = v;
	} else if (name == leaves[1]) {
		sscanf(v, "%*s %d", &code);
		if (s->in_ps) s->ps_status = code;
		else if (s->in_resp) s->cur.status = code;
	} else if (name == leaves[2]) {
		s->ps.etag = v;
	} else if (name == leaves[3]) {
		s->ps.displayname = v;
	} else if (name == leaves[4]) {
		if (s->in_ps) s->ps.token = v;
		else if (!s->in_resp) s->token = v;
	} else {
		s->ps.data = v;
	}
}

static void XMLCALL on_end(void *ud, const XML_Char *name)
{
	struct pst *s = ud;

	if (s->collect && !strcmp(name, s->collect)) {
		leaf_done(s, s->collect);
		s->collect = NULL;
	} else if (!strcmp(name, NS_DAV "resourcetype")) {
		s->in_rt = false;
	} else if (!strcmp(name, NS_DAV "propstat")) {
		s->in_ps = false;
		if (!s->ps_status || (s->ps_status >= 200 && s->ps_status < 300)) {
			if (s->ps.etag) s->cur.etag = s->ps.etag;
			if (s->ps.displayname) s->cur.displayname = s->ps.displayname;
			if (s->ps.token && *s->ps.token) s->cur.token = s->ps.token;
			if (s->ps.data) s->cur.data = s->ps.data;
			s->cur.book |= s->ps.book;
			s->cur.dir |= s->ps.dir;
		} else if (!s->bad) {
			s->bad = s->ps_status;
		}
	} else if (!strcmp(name, NS_DAV "response")) {
		s->in_resp = false;
		s->r = talloc_realloc(s->mem, s->r, struct resp, s->n + 1);
		if (!s->r) { s->err = true; return; }
		s->r[s->n++] = s->cur;
	}
}

/* Everything the parser returns lives in `mem`. */
static enum mapistore_error ms_parse(TALLOC_CTX *mem, const struct buf *b, struct pst *s)
{
	enum XML_Status st;

	memset(s, 0, sizeof *s);
	s->mem = mem;
	s->p = XML_ParserCreateNS(NULL, ' ');
	if (!s->p) return MAPISTORE_ERR_NO_MEMORY;
	XML_SetUserData(s->p, s);
	XML_SetElementHandler(s->p, on_start, on_end);
	XML_SetCharacterDataHandler(s->p, on_text);
	XML_SetStartDoctypeDeclHandler(s->p, on_doctype);
	st = XML_Parse(s->p, b->p ? b->p : "", b->len, 1);
	XML_ParserFree(s->p);
	return (st == XML_STATUS_OK && !s->err) ? MAPISTORE_SUCCESS : MAPISTORE_ERR_INVALID_DATA;
}

static char *xml_escape(TALLOC_CTX *mem, const char *s)
{
	char *o = talloc_strdup(mem, "");
	for (; o && *s; s++) {
		switch (*s) {
		case '&': o = talloc_strdup_append(o, "&amp;"); break;
		case '<': o = talloc_strdup_append(o, "&lt;"); break;
		case '>': o = talloc_strdup_append(o, "&gt;"); break;
		case '"': o = talloc_strdup_append(o, "&quot;"); break;
		default: o = talloc_asprintf_append(o, "%c", *s);
		}
	}
	return o;
}

static const char *const xml_hdrs[] = { "Content-Type: application/xml; charset=utf-8", NULL };
static const char *const depth1_hdrs[] = { "Content-Type: application/xml; charset=utf-8", "Depth: 1", NULL };
static const char *const depth0_hdrs[] = { "Content-Type: application/xml; charset=utf-8", "Depth: 0", NULL };

/* A request whose 207 body is parsed into s; *bad_token tells a 403/409 valid-sync-token error. */
static enum mapistore_error report(struct dav_http *h, TALLOC_CTX *mem, const char *method, const char *href,
				   const char *const *hdrs, const char *body, struct pst *s, bool *bad_token)
{
	struct buf b;
	long st;
	enum mapistore_error err;

	memset(s, 0, sizeof *s);
	err = dav_do(h, method, href, hdrs, body, &st, &b);
	if (err) return err;
	if (st == 207) {
		err = ms_parse(mem, &b, s);
	} else {
		if (bad_token && (st == 403 || st == 409) && b.p && strstr(b.p, "valid-sync-token")) *bad_token = true;
		err = status_err(st);
	}
	free(b.p);
	return err;
}

enum mapistore_error dav_list_books(struct dav_http *h, TALLOC_CTX *mem_ctx, struct dav_book **books, size_t *n)
{
	static const char body[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><propfind xmlns=\"DAV:\"><prop>"
		"<resourcetype/><displayname/><sync-token/></prop></propfind>";
	TALLOC_CTX *tmp = talloc_new(NULL);
	struct pst s;
	struct dav_book *out = NULL;
	size_t i, k = 0;
	char *home, *norm;
	enum mapistore_error err;

	*books = NULL;
	*n = 0;
	err = report(h, tmp, "PROPFIND", h->base_path, depth1_hdrs, body, &s, NULL);
	if (err) goto done;
	out = talloc_zero_array(mem_ctx, struct dav_book, s.n ? s.n : 1);
	home = dav_href_norm(tmp, h->base_path);
	if (!out || !home) { err = MAPISTORE_ERR_NO_MEMORY; goto done; }
	for (i = 0; i < s.n; i++) {
		struct resp *r = &s.r[i];
		if (!r->book || r->dir || !r->href) continue;
		norm = dav_href_norm(tmp, r->href);
		if (!is_member(home, norm)) continue;
		out[k].href = talloc_strdup(out, href_path(r->href));
		out[k].segment = talloc_strdup(out, strrchr(norm, '/') + 1);
		out[k].displayname = r->displayname ? talloc_strdup(out, r->displayname) : NULL;
		out[k].sync_token = r->token ? talloc_strdup(out, r->token) : NULL;
		k++;
	}
	*books = out;
	*n = k;
done:
	talloc_free(tmp);
	return err;
}

enum mapistore_error dav_sync(struct dav_http *h, TALLOC_CTX *mem_ctx, const char *book_href, const char *token,
			      struct dav_change **changes, size_t *n, char **new_token, bool *was_full)
{
	TALLOC_CTX *tmp = talloc_new(NULL);
	struct pst s;
	struct dav_change *out;
	char *body, *book;
	size_t i, k = 0;
	enum mapistore_error err;
	bool full = !token, bad_token;

	*changes = NULL;
	*n = 0;
	*new_token = NULL;
	*was_full = false;
	for (;;) {
		char *t = token ? xml_escape(tmp, token) : talloc_strdup(tmp, "");
		body = talloc_asprintf(tmp, "<?xml version=\"1.0\" encoding=\"utf-8\"?><sync-collection xmlns=\"DAV:\">"
				       "<sync-token>%s</sync-token><sync-level>1</sync-level><prop><getetag/></prop></sync-collection>", t);
		if (!body) { err = MAPISTORE_ERR_NO_MEMORY; goto done; }
		bad_token = false;
		err = report(h, tmp, "REPORT", book_href, depth0_hdrs, body, &s, &bad_token);
		if (err && bad_token && token) {
			token = NULL;
			full = true;
			continue;
		}
		break;
	}
	if (err) goto done;
	out = talloc_zero_array(mem_ctx, struct dav_change, s.n ? s.n : 1);
	book = dav_href_norm(tmp, book_href);
	if (!out || !book) { err = MAPISTORE_ERR_NO_MEMORY; goto done; }
	for (i = 0; i < s.n; i++) {
		struct resp *r = &s.r[i];
		/* the collection itself, and anything outside it, is not a card of this book */
		if (!r->href || !is_member(book, dav_href_norm(tmp, r->href))) continue;
		if (full && r->status == 404) continue;
		out[k].href = talloc_strdup(out, href_path(r->href));
		out[k].etag = r->status == 404 ? NULL : talloc_strdup(out, r->etag ? r->etag : "");
		k++;
	}
	*changes = out;
	*n = k;
	*new_token = s.token ? talloc_strdup(mem_ctx, s.token) : NULL;
	*was_full = full;
done:
	talloc_free(tmp);
	return err;
}

enum mapistore_error dav_multiget(struct dav_http *h, TALLOC_CTX *mem_ctx, const char *book_href, char **hrefs, size_t n,
				  char ***bodies, char ***etags)
{
	TALLOC_CTX *tmp = talloc_new(NULL);
	struct pst s;
	char *body, *e, **bo = NULL, **et = NULL, *want, **got = NULL;
	size_t i, j;
	enum mapistore_error err;

	*bodies = NULL;
	*etags = NULL;
	body = talloc_strdup(tmp, "<?xml version=\"1.0\" encoding=\"utf-8\"?><C:addressbook-multiget xmlns=\"DAV:\" "
			     "xmlns:C=\"urn:ietf:params:xml:ns:carddav\"><prop><getetag/><C:address-data/></prop>");
	for (i = 0; body && i < n; i++) {
		e = xml_escape(tmp, href_path(hrefs[i]));
		body = e ? talloc_asprintf_append(body, "<href>%s</href>", e) : NULL;
	}
	body = body ? talloc_strdup_append(body, "</C:addressbook-multiget>") : NULL;
	if (!body) { err = MAPISTORE_ERR_NO_MEMORY; goto done; }
	err = report(h, tmp, "REPORT", book_href, xml_hdrs, body, &s, NULL);
	if (err) goto done;
	bo = talloc_zero_array(mem_ctx, char *, n ? n : 1);
	et = talloc_zero_array(mem_ctx, char *, n ? n : 1);
	got = talloc_zero_array(tmp, char *, s.n ? s.n : 1);
	if (!bo || !et || !got) { err = MAPISTORE_ERR_NO_MEMORY; goto done; }
	for (j = 0; j < s.n; j++) {
		got[j] = s.r[j].href ? dav_href_norm(tmp, s.r[j].href) : NULL;
	}
	for (i = 0; i < n; i++) {
		if (!(want = dav_href_norm(tmp, hrefs[i]))) continue;
		for (j = 0; j < s.n; j++) {
			if (!got[j] || s.r[j].status == 404 || !s.r[j].data) continue;
			if (strcmp(got[j], want)) continue;
			bo[i] = talloc_strdup(bo, s.r[j].data);
			et[i] = s.r[j].etag ? talloc_strdup(et, s.r[j].etag) : NULL;
			break;
		}
	}
	*bodies = bo;
	*etags = et;
done:
	if (err) { talloc_free(bo); talloc_free(et); }
	talloc_free(tmp);
	return err;
}

enum mapistore_error dav_get(struct dav_http *h, TALLOC_CTX *mem_ctx, const char *href, char **body, char **etag)
{
	struct buf b;
	long st;
	enum mapistore_error err = dav_do(h, "GET", href, NULL, NULL, &st, &b);

	*body = NULL;
	if (etag) *etag = NULL;
	if (err) return err;
	err = status_err(st);
	if (!err) {
		*body = talloc_strndup(mem_ctx, b.p ? b.p : "", b.len);
		if (etag && h->etag) *etag = talloc_strdup(mem_ctx, h->etag);
		if (!*body) err = MAPISTORE_ERR_NO_MEMORY;
	}
	free(b.p);
	return err;
}

/* A request with a status check and no interesting body. */
static enum mapistore_error simple(struct dav_http *h, const char *method, const char *href, const char *const *hdrs,
				   const char *body)
{
	struct buf b;
	long st;
	enum mapistore_error err = dav_do(h, method, href, hdrs, body, &st, &b);

	if (err) return err;
	err = status_err(st);
	if (!err && st == 207) {	/* PROPPATCH/MKCOL report per property */
		TALLOC_CTX *tmp = talloc_new(NULL);
		struct pst s;
		if (ms_parse(tmp, &b, &s) == MAPISTORE_SUCCESS && s.bad) err = status_err(s.bad);
		talloc_free(tmp);
	}
	free(b.p);
	return err;
}

enum mapistore_error dav_put(struct dav_http *h, TALLOC_CTX *mem_ctx, const char *href, const char *body, const char *content_type,
			     const char *if_match, bool if_none_match, char **new_etag)
{
	const char *hdrs[5];
	char *ct = NULL, *im = NULL;
	int k = 0;
	enum mapistore_error err;
	TALLOC_CTX *tmp = talloc_new(NULL);

	if (new_etag) *new_etag = NULL;
	if (!header_safe(content_type) || !header_safe(if_match)) { talloc_free(tmp); return MAPISTORE_ERR_INVALID_PARAMETER; }
	ct = talloc_asprintf(tmp, "Content-Type: %s", content_type ? content_type : "text/vcard; charset=utf-8");
	hdrs[k++] = ct;
	if (if_match) { im = talloc_asprintf(tmp, "If-Match: %s", if_match); hdrs[k++] = im; }
	if (if_none_match) hdrs[k++] = "If-None-Match: *";
	hdrs[k] = NULL;
	err = simple(h, "PUT", href, hdrs, body ? body : "");
	if (!err && new_etag && h->etag && !(*new_etag = talloc_strdup(mem_ctx, h->etag))) err = MAPISTORE_ERR_NO_MEMORY;
	talloc_free(tmp);
	return err;
}

enum mapistore_error dav_delete(struct dav_http *h, const char *href, const char *if_match)
{
	const char *hdrs[2] = { NULL, NULL };
	char *im;
	enum mapistore_error err;

	if (!header_safe(if_match)) return MAPISTORE_ERR_INVALID_PARAMETER;
	im = if_match ? talloc_asprintf(h, "If-Match: %s", if_match) : NULL;
	hdrs[0] = im;
	err = simple(h, "DELETE", href, hdrs, NULL);
	talloc_free(im);
	return err;
}

enum mapistore_error dav_mkcol_book(struct dav_http *h, const char *href, const char *displayname)
{
	TALLOC_CTX *tmp = talloc_new(NULL);
	char *name = xml_escape(tmp, displayname), *body;
	enum mapistore_error err = MAPISTORE_ERR_NO_MEMORY;

	body = name ? talloc_asprintf(tmp, "<?xml version=\"1.0\" encoding=\"utf-8\"?><mkcol xmlns=\"DAV:\" "
		"xmlns:C=\"urn:ietf:params:xml:ns:carddav\"><set><prop><resourcetype><collection/><C:addressbook/>"
		"</resourcetype><displayname>%s</displayname></prop></set></mkcol>", name) : NULL;
	if (body) err = simple(h, "MKCOL", href, xml_hdrs, body);
	talloc_free(tmp);
	return err;
}

enum mapistore_error dav_rename_book(struct dav_http *h, const char *href, const char *displayname)
{
	TALLOC_CTX *tmp = talloc_new(NULL);
	char *name = xml_escape(tmp, displayname), *body;
	enum mapistore_error err = MAPISTORE_ERR_NO_MEMORY;

	body = name ? talloc_asprintf(tmp, "<?xml version=\"1.0\" encoding=\"utf-8\"?><propertyupdate xmlns=\"DAV:\">"
		"<set><prop><displayname>%s</displayname></prop></set></propertyupdate>", name) : NULL;
	if (body) err = simple(h, "PROPPATCH", href, xml_hdrs, body);
	talloc_free(tmp);
	return err;
}

enum mapistore_error dav_delete_book(struct dav_http *h, const char *href)
{
	return simple(h, "DELETE", href, NULL, NULL);
}
