/*
   CardDAV mapistore backend: vCard 3.0 / SOGo VLIST line model

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#ifndef	__DAV_VCARD_H__
#define	__DAV_VCARD_H__

#include <stdbool.h>
#include <stddef.h>
#include <talloc.h>

struct dav_line {
	char	*group;		/* "item1" of item1.TEL, or NULL */
	char	*name;		/* as received (case kept) */
	char	**params;	/* "TYPE=work", "ENCODING=b", ... as received */
	size_t	nparams;
	char	*value;		/* unfolded, still escaped */
	bool	touched;
	char	*raw;		/* original text incl. its folds (CRLF); rendered verbatim unless touched */
};

struct dav_card {
	char		*kind;	/* "VCARD" or "VLIST" */
	struct dav_line	*lines;	/* without BEGIN/END */
	size_t		nlines;
};

struct dav_card *dav_card_parse(TALLOC_CTX *, const char *text, size_t len);
char *dav_card_render(TALLOC_CTX *, const struct dav_card *);
const char *dav_card_kind(const struct dav_card *);
struct dav_line *dav_card_find(const struct dav_card *, const char *name, const char *type_param, unsigned index);
void dav_card_set(struct dav_card *, const char *name, const char *type_param, unsigned index, const char *value);
char *dav_text_unescape(TALLOC_CTX *, const char *);
char *dav_text_escape(TALLOC_CTX *, const char *);

#endif /* ! __DAV_VCARD_H__ */
