/*
   Shared per-item change numbers: no network, no server.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "mapistore changes check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static uint64_t counter;

static enum mapistore_error fake_source(void *source_ctx, uint64_t *cn)
{
    CHECK(source_ctx == &counter);
    *cn = ++counter << 16;
    return MAPISTORE_SUCCESS;
}

int main(void)
{
    const char *u = "alice", *uri = "dav://x/1";
    uint8_t kb[] = { 1, 2, 3 }, pb[] = { 4, 5 };
    struct Binary_r ck = { sizeof(kb), kb }, pcl = { sizeof(pb), pb };
    const struct Binary_r *gck, *gpcl;
    uint64_t a, b, c, other;
    time_t when;

    CHECK(mapistore_change_number(u, uri, "s1", fake_source, &counter, &a, &when) == MAPISTORE_SUCCESS);
    CHECK(mapistore_change_number(u, uri, "s1", fake_source, &counter, &b, &when) == MAPISTORE_SUCCESS);
    CHECK(a == b && counter == 1);
    CHECK(mapistore_change_number(u, uri, "s2", fake_source, &counter, &c, &when) == MAPISTORE_SUCCESS);
    CHECK(c != a);
    /* another user has its own change for the same URI */
    CHECK(mapistore_change_number("bob", uri, "s1", fake_source, &counter, &other, &when) == MAPISTORE_SUCCESS);
    CHECK(other != c && other != a);

    CHECK(mapistore_change_record_client(u, uri, fake_source, &counter, &ck, &pcl) == MAPISTORE_SUCCESS);
    CHECK(mapistore_change_client_keys(u, uri, c, &gck, &gpcl) != MAPISTORE_SUCCESS); /* cn moved on */
    /* the first state seen after the client's own change is that change */
    CHECK(mapistore_change_number(u, uri, "s4", fake_source, &counter, &b, &when) == MAPISTORE_SUCCESS);
    CHECK(mapistore_change_client_keys(u, uri, b, &gck, &gpcl) == MAPISTORE_SUCCESS);
    CHECK(gck->cb == 3 && gpcl->cb == 2 && gck->lpb != kb);
    CHECK(mapistore_change_number(u, uri, "s4", fake_source, &counter, &c, &when) == MAPISTORE_SUCCESS && c == b);
    CHECK(mapistore_change_number(u, uri, "s5", fake_source, &counter, &c, &when) == MAPISTORE_SUCCESS && c != b);
    CHECK(mapistore_change_client_keys(u, uri, c, &gck, &gpcl) != MAPISTORE_SUCCESS);
    puts("mapistore changes smoke: ok");
    return 0;
}
