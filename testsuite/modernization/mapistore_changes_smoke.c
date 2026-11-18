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
    /* without a URI, only the given user's own changes match: change numbers are per-user counters */
    CHECK(mapistore_change_record_client("bob", "dav://y/1", fake_source, &counter, &ck, &pcl) == MAPISTORE_SUCCESS);
    CHECK(mapistore_change_number("bob", "dav://y/1", "t1", fake_source, &counter, &other, &when) == MAPISTORE_SUCCESS);
    CHECK(mapistore_change_client_keys("bob", NULL, other, &gck, &gpcl) == MAPISTORE_SUCCESS);
    CHECK(mapistore_change_client_keys("alice", NULL, other, &gck, &gpcl) != MAPISTORE_SUCCESS);
    CHECK(mapistore_change_client_keys("bo", NULL, other, &gck, &gpcl) != MAPISTORE_SUCCESS);
    {
        /* XID of a change: replica GUID (NDR) + the 6 low bytes of cn >> 16; Outlook's own keys when it uploaded */
        struct GUID g = { .time_low = 0x11223344, .time_mid = 0x5566, .time_hi_and_version = 0x7788 };
        struct Binary_r *k = mapistore_change_value(NULL, "carol", NULL, &g, (0x0000050403020100ULL << 8) | 1, 0, PidTagChangeKey);
        struct Binary_r *p = mapistore_change_value(NULL, "carol", NULL, &g, (0x0000050403020100ULL << 8) | 1, 0, PidTagPredecessorChangeList);
        struct FILETIME *t = mapistore_change_value(NULL, "carol", NULL, &g, 1, 1, PidTagLastModificationTime);
        CHECK(k && k->cb == 22 && !memcmp(k->lpb, "\x44\x33\x22\x11\x66\x55\x88\x77", 8));
        CHECK(!memcmp(k->lpb + 16, "\x01\x02\x03\x04\x05\x00", 6));
        CHECK(p && p->cb == 23 && p->lpb[0] == 22 && !memcmp(p->lpb + 1, k->lpb, 22));
        CHECK(t && t->dwHighDateTime == 0x019DB1DE && t->dwLowDateTime == 0xD5D71680);
        k = mapistore_change_value(NULL, "bob", NULL, &g, other, 0, PidTagChangeKey);
        CHECK(k && k->cb == 3); /* bob uploaded it */
        CHECK(mapistore_change_value(NULL, "bob", NULL, &g, other, 0, PidTagSubject) == NULL);
    }
    puts("mapistore changes smoke: ok");
    return 0;
}
