/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the error_abuse_stats renderers and format negotiation in
 * src/ngx_http_error_abuse_stats.h, linked against nginx's real
 * src/core/ngx_string.c (ngx_slprintf, ngx_escape_json, ngx_strncasecmp).
 *
 * The runtime suite (ci/tools/test_runtime.py test_stats_and_matched) proves
 * the counters end to end; this file pins the byte-exact wire format, the
 * truncation oracle and the negotiation edge cases a live server cannot reach
 * cheaply.
 */

#include "ngx_http_error_abuse_stats.h"

#include <stdio.h>
#include <string.h>


static int  failures;
static int  checks;


static void
check(int ok, const char *what)
{
    checks++;
    if (ok) {
        printf("ok   %s\n", what);
        return;
    }
    printf("FAIL %s\n", what);
    failures++;
}


static ngx_str_t
str(const char *s)
{
    ngx_str_t  v;

    v.data = (u_char *) s;
    v.len = strlen(s);
    return v;
}


static ngx_int_t
query(const char *args, ngx_uint_t *format)
{
    ngx_str_t  a = str(args);

    *format = 99;
    return ngx_http_error_abuse_stats_query_format(&a, format);
}


static void
case_utf8(void)
{
    static const char *valid[] = {
        "", "zone", "\x7f", "\xc2\x80", "\xdf\xbf", "\xe0\xa0\x80",
        "\xed\x9f\xbf", "\xee\x80\x80", "\xef\xbf\xbf",
        "\xf0\x90\x80\x80", "\xf4\x8f\xbf\xbf"
    };
    static const char *invalid[] = {
        "\xe9\xe0\xe8", "\x80", "\xbf", "\xc0\xaf", "\xc1\xbf",
        "\xf5\x80\x80\x80", "\xff", "\xc2", "\xe2", "\xe2\x82",
        "\xf0", "\xf0\x90", "\xf0\x90\x80", "\xc2\x7f", "\xc2\xc0",
        "\xe2\x82\xc0", "\xf0\x90\x80\xff", "\xe0\x9f\xbf",
        "\xed\xa0\x80", "\xed\xbf\xbf", "\xf0\x8f\xbf\xbf",
        "\xf4\x90\x80\x80"
    };
    size_t     i;
    ngx_str_t  v;

    for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        v = str(valid[i]);
        check(ngx_http_error_abuse_stats_valid_utf8(&v) == NGX_OK,
              "valid UTF-8 scalar boundary accepted");
    }
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        v = str(invalid[i]);
        check(ngx_http_error_abuse_stats_valid_utf8(&v) == NGX_ERROR,
              "invalid UTF-8 sequence rejected");
    }
    /* Length, not the accessible suffix or a NUL terminator, bounds reads. */
    v = str("\xf0\x90\x80\x80");
    for (i = 1; i < 4; i++) {
        v.len = i;
        check(ngx_http_error_abuse_stats_valid_utf8(&v) == NGX_ERROR,
              "UTF-8 continuation beyond supplied length is rejected");
    }
}


static void
case_query_format(void)
{
    static u_char  big[NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES + 1];
    ngx_str_t      a;
    ngx_uint_t     f;

    check(query("", &f) == NGX_OK && f == 99, "empty query keeps default");
    check(query("format=json", &f) == NGX_OK
          && f == NGX_HTTP_ERROR_ABUSE_STATS_JSON, "format=json");
    check(query("a=1&format=prometheus&b", &f) == NGX_OK
          && f == NGX_HTTP_ERROR_ABUSE_STATS_PROMETHEUS,
          "format=prometheus among unrelated args");
    check(query("FORMAT=json&formats=x", &f) == NGX_OK && f == 99,
          "names are case-sensitive and exact");
    check(query("format=", &f) == NGX_ERROR, "empty format is an error");
    check(query("format", &f) == NGX_ERROR, "valueless format is an error");
    check(query("format=xml", &f) == NGX_ERROR, "unknown format is an error");
    check(query("format=JSON", &f) == NGX_ERROR,
          "format values are case-sensitive");
    check(query("format=json&format=json", &f) == NGX_ERROR,
          "repeated format is an error");

    memset(big, 'a', sizeof(big));
    a.data = big;
    a.len = NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES;
    check(ngx_http_error_abuse_stats_query_format(&a, &f) == NGX_OK,
          "query at the byte budget is accepted");
    a.len++;
    check(ngx_http_error_abuse_stats_query_format(&a, &f) == NGX_ERROR,
          "query one byte over the budget is rejected");
}


static ngx_int_t
try_accept(const char *value, ngx_int_t *om, ngx_int_t *plain)
{
    ngx_str_t   v = str(value);
    ngx_uint_t  items = 0, om_specificity = 0, plain_specificity = 0;

    *om = 0;
    *plain = 0;
    return ngx_http_error_abuse_accept(&v, &items, om, plain, &om_specificity,
                                       &plain_specificity);
}


static void
case_accept(void)
{
    char        many[512];
    size_t      i;
    ngx_int_t   om, plain;
    ngx_str_t   field;
    ngx_uint_t  items, om_specificity, plain_specificity;

    check(try_accept("application/openmetrics-text", &om, &plain) == NGX_OK
          && om == 1000 && plain == 0, "bare OpenMetrics media type");
    check(try_accept("Application/OpenMetrics-Text; Version=\"1.0.0\"; "
                 "charset=UTF-8; q=0.9", &om, &plain) == NGX_OK
          && om == 900, "case-insensitive, quoted version, charset, q");
    check(try_accept("application/openmetrics-text;version=\"1\\.0.0\"",
                 &om, &plain) == NGX_OK && om == 1000,
          "quoted-pair version selects OpenMetrics");
    check(try_accept("application/openmetrics-text;charset=\"U\\TF-8\"",
                 &om, &plain) == NGX_OK && om == 1000,
          "quoted-pair charset selects OpenMetrics");
    check(try_accept("text/plain;version=\"0.0\\.4\"", &om, &plain)
          == NGX_OK && plain == 1000, "quoted-pair Prometheus version");
    check(try_accept("application/openmetrics-text;version=\"1.0.0\\",
                 &om, &plain) == NGX_ERROR, "truncated quoted-pair rejected");
    check(try_accept("application/openmetrics-text;charset=\"utf-8\\\"",
                 &om, &plain) == NGX_ERROR, "escaped closing quote is not a terminator");
    check(try_accept("application/openmetrics-text;version=\"1\\\x7f.0.0\"",
                 &om, &plain) == NGX_ERROR, "quoted-pair control byte rejected");
    check(try_accept("application/openmetrics-text;version=\"1.0.0x\"",
                 &om, &plain) == NGX_OK && om == 0,
          "quoted value suffix is not accepted");
    check(try_accept("application/openmetrics-text;version=\"1.0\"",
                 &om, &plain) == NGX_OK && om == 0,
          "quoted value prefix is not accepted");
    field = str("\\");
    check(!ngx_http_error_abuse_accept_value(&field, "utf-8", 1),
          "parameter comparison rejects truncated escape directly");
    field = str("application/openmetrics-text;charset=\"utf\\-8\"");
    om = plain = 0;
    om_specificity = plain_specificity = 0;
    items = NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS - 1;
    check(ngx_http_error_abuse_accept(&field, &items, &om, &plain,
                                    &om_specificity, &plain_specificity) == NGX_OK
          && om == 1000 && items == NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS,
          "escaped parameter respects repeated-field shared item boundary");
    check(ngx_http_error_abuse_accept(&field, &items, &om, &plain,
                                    &om_specificity, &plain_specificity) == NGX_ERROR,
          "repeated escaped parameter field exceeding shared budget rejected");
    check(try_accept("text/plain;q=0.5, application/openmetrics-text;q=0.4",
                 &om, &plain) == NGX_OK && om == 400 && plain == 500,
          "both types scored");
    check(try_accept("*/*", &om, &plain) == NGX_OK && om == 0 && plain == 0,
          "wildcard never opts in");
    check(try_accept("application/openmetrics-text;version=2.0.0", &om, &plain)
          == NGX_OK && om == 0, "unsupported version excluded");
    check(try_accept("application/openmetrics-text;foo=bar", &om, &plain)
          == NGX_OK && om == 0, "unknown parameter excluded");
    check(try_accept("application/openmetrics-text;q=0.5;foo=bar", &om, &plain)
          == NGX_OK && om == 500, "extension after q ignored");
    check(try_accept("application/openmetrics-text;q=1.5", &om, &plain)
          == NGX_ERROR, "q above 1 rejected");
    check(try_accept("application/openmetrics-text;q=0.1234", &om, &plain)
          == NGX_ERROR, "q with four decimals rejected");
    check(try_accept("application/openmetrics-text;q=0.5;q=0.6", &om, &plain)
          == NGX_ERROR, "duplicate q rejected");
    check(try_accept("application/openmetrics-text;q=\"1\"", &om, &plain)
          == NGX_ERROR, "quoted q rejected");
    check(try_accept("text", &om, &plain) == NGX_ERROR, "missing subtype");
    check(try_accept("application/openmetrics-text,", &om, &plain) == NGX_OK
          && om == 1000, "trailing empty element skipped");
    check(try_accept(" , ,text/plain;q=0.3 ,, ", &om, &plain) == NGX_OK
          && plain == 300 && om == 0, "leading and inner empty elements");
    check(try_accept(",", &om, &plain) == NGX_OK && om == 0 && plain == 0,
          "list of only empty elements");
    check(try_accept("text/plain;,", &om, &plain) == NGX_OK && plain == 1000,
          "RA02-EA-20 empty parameter before comma is allowed");

    many[0] = '\0';
    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS; i++) {
        strcat(many, i ? ",a/b" : "a/b");
    }
    check(try_accept(many, &om, &plain) == NGX_OK, "item budget reached");
    strcat(many, ",a/b");
    check(try_accept(many, &om, &plain) == NGX_ERROR, "item budget exceeded");

    many[0] = '\0';
    for (i = 0; i <= NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS; i++) {
        strcat(many, ",");
    }
    check(try_accept(many, &om, &plain) == NGX_ERROR,
          "empty elements spend the item budget");
}


static void
case_accept_contract(void)
{
    static const struct {
        const char  *value;
        ngx_int_t    rc, om, plain;
        const char  *name;
    } cases[] = {
        { " \tapplication/openmetrics-text \t; \tversion=1.0.0 \t; q=0.8 \t",
          NGX_OK, 800, 0, "RA02-EA-20 delimiter OWS" },
        { "application/openmetrics-text; ;\t;version=1.0.0;;q=0.8;\t",
          NGX_OK, 800, 0, "RA02-EA-20 empty parameters around media and q" },
        { "application/openmetrics-text;\t, text/plain;q=0.5",
          NGX_OK, 1000, 500, "RA02-EA-20 empty parameter before next item" },
        { "application/openmetrics-text;version =1.0.0",
          NGX_ERROR, 0, 0, "RA02-EA-20 space before equals rejected" },
        { "application/openmetrics-text;version= 1.0.0",
          NGX_ERROR, 0, 0, "RA02-EA-20 space after equals rejected" },
        { "application/openmetrics-text;q\t=1",
          NGX_ERROR, 0, 0, "RA02-EA-20 tab before equals rejected" },
        { "application/openmetrics-text;q=\t1",
          NGX_ERROR, 0, 0, "RA02-EA-20 tab after equals rejected" },
        { "application/openmetrics-text;version",
          NGX_ERROR, 0, 0, "RA02-EA-20 missing equals rejected" },
        { "application/openmetrics-text;=1",
          NGX_ERROR, 0, 0, "RA02-EA-20 empty name rejected" },
        { "application/openmetrics-text;version=",
          NGX_ERROR, 0, 0, "RA02-EA-20 empty token value rejected" },
        { "application/openmetrics-text;version=\"\"",
          NGX_OK, 0, 0, "RA02-EA-20 empty quoted media value does not match" },
        { "application/openmetrics-text;version=\"1.0.0\"x",
          NGX_ERROR, 0, 0, "RA02-EA-20 quoted suffix rejected" },
        { "application/openmetrics-text;\r",
          NGX_ERROR, 0, 0, "RA02-EA-20 CR is not OWS" },
        { "application /openmetrics-text",
          NGX_ERROR, 0, 0, "RA02-EA-20 whitespace within type rejected" },
        { "application/openmetrics-text;version=1.0.0;q=0, "
          "application/openmetrics-text;q=1, text/plain;q=0.5",
          NGX_OK, 0, 500, "EA-04 explicit version q=0 overrides generic q=1" },
        { "application/openmetrics-text;q=1, text/plain;q=0.5, "
          "application/openmetrics-text;version=1.0.0;q=0",
          NGX_OK, 0, 500, "EA-04 specificity independent of item order" },
        { "application/openmetrics-text;version=2.0.0;q=0, "
          "application/openmetrics-text;q=0.7",
          NGX_OK, 700, 0, "EA-04 unsupported version does not override" },
        { "application/openmetrics-text;foo=bar;q=0, "
          "application/openmetrics-text;q=0.7",
          NGX_OK, 700, 0, "EA-04 unknown media parameter does not override" },
        { "application/openmetrics-text;charset=utf-8;q=0.2, "
          "application/openmetrics-text;q=0.9",
          NGX_OK, 200, 0, "EA-04 charset is a media constraint" },
        { "application/openmetrics-text;version=1.0.0;charset=utf-8;q=0.1, "
          "application/openmetrics-text;version=1.0.0;q=0.9",
          NGX_OK, 100, 0, "EA-04 two constraints outrank one" },
        { "application/openmetrics-text;version=1.0.0;q=0.2, "
          "application/openmetrics-text;version=1.0.0;q=0.8",
          NGX_OK, 800, 0, "EA-04 equal specificity retains highest q" },
        { "application/openmetrics-text;version=1.0.0;q=0.8, "
          "application/openmetrics-text;version=1.0.0;q=0.2",
          NGX_OK, 800, 0, "EA-04 equal specificity q is order independent" },
        { "application/openmetrics-text;;q=0, application/openmetrics-text;q=0.6",
          NGX_OK, 600, 0, "EA-04 empty slots add no specificity" },
        { "application/openmetrics-text;version=1.0.0;version=1.0.0;q=0.1, "
          "application/openmetrics-text;charset=utf-8;q=0.8",
          NGX_OK, 800, 0, "EA-04 duplicate names add no specificity" },
        { "application/openmetrics-text;q=0;version=1.0.0, "
          "application/openmetrics-text;q=0.6",
          NGX_OK, 600, 0, "EA-04 legacy extensions add no specificity" },
        { "text/plain;version=0.0.4;q=0, text/plain;q=1, "
          "application/openmetrics-text;q=0.5",
          NGX_OK, 500, 0, "EA-04 plain specificity uses same rule" },
        { "application/openmetrics-text;q=0.5, text/plain;q=0.5",
          NGX_OK, 500, 500, "EA-04 format quality tie" },
        { "application/openmetrics-text;q=0, text/plain;q=0",
          NGX_OK, 0, 0, "EA-04 zero quality never opts in" },
        { "application/openmetrics-text;version=1.0.0;q=0.1234",
          NGX_ERROR, 0, 0, "EA-04 invalid specific quality rejected" },
        { "application/openmetrics-text;version=1.0.0;q=0;q=1",
          NGX_ERROR, 0, 0, "EA-04 duplicate specific quality rejected" }
    };
    char        many[128];
    size_t      i;
    ngx_str_t   field;
    ngx_int_t   om, plain, rc;
    ngx_uint_t  items, om_specificity, plain_specificity, order;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rc = try_accept(cases[i].value, &om, &plain);
        check(rc == cases[i].rc
              && (rc != NGX_OK || (om == cases[i].om && plain == cases[i].plain)),
              cases[i].name);
    }

    strcpy(many, "application/openmetrics-text");
    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_NEGOTIATE_PARAMS; i++) {
        strcat(many, ";");
    }
    check(try_accept(many, &om, &plain) == NGX_OK && om == 1000,
          "RA02-EA-20 empty parameters at budget");
    strcat(many, ";");
    check(try_accept(many, &om, &plain) == NGX_ERROR,
          "RA02-EA-20 empty parameters over budget");

    for (order = 0; order < 2; order++) {
        items = om_specificity = plain_specificity = 0;
        om = plain = 0;
        field = str(order ? "application/openmetrics-text;q=1"
                          : "application/openmetrics-text;version=1.0.0;q=0");
        rc = ngx_http_error_abuse_accept(&field, &items, &om, &plain,
                                        &om_specificity, &plain_specificity);
        field = str(order ? "application/openmetrics-text;version=1.0.0;q=0"
                          : "application/openmetrics-text;q=1");
        rc |= ngx_http_error_abuse_accept(&field, &items, &om, &plain,
                                         &om_specificity, &plain_specificity);
        field = str("text/plain;q=0.5");
        rc |= ngx_http_error_abuse_accept(&field, &items, &om, &plain,
                                         &om_specificity, &plain_specificity);
        check(rc == NGX_OK && om == 0 && plain == 500 && items == 3,
              "EA-04 repeated fields preserve specificity in both orders");
    }
}


static void
fill(ngx_http_error_abuse_stats_snapshot_t *s)
{
    memset(s, 0, sizeof(*s));
    s->counters.requests = 7;
    s->counters.matched = 4;
    s->counters.blocked = 1;
    s->counters.would_block = 2;
    s->counters.bans = 1;
    s->counters.evictions = 3;
    s->counters.alloc_failures = 5;
    s->nodes = 9;
    s->blocked_clients = 1;
    s->used = 8192;
    s->size = 1048576;
}


static void
case_json(void)
{
    static const char  want[] =
        "{\"zone\":\"a\\\"b\",\"requests\":7,\"matched\":4,\"blocked\":1,"
        "\"would_block\":2,\"bans\":1,\"evictions\":3,\"alloc_failures\":5,"
        "\"nodes\":9,\"blocked_clients\":1,\"used\":8192,\"size\":1048576}";

    u_char                                 buf[1024], *last;
    size_t                                 size, len;
    ngx_str_t                              zone = str("a\"b");
    ngx_http_error_abuse_stats_snapshot_t  s;

    fill(&s);
    size = ngx_http_error_abuse_stats_json_size(&zone);
    check(size > sizeof(want) && size < sizeof(buf), "JSON size bound");

    last = ngx_http_error_abuse_stats_json(buf, buf + size, &zone, &s);
    len = last ? (size_t) (last - buf) : 0;
    check(last != NULL && len == sizeof(want) - 1
          && memcmp(buf, want, len) == 0, "JSON exact bytes, escaped zone");

    check(ngx_http_error_abuse_stats_json(buf, buf + sizeof(want) - 1, &zone,
                                          &s) == NULL,
          "JSON without the spare byte is reported truncated");
    check(ngx_http_error_abuse_stats_json(buf, buf + sizeof(want), &zone, &s)
          != NULL, "JSON with exactly one spare byte fits");
    check(ngx_http_error_abuse_stats_json(buf, buf + 9, &zone, &s) == NULL,
          "JSON zone name that cannot fit is reported truncated");
}


static void
case_prometheus(void)
{
    static const char  head[] =
        "# HELP error_abuse_requests_total Requests checked against the "
        "zone.\n"
        "# TYPE error_abuse_requests_total counter\n"
        "error_abuse_requests_total{zone=\"a\\\"b\\\\c\\nd\"} 7\n";
    static const char  head_om[] =
        "# HELP error_abuse_requests Requests checked against the zone.\n"
        "# TYPE error_abuse_requests counter\n"
        "error_abuse_requests_total{zone=\"a\\\"b\\\\c\\nd\"} 7\n";
    static const char  gauge[] =
        "# TYPE error_abuse_zone_nodes gauge\n"
        "error_abuse_zone_nodes{zone=\"a\\\"b\\\\c\\nd\"} 9\n";

    u_char                                 buf[8192], *start, *last;
    size_t                                 size, len;
    ngx_uint_t                             lines;
    ngx_str_t                              zone = str("a\"b\\c\nd");
    ngx_http_error_abuse_stats_snapshot_t  s;

    fill(&s);
    size = ngx_http_error_abuse_stats_prometheus_size(&zone);
    check(size > 0 && size < sizeof(buf), "metrics size bound");

    last = ngx_http_error_abuse_stats_prometheus(buf, buf + size, &zone, &s,
                                                 0, &start);
    check(last != NULL, "0.0.4 renders within its size bound");
    if (last == NULL) {
        return;
    }
    *last = '\0';
    len = last - start;
    check(len > sizeof(head) && memcmp(start, head, sizeof(head) - 1) == 0,
          "0.0.4 first family exact, label escaped");
    check(strstr((char *) start, gauge) != NULL, "gauge family has no _total");
    check(strstr((char *) start, "# EOF") == NULL, "0.0.4 has no EOF marker");
    lines = 0;
    for (u_char *p = start; p < last; p++) {
        lines += (*p == '\n');
    }
    check(lines == 3 * NGX_HTTP_ERROR_ABUSE_STATS_NMETRICS,
          "three lines per family");
    check(ngx_http_error_abuse_stats_prometheus(buf, buf + (last - buf),
                                                &zone, &s, 0, &start)
          == NULL, "0.0.4 without the spare byte is reported truncated");

    last = ngx_http_error_abuse_stats_prometheus(buf, buf + size, &zone, &s,
                                                 1, &start);
    check(last != NULL, "OpenMetrics renders within its size bound");
    if (last == NULL) {
        return;
    }
    *last = '\0';
    check(memcmp(start, head_om, sizeof(head_om) - 1) == 0,
          "OpenMetrics declares counter family without _total");
    check(last - start > 6 && memcmp(last - 6, "# EOF\n", 6) == 0,
          "OpenMetrics ends with EOF marker");

    check(ngx_http_error_abuse_stats_prometheus(buf, buf + 4, &zone, &s, 0,
                                                &start) == NULL,
          "label scratch that cannot fit is reported truncated");
}


int
main(void)
{
    case_utf8();
    case_query_format();
    case_accept();
    case_accept_contract();
    case_json();
    case_prometheus();

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
