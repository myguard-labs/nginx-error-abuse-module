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
    ngx_uint_t  items = 0;

    *om = 0;
    *plain = 0;
    return ngx_http_error_abuse_accept(&v, &items, om, plain);
}


static void
case_accept(void)
{
    char        many[512];
    size_t      i;
    ngx_int_t   om, plain;

    check(try_accept("application/openmetrics-text", &om, &plain) == NGX_OK
          && om == 1000 && plain == 0, "bare OpenMetrics media type");
    check(try_accept("Application/OpenMetrics-Text; Version=\"1.0.0\"; "
                 "charset=UTF-8; q=0.9", &om, &plain) == NGX_OK
          && om == 900, "case-insensitive, quoted version, charset, q");
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
    check(try_accept("text/plain,", &om, &plain) == NGX_ERROR,
          "trailing comma rejected");

    many[0] = '\0';
    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS; i++) {
        strcat(many, i ? ",a/b" : "a/b");
    }
    check(try_accept(many, &om, &plain) == NGX_OK, "item budget reached");
    strcat(many, ",a/b");
    check(try_accept(many, &om, &plain) == NGX_ERROR, "item budget exceeded");
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
    case_query_format();
    case_accept();
    case_json();
    case_prometheus();

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
