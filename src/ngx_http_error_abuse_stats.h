/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * error_abuse_stats: per-zone counters and their JSON / Prometheus renderers.
 *
 * Kept in a header of static functions so the direct-call unit harness
 * (ci/tests/unit/test_stats.c) exercises exactly the code the module runs.
 * Renderers write into a caller-sized buffer and never allocate; the module
 * sizes the request-pool buffer with the matching *_size() function.
 *
 * Format negotiation (?format=, Accept) supports JSON, Prometheus 0.0.4 and
 * explicitly requested OpenMetrics 1.0.
 */
#ifndef NGX_HTTP_ERROR_ABUSE_STATS_H_INCLUDED_
#define NGX_HTTP_ERROR_ABUSE_STATS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_HTTP_ERROR_ABUSE_STATS_JSON        0
#define NGX_HTTP_ERROR_ABUSE_STATS_PROMETHEUS  1

#define NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES   8192
#define NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS   32
#define NGX_HTTP_ERROR_ABUSE_NEGOTIATE_PARAMS  16


/* ngx_utf8_decode() is a decoder, not a strict UTF-8 validator. Check
 * continuation bytes and scalar boundaries before exposing a zone name. */
static ngx_int_t
ngx_http_error_abuse_stats_valid_utf8(ngx_str_t *value)
{
    size_t   i, n;
    u_char  *p, c;

    p = value->data;
    n = value->len;
    while (n != 0) {
        c = *p++;
        n--;
        if (c < 0x80) {
            continue;
        }
        if (c < 0xc2 || c > 0xf4) {
            return NGX_ERROR;
        }
        i = c < 0xe0 ? 1 : (c < 0xf0 ? 2 : 3);
        if (n < i) {
            return NGX_ERROR;
        }
        /* Exclude overlong forms, surrogates and values above U+10FFFF. */
        if ((c == 0xe0 && *p < 0xa0) || (c == 0xed && *p > 0x9f)
            || (c == 0xf0 && *p < 0x90) || (c == 0xf4 && *p > 0x8f))
        {
            return NGX_ERROR;
        }
        n -= i;
        while (i-- != 0) {
            if ((*p++ & 0xc0) != 0x80) {
                return NGX_ERROR;
            }
        }
    }
    return NGX_OK;
}


/*
 * Counters stored in the zone's shared memory. Every field is updated with the
 * zone slab mutex held, inside critical sections the request path already
 * takes, so the counters need no atomics (and no NGX_HAVE_ATOMIC_OPS) and stay
 * 64-bit on 32-bit and Windows builds. They are not persisted: a restart
 * resets them, which Prometheus rate()/increase() handle.
 */
typedef struct {
    uint64_t  requests;        /* requests checked against the zone */
    uint64_t  matched;         /* responses whose status the zone tracks */
    uint64_t  blocked;         /* requests rejected by the module */
    uint64_t  would_block;     /* dry-run decisions that would have blocked */
    uint64_t  bans;            /* bans armed (threshold reached) */
    uint64_t  evictions;       /* unblocked nodes evicted for room */
    uint64_t  alloc_failures;  /* tracked responses dropped: zone full */
} ngx_http_error_abuse_stats_t;


typedef struct {
    ngx_http_error_abuse_stats_t  counters;
    uint64_t                      nodes;
    uint64_t                      blocked_clients;
    uint64_t                      used;
    uint64_t                      size;
} ngx_http_error_abuse_stats_snapshot_t;


/* Order is part of the wire format: JSON keys and metric families appear in
 * table order. */
typedef struct {
    const char  *json_key;
    const char  *family;
    const char  *help;
    ngx_uint_t   counter;
    size_t       offset;
} ngx_http_error_abuse_stats_metric_t;

#define NGX_HTTP_ERROR_ABUSE_STAT(key, family, help, counter, field)         \
    { key, family, help, counter,                                           \
      offsetof(ngx_http_error_abuse_stats_snapshot_t, field) }

static const ngx_http_error_abuse_stats_metric_t
ngx_http_error_abuse_stats_metrics[] = {
    NGX_HTTP_ERROR_ABUSE_STAT("requests", "error_abuse_requests",
        "Requests checked against the zone.", 1, counters.requests),
    NGX_HTTP_ERROR_ABUSE_STAT("matched", "error_abuse_matched_responses",
        "Responses with a status tracked by the zone.", 1, counters.matched),
    NGX_HTTP_ERROR_ABUSE_STAT("blocked", "error_abuse_blocked",
        "Requests rejected by the module.", 1, counters.blocked),
    NGX_HTTP_ERROR_ABUSE_STAT("would_block", "error_abuse_dry_run_would_block",
        "Dry-run decisions that would have blocked.", 1,
        counters.would_block),
    NGX_HTTP_ERROR_ABUSE_STAT("bans", "error_abuse_bans",
        "Bans armed after the threshold was reached.", 1, counters.bans),
    NGX_HTTP_ERROR_ABUSE_STAT("evictions", "error_abuse_zone_evictions",
        "Unblocked zone nodes evicted to make room.", 1, counters.evictions),
    NGX_HTTP_ERROR_ABUSE_STAT("alloc_failures",
        "error_abuse_zone_alloc_failures",
        "Tracked responses not recorded because the zone was full.", 1,
        counters.alloc_failures),
    NGX_HTTP_ERROR_ABUSE_STAT("nodes", "error_abuse_zone_nodes",
        "Client identities held in the zone.", 0, nodes),
    NGX_HTTP_ERROR_ABUSE_STAT("blocked_clients", "error_abuse_blocked_clients",
        "Client identities currently blocked.", 0, blocked_clients),
    NGX_HTTP_ERROR_ABUSE_STAT("used", "error_abuse_zone_used_bytes",
        "Zone bytes reserved including slab overhead.", 0, used),
    NGX_HTTP_ERROR_ABUSE_STAT("size", "error_abuse_zone_size_bytes",
        "Zone size in bytes.", 0, size)
};

#undef NGX_HTTP_ERROR_ABUSE_STAT

#define NGX_HTTP_ERROR_ABUSE_STATS_NMETRICS                                  \
    (sizeof(ngx_http_error_abuse_stats_metrics)                             \
     / sizeof(ngx_http_error_abuse_stats_metrics[0]))


static ngx_inline uint64_t
ngx_http_error_abuse_stats_value(
    const ngx_http_error_abuse_stats_snapshot_t *snapshot, ngx_uint_t index)
{
    uint64_t  value;

    ngx_memcpy(&value, (const u_char *) snapshot
                       + ngx_http_error_abuse_stats_metrics[index].offset,
               sizeof(value));
    return value;
}


/* ---- negotiation (ported from shield's ngx_http_shield_negotiate.h) ---- */

/* Raw query names/values are case-sensitive and are not percent-decoded.
 * Unrelated arguments are ignored; an empty, unknown or repeated format=
 * argument, or a query over the byte budget, is an error (400). */
static ngx_int_t
ngx_http_error_abuse_stats_query_format(ngx_str_t *args, ngx_uint_t *format)
{
    size_t      pos, start, end;
    ngx_uint_t  found;

    if (args->len > NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES) {
        return NGX_ERROR;
    }

    found = 0;

    for (pos = 0; pos < args->len; pos = end + 1) {
        start = pos;
        for (end = pos; end < args->len && args->data[end] != '&'; end++) {
            /* find one query argument */
        }
        for ( /* void */ ; pos < end && args->data[pos] != '='; pos++) {
            /* find its raw name */
        }
        if (pos - start != 6
            || ngx_strncmp(args->data + start, "format", 6) != 0)
        {
            continue;
        }
        if (found++ || pos == end) {
            return NGX_ERROR;
        }
        start = pos + 1;
        if (end - start == 4
            && ngx_strncmp(args->data + start, "json", 4) == 0)
        {
            *format = NGX_HTTP_ERROR_ABUSE_STATS_JSON;

        } else if (end - start == 10
                   && ngx_strncmp(args->data + start, "prometheus", 10) == 0)
        {
            *format = NGX_HTTP_ERROR_ABUSE_STATS_PROMETHEUS;

        } else {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_error_abuse_accept_token(u_char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '!' || c == '#'
           || c == '$' || c == '%' || c == '&' || c == '\''
           || c == '*' || c == '+' || c == '-' || c == '.'
           || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}


/* q is an integer in thousandths; no floats, signs or excess precision. */
static ngx_int_t
ngx_http_error_abuse_accept_quality(ngx_str_t *v)
{
    size_t     i;
    ngx_int_t  q, scale;

    if (v->len == 0 || v->len > 5
        || (v->data[0] != '0' && v->data[0] != '1'))
    {
        return NGX_ERROR;
    }

    q = (v->data[0] - '0') * 1000;
    if (v->len == 1) {
        return q;
    }
    if (v->data[1] != '.') {
        return NGX_ERROR;
    }

    scale = 100;
    for (i = 2; i < v->len; i++, scale /= 10) {
        if (v->data[i] < '0' || v->data[i] > '9'
            || (q >= 1000 && v->data[i] != '0'))
        {
            return NGX_ERROR;
        }
        q += (v->data[i] - '0') * scale;
    }

    return q;
}


static void
ngx_http_error_abuse_accept_space(u_char **p, u_char *end)
{
    while (*p < end && (**p == ' ' || **p == '\t')) {
        (*p)++;
    }
}


/* Compare a validated parameter without copying or modifying the header.
 * Quoted pairs denote the escaped byte; token values have no escapes. */
static ngx_flag_t
ngx_http_error_abuse_accept_value(ngx_str_t *value, const char *expected,
    ngx_flag_t quoted)
{
    size_t   i;
    u_char   c;

    i = 0;
    while (i < value->len && *expected != '\0') {
        c = value->data[i++];
        if (quoted && c == '\\') {
            if (i == value->len) {
                return 0;
            }
            c = value->data[i++];
        }
        if (ngx_tolower(c) != (u_char) *expected++) {
            return 0;
        }
    }
    return i == value->len && *expected == '\0';
}


/* Parse one Accept field, sharing an item budget and best scores across
 * repeated fields. Any malformed or over-budget field makes the caller fall
 * back to Prometheus 0.0.4. Empty list elements are skipped but spend the
 * item budget. Wildcards never opt into OpenMetrics. Unknown media parameters
 * do not match our representations; syntactically valid accept extensions
 * after q are ignored. Matching media parameters take precedence over bare
 * media types, even at q=0; equal specificity retains the highest q. */
static ngx_int_t
ngx_http_error_abuse_accept(ngx_str_t *v, ngx_uint_t *items,
    ngx_int_t *openmetrics, ngx_int_t *plain, ngx_uint_t *om_specificity,
    ngx_uint_t *plain_specificity)
{
    u_char      *p, *end, *start;
    ngx_str_t    type, name, value;
    ngx_int_t    q;
    ngx_uint_t   params, seen_q, supported, quoted, om, text, media;
    ngx_uint_t   specificity;

    if (v->len == 0) {
        return NGX_OK;
    }

    p = v->data;
    end = p + v->len;

    for ( ;; ) {
        if (++*items > NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS) {
            return NGX_ERROR;
        }

        ngx_http_error_abuse_accept_space(&p, end);

        /* RFC 9110 5.6.1: tolerate empty list elements. Each one still
         * spends an item from the budget above. */
        if (p == end) {
            return NGX_OK;
        }
        if (*p == ',') {
            p++;
            continue;
        }

        start = p;
        while (p < end && ngx_http_error_abuse_accept_token(*p)) {
            p++;
        }
        if (p == start || p == end || *p++ != '/') {
            return NGX_ERROR;
        }
        value.data = p;
        while (p < end && ngx_http_error_abuse_accept_token(*p)) {
            p++;
        }
        if (p == value.data) {
            return NGX_ERROR;
        }

        type.data = start;
        type.len = p - start;
        om = type.len == sizeof("application/openmetrics-text") - 1
             && ngx_strncasecmp(type.data,
                                (u_char *) "application/openmetrics-text",
                                type.len) == 0;
        text = type.len == sizeof("text/plain") - 1
               && ngx_strncasecmp(type.data, (u_char *) "text/plain",
                                  type.len) == 0;
        q = 1000;
        seen_q = params = media = 0;
        supported = 1;

        ngx_http_error_abuse_accept_space(&p, end);

        while (p < end && *p == ';') {
            if (++params > NGX_HTTP_ERROR_ABUSE_NEGOTIATE_PARAMS) {
                return NGX_ERROR;
            }
            p++;
            ngx_http_error_abuse_accept_space(&p, end);
            /* RFC 9110 5.6.6 permits empty parameters. Each semicolon
             * still spends a parameter slot, including trailing ones. */
            if (p == end || *p == ';' || *p == ',') {
                continue;
            }
            name.data = p;
            while (p < end && ngx_http_error_abuse_accept_token(*p)) {
                p++;
            }
            name.len = p - name.data;
            if (name.len == 0 || p == end || *p++ != '=') {
                return NGX_ERROR;
            }

            quoted = p < end && *p == '"';
            if (quoted) {
                p++;
            }
            value.data = p;

            if (quoted) {
                while (p < end && *p != '"') {
                    if (*p == '\\') {
                        p++;
                        if (p == end) {
                            return NGX_ERROR;
                        }
                    }
                    if ((*p < 0x20 && *p != '\t') || *p == 0x7f) {
                        return NGX_ERROR;
                    }
                    p++;
                }
                if (p == end) {
                    return NGX_ERROR;
                }
                value.len = p++ - value.data;

            } else {
                while (p < end && ngx_http_error_abuse_accept_token(*p)) {
                    p++;
                }
                value.len = p - value.data;
                if (value.len == 0) {
                    return NGX_ERROR;
                }
            }

            if (name.len == 1 && ngx_tolower(name.data[0]) == 'q') {
                if (seen_q++ || quoted
                    || (q = ngx_http_error_abuse_accept_quality(&value)) < 0)
                {
                    return NGX_ERROR;
                }

            } else if (!seen_q) {
                if (name.len == 7
                    && ngx_strncasecmp(name.data, (u_char *) "version", 7)
                       == 0)
                {
                    media |= 1;
                    supported &= (om
                                  && ngx_http_error_abuse_accept_value(
                                         &value, "1.0.0", quoted))
                                 || (text
                                     && ngx_http_error_abuse_accept_value(
                                            &value, "0.0.4", quoted));

                } else if (name.len == 7
                           && ngx_strncasecmp(name.data,
                                              (u_char *) "charset", 7) == 0)
                {
                    media |= 2;
                    supported &= ngx_http_error_abuse_accept_value(&value,
                                                          "utf-8", quoted);

                } else {
                    supported = 0;
                }
            }

            ngx_http_error_abuse_accept_space(&p, end);
        }

        /* Count distinct matching media parameters, never q, extensions,
         * duplicate names or empty parameter slots. */
        specificity = ((media & 1) != 0) + ((media & 2) != 0);
        if (supported && om
            && (specificity > *om_specificity
                || (specificity == *om_specificity && q > *openmetrics)))
        {
            *openmetrics = q;
            *om_specificity = specificity;
        }
        if (supported && text
            && (specificity > *plain_specificity
                || (specificity == *plain_specificity && q > *plain)))
        {
            *plain = q;
            *plain_specificity = specificity;
        }

        if (p == end) {
            return NGX_OK;
        }
        if (*p++ != ',') {
            return NGX_ERROR;
        }
    }
}


/* Apply the request-wide byte budget before parsing one Accept field. The
 * request handler and direct fuzz harness share this helper so repeated-field
 * accounting cannot drift between production and the test seam. */
static ngx_int_t
ngx_http_error_abuse_accept_field(ngx_str_t *v, size_t *bytes,
    ngx_uint_t *items, ngx_int_t *openmetrics, ngx_int_t *plain,
    ngx_uint_t *om_specificity, ngx_uint_t *plain_specificity)
{
    if (v->len > NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES - *bytes) {
        return NGX_ERROR;
    }

    *bytes += v->len;

    return ngx_http_error_abuse_accept(v, items, openmetrics, plain,
                                       om_specificity, plain_specificity);
}


/* ---- renderers -------------------------------------------------------- */

/* Overflow-checked size accumulation. */
static ngx_inline ngx_int_t
ngx_http_error_abuse_stats_size_add(size_t *size, size_t add)
{
    if (add > NGX_MAX_SIZE_T_VALUE - *size) {
        return NGX_ERROR;
    }

    *size += add;
    return NGX_OK;
}


/* Upper bound for the JSON document, including one spare byte that serves as
 * the truncation oracle in the renderer. 0 on arithmetic overflow. */
static size_t
ngx_http_error_abuse_stats_json_size(ngx_str_t *zone)
{
    size_t      size, escape;
    ngx_uint_t  i;

    size = 1 + sizeof("{\"zone\":\"\"}") - 1;

    /* ngx_escape_json() reports the extra bytes only; reserve the raw bytes
     * too. A synthetic impossible length is rejected before it is read. */
    if (zone->len > NGX_MAX_SIZE_T_VALUE / 8) {
        return 0;
    }
    escape = ngx_escape_json(NULL, zone->data, zone->len);
    if (ngx_http_error_abuse_stats_size_add(&size, zone->len) != NGX_OK
        || ngx_http_error_abuse_stats_size_add(&size, escape) != NGX_OK)
    {
        return 0;
    }

    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_STATS_NMETRICS; i++) {
        if (ngx_http_error_abuse_stats_size_add(&size,
                ngx_strlen(ngx_http_error_abuse_stats_metrics[i].json_key)
                + sizeof(",\"\":") - 1 + NGX_INT64_LEN)
            != NGX_OK)
        {
            return 0;
        }
    }

    return size;
}


/* Render JSON into [buf, last). Returns the end of the document, or NULL when
 * the buffer was too small (the formatter reached `last`). */
static u_char *
ngx_http_error_abuse_stats_json(u_char *buf, u_char *last, ngx_str_t *zone,
    const ngx_http_error_abuse_stats_snapshot_t *snapshot)
{
    u_char      *p;
    ngx_uint_t   i;

    p = ngx_slprintf(buf, last, "{\"zone\":\"");
    if ((size_t) (last - p)
        <= zone->len + ngx_escape_json(NULL, zone->data, zone->len))
    {
        return NULL;
    }
    p = (u_char *) ngx_escape_json(p, zone->data, zone->len);
    p = ngx_slprintf(p, last, "\"");

    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_STATS_NMETRICS; i++) {
        p = ngx_slprintf(p, last, ",\"%s\":%uL",
                         ngx_http_error_abuse_stats_metrics[i].json_key,
                         ngx_http_error_abuse_stats_value(snapshot, i));
    }

    p = ngx_slprintf(p, last, "}");

    return (p < last) ? p : NULL;
}


/* Upper bound for the metrics document: escaped zone label scratch, every
 * family's HELP/TYPE/sample lines, "# EOF\n" and one spare byte. 0 on
 * arithmetic overflow. */
static size_t
ngx_http_error_abuse_stats_prometheus_size(ngx_str_t *zone)
{
    size_t                                      size, line;
    ngx_uint_t                                  i;
    const ngx_http_error_abuse_stats_metric_t  *m;

    /* A quote, backslash or line feed expands to two bytes. */
    if (zone->len > NGX_MAX_SIZE_T_VALUE / 4
                    / (NGX_HTTP_ERROR_ABUSE_STATS_NMETRICS + 1))
    {
        return 0;
    }

    size = 1 + sizeof("# EOF\n") - 1 + 2 * zone->len;

    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_STATS_NMETRICS; i++) {
        m = &ngx_http_error_abuse_stats_metrics[i];
        line = sizeof("# HELP _total \n# TYPE _total counter\n"
                      "_total{zone=\"\"} \n") - 1
               + 3 * ngx_strlen(m->family) + ngx_strlen(m->help)
               + 2 * zone->len + NGX_INT64_LEN;
        if (ngx_http_error_abuse_stats_size_add(&size, line) != NGX_OK) {
            return 0;
        }
    }

    return size;
}


/* Render Prometheus 0.0.4 or OpenMetrics 1.0 text into [buf, last). The
 * escaped zone label is written first as scratch; *start receives the
 * beginning of the document proper. Returns the end of the document, or NULL
 * when the buffer was too small. Only aggregate, fixed-label series are
 * emitted: per-client labels would be unbounded cardinality. */
static u_char *
ngx_http_error_abuse_stats_prometheus(u_char *buf, u_char *last,
    ngx_str_t *zone, const ngx_http_error_abuse_stats_snapshot_t *snapshot,
    ngx_flag_t openmetrics, u_char **start)
{
    u_char                                     *p;
    ngx_str_t                                   label;
    ngx_uint_t                                  i;
    const char                                 *suffix;
    const ngx_http_error_abuse_stats_metric_t  *m;

    if ((size_t) (last - buf) <= 2 * zone->len) {
        return NULL;
    }

    p = buf;
    for (i = 0; i < zone->len; i++) {
        switch (zone->data[i]) {
        case '\\':
        case '"':
            *p++ = '\\';
            *p++ = zone->data[i];
            break;
        case '\n':
            *p++ = '\\';
            *p++ = 'n';
            break;
        default:
            *p++ = zone->data[i];
            break;
        }
    }
    label.data = buf;
    label.len = p - buf;
    *start = p;

    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_STATS_NMETRICS; i++) {
        m = &ngx_http_error_abuse_stats_metrics[i];

        /* OpenMetrics declares a counter family without _total; 0.0.4 uses
         * the sample name in HELP/TYPE. Samples always carry _total. */
        suffix = (m->counter && !openmetrics) ? "_total" : "";

        p = ngx_slprintf(p, last,
                         "# HELP %s%s %s\n# TYPE %s%s %s\n"
                         "%s%s{zone=\"%V\"} %uL\n",
                         m->family, suffix, m->help,
                         m->family, suffix, m->counter ? "counter" : "gauge",
                         m->family, m->counter ? "_total" : "", &label,
                         ngx_http_error_abuse_stats_value(snapshot, i));
    }

    if (openmetrics) {
        p = ngx_slprintf(p, last, "# EOF\n");
    }

    return (p < last) ? p : NULL;
}


#endif /* NGX_HTTP_ERROR_ABUSE_STATS_H_INCLUDED_ */
