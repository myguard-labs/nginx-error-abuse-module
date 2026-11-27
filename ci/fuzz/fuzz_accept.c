/*
 * libFuzzer harness for the production stats query and Accept parsers.
 *
 * Ordinary inputs use a compact raw framing: the first line is the query
 * string and each following line is one Accept field. The line bytes are
 * borrowed directly from libFuzzer's buffer; repeated fields retain the same
 * scores and item/byte accumulators used by the request path.
 *
 * Curated five-byte "EA05?" inputs run deterministic positive, boundary and
 * error oracles. They keep important grammar and budget edges in every corpus
 * replay while arbitrary mutations still exercise the raw framing.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_error_abuse_stats.h"


static void
fuzz_require(ngx_flag_t condition)
{
    if (!condition) {
        __builtin_trap();
    }
}


static ngx_str_t
fuzz_str(const char *value)
{
    ngx_str_t  result;

    result.data = (u_char *) value;
    result.len = strlen(value);
    return result;
}


static ngx_int_t
fuzz_accept_field(ngx_str_t *field, size_t *bytes, ngx_uint_t *items,
    ngx_int_t *openmetrics, ngx_int_t *plain, ngx_uint_t *om_specificity,
    ngx_uint_t *plain_specificity)
{
    return ngx_http_error_abuse_accept_field(field, bytes, items, openmetrics,
                                              plain, om_specificity,
                                              plain_specificity);
}


static void
fuzz_quoted_escape(void)
{
    ngx_str_t   field;
    size_t      bytes;
    ngx_int_t   openmetrics, plain;
    ngx_uint_t  items, om_specificity, plain_specificity;

    field = fuzz_str("application/openmetrics-text;version=\"1\\.0.0\";"
                     "charset=\"U\\TF-8\";q=0.9");
    bytes = 0;
    items = om_specificity = plain_specificity = 0;
    openmetrics = plain = 0;

    fuzz_require(fuzz_accept_field(&field, &bytes, &items, &openmetrics,
                                   &plain, &om_specificity,
                                   &plain_specificity) == NGX_OK);
    fuzz_require(openmetrics == 900 && plain == 0 && items == 1);
}


static void
fuzz_repeated_fields(void)
{
    static const char *fields[] = {
        "application/openmetrics-text;q=1",
        "application/openmetrics-text;version=1.0.0;q=0",
        "text/plain;q=0.5"
    };
    ngx_str_t   field;
    size_t      bytes, i;
    ngx_int_t   openmetrics, plain;
    ngx_uint_t  items, om_specificity, plain_specificity;

    bytes = 0;
    items = om_specificity = plain_specificity = 0;
    openmetrics = plain = 0;

    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        field = fuzz_str(fields[i]);
        fuzz_require(fuzz_accept_field(&field, &bytes, &items, &openmetrics,
                                       &plain, &om_specificity,
                                       &plain_specificity) == NGX_OK);
    }

    fuzz_require(openmetrics == 0 && plain == 500 && items == 3);
}


static void
fuzz_item_budget(void)
{
    ngx_str_t   field;
    size_t      bytes;
    ngx_int_t   openmetrics, plain;
    ngx_uint_t  i, items, om_specificity, plain_specificity;

    field = fuzz_str("a/b");
    bytes = 0;
    items = om_specificity = plain_specificity = 0;
    openmetrics = plain = 0;

    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS; i++) {
        fuzz_require(fuzz_accept_field(&field, &bytes, &items, &openmetrics,
                                       &plain, &om_specificity,
                                       &plain_specificity) == NGX_OK);
    }
    fuzz_require(items == NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS);
    fuzz_require(fuzz_accept_field(&field, &bytes, &items, &openmetrics,
                                   &plain, &om_specificity,
                                   &plain_specificity) == NGX_ERROR);
    fuzz_require(items == NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS + 1);
}


static void
fuzz_byte_budget(void)
{
    u_char      storage[4097];
    ngx_str_t   field;
    size_t      bytes;
    ngx_int_t   openmetrics, plain;
    ngx_uint_t  items, om_specificity, plain_specificity;

    ngx_memset(storage, 'b', sizeof(storage));
    storage[0] = 'a';
    storage[1] = '/';
    field.data = storage;
    field.len = 4096;
    bytes = 0;
    items = om_specificity = plain_specificity = 0;
    openmetrics = plain = 0;

    fuzz_require(fuzz_accept_field(&field, &bytes, &items, &openmetrics,
                                   &plain, &om_specificity,
                                   &plain_specificity) == NGX_OK);
    fuzz_require(fuzz_accept_field(&field, &bytes, &items, &openmetrics,
                                   &plain, &om_specificity,
                                   &plain_specificity) == NGX_OK);
    fuzz_require(bytes == NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES);

    field.len = 1;
    fuzz_require(fuzz_accept_field(&field, &bytes, &items, &openmetrics,
                                   &plain, &om_specificity,
                                   &plain_specificity) == NGX_ERROR);
    fuzz_require(bytes == NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES);
}


static void
fuzz_query_format(void)
{
    u_char      storage[NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES + 1];
    ngx_str_t   query;
    ngx_uint_t  format;

    query = fuzz_str("format=prometheus");
    format = 99;
    fuzz_require(ngx_http_error_abuse_stats_query_format(&query, &format)
                 == NGX_OK);
    fuzz_require(format == NGX_HTTP_ERROR_ABUSE_STATS_PROMETHEUS);

    query = fuzz_str("format=json&format=prometheus");
    format = 99;
    fuzz_require(ngx_http_error_abuse_stats_query_format(&query, &format)
                 == NGX_ERROR);

    ngx_memset(storage, 'a', sizeof(storage));
    query.data = storage;
    query.len = NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES;
    format = 99;
    fuzz_require(ngx_http_error_abuse_stats_query_format(&query, &format)
                 == NGX_OK);
    fuzz_require(format == 99);
    query.len++;
    fuzz_require(ngx_http_error_abuse_stats_query_format(&query, &format)
                 == NGX_ERROR);
}


static void
fuzz_malformed(void)
{
    ngx_str_t   field, query;
    size_t      bytes;
    ngx_int_t   openmetrics, plain;
    ngx_uint_t  format, items, om_specificity, plain_specificity;

    field = fuzz_str("application/openmetrics-text;version=\"1.0.0\\");
    bytes = 0;
    items = om_specificity = plain_specificity = 0;
    openmetrics = plain = 0;
    fuzz_require(fuzz_accept_field(&field, &bytes, &items, &openmetrics,
                                   &plain, &om_specificity,
                                   &plain_specificity) == NGX_ERROR);

    query = fuzz_str("format=");
    format = 99;
    fuzz_require(ngx_http_error_abuse_stats_query_format(&query, &format)
                 == NGX_ERROR);
}


static ngx_flag_t
fuzz_curated(const uint8_t *data, size_t size)
{
    if (size < 5 || ngx_memcmp(data, "EA05", 4) != 0) {
        return 0;
    }

    switch (data[4]) {
    case 'Q':
        fuzz_quoted_escape();
        break;
    case 'R':
        fuzz_repeated_fields();
        break;
    case 'I':
        fuzz_item_budget();
        break;
    case 'B':
        fuzz_byte_budget();
        break;
    case 'F':
        fuzz_query_format();
        break;
    case 'E':
        fuzz_malformed();
        break;
    default:
        return 0;
    }

    return 1;
}


static void
fuzz_raw(const uint8_t *data, size_t size)
{
    ngx_str_t   value;
    size_t      bytes, end, pos;
    ngx_int_t   openmetrics, plain, rc;
    ngx_uint_t  format, items, om_specificity, plain_specificity;

    for (end = 0; end < size && data[end] != '\n'; end++) {
        /* find the raw query line */
    }
    value.data = (u_char *) data;
    value.len = end;
    format = 99;
    rc = ngx_http_error_abuse_stats_query_format(&value, &format);
    fuzz_require(rc == NGX_OK || rc == NGX_ERROR);
    if (rc == NGX_OK) {
        fuzz_require(format == 99
                     || format == NGX_HTTP_ERROR_ABUSE_STATS_JSON
                     || format == NGX_HTTP_ERROR_ABUSE_STATS_PROMETHEUS);
    }

    bytes = 0;
    items = om_specificity = plain_specificity = 0;
    openmetrics = plain = 0;
    pos = end < size ? end + 1 : size;

    while (pos < size) {
        for (end = pos; end < size && data[end] != '\n'; end++) {
            /* find one raw Accept field */
        }
        value.data = (u_char *) data + pos;
        value.len = end - pos;
        rc = fuzz_accept_field(&value, &bytes, &items, &openmetrics, &plain,
                               &om_specificity, &plain_specificity);
        fuzz_require(rc == NGX_OK || rc == NGX_ERROR);
        if (rc != NGX_OK) {
            break;
        }
        pos = end < size ? end + 1 : size;
    }

    fuzz_require(bytes <= NGX_HTTP_ERROR_ABUSE_NEGOTIATE_BYTES);
    fuzz_require(items <= NGX_HTTP_ERROR_ABUSE_NEGOTIATE_ITEMS + 1);
    fuzz_require(openmetrics >= 0 && openmetrics <= 1000);
    fuzz_require(plain >= 0 && plain <= 1000);
    fuzz_require(om_specificity <= 2 && plain_specificity <= 2);
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!fuzz_curated(data, size)) {
        fuzz_raw(data, size);
    }

    return 0;
}
