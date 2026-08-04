/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The scan core -- see ngx_http_error_abuse_scan.h for what belongs here and
 * why. Nothing in this file may take an ngx_http_request_t or ngx_conf_t,
 * allocate, or log: the fuzz and unit targets link it without those subsystems.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_error_abuse_scan.h"


/* RFC-3 little-endian codecs. Not static: the loader in the module .c and the
 * fuzz harness's load()-stride replay both decode through these, so there is
 * exactly one implementation of the on-disk field encoding. */

u_char *
ngx_http_error_abuse_put_u16(u_char *p, uint16_t v)
{
    p[0] = (u_char) v;
    p[1] = (u_char) (v >> 8);
    return p + 2;
}


u_char *
ngx_http_error_abuse_put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char) v;
    p[1] = (u_char) (v >> 8);
    p[2] = (u_char) (v >> 16);
    p[3] = (u_char) (v >> 24);
    return p + 4;
}


u_char *
ngx_http_error_abuse_put_u64(u_char *p, uint64_t v)
{
    ngx_uint_t  i;

    for (i = 0; i < 8; i++) {
        p[i] = (u_char) (v >> (8 * i));
    }
    return p + 8;
}


uint16_t
ngx_http_error_abuse_get_u16(const u_char *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}


uint32_t
ngx_http_error_abuse_get_u32(const u_char *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
           | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}


uint64_t
ngx_http_error_abuse_get_u64(const u_char *p)
{
    uint64_t    v = 0;
    ngx_uint_t  i;

    for (i = 0; i < 8; i++) {
        v |= (uint64_t) p[i] << (8 * i);
    }
    return v;
}


ngx_http_error_abuse_statuses_rc_t
ngx_http_error_abuse_parse_statuses(u_char *data, size_t len, u_char *bitmap)
{
    u_char      *p, *last, *dash, *end;
    ngx_int_t    first, final;
    ngx_uint_t   status;

    p = data;
    last = data + len;

    while (p < last) {
        end = ngx_strlchr(p, last, ',');
        if (end == NULL) {
            end = last;
        }

        /* COR-8: reject empty tokens such as a trailing comma ("404,") or a
         * double comma, instead of silently skipping them. */
        if (end == p) {
            return NGX_HTTP_ERROR_ABUSE_STATUSES_EMPTY_ELEMENT;
        }

        dash = ngx_strlchr(p, end, '-');
        if (dash == NULL) {
            first = ngx_atoi(p, end - p);
            final = first;
        } else {
            first = ngx_atoi(p, dash - p);
            final = ngx_atoi(dash + 1, end - dash - 1);
        }

        if (first < 100 || final < first
            || final > NGX_HTTP_ERROR_ABUSE_MAX_STATUS)
        {
            return NGX_HTTP_ERROR_ABUSE_STATUSES_RANGE;
        }

        for (status = (ngx_uint_t) first;
             status <= (ngx_uint_t) final;
             status++)
        {
            bitmap[status >> 3] |= 1U << (status & 7);
        }

        /* COR-8: do not form a pointer past one-past-last when the final
         * element ends at the buffer end. */
        if (end == last) {
            break;
        }
        p = end + 1;
        if (p == last) {
            /* trailing comma, e.g. "404," */
            return NGX_HTTP_ERROR_ABUSE_STATUSES_TRAILING_COMMA;
        }
    }

    return NGX_HTTP_ERROR_ABUSE_STATUSES_OK;
}


ngx_int_t
ngx_http_error_abuse_validate_snapshot(u_char *p, u_char *last,
    uint32_t records, ngx_uint_t threshold)
{
    uint32_t   i;
    uint16_t   rec_key_len, rec_event_count;
    size_t     payload;

    for (i = 0; i < records; i++) {
        if ((size_t) (last - p) < NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN) {
            return NGX_ERROR;
        }

        rec_key_len = ngx_http_error_abuse_get_u16(p);
        rec_event_count = ngx_http_error_abuse_get_u16(p + 2);
        p += NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN;

        /* Identities are always a fixed 32-byte SHA-256 digest (SEC-3); a
         * record with any other key length is forged or corrupt — reject the
         * whole snapshot rather than admit an unmatchable dead-weight node. */
        if (rec_key_len != NGX_HTTP_ERROR_ABUSE_DIGEST_LEN
            || rec_event_count > threshold)
        {
            return NGX_ERROR;
        }

        payload = (size_t) rec_key_len + (size_t) rec_event_count * 8;
        if ((size_t) (last - p) < payload) {
            return NGX_ERROR;
        }

        p += payload;
    }

    return (p == last) ? NGX_OK : NGX_ERROR;
}


size_t
ngx_http_error_abuse_redis_key_len(size_t prefix_len, size_t zone_name_len,
    size_t digest_len)
{
    /* prefix + '{' + zone_name + ':' + hex(digest) + '}' */
    return prefix_len + 1 + zone_name_len + 1 + digest_len * 2 + 1;
}


u_char *
ngx_http_error_abuse_redis_key_write(u_char *buf,
    const u_char *prefix, size_t prefix_len,
    const u_char *zone_name, size_t zone_name_len,
    const u_char *digest, size_t digest_len)
{
    static const u_char  hex[] = "0123456789abcdef";
    u_char              *p;
    size_t               i;

    p = ngx_cpymem(buf, prefix, prefix_len);
    *p++ = '{';
    p = ngx_cpymem(p, zone_name, zone_name_len);
    *p++ = ':';
    for (i = 0; i < digest_len; i++) {
        *p++ = hex[digest[i] >> 4];
        *p++ = hex[digest[i] & 0x0f];
    }
    *p++ = '}';

    return p;
}


size_t
ngx_http_error_abuse_serialize_rec_len(size_t key_len, size_t event_count)
{
    return NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN + key_len + event_count * 8;
}
