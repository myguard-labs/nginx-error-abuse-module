/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Compile the production record function with a capturing Redis boundary.
 * Only duration fields use the selected width: int32_t models signed time32
 * arithmetic even on hosts whose libc cannot build a 32-bit executable.
 */
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NGX_INT64_LEN 20
#define NGX_INT_T_LEN 20
#define NGX_OK 0
#define REDIS_OK 0
#define NGX_LOG_WARN 0
#define NGX_LOG_DEBUG_HTTP 0

typedef unsigned char u_char;
typedef int ngx_flag_t;
typedef void (redisCallbackFn)(void *, void *, void *);
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { DURATION_TYPE interval, block, inactive; unsigned threshold; }
    test_zone_t;
typedef struct { test_zone_t *zone; ngx_str_t log_key; }
    ngx_http_error_abuse_req_ctx_t;
typedef struct { void *pool; } ngx_http_request_t;

static struct { void *context; uint64_t nonce; unsigned sequence; }
    ngx_http_error_abuse_redis_worker;
static char ngx_http_error_abuse_script_sha[40];
static int available = 1, keys_result, queue_result, queued, warnings;
static int fallback_bans;
static int64_t expected[3];

#define ngx_log_debug0(...) ((void) 0)
#define ngx_log_debug3(...) ((void) 0)
#define ngx_log_error(...) ((void) warnings++)
#define ngx_http_error_abuse_redis_record_callback NULL
#define ngx_http_error_abuse_redis_record_local_callback NULL

static void
check(int ok, const char *message)
{
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static time_t
ngx_time(void)
{
    return 100;
}

static int
ngx_http_error_abuse_redis_available(time_t now)
{
    check(now == 100, "record readiness timestamp");
    return available;
}

static int
ngx_http_error_abuse_redis_keys(void *pool,
    ngx_http_error_abuse_req_ctx_t *ctx, ngx_str_t *events, ngx_str_t *block)
{
    (void) pool;
    (void) ctx;
    events->data = (u_char *) "events";
    events->len = 6;
    block->data = (u_char *) "block";
    block->len = 5;
    return keys_result;
}

static void
ngx_http_error_abuse_stats_count_ban(test_zone_t *zone)
{
    check(zone != NULL, "fallback ban zone");
    fallback_bans++;
}

/* The only formatting adapter: preserve the production macro's int64_t
 * argument and bounded-buffer return convention, then capture its bytes. */
static u_char *
ngx_snprintf(u_char *buffer, size_t size, const char *format, ...)
{
    va_list args;
    int     length;

    va_start(args, format);
    if (strcmp(format, "%L") == 0) {
        length = snprintf((char *) buffer, size, "%" PRId64,
                          va_arg(args, int64_t));
    } else {
        uint64_t nonce = va_arg(args, uint64_t);
        unsigned sequence = va_arg(args, unsigned);
        check(strcmp(format, "%uL:%ui") == 0, "nonce format");
        length = snprintf((char *) buffer, size, "%" PRIu64 ":%u",
                          nonce, sequence);
    }
    va_end(args);
    check(length >= 0 && (size_t) length < size, "Redis number buffer capacity");
    return buffer + length;
}

static int
redisAsyncCommandArgv(void *context, void *callback, void *data, int count,
    const char **argv, const size_t *lengths)
{
    const int slots[] = {5, 7, 8};
    const char *names[] = {"interval milliseconds", "block milliseconds",
                          "inactive milliseconds"};
    char expected_text[32];

    (void) context;
    (void) callback;
    (void) data;
    check(count == 10, "record command argument count");
    check(lengths[0] == 7 && memcmp(argv[0], "EVALSHA", 7) == 0,
          "record command remains EVALSHA");
    check(lengths[6] == 1 && argv[6][0] == '3', "threshold remains a count");
    for (size_t i = 0; i < 3; i++) {
        int length = snprintf(expected_text, sizeof(expected_text), "%" PRId64,
                              expected[i]);
        check(lengths[slots[i]] == (size_t) length
              && memcmp(argv[slots[i]], expected_text, (size_t) length) == 0,
              names[i]);
    }
    queued++;
    return queue_result;
}

#include "redis_record.inc"

int
main(void)
{
    /* Last safe signed time32 product, first overflowing product and the
     * admitted maximum must all retain their exact Redis millisecond value. */
    const int64_t seconds[] = {1, 300, INT32_MAX / 1000,
                              INT32_MAX / 1000 + 1, MAX_SECONDS};
    test_zone_t zone = {.threshold = 3};
    ngx_http_error_abuse_req_ctx_t ctx = {.zone = &zone};
    ngx_http_request_t request = {0};

    for (size_t i = 0; i < sizeof(seconds) / sizeof(seconds[0]); i++) {
        zone.interval = (DURATION_TYPE) seconds[i];
        zone.block = (DURATION_TYPE) seconds[(i + 1) % 5];
        zone.inactive = (DURATION_TYPE) seconds[(i + 2) % 5];
        expected[0] = seconds[i] * INT64_C(1000);
        expected[1] = seconds[(i + 1) % 5] * INT64_C(1000);
        expected[2] = seconds[(i + 2) % 5] * INT64_C(1000);
        ngx_http_error_abuse_redis_record(&request, &ctx, 0);
        check(queued == (int) i + 1, "each accepted duration queues a record");
    }

    available = 0;
    ngx_http_error_abuse_redis_record(&request, &ctx, 1);
    check(queued == 5, "unavailable Redis does not queue a record");
    check(fallback_bans == 1, "unavailable Redis counts a local ban once");
    available = 1;
    keys_result = -1;
    ngx_http_error_abuse_redis_record(&request, &ctx, 1);
    check(queued == 5, "key failure does not queue a record");
    check(fallback_bans == 2, "key failure counts a local ban once");
    keys_result = 0;
    queue_result = -1;
    ngx_http_error_abuse_redis_record(&request, &ctx, 1);
    check(queued == 6 && warnings == 1, "queue failure emits a warning");
    check(fallback_bans == 3, "queue failure counts a local ban once");
    puts("OK: all three Redis durations, time32 boundary, maximum, error paths");
    return 0;
}
