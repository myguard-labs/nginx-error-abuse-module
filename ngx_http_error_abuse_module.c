/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <hiredis/async.h>
#include <hiredis/hiredis_ssl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <poll.h>
#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif

/* SEC-3: the identity stored in shared memory, Redis and snapshots is a fixed
 * 32-byte SHA-256 digest of the configured key, regardless of how large the raw
 * key variable is. This bounds per-identity memory and Redis traffic so an
 * attacker cannot amplify them with a large $request_uri/$http_* key. The raw
 * key is kept (capped) only for human-readable logging. */
#define NGX_HTTP_ERROR_ABUSE_DIGEST_LEN   SHA256_DIGEST_LENGTH  /* 32 */
#define NGX_HTTP_ERROR_ABUSE_RAW_LOG_MAX  256

#define NGX_HTTP_ERROR_ABUSE_VERSION       2  /* RFC-3: portable LE format */
#define NGX_HTTP_ERROR_ABUSE_FILE_HDR_LEN  24 /* magic8+ver4+thr4+rec4+crc4 */
#define NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN  20 /* klen2+ecnt2+blk8+seen8 */
#define NGX_HTTP_ERROR_ABUSE_MAX_STATUS    599
#define NGX_HTTP_ERROR_ABUSE_STATUS_BYTES  75
#define NGX_HTTP_ERROR_ABUSE_MAX_THRESHOLD 1024
/* STAB-1: cap configured durations (seconds) so now+block, now-interval and
 * value*1000 cannot overflow signed time_t/int64_t, including on 32-bit. */
#define NGX_HTTP_ERROR_ABUSE_MAX_SECONDS   315360000  /* 10 years */
#define NGX_HTTP_ERROR_ABUSE_DEFAULT_KEY       "$binary_remote_addr"
#define NGX_HTTP_ERROR_ABUSE_DEFAULT_STATUSES  "403,404,500-599"
#define NGX_HTTP_ERROR_ABUSE_DEFAULT_INTERVAL  300
#define NGX_HTTP_ERROR_ABUSE_DEFAULT_THRESHOLD 100
#define NGX_HTTP_ERROR_ABUSE_DEFAULT_BLOCK     3600
#define NGX_HTTP_ERROR_ABUSE_FILE_MAGIC    "NGEAB01"
#define NGX_HTTP_ERROR_ABUSE_FILE_MAGIC_LEN 8
#define NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT 1000
#define NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT_MAX 30000
#define NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_THRESHOLD 5
#define NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_DURATION 30

typedef struct {
    ngx_str_t   host;       /* numeric address (resolved at config time) */
    ngx_str_t   sni;        /* original host text, for TLS SNI + cert verify */
    ngx_str_t   prefix;
    ngx_str_t   user;
    ngx_str_t   password;
    in_port_t   port;
    ngx_int_t   db;
    ngx_msec_t  timeout;
    ngx_flag_t  tls;
    ngx_flag_t  configured;
} ngx_http_error_abuse_redis_conf_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
} ngx_http_error_abuse_shctx_t;

typedef struct {
    ngx_rbtree_node_t  node;
    ngx_queue_t        queue;
    time_t             blocked_until;
    time_t             last_seen;
    ngx_uint_t         event_head;
    ngx_uint_t         event_count;
    u_short            key_len;
    u_char             data[1];
} ngx_http_error_abuse_node_t;

typedef struct ngx_http_error_abuse_zone_s
    ngx_http_error_abuse_zone_t;

struct ngx_http_error_abuse_zone_s {
    ngx_str_t                         name;
    ngx_shm_zone_t                   *shm_zone;
    ngx_http_error_abuse_shctx_t     *sh;
    ngx_slab_pool_t                  *shpool;
    ngx_http_complex_value_t          key;
    u_char                            statuses[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES];
    time_t                            interval;
    time_t                            block;
    time_t                            inactive;
    ngx_uint_t                        threshold;
    ngx_str_t                         persist;
    ngx_str_t                         persist_secret;  /* SEC-5: HMAC key */
    ngx_msec_t                        persist_interval;
    ngx_event_t                       persist_event;
    u_char                           *persist_buf;     /* reused serialize buf */
    size_t                            persist_buf_cap;
    ngx_flag_t                        redis;
#if (NGX_THREADS)
    ngx_thread_task_t                *persist_task;   /* PERF-1 */
    unsigned                          persist_busy:1;
#endif
};

#define NGX_HTTP_ERROR_ABUSE_MAC_LEN  32  /* SEC-5: HMAC-SHA256 */

#if (NGX_THREADS)
/* PERF-1: snapshot is serialized in the event loop (brief mutex hold), then the
 * open/write/fsync/rename runs on a thread-pool task so disk latency never
 * stalls worker 0's event loop. */
typedef struct {
    ngx_http_error_abuse_zone_t  *zone;
    u_char                       *buffer;
    size_t                        len;
    ngx_int_t                     rc;
} ngx_http_error_abuse_save_ctx_t;

static void ngx_http_error_abuse_persist_thread(void *data, ngx_log_t *log);
static void ngx_http_error_abuse_persist_complete(ngx_event_t *ev);
#endif

typedef struct {
    ngx_array_t                         zones;
    ngx_http_error_abuse_redis_conf_t   redis;
} ngx_http_error_abuse_main_conf_t;

typedef struct {
    ngx_http_error_abuse_zone_t  *zone;
    ngx_uint_t                    reject_status;
    ngx_uint_t                    log_level;
    ngx_flag_t                    dry_run;
    ngx_flag_t                    enabled;
} ngx_http_error_abuse_loc_conf_t;

typedef enum {
    NGX_HTTP_ERROR_ABUSE_BYPASSED = 0,
    NGX_HTTP_ERROR_ABUSE_PASSED,
    NGX_HTTP_ERROR_ABUSE_COUNTED,
    NGX_HTTP_ERROR_ABUSE_BLOCKED,
    NGX_HTTP_ERROR_ABUSE_DRY_RUN
} ngx_http_error_abuse_state_e;

typedef struct {
    ngx_http_error_abuse_zone_t  *zone;
    ngx_str_t                     key;            /* 32-byte SHA-256 identity */
    ngx_str_t                     raw_key;        /* capped, for logging only */
    ngx_str_t                     redis_events;   /* PERF-3: built once */
    ngx_str_t                     redis_block;
    ngx_uint_t                    count;
    time_t                        blocked_until;
    ngx_http_error_abuse_state_e  state;
    unsigned                      response_seen:1;
    unsigned                      own_rejection:1;
    unsigned                      dry_run:1;
    unsigned                      redis_pending:1;
    unsigned                      redis_checked:1;
    unsigned                      redis_blocked:1;
} ngx_http_error_abuse_req_ctx_t;

/* Binds the hiredis async context's socket into nginx's own epoll, so I/O is
 * fully event-driven instead of polled on a recurring timer. */
typedef struct {
    redisAsyncContext  *context;
    ngx_connection_t   *conn;
    ngx_event_t         timeout;
} ngx_http_error_abuse_redis_event_t;

typedef struct {
    redisAsyncContext                   *context;
    redisSSLContext                     *ssl;
    ngx_http_error_abuse_redis_conf_t   *conf;
    ngx_http_error_abuse_redis_event_t   adapter;
    ngx_event_t                          reconnect;
    ngx_log_t                           *log;
    ngx_uint_t                           sequence;
    uint64_t                             nonce;
    ngx_uint_t                           consecutive_failures;
    time_t                               circuit_breaker_until;
    ngx_msec_t                           reconnect_backoff;
    unsigned                             ready:1;
    unsigned                             exiting:1;
} ngx_http_error_abuse_redis_worker_t;

/* On-disk snapshot is a portable little-endian byte stream (see RFC-3 codecs);
 * header = magic(8) + version(u32) + threshold(u32) + records(u32) + crc32(u32)
 * = NGX_HTTP_ERROR_ABUSE_FILE_HDR_LEN; each record = key_len(u16) +
 * event_count(u16) + blocked_until(i64) + last_seen(i64) =
 * NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN, followed by the key bytes and the event
 * timestamps (i64 each). */

static ngx_int_t ngx_http_error_abuse_preaccess(ngx_http_request_t *r);
static ngx_int_t ngx_http_error_abuse_header_filter(ngx_http_request_t *r);
static ngx_http_error_abuse_req_ctx_t *ngx_http_error_abuse_prepare_ctx(
    ngx_http_request_t *r, ngx_http_error_abuse_loc_conf_t *conf);
static ngx_int_t ngx_http_error_abuse_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_error_abuse_init_process(ngx_cycle_t *cycle);
static void ngx_http_error_abuse_exit_process(ngx_cycle_t *cycle);
static void *ngx_http_error_abuse_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_error_abuse_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_error_abuse_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_error_abuse_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_error_abuse_redis(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_error_abuse_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_error_abuse_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static void ngx_http_error_abuse_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_http_error_abuse_persist_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_error_abuse_save(
    ngx_http_error_abuse_zone_t *zone, ngx_log_t *log);
static u_char *ngx_http_error_abuse_serialize(
    ngx_http_error_abuse_zone_t *zone, ngx_log_t *log, size_t *outlen);
static ngx_int_t ngx_http_error_abuse_write_file(u_char *buffer, size_t len,
    ngx_str_t *persist, ngx_log_t *log);
static ngx_int_t ngx_http_error_abuse_load(
    ngx_http_error_abuse_zone_t *zone, ngx_log_t *log);
static ngx_int_t ngx_http_error_abuse_validate_snapshot(
    ngx_http_error_abuse_zone_t *zone, u_char *p, u_char *last,
    uint32_t records);
static ngx_int_t ngx_http_error_abuse_variable_status(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_error_abuse_variable_count(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_error_abuse_variable_blocked_until(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_error_abuse_redis_check(
    ngx_http_request_t *r, ngx_http_error_abuse_req_ctx_t *ctx);
static void ngx_http_error_abuse_redis_record(
    ngx_http_request_t *r, ngx_http_error_abuse_req_ctx_t *ctx);
static ngx_int_t ngx_http_error_abuse_redis_connect(void);
static void ngx_http_error_abuse_redis_arm_reconnect(void);
static ngx_int_t ngx_http_error_abuse_redis_attach(redisAsyncContext *ac,
    ngx_log_t *log);
static void ngx_http_error_abuse_redis_read_handler(ngx_event_t *rev);
static void ngx_http_error_abuse_redis_write_handler(ngx_event_t *wev);
static void ngx_http_error_abuse_redis_reconnect(ngx_event_t *ev);
static void ngx_http_error_abuse_redis_connect_callback(
    const redisAsyncContext *ac, int status);
static void ngx_http_error_abuse_redis_disconnect_callback(
    const redisAsyncContext *ac, int status);
static void ngx_http_error_abuse_redis_check_callback(
    redisAsyncContext *ac, void *reply, void *privdata);
static void ngx_http_error_abuse_redis_handshake_callback(
    redisAsyncContext *ac, void *reply, void *privdata);

static ngx_http_output_header_filter_pt ngx_http_error_abuse_next_header_filter;
static ngx_http_error_abuse_redis_worker_t ngx_http_error_abuse_redis_worker;

static const char ngx_http_error_abuse_redis_record_script[] =
    "local t=redis.call('TIME') "
    "local now=t[1]*1000+math.floor(t[2]/1000) "
    "redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now-ARGV[1]) "
    "redis.call('ZADD',KEYS[1],now,now..':'..ARGV[5]) "
    "local n=redis.call('ZCARD',KEYS[1]) "
    "redis.call('PEXPIRE',KEYS[1],ARGV[4]) "
    "if n>=tonumber(ARGV[2]) then "
    "local deadline=math.floor((now+ARGV[3])/1000) "
    "redis.call('SET',KEYS[2],deadline,'PX',ARGV[3]) "
    "redis.call('DEL',KEYS[1]) return {1,n,deadline} end "
    "return {0,n}";

/* SHA1 hex of the record script. The script never changes, so this is computed
 * once at init_process; record() then uses EVALSHA instead of shipping the full
 * ~470-byte script on every tracked error response. The script is primed into
 * the Redis script cache via SCRIPT LOAD on each (re)connect, and a NOSCRIPT
 * reply (cache flushed) re-primes it. */
static u_char ngx_http_error_abuse_script_sha[40];

static ngx_conf_enum_t ngx_http_error_abuse_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_error_abuse_commands[] = {
    {
        ngx_string("error_abuse_zone"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
        ngx_http_error_abuse_zone,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("error_abuse"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_error_abuse_enable,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("error_abuse_redis"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
        ngx_http_error_abuse_redis,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_error_abuse_module_ctx = {
    NULL,
    ngx_http_error_abuse_init,
    ngx_http_error_abuse_create_main_conf,
    NULL,
    NULL,
    NULL,
    ngx_http_error_abuse_create_loc_conf,
    ngx_http_error_abuse_merge_loc_conf
};

ngx_module_t ngx_http_error_abuse_module = {
    NGX_MODULE_V1,
    &ngx_http_error_abuse_module_ctx,
    ngx_http_error_abuse_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_error_abuse_init_process,
    NULL,
    NULL,
    ngx_http_error_abuse_exit_process,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t ngx_http_error_abuse_variables[] = {
    {
        ngx_string("error_abuse_status"),
        NULL,
        ngx_http_error_abuse_variable_status,
        0,
        NGX_HTTP_VAR_NOCACHEABLE,
        0
    },
    {
        ngx_string("error_abuse_count"),
        NULL,
        ngx_http_error_abuse_variable_count,
        0,
        NGX_HTTP_VAR_NOCACHEABLE,
        0
    },
    {
        ngx_string("error_abuse_blocked_until"),
        NULL,
        ngx_http_error_abuse_variable_blocked_until,
        0,
        NGX_HTTP_VAR_NOCACHEABLE,
        0
    },
    ngx_http_null_variable
};

/* RFC-3: explicit little-endian field codecs so a snapshot is portable across
 * endianness and compiler ABI, not a raw native struct dump. */
static ngx_inline u_char *
ngx_http_error_abuse_put_u16(u_char *p, uint16_t v)
{
    p[0] = (u_char) v;
    p[1] = (u_char) (v >> 8);
    return p + 2;
}

static ngx_inline u_char *
ngx_http_error_abuse_put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char) v;
    p[1] = (u_char) (v >> 8);
    p[2] = (u_char) (v >> 16);
    p[3] = (u_char) (v >> 24);
    return p + 4;
}

static ngx_inline u_char *
ngx_http_error_abuse_put_u64(u_char *p, uint64_t v)
{
    ngx_uint_t  i;

    for (i = 0; i < 8; i++) {
        p[i] = (u_char) (v >> (8 * i));
    }
    return p + 8;
}

static ngx_inline uint16_t
ngx_http_error_abuse_get_u16(const u_char *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}

static ngx_inline uint32_t
ngx_http_error_abuse_get_u32(const u_char *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
           | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static ngx_inline uint64_t
ngx_http_error_abuse_get_u64(const u_char *p)
{
    uint64_t    v = 0;
    ngx_uint_t  i;

    for (i = 0; i < 8; i++) {
        v |= (uint64_t) p[i] << (8 * i);
    }
    return v;
}

static ngx_inline time_t *
ngx_http_error_abuse_events(ngx_http_error_abuse_node_t *ean)
{
    return (time_t *) ngx_align_ptr(ean->data + ean->key_len,
                                    sizeof(time_t));
}

static ngx_inline size_t
ngx_http_error_abuse_node_size(size_t key_len, ngx_uint_t threshold)
{
    return offsetof(ngx_http_error_abuse_node_t, data)
           + key_len + sizeof(time_t) - 1
           + threshold * sizeof(time_t);
}

static ngx_inline ngx_flag_t
ngx_http_error_abuse_status_matches(ngx_http_error_abuse_zone_t *zone,
    ngx_uint_t status)
{
    if (status > NGX_HTTP_ERROR_ABUSE_MAX_STATUS) {
        return 0;
    }

    return (zone->statuses[status >> 3] & (1U << (status & 7))) != 0;
}

static ngx_http_error_abuse_node_t *
ngx_http_error_abuse_lookup(ngx_http_error_abuse_zone_t *zone, uint32_t hash,
    ngx_str_t *key)
{
    ngx_int_t                      rc;
    ngx_rbtree_node_t             *node, *sentinel;
    ngx_http_error_abuse_node_t   *ean;

    node = zone->sh->rbtree.root;
    sentinel = zone->sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        ean = (ngx_http_error_abuse_node_t *) node;

        rc = ngx_memn2cmp(key->data, ean->data, key->len, ean->key_len);
        if (rc == 0) {
            return ean;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static void
ngx_http_error_abuse_touch(ngx_http_error_abuse_zone_t *zone,
    ngx_http_error_abuse_node_t *ean)
{
    ngx_queue_remove(&ean->queue);
    ngx_queue_insert_head(&zone->sh->queue, &ean->queue);
}

static void
ngx_http_error_abuse_delete(ngx_http_error_abuse_zone_t *zone,
    ngx_http_error_abuse_node_t *ean)
{
    ngx_queue_remove(&ean->queue);
    ngx_rbtree_delete(&zone->sh->rbtree, &ean->node);
    ngx_slab_free_locked(zone->shpool, ean);
}

static void
ngx_http_error_abuse_expire(ngx_http_error_abuse_zone_t *zone, time_t now,
    ngx_uint_t limit)
{
    ngx_queue_t                    *q;
    ngx_http_error_abuse_node_t    *ean;

    while (limit-- && !ngx_queue_empty(&zone->sh->queue)) {
        q = ngx_queue_last(&zone->sh->queue);
        ean = ngx_queue_data(q, ngx_http_error_abuse_node_t, queue);

        if (ean->blocked_until > now
            || ean->last_seen + zone->inactive > now)
        {
            return;
        }

        ngx_http_error_abuse_delete(zone, ean);
    }
}

/* SEC-1: evict the oldest non-blocked node (LRU tail) to make room for a new
 * identity, preserving active bans. Returns 1 if a node was freed. */
static ngx_flag_t
ngx_http_error_abuse_evict_one_unblocked(ngx_http_error_abuse_zone_t *zone,
    time_t now)
{
    ngx_queue_t                  *q;
    ngx_http_error_abuse_node_t  *ean;

    for (q = ngx_queue_last(&zone->sh->queue);
         q != ngx_queue_sentinel(&zone->sh->queue);
         q = ngx_queue_prev(q))
    {
        ean = ngx_queue_data(q, ngx_http_error_abuse_node_t, queue);
        if (ean->blocked_until <= now) {
            ngx_http_error_abuse_delete(zone, ean);
            return 1;
        }
    }

    return 0;
}

static ngx_http_error_abuse_node_t *
ngx_http_error_abuse_create_node(ngx_http_error_abuse_zone_t *zone,
    uint32_t hash, ngx_str_t *key, time_t now)
{
    size_t                          size;
    size_t                          key_len;
    ngx_http_error_abuse_node_t    *ean;

    /* SEC: the key is always a fixed-size SHA-256 digest, produced internally
     * (request handler) or validated against NGX_HTTP_ERROR_ABUSE_DIGEST_LEN on
     * the persistence-load path. Reject anything larger so the allocation size
     * can never be driven by a forged/corrupt key length (CWE-789), and so the
     * (u_short) key_len cast below cannot truncate. The result is copied into a
     * local whose value is provably in [0, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN] and
     * which is the only length used for sizing, allocation and the key copy —
     * giving the allocation size a fixed, non-tainted upper bound. */
    if (key->len > NGX_HTTP_ERROR_ABUSE_DIGEST_LEN) {
        return NULL;
    }
    key_len = key->len;

    size = ngx_http_error_abuse_node_size(key_len, zone->threshold);
    ean = ngx_slab_alloc_locked(zone->shpool, size);

    if (ean == NULL) {
        /* PERF-2: bound housekeeping eviction so a single request cannot scan
         * and delete the entire inactive tail while holding the zone mutex. */
        ngx_http_error_abuse_expire(zone, now, 64);
        ean = ngx_slab_alloc_locked(zone->shpool, size);
    }

    /* SEC-1: under sustained pressure expire frees nothing (every node is
     * recent), which previously left new identities untracked — fail-open.
     * Force-evict the oldest unblocked node instead so tracking continues. */
    while (ean == NULL
           && ngx_http_error_abuse_evict_one_unblocked(zone, now))
    {
        ean = ngx_slab_alloc_locked(zone->shpool, size);
    }

    if (ean == NULL) {
        return NULL;
    }

    ngx_memzero(ean, size);
    ean->node.key = hash;
    ean->key_len = (u_short) key_len;
    ean->last_seen = now;
    ngx_memcpy(ean->data, key->data, key_len);

    ngx_rbtree_insert(&zone->sh->rbtree, &ean->node);
    ngx_queue_insert_head(&zone->sh->queue, &ean->queue);

    return ean;
}

static void
ngx_http_error_abuse_prune_events(ngx_http_error_abuse_zone_t *zone,
    ngx_http_error_abuse_node_t *ean, time_t now)
{
    time_t     *events;
    time_t      cutoff;

    events = ngx_http_error_abuse_events(ean);
    cutoff = now - zone->interval;

    while (ean->event_count
           && events[ean->event_head] <= cutoff)
    {
        ean->event_head = (ean->event_head + 1) % zone->threshold;
        ean->event_count--;
    }
}

/* CQ-2: shared locked prologue used by record() and is_blocked() — runs the
 * bounded expiry, looks the node up, and (if found) refreshes recency + LRU
 * position. Returns NULL on miss. Caller holds the zone mutex. */
static ngx_http_error_abuse_node_t *
ngx_http_error_abuse_find_touch_locked(ngx_http_error_abuse_zone_t *zone,
    uint32_t hash, ngx_str_t *key, time_t now)
{
    ngx_http_error_abuse_node_t  *ean;

    ngx_http_error_abuse_expire(zone, now, 2);
    ean = ngx_http_error_abuse_lookup(zone, hash, key);
    if (ean == NULL) {
        return NULL;
    }
    ean->last_seen = now;
    ngx_http_error_abuse_touch(zone, ean);
    return ean;
}

static ngx_int_t
ngx_http_error_abuse_record(ngx_http_error_abuse_zone_t *zone, ngx_str_t *key,
    time_t now, ngx_uint_t *count, time_t *blocked_until)
{
    uint32_t                        hash;
    ngx_uint_t                      index;
    time_t                         *events;
    ngx_http_error_abuse_node_t    *ean;

    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&zone->shpool->mutex);

    ean = ngx_http_error_abuse_find_touch_locked(zone, hash, key, now);
    if (ean == NULL) {
        /* create_node sets last_seen and inserts at the LRU head itself. */
        ean = ngx_http_error_abuse_create_node(zone, hash, key, now);
        if (ean == NULL) {
            ngx_shmtx_unlock(&zone->shpool->mutex);
            return NGX_ERROR;
        }
    }

    if (ean->blocked_until > now) {
        /* COR-4: a blocked client matched the threshold in this window. */
        *count = zone->threshold;
        *blocked_until = ean->blocked_until;
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return NGX_BUSY;
    }

    if (ean->blocked_until != 0) {
        ean->blocked_until = 0;
        ean->event_head = 0;
        ean->event_count = 0;
    }

    ngx_http_error_abuse_prune_events(zone, ean, now);
    events = ngx_http_error_abuse_events(ean);
    index = (ean->event_head + ean->event_count) % zone->threshold;
    events[index] = now;
    ean->event_count++;

    if (ean->event_count >= zone->threshold) {
        ean->blocked_until = now + zone->block;
        ean->event_head = 0;
        ean->event_count = 0;
    }

    *count = (ean->blocked_until > now) ? zone->threshold
                                        : ean->event_count;
    *blocked_until = ean->blocked_until;

    ngx_shmtx_unlock(&zone->shpool->mutex);
    return (*blocked_until > now) ? NGX_BUSY : NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_is_blocked(ngx_http_error_abuse_zone_t *zone,
    ngx_str_t *key, time_t now, ngx_uint_t *count, time_t *blocked_until)
{
    uint32_t                        hash;
    ngx_http_error_abuse_node_t    *ean;

    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&zone->shpool->mutex);

    ean = ngx_http_error_abuse_find_touch_locked(zone, hash, key, now);
    if (ean == NULL) {
        *count = 0;
        *blocked_until = 0;
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return NGX_DECLINED;
    }

    if (ean->blocked_until > now) {
        /* COR-4: report a stable count for blocked clients. */
        *count = zone->threshold;
        *blocked_until = ean->blocked_until;
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return NGX_OK;
    }

    if (ean->blocked_until != 0) {
        ean->blocked_until = 0;
        ean->event_head = 0;
        ean->event_count = 0;
    } else {
        ngx_http_error_abuse_prune_events(zone, ean, now);
    }

    *count = ean->event_count;
    *blocked_until = 0;
    ngx_shmtx_unlock(&zone->shpool->mutex);
    return NGX_DECLINED;
}

/* COR-2: read-only observation for dry-run. Computes what a tracked response
 * WOULD do without mutating shared state: it never inserts an event, never sets
 * blocked_until and never touches Redis. The current response is counted
 * hypothetically (existing in-window events + 1). */
static void
ngx_http_error_abuse_peek(ngx_http_error_abuse_zone_t *zone, ngx_str_t *key,
    time_t now, ngx_uint_t *count, time_t *blocked_until,
    ngx_uint_t *would_block)
{
    uint32_t                        hash;
    ngx_uint_t                      i, valid;
    time_t                          cutoff, *events;
    ngx_http_error_abuse_node_t    *ean;

    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&zone->shpool->mutex);

    ean = ngx_http_error_abuse_lookup(zone, hash, key);
    if (ean == NULL) {
        *count = (zone->threshold <= 1) ? zone->threshold : 1;
        *blocked_until = (zone->threshold <= 1) ? now + zone->block : 0;
        *would_block = (zone->threshold <= 1);
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return;
    }

    if (ean->blocked_until > now) {
        *count = zone->threshold;
        *blocked_until = ean->blocked_until;
        *would_block = 1;
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return;
    }

    cutoff = now - zone->interval;
    events = ngx_http_error_abuse_events(ean);
    valid = 0;
    for (i = 0; i < ean->event_count; i++) {
        if (events[(ean->event_head + i) % zone->threshold] > cutoff) {
            valid++;
        }
    }

    *count = valid + 1;
    *would_block = (*count >= zone->threshold);
    *blocked_until = *would_block ? now + zone->block : 0;

    ngx_shmtx_unlock(&zone->shpool->mutex);
}

/* COR-7: single place that emits an operator-visible decision line at the
 * configured log_level, so local, Redis and dry-run enforcement are all
 * surfaced in normal logs (not only debug). */
static void
ngx_http_error_abuse_log_decision(ngx_http_request_t *r,
    ngx_http_error_abuse_loc_conf_t *conf,
    ngx_http_error_abuse_req_ctx_t *ctx, const char *source,
    const char *action)
{
    ngx_log_error(conf->log_level, r->connection->log, 0,
                  "error_abuse %s: client \"%V\" in zone \"%V\" %s "
                  "(count=%ui, until=%T)",
                  source, &ctx->raw_key, &ctx->zone->name, action,
                  ctx->count, ctx->blocked_until);
}

static ngx_int_t
ngx_http_error_abuse_add_header(ngx_http_request_t *r, const char *key,
    size_t key_len, u_char *value, size_t value_len)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = key_len;
    h->key.data = (u_char *) key;
    h->value.len = value_len;
    h->value.data = value;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    return NGX_OK;
}

/* SEC-2/RFC-1/RFC-2: every module-generated rejection is per-client
 * authorization state. Mark it private and non-storable so a downstream shared
 * cache can never replay one client's ban to another, and advertise a
 * Retry-After deadline for 429/503 so clients know when to come back. */
static void
ngx_http_error_abuse_add_reject_headers(ngx_http_request_t *r,
    ngx_http_error_abuse_req_ctx_t *ctx)
{
    time_t   retry;
    u_char  *p;

    /* Drop any inherited cache directives from a custom error page first. */
    r->headers_out.last_modified_time = -1;
    if (r->headers_out.last_modified) {
        r->headers_out.last_modified->hash = 0;
        r->headers_out.last_modified = NULL;
    }

    (void) ngx_http_error_abuse_add_header(r, "Cache-Control",
        sizeof("Cache-Control") - 1, (u_char *) "private, no-store",
        sizeof("private, no-store") - 1);

    if ((r->headers_out.status == NGX_HTTP_TOO_MANY_REQUESTS
         || r->headers_out.status == NGX_HTTP_SERVICE_UNAVAILABLE)
        && ctx->blocked_until > ngx_time())
    {
        retry = ctx->blocked_until - ngx_time();
        if (retry < 1) {
            retry = 1;
        }
        p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (p != NULL) {
            (void) ngx_http_error_abuse_add_header(r, "Retry-After",
                sizeof("Retry-After") - 1, p,
                ngx_sprintf(p, "%T", retry) - p);
        }
    }
}

static ngx_int_t
ngx_http_error_abuse_preaccess(ngx_http_request_t *r)
{
    ngx_int_t                         rc;
    time_t                            now;
    ngx_http_error_abuse_req_ctx_t   *ctx;
    ngx_http_error_abuse_loc_conf_t  *conf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_error_abuse_module);
    if (!conf->enabled || conf->zone == NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_error_abuse_prepare_ctx(r, conf);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx->zone == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: empty key, bypassing");
        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "error_abuse: preaccess check for client \"%V\" "
                   "in zone \"%V\"",
                   &ctx->raw_key, &ctx->zone->name);

    if (ctx->zone->redis && !ctx->redis_checked) {
        rc = ngx_http_error_abuse_redis_check(r, ctx);
        if (rc == NGX_AGAIN) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "error_abuse: waiting for Redis response");
            return NGX_AGAIN;
        }
    }
    if (ctx->redis_blocked) {
        /* COR-4: ctx->blocked_until was populated from the Redis deadline in
         * the check callback; count reflects a threshold match. */
        ctx->count = ctx->zone->threshold;
        if (conf->dry_run) {
            ctx->state = NGX_HTTP_ERROR_ABUSE_DRY_RUN;
            ngx_http_error_abuse_log_decision(r, conf, ctx, "dry-run",
                                              "would block (Redis)");
            return NGX_DECLINED;
        }
        ctx->state = NGX_HTTP_ERROR_ABUSE_BLOCKED;
        ctx->own_rejection = 1;
        ngx_http_error_abuse_log_decision(r, conf, ctx, "blocked",
                                          "rejected (Redis)");
        return conf->reject_status;
    }

    now = ngx_time();
    rc = ngx_http_error_abuse_is_blocked(conf->zone, &ctx->key, now,
                                         &ctx->count,
                                         &ctx->blocked_until);
    if (rc == NGX_OK) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: client \"%V\" in zone \"%V\" "
                       "currently blocked",
                       &ctx->raw_key, &ctx->zone->name);
        if (conf->dry_run) {
            ctx->state = NGX_HTTP_ERROR_ABUSE_DRY_RUN;
            ngx_http_error_abuse_log_decision(r, conf, ctx, "dry-run",
                                              "would block (local)");
            return NGX_DECLINED;
        }

        ctx->state = NGX_HTTP_ERROR_ABUSE_BLOCKED;
        ctx->own_rejection = 1;

        ngx_http_error_abuse_log_decision(r, conf, ctx, "blocked",
                                          "rejected (local)");

        return conf->reject_status;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "error_abuse: client \"%V\" in zone \"%V\" passed, "
                   "count=%ui",
                   &ctx->raw_key, &ctx->zone->name, ctx->count);
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_error_abuse_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    time_t                           now;
    ngx_http_error_abuse_req_ctx_t  *ctx;
    ngx_http_error_abuse_loc_conf_t *conf;

    if (r != r->main) {
        return ngx_http_error_abuse_next_header_filter(r);
    }

    /* skip when module disabled or no zone bound */
    conf = ngx_http_get_module_loc_conf(r, ngx_http_error_abuse_module);
    if (!conf->enabled || conf->zone == NULL) {
        return ngx_http_error_abuse_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_error_abuse_module);
    if (ctx == NULL) {
        ctx = ngx_http_error_abuse_prepare_ctx(r, conf);
    }

    if (ctx == NULL || ctx->zone == NULL || ctx->response_seen) {
        return ngx_http_error_abuse_next_header_filter(r);
    }

    ctx->response_seen = 1;

    /* COR-2: an error_page internal redirect can land the response in a
     * location whose dry_run= differs from where the ctx was first prepared
     * (preaccess). Re-derive it from the location actually producing this
     * response so enforcement and observation follow the final location
     * deterministically, matching conf->log_level used below. */
    ctx->dry_run = conf->dry_run;

    /* SEC-2/RFC-1/RFC-2: this is our own synthetic rejection; tag it private,
     * no-store and (for 429/503) Retry-After so it is never shared-cached. */
    if (ctx->own_rejection) {
        ngx_http_error_abuse_add_reject_headers(r, ctx);
        return ngx_http_error_abuse_next_header_filter(r);
    }

    if (ctx->state == NGX_HTTP_ERROR_ABUSE_DRY_RUN) {
        return ngx_http_error_abuse_next_header_filter(r);
    }

    /* Early return for non-error responses (common case optimization) */
    if (!ngx_http_error_abuse_status_matches(ctx->zone,
                                             r->headers_out.status))
    {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: status %ui not tracked in zone \"%V\" "
                       "for client \"%V\"",
                       r->headers_out.status, &ctx->zone->name, &ctx->raw_key);
        return ngx_http_error_abuse_next_header_filter(r);
    }

    now = ngx_time();

    /* COR-2: dry-run observes only. It must never insert events, set a block
     * deadline or write the Redis block key — otherwise an enforcing sibling
     * location (or a reload with dry_run off) would activate accumulated bans. */
    if (ctx->dry_run) {
        ngx_uint_t  would_block;

        ngx_http_error_abuse_peek(ctx->zone, &ctx->key, now, &ctx->count,
                                  &ctx->blocked_until, &would_block);
        ctx->state = NGX_HTTP_ERROR_ABUSE_DRY_RUN;
        if (would_block) {
            ngx_http_error_abuse_log_decision(r, conf, ctx, "dry-run",
                                              "would block (threshold reached)");
        } else {
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "error_abuse: dry-run status %ui for client \"%V\" "
                           "in zone \"%V\", count=%ui",
                           r->headers_out.status, &ctx->raw_key,
                           &ctx->zone->name, ctx->count);
        }
        return ngx_http_error_abuse_next_header_filter(r);
    }

    rc = ngx_http_error_abuse_record(ctx->zone, &ctx->key, now,
                                     &ctx->count, &ctx->blocked_until);
    if (ctx->zone->redis) {
        ngx_http_error_abuse_redis_record(r, ctx);
    }
    if (rc == NGX_ERROR) {
        /* SEC-1: do not fail open. The configured shm pressure policy decides
         * whether a new identity that could not be tracked is rejected. */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error_abuse zone \"%V\" has insufficient shared memory",
                      &ctx->zone->name);
    } else if (rc == NGX_BUSY) {
        ctx->state = NGX_HTTP_ERROR_ABUSE_BLOCKED;
        ngx_http_error_abuse_log_decision(r, conf, ctx, "blocked",
                                          "threshold reached");
    } else {
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: status %ui counted for client \"%V\" "
                       "in zone \"%V\", count=%ui",
                       r->headers_out.status, &ctx->raw_key, &ctx->zone->name, ctx->count);
        ctx->state = NGX_HTTP_ERROR_ABUSE_COUNTED;
    }

    return ngx_http_error_abuse_next_header_filter(r);
}

static ngx_http_error_abuse_req_ctx_t *
ngx_http_error_abuse_prepare_ctx(ngx_http_request_t *r,
    ngx_http_error_abuse_loc_conf_t *conf)
{
    ngx_str_t                        key;
    ngx_http_error_abuse_req_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_error_abuse_module);
    if (ctx != NULL) {
        return ctx;
    }

    if (ngx_http_complex_value(r, &conf->zone->key, &key) != NGX_OK) {
        return NULL;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_error_abuse_req_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->state = NGX_HTTP_ERROR_ABUSE_BYPASSED;
    ctx->dry_run = conf->dry_run;
    ngx_http_set_ctx(r, ctx, ngx_http_error_abuse_module);

    if (key.len == 0) {
        return ctx;
    }

    /* SEC-3: hash the (arbitrary-length) raw key to a fixed 32-byte identity.
     * No length limit is needed — memory and Redis traffic are bounded by the
     * digest, not the raw key. Keep a capped copy of the raw key for logs. */
    ctx->key.data = ngx_pnalloc(r->pool, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN);
    if (ctx->key.data == NULL) {
        return NULL;
    }
    SHA256(key.data, key.len, ctx->key.data);
    ctx->key.len = NGX_HTTP_ERROR_ABUSE_DIGEST_LEN;

    ctx->raw_key.len = ngx_min(key.len, NGX_HTTP_ERROR_ABUSE_RAW_LOG_MAX);
    ctx->raw_key.data = ngx_pnalloc(r->pool, ctx->raw_key.len);
    if (ctx->raw_key.data == NULL) {
        return NULL;
    }
    ngx_memcpy(ctx->raw_key.data, key.data, ctx->raw_key.len);

    ctx->zone = conf->zone;
    ctx->state = NGX_HTTP_ERROR_ABUSE_PASSED;

    return ctx;
}

static void
ngx_http_error_abuse_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_int_t                       rc;
    ngx_rbtree_node_t            **p;
    ngx_http_error_abuse_node_t   *ean, *eant;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            ean = (ngx_http_error_abuse_node_t *) node;
            eant = (ngx_http_error_abuse_node_t *) temp;
            rc = ngx_memn2cmp(ean->data, eant->data,
                              ean->key_len, eant->key_len);
            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static ngx_int_t
ngx_http_error_abuse_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                         len;
    ngx_http_error_abuse_zone_t   *old;
    ngx_http_error_abuse_zone_t   *zone;

    zone = shm_zone->data;
    old = data;

    if (old != NULL) {
        if (old->key.value.len != zone->key.value.len
            || ngx_strncmp(old->key.value.data, zone->key.value.data,
                           zone->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "error_abuse zone \"%V\" key cannot change "
                          "during reload", &zone->name);
            return NGX_ERROR;
        }

        if (old->threshold != zone->threshold) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "error_abuse zone \"%V\" threshold cannot change "
                          "during reload", &zone->name);
            return NGX_ERROR;
        }

        zone->sh = old->sh;
        zone->shpool = old->shpool;
        return NGX_OK;
    }

    zone->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        zone->sh = zone->shpool->data;
        return NGX_OK;
    }

    zone->sh = ngx_slab_alloc(zone->shpool,
                              sizeof(ngx_http_error_abuse_shctx_t));
    if (zone->sh == NULL) {
        return NGX_ERROR;
    }

    zone->shpool->data = zone->sh;
    ngx_rbtree_init(&zone->sh->rbtree, &zone->sh->sentinel,
                    ngx_http_error_abuse_rbtree_insert);
    ngx_queue_init(&zone->sh->queue);

    len = sizeof(" in error_abuse zone \"\"") + zone->name.len;
    zone->shpool->log_ctx = ngx_slab_alloc(zone->shpool, len);
    if (zone->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(zone->shpool->log_ctx, " in error_abuse zone \"%V\"%Z",
                &zone->name);

    if (zone->persist.len != 0) {
        return ngx_http_error_abuse_load(zone, shm_zone->shm.log);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_parse_statuses(ngx_conf_t *cf,
    ngx_http_error_abuse_zone_t *zone, ngx_str_t *value)
{
    u_char      *p, *last, *dash, *end;
    ngx_int_t    first, final;
    ngx_uint_t   status;

    p = value->data;
    last = value->data + value->len;

    while (p < last) {
        end = ngx_strlchr(p, last, ',');
        if (end == NULL) {
            end = last;
        }

        /* COR-8: reject empty tokens such as a trailing comma ("404,") or a
         * double comma, instead of silently skipping them. */
        if (end == p) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid error_abuse status list \"%V\" "
                               "(empty element)", value);
            return NGX_ERROR;
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
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid error_abuse status list \"%V\"",
                               value);
            return NGX_ERROR;
        }

        for (status = (ngx_uint_t) first;
             status <= (ngx_uint_t) final;
             status++)
        {
            zone->statuses[status >> 3] |= 1U << (status & 7);
        }

        /* COR-8: do not form a pointer past one-past-last when the final
         * element ends at the buffer end. */
        if (end == last) {
            break;
        }
        p = end + 1;
        if (p == last) {
            /* trailing comma, e.g. "404," */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid error_abuse status list \"%V\" "
                               "(trailing comma)", value);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_http_error_abuse_zone_t *
ngx_http_error_abuse_find_zone(ngx_http_error_abuse_main_conf_t *mcf,
    ngx_str_t *name)
{
    ngx_uint_t                      i;
    ngx_http_error_abuse_zone_t   **zones;

    zones = mcf->zones.elts;
    for (i = 0; i < mcf->zones.nelts; i++) {
        if (zones[i]->name.len == name->len
            && ngx_strncmp(zones[i]->name.data, name->data, name->len) == 0)
        {
            return zones[i];
        }
    }

    return NULL;
}

/* CQ-3: parse a positive duration (seconds) with the overflow cap, shared by
 * the interval/block/inactive options. */
static ngx_int_t
ngx_http_error_abuse_parse_seconds(u_char *data, size_t len, time_t *out)
{
    ngx_str_t   s;
    ngx_msec_t  t;

    s.len = len;
    s.data = data;
    t = ngx_parse_time(&s, 1);
    if (t == (ngx_msec_t) NGX_ERROR || t == 0
        || t > NGX_HTTP_ERROR_ABUSE_MAX_SECONDS)
    {
        return NGX_ERROR;
    }
    *out = (time_t) t;
    return NGX_OK;
}

static char *
ngx_http_error_abuse_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                            *p;
    size_t                             size;
    ssize_t                            parsed_size;
    ngx_str_t                         *value, name, key, statuses, persist;
    ngx_int_t                          n;
    ngx_uint_t                         i;
    ngx_msec_t                         parsed_time;
    ngx_uint_t                         seen;
    ngx_http_compile_complex_value_t   ccv;
    ngx_http_error_abuse_zone_t       *zone, **slot;
    ngx_http_error_abuse_main_conf_t  *mcf;

    enum {
        NGX_HTTP_ERROR_ABUSE_SEEN_ZONE = 1 << 0,
        NGX_HTTP_ERROR_ABUSE_SEEN_KEY = 1 << 1,
        NGX_HTTP_ERROR_ABUSE_SEEN_STATUSES = 1 << 2,
        NGX_HTTP_ERROR_ABUSE_SEEN_INTERVAL = 1 << 3,
        NGX_HTTP_ERROR_ABUSE_SEEN_THRESHOLD = 1 << 4,
        NGX_HTTP_ERROR_ABUSE_SEEN_BLOCK = 1 << 5,
        NGX_HTTP_ERROR_ABUSE_SEEN_INACTIVE = 1 << 6,
        NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST = 1 << 7,
        NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST_INTERVAL = 1 << 8,
        NGX_HTTP_ERROR_ABUSE_SEEN_REDIS = 1 << 9,
        NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST_SECRET = 1 << 10
    };

    mcf = conf;
    value = cf->args->elts;
    size = 0;
    seen = 0;
    key.len = 0;
    statuses.len = 0;
    persist.len = 0;

    zone = ngx_pcalloc(cf->pool, sizeof(ngx_http_error_abuse_zone_t));
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_ZONE) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_ZONE;

            name.data = value[i].data + 5;
            p = (u_char *) ngx_strchr(name.data, ':');
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "error_abuse zone requires name:size");
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;
            parsed_size = ngx_parse_size(&(ngx_str_t) {
                (size_t) (value[i].data + value[i].len - p - 1), p + 1
            });
            if (parsed_size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "error_abuse zone has invalid size");
                return NGX_CONF_ERROR;
            }
            if (parsed_size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "error_abuse zone is too small");
                return NGX_CONF_ERROR;
            }
            size = (size_t) parsed_size;
            zone->name = name;

        } else if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_KEY) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_KEY;
            key.data = value[i].data + 4;
            key.len = value[i].len - 4;

        } else if (ngx_strncmp(value[i].data, "statuses=", 9) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_STATUSES) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_STATUSES;
            statuses.data = value[i].data + 9;
            statuses.len = value[i].len - 9;

        } else if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_INTERVAL) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_INTERVAL;
            if (ngx_http_error_abuse_parse_seconds(value[i].data + 9,
                    value[i].len - 9, &zone->interval) != NGX_OK)
            {
                goto invalid;
            }

        } else if (ngx_strncmp(value[i].data, "threshold=", 10) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_THRESHOLD) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_THRESHOLD;
            n = ngx_atoi(value[i].data + 10, value[i].len - 10);
            if (n < 1 || n > NGX_HTTP_ERROR_ABUSE_MAX_THRESHOLD) {
                goto invalid;
            }
            zone->threshold = (ngx_uint_t) n;

        } else if (ngx_strncmp(value[i].data, "block=", 6) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_BLOCK) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_BLOCK;
            if (ngx_http_error_abuse_parse_seconds(value[i].data + 6,
                    value[i].len - 6, &zone->block) != NGX_OK)
            {
                goto invalid;
            }

        } else if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_INACTIVE) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_INACTIVE;
            if (ngx_http_error_abuse_parse_seconds(value[i].data + 9,
                    value[i].len - 9, &zone->inactive) != NGX_OK)
            {
                goto invalid;
            }

        } else if (ngx_strncmp(value[i].data, "persist=", 8) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST;
            persist.data = value[i].data + 8;
            persist.len = value[i].len - 8;
            if (persist.len == 0) {
                goto invalid;
            }

        } else if (ngx_strncmp(value[i].data, "persist_interval=", 17) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST_INTERVAL) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST_INTERVAL;
            ngx_str_t s = { value[i].len - 17, value[i].data + 17 };
            parsed_time = ngx_parse_time(&s, 0);
            if (parsed_time == (ngx_msec_t) NGX_ERROR || parsed_time < 100) {
                goto invalid;
            }
            zone->persist_interval = parsed_time;

        } else if (ngx_strncmp(value[i].data, "persist_secret=", 15) == 0) {
            u_char     *hexp;
            size_t      hexlen, b;

            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST_SECRET) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_PERSIST_SECRET;
            hexp = value[i].data + 15;
            hexlen = value[i].len - 15;
            /* SEC-5: even-length hex string -> raw HMAC key bytes. */
            if (hexlen == 0 || (hexlen & 1)) {
                goto invalid;
            }
            zone->persist_secret.data = ngx_pnalloc(cf->pool, hexlen / 2);
            if (zone->persist_secret.data == NULL) {
                return NGX_CONF_ERROR;
            }
            for (b = 0; b < hexlen / 2; b++) {
                ngx_int_t hi = ngx_hextoi(hexp + b * 2, 1);
                ngx_int_t lo = ngx_hextoi(hexp + b * 2 + 1, 1);
                if (hi == NGX_ERROR || lo == NGX_ERROR) {
                    goto invalid;
                }
                zone->persist_secret.data[b] = (u_char) ((hi << 4) | lo);
            }
            zone->persist_secret.len = hexlen / 2;

        } else if (ngx_strncmp(value[i].data, "redis=", 6) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_REDIS) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_REDIS;
            ngx_str_t s = { value[i].len - 6, value[i].data + 6 };
            if (s.len == 2
                && ngx_strcasecmp(s.data, (u_char *) "on") == 0)
            {
                zone->redis = 1;
            } else if (s.len == 3
                       && ngx_strcasecmp(s.data, (u_char *) "off") == 0)
            {
                zone->redis = 0;
            } else {
                goto invalid;
            }

        } else {
            goto invalid;
        }
    }

    if (zone->name.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "error_abuse_zone requires zone=name:size");
        return NGX_CONF_ERROR;
    }

    if (key.len == 0) {
        ngx_str_set(&key, NGX_HTTP_ERROR_ABUSE_DEFAULT_KEY);
    }
    if (statuses.len == 0) {
        ngx_str_set(&statuses, NGX_HTTP_ERROR_ABUSE_DEFAULT_STATUSES);
    }
    if (zone->interval == 0) {
        zone->interval = NGX_HTTP_ERROR_ABUSE_DEFAULT_INTERVAL;
    }
    if (zone->threshold == 0) {
        zone->threshold = NGX_HTTP_ERROR_ABUSE_DEFAULT_THRESHOLD;
    }
    if (zone->block == 0) {
        zone->block = NGX_HTTP_ERROR_ABUSE_DEFAULT_BLOCK;
    }

    if (ngx_http_error_abuse_find_zone(mcf, &zone->name) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate error_abuse zone \"%V\"", &zone->name);
        return NGX_CONF_ERROR;
    }

    if (zone->inactive == 0) {
        zone->inactive = 3600;
        if (zone->inactive < zone->interval) {
            zone->inactive = zone->interval;
        }
        if (zone->inactive < zone->block) {
            zone->inactive = zone->block;
        }
    } else if (zone->inactive < zone->interval
               || zone->inactive < zone->block)
    {
        /* COR-3: an explicit inactive shorter than the sliding window or the
         * block deadline would evict live event sets early (locally and via
         * Redis PEXPIRE), silently weakening enforcement. Reject it. */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "error_abuse_zone \"%V\" inactive must be >= "
                           "interval and >= block", &zone->name);
        return NGX_CONF_ERROR;
    }

    if (ngx_http_error_abuse_parse_statuses(cf, zone, &statuses) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &key;
    ccv.complex_value = &zone->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (persist.len != 0) {
        zone->persist.data = ngx_pnalloc(cf->pool, persist.len + 1);
        if (zone->persist.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(zone->persist.data, persist.data, persist.len);
        zone->persist.data[persist.len] = '\0';
        zone->persist.len = persist.len;

        if (ngx_conf_full_name(cf->cycle, &zone->persist, 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        {
            ngx_http_error_abuse_zone_t  **zones;

            zones = mcf->zones.elts;
            for (i = 0; i < mcf->zones.nelts; i++) {
                if (zones[i]->persist.len == zone->persist.len
                    && ngx_strncmp(zones[i]->persist.data,
                                   zone->persist.data,
                                   zone->persist.len)
                       == 0)
                {
                    ngx_conf_log_error(
                        NGX_LOG_EMERG, cf, 0,
                        "error_abuse zones \"%V\" and \"%V\" use the same "
                        "persistence file \"%V\"",
                        &zones[i]->name, &zone->name, &zone->persist);
                    return NGX_CONF_ERROR;
                }
            }
        }

        if (zone->persist_interval == 0) {
            zone->persist_interval = 5000;
        }
    } else if (zone->persist_interval != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "persist_interval requires persist");
        return NGX_CONF_ERROR;
    } else if (zone->persist_secret.len != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "persist_secret requires persist");
        return NGX_CONF_ERROR;
    }

    if (ngx_strlchr(zone->name.data, zone->name.data + zone->name.len, '{')
        != NULL
        || ngx_strlchr(zone->name.data, zone->name.data + zone->name.len, '}')
           != NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "error_abuse zone name may not contain braces");
        return NGX_CONF_ERROR;
    }

    zone->shm_zone = ngx_shared_memory_add(cf, &zone->name, size,
                                           &ngx_http_error_abuse_module);
    if (zone->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (zone->shm_zone->data != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "shared memory zone \"%V\" is already used",
                           &zone->name);
        return NGX_CONF_ERROR;
    }

    zone->shm_zone->init = ngx_http_error_abuse_init_zone;
    zone->shm_zone->data = zone;

    slot = ngx_array_push(&mcf->zones);
    if (slot == NULL) {
        return NGX_CONF_ERROR;
    }
    *slot = zone;

    return NGX_CONF_OK;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid error_abuse_zone parameter \"%V\"",
                       &value[i]);
    return NGX_CONF_ERROR;

duplicate:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "duplicate error_abuse_zone parameter \"%V\"",
                       &value[i]);
    return NGX_CONF_ERROR;
}

static char *
ngx_http_error_abuse_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                         *value, name;
    ngx_int_t                          status;
    ngx_uint_t                         i, seen;
    ngx_http_error_abuse_loc_conf_t   *lcf;
    ngx_http_error_abuse_main_conf_t  *mcf;

    enum {
        NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_ZONE = 1 << 0,
        NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_STATUS = 1 << 1,
        NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_DRY_RUN = 1 << 2,
        NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_LOG_LEVEL = 1 << 3
    };

    lcf = conf;
    value = cf->args->elts;
    seen = 0;

    /* COR-6: reject same-level duplicates before the special "off" branch so
     * ordering is irrelevant; "error_abuse off; error_abuse zone=x;" and the
     * reverse both fail, as do repeated "off" directives. */
    if (lcf->enabled != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (cf->args->nelts == 2
        && value[1].len == 3
        && ngx_strncmp(value[1].data, "off", 3) == 0)
    {
        lcf->enabled = 0;
        lcf->zone = NULL;
        return NGX_CONF_OK;
    }

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_error_abuse_module);
    lcf->enabled = 1;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_ZONE) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_ZONE;
            name.data = value[i].data + 5;
            name.len = value[i].len - 5;
            lcf->zone = ngx_http_error_abuse_find_zone(mcf, &name);
            if (lcf->zone == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "unknown error_abuse zone \"%V\"", &name);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "status=", 7) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_STATUS) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_STATUS;
            status = ngx_atoi(value[i].data + 7, value[i].len - 7);
            if (status < 400 || status > 599) {
                goto invalid;
            }
            lcf->reject_status = (ngx_uint_t) status;

        } else if (ngx_strncmp(value[i].data, "dry_run=", 8) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_DRY_RUN) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_DRY_RUN;
            if (value[i].len == 10
                && ngx_strncmp(value[i].data + 8, "on", 2) == 0)
            {
                lcf->dry_run = 1;
            } else if (value[i].len == 11
                       && ngx_strncmp(value[i].data + 8, "off", 3) == 0)
            {
                lcf->dry_run = 0;
            } else {
                goto invalid;
            }

        } else if (ngx_strncmp(value[i].data, "log_level=", 10) == 0) {
            ngx_uint_t log_level;

            if (seen & NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_LOG_LEVEL) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_ENABLE_SEEN_LOG_LEVEL;

            for (log_level = 0;
                 ngx_http_error_abuse_log_levels[log_level].name.len != 0;
                 log_level++)
            {
                if (value[i].len - 10
                    == ngx_http_error_abuse_log_levels[log_level].name.len
                    && ngx_strncmp(value[i].data + 10,
                       ngx_http_error_abuse_log_levels[log_level].name.data,
                       value[i].len - 10) == 0)
                {
                    lcf->log_level =
                        ngx_http_error_abuse_log_levels[log_level].value;
                    break;
                }
            }
            if (ngx_http_error_abuse_log_levels[log_level].name.len == 0) {
                goto invalid;
            }

        } else {
            goto invalid;
        }
    }

    if (lcf->zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "error_abuse requires zone=name");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid error_abuse parameter \"%V\"", &value[i]);
    return NGX_CONF_ERROR;

duplicate:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "duplicate error_abuse parameter \"%V\"", &value[i]);
    return NGX_CONF_ERROR;
}

static char *
ngx_http_error_abuse_redis(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                         n, db;
    ngx_uint_t                        i, seen, tls;
    ngx_msec_t                        timeout;
    ngx_str_t                        *value, host, prefix, user, password;
    ngx_http_error_abuse_main_conf_t *mcf;

    enum {
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_HOST = 1 << 0,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PORT = 1 << 1,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PREFIX = 1 << 2,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_TIMEOUT = 1 << 3,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_USER = 1 << 4,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PASSWORD = 1 << 5,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_DB = 1 << 6
    };

    mcf = conf;
    if (mcf->redis.configured) {
        return "is duplicate";
    }

    value = cf->args->elts;
    host.data = NULL;
    host.len = 0;
    ngx_str_set(&prefix, "ea_");
    user.data = NULL;
    user.len = 0;
    password.data = NULL;
    password.len = 0;
    db = 0;
    tls = 0;
    timeout = 100;
    seen = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "host=", 5) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_HOST) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_HOST;
            host.data = value[i].data + 5;
            host.len = value[i].len - 5;
            /* optional tls:// (or rediss://) scheme enables TLS transport */
            if (host.len > 6
                && ngx_strncmp(host.data, "tls://", 6) == 0)
            {
                tls = 1;
                host.data += 6;
                host.len -= 6;
            } else if (host.len > 9
                       && ngx_strncmp(host.data, "rediss://", 9) == 0)
            {
                tls = 1;
                host.data += 9;
                host.len -= 9;
            }
            if (host.len == 0) {
                goto invalid;
            }
        } else if (ngx_strncmp(value[i].data, "port=", 5) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PORT) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PORT;
            n = ngx_atoi(value[i].data + 5, value[i].len - 5);
            if (n < 1 || n > 65535) {
                goto invalid;
            }
            mcf->redis.port = (in_port_t) n;
        } else if (ngx_strncmp(value[i].data, "prefix=", 7) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PREFIX) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PREFIX;
            prefix.data = value[i].data + 7;
            prefix.len = value[i].len - 7;
            if (prefix.len == 0
                || ngx_strlchr(prefix.data, prefix.data + prefix.len, '{')
                   != NULL
                || ngx_strlchr(prefix.data, prefix.data + prefix.len, '}')
                   != NULL)
            {
                goto invalid;
            }
        } else if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            ngx_str_t s;

            if (seen & NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_TIMEOUT) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_TIMEOUT;
            s.data = value[i].data + 8;
            s.len = value[i].len - 8;
            timeout = ngx_parse_time(&s, 0);
            if (timeout == (ngx_msec_t) NGX_ERROR || timeout == 0) {
                goto invalid;
            }
        } else if (ngx_strncmp(value[i].data, "user=", 5) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_USER) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_USER;
            user.data = value[i].data + 5;
            user.len = value[i].len - 5;
            if (user.len == 0) {
                goto invalid;
            }
        } else if (ngx_strncmp(value[i].data, "password=", 9) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PASSWORD) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PASSWORD;
            password.data = value[i].data + 9;
            password.len = value[i].len - 9;
            if (password.len == 0) {
                goto invalid;
            }
        } else if (ngx_strncmp(value[i].data, "db=", 3) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_DB) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_DB;
            db = ngx_atoi(value[i].data + 3, value[i].len - 3);
            if (db < 0 || db > 65535) {
                goto invalid;
            }
        } else {
            goto invalid;
        }
    }

    if (host.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "error_abuse_redis requires host");
        return NGX_CONF_ERROR;
    }

    /* a username only makes sense with a password (Redis 6 ACL AUTH) */
    if (user.len != 0 && password.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "error_abuse_redis user= requires password=");
        return NGX_CONF_ERROR;
    }

    /* Resolve the host to a numeric address at config time. redisAsyncConnect
     * otherwise calls getaddrinfo() synchronously inside the worker event
     * loop on every (re)connect; a slow or hung resolver would then stall all
     * request processing in that worker for the duration of a Redis outage
     * (reconnects fire on a 1s..30s backoff). Handing hiredis a numeric
     * address keeps the connect path non-blocking. */
    {
        ngx_url_t  u;
        u_char     text[NGX_SOCKADDR_STRLEN];
        size_t     tlen;

        /* Keep the original host text for TLS SNI + certificate hostname
         * verification, since the connect address is now numeric. */
        mcf->redis.sni.data = ngx_pnalloc(cf->pool, host.len + 1);
        if (mcf->redis.sni.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(mcf->redis.sni.data, host.data, host.len);
        mcf->redis.sni.data[host.len] = '\0';
        mcf->redis.sni.len = host.len;

        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = host;
        u.default_port = mcf->redis.port;

        /* Resolve to a numeric address at config time so redisAsyncConnect does
         * not call getaddrinfo() synchronously inside the worker event loop on
         * every (re)connect. Only u.addrs[0] is used, so a multi-A / DNS-
         * failover name is pinned to its first address for the life of the
         * config. If resolution fails (e.g. a transient DNS outage at reload),
         * do NOT fail the whole configuration — that would couple every reload
         * to Redis DNS and contradict the module's fail-open-on-Redis design.
         * Fall back to handing hiredis the hostname (worker-time resolution,
         * which can block the event loop on reconnect during an outage but
         * keeps reloads working) and warn the operator to use a numeric IP. */
        if (ngx_parse_url(cf->pool, &u) != NGX_OK || u.naddrs == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "error_abuse_redis cannot resolve host \"%V\" at "
                               "config time%s%s; falling back to worker-time "
                               "resolution (may block the event loop on "
                               "reconnect); use a numeric IP to avoid this",
                               &host, u.err ? ": " : "",
                               u.err ? u.err : "");
            mcf->redis.host = mcf->redis.sni;
        } else {
            tlen = ngx_sock_ntop(u.addrs[0].sockaddr, u.addrs[0].socklen,
                                 text, NGX_SOCKADDR_STRLEN, 0);

            mcf->redis.host.data = ngx_pnalloc(cf->pool, tlen + 1);
            if (mcf->redis.host.data == NULL) {
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(mcf->redis.host.data, text, tlen);
            mcf->redis.host.data[tlen] = '\0';
            mcf->redis.host.len = tlen;
        }
    }

    mcf->redis.prefix.data = ngx_pnalloc(cf->pool, prefix.len);
    if (mcf->redis.prefix.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(mcf->redis.prefix.data, prefix.data, prefix.len);
    mcf->redis.prefix.len = prefix.len;

    if (user.len != 0) {
        mcf->redis.user.data = ngx_pnalloc(cf->pool, user.len);
        if (mcf->redis.user.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(mcf->redis.user.data, user.data, user.len);
        mcf->redis.user.len = user.len;
    }

    if (password.len != 0) {
        mcf->redis.password.data = ngx_pnalloc(cf->pool, password.len);
        if (mcf->redis.password.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(mcf->redis.password.data, password.data, password.len);
        mcf->redis.password.len = password.len;
    }

    mcf->redis.db = db;
    mcf->redis.tls = tls ? 1 : 0;
    mcf->redis.timeout = timeout;
    mcf->redis.configured = 1;

    return NGX_CONF_OK;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid error_abuse_redis parameter \"%V\"",
                       &value[i]);
    return NGX_CONF_ERROR;

duplicate:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "duplicate error_abuse_redis parameter \"%V\"",
                       &value[i]);
    return NGX_CONF_ERROR;
}

static void *
ngx_http_error_abuse_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_error_abuse_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_error_abuse_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&mcf->zones, cf->pool, 2,
                       sizeof(ngx_http_error_abuse_zone_t *)) != NGX_OK)
    {
        return NULL;
    }
    mcf->redis.port = 6379;

    return mcf;
}

static void *
ngx_http_error_abuse_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_error_abuse_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_error_abuse_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->reject_status = NGX_CONF_UNSET_UINT;
    conf->log_level = NGX_CONF_UNSET_UINT;
    conf->dry_run = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_error_abuse_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_error_abuse_loc_conf_t  *prev = parent;
    ngx_http_error_abuse_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_uint_value(conf->reject_status, prev->reject_status,
                              NGX_HTTP_TOO_MANY_REQUESTS);
    ngx_conf_merge_uint_value(conf->log_level, prev->log_level,
                              NGX_LOG_NOTICE);
    ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    if (conf->zone == NULL && conf->enabled) {
        conf->zone = prev->zone;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_error_abuse_init(ngx_conf_t *cf)
{
    ngx_uint_t                  i;
    ngx_http_handler_pt        *handler;
    ngx_http_error_abuse_zone_t **zones;
    ngx_http_error_abuse_main_conf_t *mcf;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_variable_t        *var;

    mcf = ngx_http_conf_get_module_main_conf(
        cf, ngx_http_error_abuse_module);
    zones = mcf->zones.elts;
    for (i = 0; i < mcf->zones.nelts; i++) {
        if (zones[i]->redis && !mcf->redis.configured) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "redis=on in zone \"%V\" requires "
                               "error_abuse_redis", &zones[i]->name);
            return NGX_ERROR;
        }
#if (NGX_THREADS)
        /* PERF-1: ensure the default thread pool exists so persistence I/O can
         * run off the event loop. Falls back to synchronous saves if the build
         * has no threads or the pool cannot be created. */
        if (zones[i]->persist.len != 0) {
            (void) ngx_thread_pool_add(cf, NULL);
        }
#endif
    }

    for (var = ngx_http_error_abuse_variables; var->name.len; var++) {
        ngx_http_variable_t *v = ngx_http_add_variable(
            cf, &var->name, var->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }
        v->get_handler = var->get_handler;
        v->data = var->data;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    handler = ngx_array_push(
        &cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (handler == NULL) {
        return NGX_ERROR;
    }
    *handler = ngx_http_error_abuse_preaccess;

    ngx_http_error_abuse_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_error_abuse_header_filter;

    return NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_redis_keys(ngx_pool_t *pool,
    ngx_http_error_abuse_req_ctx_t *ctx, ngx_str_t *events, ngx_str_t *block)
{
    static u_char hex[] = "0123456789abcdef";
    u_char       *p;
    size_t        base_len;
    ngx_uint_t    i;
    ngx_str_t    *prefix;

    /* PERF-3: the keys are stable for the life of the request; build the hex
     * encoding once and reuse it across the preaccess GET and the response
     * filter's EVAL instead of re-encoding (twice) per call. */
    if (ctx->redis_block.len != 0) {
        *events = ctx->redis_events;
        *block = ctx->redis_block;
        return NGX_OK;
    }

    prefix = &ngx_http_error_abuse_redis_worker.conf->prefix;
    base_len = prefix->len + 1 + ctx->zone->name.len + 1
               + ctx->key.len * 2 + 1;

    events->len = base_len + sizeof(":events") - 1;
    events->data = ngx_pnalloc(pool, events->len);
    block->len = base_len + sizeof(":block") - 1;
    block->data = ngx_pnalloc(pool, block->len);
    if (events->data == NULL || block->data == NULL) {
        return NGX_ERROR;
    }

    p = events->data;
    p = ngx_cpymem(p, prefix->data, prefix->len);
    *p++ = '{';
    p = ngx_cpymem(p, ctx->zone->name.data, ctx->zone->name.len);
    *p++ = ':';
    for (i = 0; i < ctx->key.len; i++) {
        *p++ = hex[ctx->key.data[i] >> 4];
        *p++ = hex[ctx->key.data[i] & 0x0f];
    }
    *p++ = '}';
    p = ngx_cpymem(p, ":events", sizeof(":events") - 1);

    ngx_memcpy(block->data, events->data, base_len);
    ngx_memcpy(block->data + base_len, ":block", sizeof(":block") - 1);

    ctx->redis_events = *events;
    ctx->redis_block = *block;

    return NGX_OK;
}

static ngx_flag_t
ngx_http_error_abuse_redis_available(time_t now)
{
    ngx_http_error_abuse_redis_worker_t *worker;

    worker = &ngx_http_error_abuse_redis_worker;

    return worker->circuit_breaker_until <= now
           && worker->ready
           && worker->context != NULL;
}

static void
ngx_http_error_abuse_redis_record_failure(time_t now)
{
    ngx_http_error_abuse_redis_worker_t *worker;

    worker = &ngx_http_error_abuse_redis_worker;

    if (++worker->consecutive_failures
        >= NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_THRESHOLD)
    {
        worker->circuit_breaker_until =
            now + NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_DURATION;
        worker->consecutive_failures = 0;
        ngx_log_error(NGX_LOG_ERR, worker->log, 0,
                      "error_abuse: Redis circuit breaker triggered, "
                      "suspending for %ui seconds",
                      (ngx_uint_t)
                      NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_DURATION);
    }
}

static ngx_int_t
ngx_http_error_abuse_redis_check(ngx_http_request_t *r,
    ngx_http_error_abuse_req_ctx_t *ctx)
{
    int         rc;
    time_t      now;
    ngx_str_t   events, block;
    const char *argv[2];
    size_t      argvlen[2];

    if (ctx->redis_pending) {
        return NGX_AGAIN;
    }

    /* Circuit breaker / readiness: skip Redis when unavailable */
    now = ngx_time();
    if (!ngx_http_error_abuse_redis_available(now)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis unavailable, skipping check");
        ctx->redis_checked = 1;
        return NGX_DECLINED;
    }

    if (ngx_http_error_abuse_redis_keys(r->pool, ctx, &events, &block)
        != NGX_OK)
    {
        ctx->redis_checked = 1;
        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "error_abuse: checking Redis block key \"%V\" "
                   "for client \"%V\"",
                   &block, &ctx->raw_key);

    argv[0] = "GET";
    argvlen[0] = 3;
    argv[1] = (const char *) block.data;
    argvlen[1] = block.len;
    ctx->redis_pending = 1;
    rc = redisAsyncCommandArgv(ngx_http_error_abuse_redis_worker.context,
                               ngx_http_error_abuse_redis_check_callback,
                               r, 2, argv, argvlen);
    if (rc != REDIS_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "error_abuse: failed to queue Redis GET command");
        ngx_http_error_abuse_redis_record_failure(now);

        ctx->redis_pending = 0;
        ctx->redis_checked = 1;
        return NGX_DECLINED;
    }

    /* Async park: hold a reference so the request survives until the Redis
     * callback resumes it. Released by ngx_http_finalize_request(NGX_DONE)
     * in ngx_http_error_abuse_redis_check_callback. */
    r->main->count++;

    return NGX_AGAIN;
}

static void
ngx_http_error_abuse_redis_check_callback(redisAsyncContext *ac, void *data,
    void *privdata)
{
    redisReply                        *reply;
    ngx_http_request_t               *r;
    ngx_http_error_abuse_req_ctx_t   *ctx;

    r = privdata;
    ctx = ngx_http_get_module_ctx(r, ngx_http_error_abuse_module);
    if (ctx == NULL) {
        /* release the reference taken at park time */
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    reply = data;
    ctx->redis_pending = 0;
    ctx->redis_checked = 1;
    ctx->redis_blocked = 0;

    if (reply == NULL) {
        /* connection-level failure */
        ngx_http_error_abuse_redis_record_failure(ngx_time());
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "error_abuse: Redis check failed (consecutive=%ui)",
                      ngx_http_error_abuse_redis_worker.consecutive_failures);

    } else if (reply->type == REDIS_REPLY_STRING) {
        /* COR-4: the block value is the absolute Unix deadline. */
        time_t    now = ngx_time();
        ngx_int_t deadline = ngx_atoi((u_char *) reply->str, reply->len);
        ctx->redis_blocked = 1;
        ctx->blocked_until = (deadline > 0) ? (time_t) deadline
                                            : now + ctx->zone->block;
        /* Clamp a Redis-provided deadline to now+block (mirrors the snapshot
         * SNAP-CLAMP on load) so a rogue or corrupt block value cannot drive a
         * multi-decade Retry-After or local deadline. */
        if (ctx->blocked_until > now + ctx->zone->block) {
            ctx->blocked_until = now + ctx->zone->block;
        }
        ctx->count = ctx->zone->threshold;
        ngx_http_error_abuse_redis_worker.consecutive_failures = 0;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis check for client \"%V\" "
                       "returned BLOCKED until %T",
                       &ctx->raw_key, ctx->blocked_until);

    } else if (reply->type == REDIS_REPLY_NIL) {
        /* not blocked: a valid, successful answer — reset the breaker. */
        ngx_http_error_abuse_redis_worker.consecutive_failures = 0;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis check for client \"%V\" "
                       "returned not blocked", &ctx->raw_key);

    } else {
        /* COR-5: REDIS_REPLY_ERROR (NOAUTH, WRONGTYPE, ...) or an unexpected
         * type is a failure, not a success — trip the breaker. */
        ngx_http_error_abuse_redis_record_failure(ngx_time());
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "error_abuse: Redis check returned unexpected reply "
                      "type %d%s%s", reply->type,
                      reply->type == REDIS_REPLY_ERROR && reply->str
                          ? ": " : "",
                      reply->type == REDIS_REPLY_ERROR && reply->str
                          ? reply->str : "");
    }

    /* Resume the parked request, then release the reference taken at park
     * time. finalize(NGX_DONE) frees the request if nothing else holds it. */
    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, NGX_DONE);
}

/* COR-5: validate the record EVAL reply. The script returns {blocked, count}
 * (plus an optional deadline). OOM, ACL, read-only-replica, script and
 * protocol errors all arrive here; treat anything but the expected integer
 * array as a failure so the circuit breaker can trip. privdata is NULL — the
 * originating request is long gone, so log against the worker. */
static void
ngx_http_error_abuse_redis_record_callback(redisAsyncContext *ac, void *data,
    void *privdata)
{
    redisReply  *reply = data;

    if (reply == NULL) {
        ngx_http_error_abuse_redis_record_failure(ngx_time());
        return;
    }

    if (reply->type == REDIS_REPLY_ARRAY
        && reply->elements >= 2
        && reply->element[0]->type == REDIS_REPLY_INTEGER
        && reply->element[1]->type == REDIS_REPLY_INTEGER)
    {
        ngx_http_error_abuse_redis_worker.consecutive_failures = 0;
        return;
    }

    if (reply->type == REDIS_REPLY_ERROR && reply->str
        && ngx_strncmp(reply->str, "NOSCRIPT", 8) == 0)
    {
        /* The script cache was flushed (e.g. SCRIPT FLUSH on the server). This
         * one request's event is lost, but it is not a connection failure, so
         * do not trip the breaker; re-prime the cache so subsequent EVALSHA
         * calls succeed. */
        (void) redisAsyncCommand(ac,
            ngx_http_error_abuse_redis_handshake_callback, NULL,
            "SCRIPT LOAD %b",
            (const char *) ngx_http_error_abuse_redis_record_script,
            (size_t) (sizeof(ngx_http_error_abuse_redis_record_script) - 1));
        ngx_log_error(NGX_LOG_WARN, ngx_http_error_abuse_redis_worker.log, 0,
                      "error_abuse: Redis script cache miss (NOSCRIPT); "
                      "reloading record script");
        return;
    }

    ngx_http_error_abuse_redis_record_failure(ngx_time());
    ngx_log_error(NGX_LOG_WARN, ngx_http_error_abuse_redis_worker.log, 0,
                  "error_abuse: Redis EVAL returned unexpected reply (type %d)"
                  "%s%s", reply->type,
                  reply->type == REDIS_REPLY_ERROR && reply->str ? ": " : "",
                  reply->type == REDIS_REPLY_ERROR && reply->str
                      ? reply->str : "");
}

static void
ngx_http_error_abuse_redis_record(ngx_http_request_t *r,
    ngx_http_error_abuse_req_ctx_t *ctx)
{
    char        interval[NGX_INT64_LEN + 1];
    char        threshold[NGX_INT_T_LEN + 1];
    char        block_ms[NGX_INT64_LEN + 1];
    char        inactive[NGX_INT64_LEN + 1];
    char        nonce[NGX_INT64_LEN * 2 + 2];
    u_char     *p;
    time_t      now;
    ngx_str_t   events, block;
    const char *argv[10];
    size_t      argvlen[10];

    /* Circuit breaker / readiness: skip Redis when unavailable */
    now = ngx_time();
    if (!ngx_http_error_abuse_redis_available(now)
        || ngx_http_error_abuse_redis_keys(r->pool, ctx, &events, &block)
           != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis unavailable for record");
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "error_abuse: recording event to Redis for client \"%V\", "
                   "events_key=\"%V\", block_key=\"%V\"",
                   &ctx->raw_key, &events, &block);

#define NGX_ERROR_ABUSE_REDIS_NUMBER(buf, value)                              \
    (size_t) (ngx_snprintf((u_char *) (buf), sizeof(buf), "%L",               \
                           (int64_t) (value)) - (u_char *) (buf))

    argv[0] = "EVALSHA";
    argvlen[0] = 7;
    argv[1] = (const char *) ngx_http_error_abuse_script_sha;
    argvlen[1] = sizeof(ngx_http_error_abuse_script_sha);   /* 40 hex chars */
    argv[2] = "2";
    argvlen[2] = 1;
    argv[3] = (const char *) events.data;
    argvlen[3] = events.len;
    argv[4] = (const char *) block.data;
    argvlen[4] = block.len;
    argv[5] = interval;
    argvlen[5] = NGX_ERROR_ABUSE_REDIS_NUMBER(interval,
                                               ctx->zone->interval * 1000);
    argv[6] = threshold;
    argvlen[6] = NGX_ERROR_ABUSE_REDIS_NUMBER(threshold,
                                               ctx->zone->threshold);
    argv[7] = block_ms;
    argvlen[7] = NGX_ERROR_ABUSE_REDIS_NUMBER(block_ms,
                                               ctx->zone->block * 1000);
    argv[8] = inactive;
    argvlen[8] = NGX_ERROR_ABUSE_REDIS_NUMBER(inactive,
                                               ctx->zone->inactive * 1000);
    p = ngx_snprintf((u_char *) nonce, sizeof(nonce), "%uL:%ui",
                     ngx_http_error_abuse_redis_worker.nonce,
                     ++ngx_http_error_abuse_redis_worker.sequence);
    argv[9] = nonce;
    argvlen[9] = (size_t) (p - (u_char *) nonce);

    if (redisAsyncCommandArgv(ngx_http_error_abuse_redis_worker.context,
                              ngx_http_error_abuse_redis_record_callback,
                              NULL, 10, argv, argvlen) != REDIS_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "error_abuse could not queue Redis event");
    }

#undef NGX_ERROR_ABUSE_REDIS_NUMBER
}

/* nginx epoll is edge-triggered only, and redisAsyncHandleRead does a single
 * recv() per call, so a single notification can leave replies buffered in the
 * socket with no further edge. Drain: keep handling while poll() still reports
 * the fd readable. The context may be freed mid-drain (a reply callback can
 * trigger disconnect), so re-check it each iteration — the cleanup callback
 * NULLs adapter.context synchronously before the context is freed. */
static void
ngx_http_error_abuse_redis_read_handler(ngx_event_t *rev)
{
    ngx_connection_t                    *c;
    struct pollfd                        pfd;
    ngx_http_error_abuse_redis_event_t  *ev;

    c = rev->data;
    ev = c->data;

    while (ev->context != NULL) {
        redisAsyncHandleRead(ev->context);

        if (ev->context == NULL) {
            break;
        }

        pfd.fd = c->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN)) {
            break;
        }
    }
}

static void
ngx_http_error_abuse_redis_write_handler(ngx_event_t *wev)
{
    ngx_connection_t                    *c;
    ngx_http_error_abuse_redis_event_t  *ev;

    c = wev->data;
    ev = c->data;

    if (ev->context != NULL) {
        /* redisAsyncHandleWrite drains its own write buffer to EAGAIN */
        redisAsyncHandleWrite(ev->context);
    }
}

static void
ngx_http_error_abuse_redis_timeout_handler(ngx_event_t *t)
{
    ngx_http_error_abuse_redis_event_t *ev = t->data;

    if (ev->context != NULL) {
        redisAsyncHandleTimeout(ev->context);
    }
}

/* hiredis asks us to (re)arm a one-shot command-timeout timer. */
static void
ngx_http_error_abuse_redis_schedule_timer(void *privdata, struct timeval tv)
{
    ngx_msec_t                           t;
    ngx_http_error_abuse_redis_event_t  *ev = privdata;

    if (ev->conn == NULL) {
        return;
    }

    t = (ngx_msec_t) tv.tv_sec * 1000 + (ngx_msec_t) tv.tv_usec / 1000;
    if (t == 0) {
        t = 1;
    }

    if (ev->timeout.timer_set) {
        ngx_del_timer(&ev->timeout);
    }
    ngx_add_timer(&ev->timeout, t);
}

static void
ngx_http_error_abuse_redis_add_read(void *privdata)
{
    ngx_http_error_abuse_redis_event_t *ev = privdata;

    if (ev->conn != NULL && !ev->conn->read->active) {
        /* STAB-5: a failed registration leaves the context unable to receive
         * replies; mark the worker not ready so requests fail open to local
         * enforcement and the timeout/disconnect path can recover it. */
        if (ngx_handle_read_event(ev->conn->read, 0) != NGX_OK) {
            ngx_http_error_abuse_redis_worker.ready = 0;
            ngx_log_error(NGX_LOG_ERR, ev->conn->log, 0,
                          "error_abuse: ngx_handle_read_event failed for "
                          "Redis connection");
        }
    }
}

static void
ngx_http_error_abuse_redis_del_read(void *privdata)
{
    ngx_http_error_abuse_redis_event_t *ev = privdata;

    if (ev->conn != NULL && ev->conn->read->active) {
        (void) ngx_del_event(ev->conn->read, NGX_READ_EVENT, 0);
    }
}

static void
ngx_http_error_abuse_redis_add_write(void *privdata)
{
    ngx_http_error_abuse_redis_event_t *ev = privdata;

    if (ev->conn == NULL) {
        return;
    }

    if (!ev->conn->write->active) {
        if (ngx_handle_write_event(ev->conn->write, 0) != NGX_OK) {
            ngx_http_error_abuse_redis_worker.ready = 0;
            ngx_log_error(NGX_LOG_ERR, ev->conn->log, 0,
                          "error_abuse: ngx_handle_write_event failed for "
                          "Redis connection");
        }
    }

    /* Edge-triggered epoll only signals empty->writable transitions. Once the
     * connect edge is consumed the socket stays writable with no further edge,
     * so a freshly queued command would never flush. If the socket is already
     * writable, post the write handler to run it this event cycle. */
    if (ev->conn->write->ready) {
        ngx_post_event(ev->conn->write, &ngx_posted_events);
    }
}

static void
ngx_http_error_abuse_redis_del_write(void *privdata)
{
    ngx_http_error_abuse_redis_event_t *ev = privdata;

    if (ev->conn != NULL && ev->conn->write->active) {
        (void) ngx_del_event(ev->conn->write, NGX_WRITE_EVENT, 0);
    }
}

/* hiredis calls this just before it closes the fd and frees the context.
 * Detach the nginx connection (delete its epoll events, return the slot) but
 * leave the fd open — hiredis closes it. Never free the adapter struct itself;
 * it lives in the worker and may be on the stack of redis_read_handler. */
static void
ngx_http_error_abuse_redis_cleanup(void *privdata)
{
    ngx_connection_t                    *c;
    ngx_http_error_abuse_redis_event_t  *ev = privdata;

    c = ev->conn;
    ev->context = NULL;
    ev->conn = NULL;

    if (c == NULL) {
        return;
    }

    if (c->read->active) {
        (void) ngx_del_event(c->read, NGX_READ_EVENT, 0);
    }
    if (c->write->active) {
        (void) ngx_del_event(c->write, NGX_WRITE_EVENT, 0);
    }
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    if (ev->timeout.timer_set) {
        ngx_del_timer(&ev->timeout);
    }
    if (c->read->posted) {
        ngx_delete_posted_event(c->read);
    }
    if (c->write->posted) {
        ngx_delete_posted_event(c->write);
    }

    ngx_free_connection(c);
    c->fd = (ngx_socket_t) -1;
}

static ngx_int_t
ngx_http_error_abuse_redis_attach(redisAsyncContext *ac, ngx_log_t *log)
{
    ngx_connection_t                    *c;
    ngx_http_error_abuse_redis_event_t  *ev;

    if (ac->ev.addRead != NULL) {
        /* already attached to an event loop */
        return NGX_ERROR;
    }

    c = ngx_get_connection(ac->c.fd, log);
    if (c == NULL) {
        return NGX_ERROR;
    }

    c->log = log;
    c->read->log = log;
    c->write->log = log;
    c->read->handler = ngx_http_error_abuse_redis_read_handler;
    c->write->handler = ngx_http_error_abuse_redis_write_handler;

    ev = &ngx_http_error_abuse_redis_worker.adapter;
    ev->context = ac;
    ev->conn = c;
    ev->timeout.handler = ngx_http_error_abuse_redis_timeout_handler;
    ev->timeout.data = ev;
    ev->timeout.log = log;
    ev->timeout.cancelable = 1;
    c->data = ev;

    ac->ev.data = ev;
    ac->ev.addRead = ngx_http_error_abuse_redis_add_read;
    ac->ev.delRead = ngx_http_error_abuse_redis_del_read;
    ac->ev.addWrite = ngx_http_error_abuse_redis_add_write;
    ac->ev.delWrite = ngx_http_error_abuse_redis_del_write;
    ac->ev.scheduleTimer = ngx_http_error_abuse_redis_schedule_timer;
    ac->ev.cleanup = ngx_http_error_abuse_redis_cleanup;

    return NGX_OK;
}

static void
ngx_http_error_abuse_redis_handshake_callback(redisAsyncContext *ac,
    void *data, void *privdata)
{
    redisReply                          *reply = data;
    ngx_http_error_abuse_redis_worker_t *worker = ac->data;

    if (reply == NULL) {
        /* connection-level error; disconnect callback drives reconnect */
        return;
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        worker->ready = 0;
        ngx_log_error(NGX_LOG_ERR, worker->log, 0,
                      "error_abuse: Redis handshake (AUTH/SELECT) failed: %s",
                      reply->str ? reply->str : "(unknown)");
    }
}

static void
ngx_http_error_abuse_redis_connect_callback(const redisAsyncContext *ac,
    int status)
{
    ngx_http_error_abuse_redis_worker_t *worker;
    int                                  rc = REDIS_OK;

    worker = ac->data;
    if (status == REDIS_OK) {
        worker->ready = 1;
        worker->reconnect_backoff = 0;   /* PERF-4: reset on success */
        ngx_log_error(NGX_LOG_NOTICE, worker->log, 0,
                      "error_abuse connected to Redis at \"%V:%ui\"",
                      &worker->conf->host, worker->conf->port);

        /* Send AUTH and SELECT first; hiredis preserves command order so
         * these complete before any GET/EVAL queued by a request. COR-5: if a
         * handshake command cannot even be queued, the connection is unusable —
         * disconnect so the reconnect path retries cleanly. */
        if (worker->conf->password.len) {
            if (worker->conf->user.len) {
                rc = redisAsyncCommand(worker->context,
                    ngx_http_error_abuse_redis_handshake_callback, NULL,
                    "AUTH %b %b",
                    worker->conf->user.data,
                    (size_t) worker->conf->user.len,
                    worker->conf->password.data,
                    (size_t) worker->conf->password.len);
            } else {
                rc = redisAsyncCommand(worker->context,
                    ngx_http_error_abuse_redis_handshake_callback, NULL,
                    "AUTH %b",
                    worker->conf->password.data,
                    (size_t) worker->conf->password.len);
            }
        }
        if (rc == REDIS_OK && worker->conf->db > 0) {
            rc = redisAsyncCommand(worker->context,
                ngx_http_error_abuse_redis_handshake_callback, NULL,
                "SELECT %d", (int) worker->conf->db);
        }
        if (rc == REDIS_OK) {
            /* Prime the script cache so request-path EVALSHA calls hit. hiredis
             * preserves order, so this completes before any queued EVALSHA. */
            rc = redisAsyncCommand(worker->context,
                ngx_http_error_abuse_redis_handshake_callback, NULL,
                "SCRIPT LOAD %b",
                (const char *) ngx_http_error_abuse_redis_record_script,
                (size_t) (sizeof(ngx_http_error_abuse_redis_record_script) - 1));
        }
        if (rc != REDIS_OK) {
            worker->ready = 0;
            ngx_log_error(NGX_LOG_ERR, worker->log, 0,
                          "error_abuse: failed to queue Redis handshake; "
                          "disconnecting");
            if (worker->context != NULL) {
                redisAsyncDisconnect(worker->context);
            }
        }
    } else {
        worker->ready = 0;
        ngx_log_error(NGX_LOG_WARN, worker->log, 0,
                      "error_abuse Redis connection failed: %s", ac->errstr);
    }
}

static void
ngx_http_error_abuse_redis_disconnect_callback(const redisAsyncContext *ac,
    int status)
{
    ngx_http_error_abuse_redis_worker_t *worker;

    worker = ac->data;
    worker->context = NULL;
    worker->ready = 0;
    ngx_http_error_abuse_redis_arm_reconnect();
}

static ngx_int_t
ngx_http_error_abuse_redis_connect(void)
{
    struct timeval                       timeout;
    redisAsyncContext                   *ac;
    ngx_http_error_abuse_redis_worker_t *worker;

    worker = &ngx_http_error_abuse_redis_worker;
    ac = redisAsyncConnect((char *) worker->conf->host.data,
                           worker->conf->port);
    if (ac == NULL) {
        return NGX_ERROR;
    }
    if (ac->err) {
        redisAsyncFree(ac);
        return NGX_ERROR;
    }

    /* TLS: must initiate the SSL session before attaching the event adapter
     * and before any command is queued. Verifies the server certificate
     * against the system CA store (capath) and the hostname (server_name). */
    if (worker->conf->tls) {
        if (worker->ssl == NULL) {
            redisSSLContextError ssl_err = REDIS_SSL_CTX_NONE;

            redisInitOpenSSL();
            worker->ssl = redisCreateSSLContext(
                NULL, "/etc/ssl/certs", NULL, NULL,
                (char *) worker->conf->sni.data, &ssl_err);
            if (worker->ssl == NULL) {
                ngx_log_error(NGX_LOG_ERR, worker->log, 0,
                    "error_abuse: Redis TLS context init failed: %s",
                    redisSSLContextGetError(ssl_err));
                redisAsyncFree(ac);
                return NGX_ERROR;
            }
        }
        if (redisInitiateSSLWithContext(&ac->c, worker->ssl) != REDIS_OK) {
            ngx_log_error(NGX_LOG_ERR, worker->log, 0,
                "error_abuse: Redis TLS handshake init failed: %s",
                ac->c.errstr);
            redisAsyncFree(ac);
            return NGX_ERROR;
        }
    }

    ac->data = worker;
    if (ngx_http_error_abuse_redis_attach(ac, worker->log) != NGX_OK) {
        redisAsyncFree(ac);
        return NGX_ERROR;
    }

    worker->context = ac;
    timeout.tv_sec = worker->conf->timeout / 1000;
    timeout.tv_usec = (worker->conf->timeout % 1000) * 1000;
    (void) redisAsyncSetTimeout(ac, timeout);
    (void) redisAsyncSetConnectCallback(
        ac, ngx_http_error_abuse_redis_connect_callback);
    (void) redisAsyncSetDisconnectCallback(
        ac, ngx_http_error_abuse_redis_disconnect_callback);

    return NGX_OK;
}

/* PERF-4: arm the reconnect timer with capped exponential backoff and
 * per-worker jitter so an outage does not produce a synchronized 1 Hz
 * reconnect storm across every worker. Reset by a successful connect. */
static void
ngx_http_error_abuse_redis_arm_reconnect(void)
{
    ngx_http_error_abuse_redis_worker_t *w;
    ngx_msec_t                           base, delay, jitter;

    w = &ngx_http_error_abuse_redis_worker;
    if (w->exiting || w->reconnect.timer_set) {
        return;
    }

    base = w->reconnect_backoff ? w->reconnect_backoff
                                : NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT;

    /* delay in [0.75*base, 1.25*base) */
    jitter = (ngx_msec_t) (ngx_random() % (base / 2 + 1));
    delay = base - base / 4 + jitter;

    w->reconnect_backoff =
        (base * 2 > NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT_MAX)
            ? NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT_MAX
            : base * 2;

    ngx_add_timer(&w->reconnect, delay);
}

static void
ngx_http_error_abuse_redis_reconnect(ngx_event_t *ev)
{
    ngx_http_error_abuse_redis_worker_t *worker;

    worker = ev->data;
    if (!worker->exiting && ngx_http_error_abuse_redis_connect() != NGX_OK)
    {
        ngx_http_error_abuse_redis_arm_reconnect();
    }
}

static ngx_int_t
ngx_http_error_abuse_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                         i;
    ngx_http_error_abuse_zone_t      **zones;
    ngx_http_error_abuse_main_conf_t  *mcf;

    mcf = ngx_http_cycle_get_module_main_conf(cycle,
                                              ngx_http_error_abuse_module);
    if (mcf == NULL) {
        return NGX_OK;
    }

    /* STAB-3: cache manager/loader helpers also call init_process. They never
     * serve HTTP, so they must not open Redis connections, reconnect timers,
     * TLS contexts or persistence timers. Only real request-serving processes
     * proceed; worker-0 restriction below applies to persistence only. */
    if (ngx_process != NGX_PROCESS_SINGLE
        && ngx_process != NGX_PROCESS_WORKER)
    {
        return NGX_OK;
    }

    if (mcf->redis.configured) {
        static const u_char  hex[] = "0123456789abcdef";
        u_char               digest[20];
        ngx_uint_t           k;

        /* Precompute the EVALSHA digest of the (constant) record script. */
        SHA1((const unsigned char *) ngx_http_error_abuse_redis_record_script,
             sizeof(ngx_http_error_abuse_redis_record_script) - 1, digest);
        for (k = 0; k < 20; k++) {
            ngx_http_error_abuse_script_sha[k * 2] = hex[digest[k] >> 4];
            ngx_http_error_abuse_script_sha[k * 2 + 1] = hex[digest[k] & 0x0f];
        }

        ngx_memzero(&ngx_http_error_abuse_redis_worker,
                    sizeof(ngx_http_error_abuse_redis_worker));
        ngx_http_error_abuse_redis_worker.conf = &mcf->redis;
        ngx_http_error_abuse_redis_worker.log = cycle->log;
        ngx_http_error_abuse_redis_worker.nonce =
            ((uint64_t) ngx_current_msec << 32)
            ^ (uint64_t) ngx_random()
            ^ (uint64_t) ngx_pid;
        ngx_http_error_abuse_redis_worker.reconnect.handler =
            ngx_http_error_abuse_redis_reconnect;
        ngx_http_error_abuse_redis_worker.reconnect.data =
            &ngx_http_error_abuse_redis_worker;
        ngx_http_error_abuse_redis_worker.reconnect.log = cycle->log;
        ngx_http_error_abuse_redis_worker.reconnect.cancelable = 1;
        if (ngx_http_error_abuse_redis_connect() != NGX_OK) {
            ngx_http_error_abuse_redis_arm_reconnect();
        }
    }

    if (ngx_process != NGX_PROCESS_SINGLE
        && (ngx_process != NGX_PROCESS_WORKER || ngx_worker != 0))
    {
        return NGX_OK;
    }

    zones = mcf->zones.elts;
    for (i = 0; i < mcf->zones.nelts; i++) {
        if (zones[i]->persist.len == 0) {
            continue;
        }

        ngx_memzero(&zones[i]->persist_event, sizeof(ngx_event_t));
        zones[i]->persist_event.handler =
            ngx_http_error_abuse_persist_handler;
        zones[i]->persist_event.data = zones[i];
        zones[i]->persist_event.log = cycle->log;
        zones[i]->persist_event.cancelable = 1;

#if (NGX_THREADS)
        /* PERF-1: one reusable thread task per zone (guarded by persist_busy,
         * so only one save is ever in flight). */
        zones[i]->persist_task = ngx_thread_task_alloc(cycle->pool,
            sizeof(ngx_http_error_abuse_save_ctx_t));
        if (zones[i]->persist_task != NULL) {
            ngx_http_error_abuse_save_ctx_t *tctx =
                zones[i]->persist_task->ctx;
            tctx->zone = zones[i];
            zones[i]->persist_task->handler =
                ngx_http_error_abuse_persist_thread;
            zones[i]->persist_task->event.handler =
                ngx_http_error_abuse_persist_complete;
            zones[i]->persist_task->event.data = tctx;
        }
#endif

        ngx_add_timer(&zones[i]->persist_event,
                      zones[i]->persist_interval);
    }

    return NGX_OK;
}

static void
ngx_http_error_abuse_exit_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                         i;
    ngx_http_error_abuse_zone_t      **zones;
    ngx_http_error_abuse_main_conf_t  *mcf;

    if (ngx_http_error_abuse_redis_worker.conf != NULL) {
        ngx_http_error_abuse_redis_worker.exiting = 1;
        if (ngx_http_error_abuse_redis_worker.reconnect.timer_set) {
            ngx_del_timer(&ngx_http_error_abuse_redis_worker.reconnect);
        }
        if (ngx_http_error_abuse_redis_worker.context != NULL) {
            redisAsyncFree(ngx_http_error_abuse_redis_worker.context);
            ngx_http_error_abuse_redis_worker.context = NULL;
        }
        if (ngx_http_error_abuse_redis_worker.ssl != NULL) {
            redisFreeSSLContext(ngx_http_error_abuse_redis_worker.ssl);
            ngx_http_error_abuse_redis_worker.ssl = NULL;
        }
    }

    mcf = ngx_http_cycle_get_module_main_conf(cycle,
                                              ngx_http_error_abuse_module);
    if (mcf == NULL) {
        return;
    }

    if (ngx_process != NGX_PROCESS_SINGLE
        && (ngx_process != NGX_PROCESS_WORKER || ngx_worker != 0))
    {
        return;
    }

    zones = mcf->zones.elts;
    for (i = 0; i < mcf->zones.nelts; i++) {
        if (zones[i]->persist.len != 0) {
            (void) ngx_http_error_abuse_save(zones[i], cycle->log);
            /* Release the reused serialize buffer (the thread pool has already
             * been drained by its own earlier exit handler, so no in-flight
             * write still references it). */
            if (zones[i]->persist_buf != NULL) {
                ngx_free(zones[i]->persist_buf);
                zones[i]->persist_buf = NULL;
                zones[i]->persist_buf_cap = 0;
            }
        }
    }
}

#if (NGX_THREADS)
static void
ngx_http_error_abuse_persist_thread(void *data, ngx_log_t *log)
{
    ngx_http_error_abuse_save_ctx_t  *ctx = data;

    ctx->rc = ngx_http_error_abuse_write_file(ctx->buffer, ctx->len,
                                              &ctx->zone->persist, log);
}

static void
ngx_http_error_abuse_persist_complete(ngx_event_t *ev)
{
    ngx_http_error_abuse_save_ctx_t  *ctx = ev->data;

    /* ctx->buffer points at the zone-owned reusable serialize buffer; the next
     * serialize reuses it. Just clear the handle and release the in-flight
     * guard so the next tick can serialize again. */
    ctx->buffer = NULL;
    ctx->zone->persist_busy = 0;
}
#endif

static void
ngx_http_error_abuse_persist_handler(ngx_event_t *ev)
{
    ngx_http_error_abuse_zone_t  *zone;

    zone = ev->data;

#if (NGX_THREADS)
    {
        ngx_thread_pool_t  *tp;
        ngx_str_t           tp_name = ngx_string("default");

        tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &tp_name);
        if (tp != NULL && zone->persist_task != NULL) {
            if (!zone->persist_busy) {
                ngx_http_error_abuse_save_ctx_t *ctx = zone->persist_task->ctx;

                ctx->buffer = ngx_http_error_abuse_serialize(zone, ev->log,
                                                             &ctx->len);
                if (ctx->buffer != NULL) {
                    zone->persist_busy = 1;
                    if (ngx_thread_task_post(tp, zone->persist_task)
                        != NGX_OK)
                    {
                        /* Could not queue: fall back to a synchronous write
                         * this tick rather than dropping the snapshot. The
                         * buffer is zone-owned and reused — do not free. */
                        zone->persist_busy = 0;
                        (void) ngx_http_error_abuse_write_file(ctx->buffer,
                            ctx->len, &zone->persist, ev->log);
                        ctx->buffer = NULL;
                    }
                }
            }
            /* busy: a previous save is still in flight — skip this tick. */
            ngx_add_timer(ev, zone->persist_interval);
            return;
        }
    }
#endif

    (void) ngx_http_error_abuse_save(zone, ev->log);
    ngx_add_timer(ev, zone->persist_interval);
}

static ngx_int_t
ngx_http_error_abuse_write_all(ngx_fd_t fd, u_char *data, size_t len)
{
    ssize_t  n;

    while (len != 0) {
        n = ngx_write_fd(fd, data, len);
        if (n > 0) {
            data += n;
            len -= (size_t) n;
            continue;
        }

        if (n == NGX_ERROR && ngx_errno == NGX_EINTR) {
            continue;
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_read_all(ngx_fd_t fd, u_char *data, size_t len)
{
    ssize_t  n;

    while (len != 0) {
        n = ngx_read_fd(fd, data, len);
        if (n > 0) {
            data += n;
            len -= (size_t) n;
            continue;
        }

        if (n == NGX_ERROR && ngx_errno == NGX_EINTR) {
            continue;
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}

/* STAB-2: fsync the directory containing `path` so a rename into it survives a
 * crash. Best-effort: logs but does not fail the save on error. */
static void
ngx_http_error_abuse_fsync_dir(u_char *path, ngx_log_t *log)
{
    u_char    *slash;
    ngx_fd_t   dfd;
    u_char     dir[NGX_MAX_PATH];
    size_t     len;

    slash = (u_char *) strrchr((char *) path, '/');
    if (slash == NULL || slash == path) {
        ngx_memcpy(dir, slash == path ? (u_char *) "/" : (u_char *) ".", 2);
    } else {
        len = slash - path;
        if (len >= sizeof(dir)) {
            return;
        }
        ngx_memcpy(dir, path, len);
        dir[len] = '\0';
    }

    dfd = open((const char *) dir, O_RDONLY|O_DIRECTORY);
    if (dfd == -1) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "open(\"%s\") for fsync failed", dir);
        return;
    }
    if (fsync(dfd) == -1) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "fsync(\"%s\") failed", dir);
    }
    (void) close(dfd);
}

/* PERF-1: serialize the whole zone into a freshly allocated heap buffer while
 * holding the slab mutex only for the copy (no I/O under the lock). Returns the
 * buffer (caller frees with ngx_free) and its length, or NULL. */
static u_char *
ngx_http_error_abuse_serialize(ngx_http_error_abuse_zone_t *zone,
    ngx_log_t *log, size_t *outlen)
{
    u_char                       *buffer, *p, *last, *h;
    size_t                        capacity, key_len, total;
    uint32_t                      records, crc;
    ngx_uint_t                    i;
    ngx_queue_t                  *q;
    time_t                       *events;
    ngx_http_error_abuse_node_t  *ean;

    capacity = zone->shm_zone->shm.size;
    /* SEC-5: reserve room for the trailing HMAC when a secret is configured.
     * PERF: serialize runs single-threaded (event loop, never concurrent with
     * an in-flight write — persist_busy gates that), so keep one grow-only
     * buffer per zone instead of mmap/munmap-ing the whole shm size every
     * persist tick. Owned by the zone; never freed by the caller. */
    {
        size_t  need = capacity + NGX_HTTP_ERROR_ABUSE_MAC_LEN;

        if (zone->persist_buf == NULL || zone->persist_buf_cap < need) {
            u_char  *nb = ngx_alloc(need, log);
            if (nb == NULL) {
                return NULL;
            }
            if (zone->persist_buf != NULL) {
                ngx_free(zone->persist_buf);
            }
            zone->persist_buf = nb;
            zone->persist_buf_cap = need;
        }
    }
    buffer = zone->persist_buf;

    p = buffer + NGX_HTTP_ERROR_ABUSE_FILE_HDR_LEN;
    last = buffer + capacity;
    records = 0;

    ngx_shmtx_lock(&zone->shpool->mutex);

    for (q = ngx_queue_last(&zone->sh->queue);
         q != ngx_queue_sentinel(&zone->sh->queue);
         q = ngx_queue_prev(q))
    {
        ean = ngx_queue_data(q, ngx_http_error_abuse_node_t, queue);
        key_len = ean->key_len;

        if ((size_t) (last - p)
            < NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN + key_len
              + (size_t) ean->event_count * 8)
        {
            break;
        }

        /* RFC-3: each field written explicitly little-endian. */
        p = ngx_http_error_abuse_put_u16(p, (uint16_t) ean->key_len);
        p = ngx_http_error_abuse_put_u16(p, (uint16_t) ean->event_count);
        p = ngx_http_error_abuse_put_u64(p, (uint64_t) ean->blocked_until);
        p = ngx_http_error_abuse_put_u64(p, (uint64_t) ean->last_seen);
        p = ngx_cpymem(p, ean->data, key_len);

        events = ngx_http_error_abuse_events(ean);
        for (i = 0; i < ean->event_count; i++) {
            p = ngx_http_error_abuse_put_u64(p, (uint64_t)
                events[(ean->event_head + i) % zone->threshold]);
        }
        records++;
    }

    ngx_shmtx_unlock(&zone->shpool->mutex);

    /* RFC-3: header is magic(8) + version + threshold + records + crc32, all
     * little-endian. CRC32 covers the payload after the header. */
    crc = ngx_crc32_long(buffer + NGX_HTTP_ERROR_ABUSE_FILE_HDR_LEN,
                         p - buffer - NGX_HTTP_ERROR_ABUSE_FILE_HDR_LEN);
    h = buffer;
    ngx_memcpy(h, NGX_HTTP_ERROR_ABUSE_FILE_MAGIC,
               NGX_HTTP_ERROR_ABUSE_FILE_MAGIC_LEN);
    h += NGX_HTTP_ERROR_ABUSE_FILE_MAGIC_LEN;
    h = ngx_http_error_abuse_put_u32(h, NGX_HTTP_ERROR_ABUSE_VERSION);
    h = ngx_http_error_abuse_put_u32(h, (uint32_t) zone->threshold);
    h = ngx_http_error_abuse_put_u32(h, records);
    h = ngx_http_error_abuse_put_u32(h, crc);

    total = (size_t) (p - buffer);

    /* SEC-5: authenticate header + payload with HMAC-SHA256 (appended). */
    if (zone->persist_secret.len != 0) {
        unsigned int maclen = NGX_HTTP_ERROR_ABUSE_MAC_LEN;
        if (HMAC(EVP_sha256(), zone->persist_secret.data,
                 (int) zone->persist_secret.len, buffer, total,
                 p, &maclen) == NULL
            || maclen != NGX_HTTP_ERROR_ABUSE_MAC_LEN)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "error_abuse: HMAC computation failed for \"%V\"",
                          &zone->persist);
            return NULL;   /* buffer is zone-owned; reused next tick */
        }
        p += NGX_HTTP_ERROR_ABUSE_MAC_LEN;
    }

    *outlen = (size_t) (p - buffer);
    return buffer;
}

/* PERF-1: write a prepared snapshot buffer to disk. Pure I/O — no shared
 * memory, no mutex — so it is safe to run on a thread-pool task off the event
 * loop. Does not free `buffer`. */
static ngx_int_t
ngx_http_error_abuse_write_file(u_char *buffer, size_t len,
    ngx_str_t *persist, ngx_log_t *log)
{
    u_char     *tmp;
    ngx_fd_t    fd;
    ngx_uint_t  i;

    tmp = ngx_alloc(persist->len + 64, log);
    if (tmp == NULL) {
        return NGX_ERROR;
    }

    /* SEC-4: create the temp exclusively (O_CREAT|O_EXCL|O_NOFOLLOW) with an
     * unpredictable suffix, retrying on collision, so no pre-created symlink
     * can redirect our write. */
    fd = NGX_INVALID_FILE;
    for (i = 0; i < 8; i++) {
        ngx_sprintf(tmp, "%V.tmp.%P.%xL%Z", persist, ngx_pid,
                    (uint64_t) ngx_random() ^ ((uint64_t) ngx_random() << 24)
                    ^ ((uint64_t) i << 48));
        fd = ngx_open_file(tmp, NGX_FILE_WRONLY,
                           O_CREAT|O_EXCL|O_NOFOLLOW, NGX_FILE_OWNER_ACCESS);
        if (fd != NGX_INVALID_FILE || ngx_errno != NGX_EEXIST) {
            break;
        }
    }
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", tmp);
        ngx_free(tmp);
        return NGX_ERROR;
    }

    if (ngx_http_error_abuse_write_all(fd, buffer, len) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      ngx_write_fd_n " \"%s\" failed", tmp);
        (void) ngx_close_file(fd);
        (void) ngx_delete_file(tmp);
        ngx_free(tmp);
        return NGX_ERROR;
    }

    /* STAB-2: flush data before the rename so a crash cannot leave an empty
     * renamed snapshot. */
    if (fsync(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "fsync() \"%s\" failed", tmp);
        (void) ngx_close_file(fd);
        (void) ngx_delete_file(tmp);
        ngx_free(tmp);
        return NGX_ERROR;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", tmp);
        (void) ngx_delete_file(tmp);
        ngx_free(tmp);
        return NGX_ERROR;
    }

    if (ngx_rename_file(tmp, persist->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      ngx_rename_file_n " \"%s\" to \"%V\" failed",
                      tmp, persist);
        (void) ngx_delete_file(tmp);
        ngx_free(tmp);
        return NGX_ERROR;
    }

    /* STAB-2: fsync the parent directory so the rename itself is durable. */
    ngx_http_error_abuse_fsync_dir(persist->data, log);

    ngx_free(tmp);
    return NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_save(ngx_http_error_abuse_zone_t *zone, ngx_log_t *log)
{
    u_char     *buffer;
    size_t      len;
    ngx_int_t   rc;

    buffer = ngx_http_error_abuse_serialize(zone, log, &len);
    if (buffer == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_error_abuse_write_file(buffer, len, &zone->persist, log);
    /* buffer is zone-owned and reused on the next serialize — do not free. */
    return rc;
}

static ngx_int_t
ngx_http_error_abuse_load(ngx_http_error_abuse_zone_t *zone, ngx_log_t *log)
{
    u_char                       *buffer, *p, *last;
    off_t                         file_size;
    size_t                        mac_len, payload_size;
    uint32_t                      hash, record_index;
    uint32_t                      loaded, dropped, f_records;
    uint16_t                      rec_key_len, rec_event_count;
    int64_t                       rec_blocked, rec_seen, stored_when;
    ngx_fd_t                      fd;
    ngx_file_info_t               fi;
    ngx_uint_t                    i;
    time_t                        now, *events;
    ngx_str_t                     key;
    ngx_http_error_abuse_node_t  *ean;

    fd = ngx_open_file(zone->persist.data, NGX_FILE_RDONLY,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        if (ngx_errno != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          ngx_open_file_n " \"%V\" failed", &zone->persist);
        }
        return NGX_OK;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      ngx_fd_info_n " \"%V\" failed", &zone->persist);
        (void) ngx_close_file(fd);
        return NGX_OK;
    }

    mac_len = (zone->persist_secret.len != 0)
              ? NGX_HTTP_ERROR_ABUSE_MAC_LEN : 0;

    file_size = ngx_file_size(&fi);
    if (file_size < (off_t) (NGX_HTTP_ERROR_ABUSE_FILE_HDR_LEN + mac_len)
        || file_size > (off_t) (zone->shm_zone->shm.size + mac_len))
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "error_abuse persistence file \"%V\" has invalid size",
                      &zone->persist);
        (void) ngx_close_file(fd);
        return NGX_OK;
    }

    buffer = ngx_alloc((size_t) file_size, log);
    if (buffer == NULL) {
        (void) ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (ngx_http_error_abuse_read_all(fd, buffer, (size_t) file_size)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      ngx_read_fd_n " \"%V\" failed", &zone->persist);
        (void) ngx_close_file(fd);
        ngx_free(buffer);
        return NGX_OK;
    }

    (void) ngx_close_file(fd);

    payload_size = (size_t) file_size - mac_len;

    /* SEC-5: verify the trailing HMAC over header+payload before trusting any
     * field. A mismatch means tampering or wrong key — ignore the file (do not
     * delete; the operator may have rotated the key). */
    if (mac_len != 0) {
        u_char        mac[NGX_HTTP_ERROR_ABUSE_MAC_LEN];
        unsigned int  maclen = NGX_HTTP_ERROR_ABUSE_MAC_LEN;

        if (HMAC(EVP_sha256(), zone->persist_secret.data,
                 (int) zone->persist_secret.len, buffer, payload_size,
                 mac, &maclen) == NULL
            || maclen != NGX_HTTP_ERROR_ABUSE_MAC_LEN
            || CRYPTO_memcmp(mac, buffer + payload_size,
                             NGX_HTTP_ERROR_ABUSE_MAC_LEN) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "error_abuse persistence file \"%V\" failed HMAC "
                          "verification; ignoring", &zone->persist);
            ngx_free(buffer);
            return NGX_OK;
        }
    }

    /* RFC-3: parse the little-endian header. */
    if (ngx_memcmp(buffer, NGX_HTTP_ERROR_ABUSE_FILE_MAGIC,
                   NGX_HTTP_ERROR_ABUSE_FILE_MAGIC_LEN) != 0
        || ngx_http_error_abuse_get_u32(buffer + 8)
           != NGX_HTTP_ERROR_ABUSE_VERSION
        || ngx_http_error_abuse_get_u32(buffer + 12) != zone->threshold)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "error_abuse persistence file \"%V\" is incompatible",
                      &zone->persist);
        ngx_free(buffer);
        return NGX_OK;
    }
    f_records = ngx_http_error_abuse_get_u32(buffer + 16);

    p = buffer + NGX_HTTP_ERROR_ABUSE_FILE_HDR_LEN;
    last = buffer + payload_size;

    /* Verify CRC32 checksum to detect corruption */
    if (ngx_http_error_abuse_get_u32(buffer + 20)
        != ngx_crc32_long(p, last - p))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "error_abuse persistence file \"%V\" is corrupted "
                      "(CRC32 mismatch), deleting",
                      &zone->persist);
        ngx_free(buffer);
        (void) ngx_delete_file((u_char *) zone->persist.data);
        return NGX_OK;
    }

    if (ngx_http_error_abuse_validate_snapshot(zone, p, last, f_records)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "error_abuse persistence file \"%V\" is malformed",
                      &zone->persist);
        ngx_free(buffer);
        return NGX_OK;
    }

    now = ngx_time();
    loaded = 0;
    dropped = 0;

    ngx_shmtx_lock(&zone->shpool->mutex);

    for (record_index = 0; record_index < f_records; record_index++) {
        if ((size_t) (last - p) < NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN) {
            dropped = f_records - record_index;
            break;
        }

        rec_key_len = ngx_http_error_abuse_get_u16(p);
        rec_event_count = ngx_http_error_abuse_get_u16(p + 2);
        rec_blocked = (int64_t) ngx_http_error_abuse_get_u64(p + 4);
        rec_seen = (int64_t) ngx_http_error_abuse_get_u64(p + 12);
        p += NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN;

        if (rec_key_len != NGX_HTTP_ERROR_ABUSE_DIGEST_LEN
            || rec_event_count > zone->threshold
            || (size_t) (last - p)
               < (size_t) rec_key_len + (size_t) rec_event_count * 8)
        {
            dropped += f_records - record_index;
            break;
        }

        key.data = p;
        key.len = rec_key_len;
        p += rec_key_len;

        if (rec_blocked <= (int64_t) now && rec_event_count == 0) {
            continue;
        }

        hash = ngx_crc32_short(key.data, key.len);
        ean = ngx_http_error_abuse_lookup(zone, hash, &key);
        if (ean == NULL) {
            ean = ngx_http_error_abuse_create_node(zone, hash, &key, now);
            if (ean == NULL) {
                /* STAB-4: shared memory exhausted mid-load; remaining records
                 * are dropped. Report rather than appear healthy. */
                dropped += f_records - record_index;
                break;
            }
        }

        /* Clamp a restored ban to at most now+block so a forged or stale
         * snapshot cannot install a ban decades in the future (and the
         * (time_t) cast cannot truncate on 32-bit) — mirrors STAB-1. */
        if (rec_blocked > (int64_t) now) {
            int64_t max_deadline = (int64_t) now + (int64_t) zone->block;
            ean->blocked_until = (time_t) (rec_blocked < max_deadline
                                           ? rec_blocked : max_deadline);
        } else {
            ean->blocked_until = 0;
        }
        ean->last_seen = (rec_seen > 0 && rec_seen <= (int64_t) now)
                         ? (time_t) rec_seen : now;
        ean->event_head = 0;
        ean->event_count = 0;
        events = ngx_http_error_abuse_events(ean);

        for (i = 0; i < rec_event_count; i++) {
            stored_when = (int64_t) ngx_http_error_abuse_get_u64(p);
            p += 8;
            if (stored_when > (int64_t) (now - zone->interval)
                && stored_when <= (int64_t) now)
            {
                events[ean->event_count++] = (time_t) stored_when;
            }
        }
        loaded++;
    }

    ngx_shmtx_unlock(&zone->shpool->mutex);
    ngx_free(buffer);

    if (dropped != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "error_abuse persistence file \"%V\" partially loaded: "
                      "%uD records restored, %uD dropped (insufficient shared "
                      "memory or truncated file)",
                      &zone->persist, loaded, dropped);
    } else {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "error_abuse persistence file \"%V\" loaded: %uD records",
                      &zone->persist, loaded);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_validate_snapshot(ngx_http_error_abuse_zone_t *zone,
    u_char *p, u_char *last, uint32_t records)
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
            || rec_event_count > zone->threshold)
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

static ngx_http_error_abuse_req_ctx_t *
ngx_http_error_abuse_get_req_ctx(ngx_http_request_t *r)
{
    return ngx_http_get_module_ctx(r, ngx_http_error_abuse_module);
}

static ngx_int_t
ngx_http_error_abuse_set_variable(ngx_http_variable_value_t *v,
    u_char *data, size_t len)
{
    v->data = data;
    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_variable_status(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    static ngx_str_t states[] = {
        ngx_string("BYPASSED"),
        ngx_string("PASSED"),
        ngx_string("COUNTED"),
        ngx_string("BLOCKED"),
        ngx_string("DRY_RUN")
    };
    ngx_http_error_abuse_req_ctx_t  *ctx;

    ctx = ngx_http_error_abuse_get_req_ctx(r);
    if (ctx == NULL || ctx->state > NGX_HTTP_ERROR_ABUSE_DRY_RUN) {
        return ngx_http_error_abuse_set_variable(
            v, states[NGX_HTTP_ERROR_ABUSE_BYPASSED].data,
            states[NGX_HTTP_ERROR_ABUSE_BYPASSED].len);
    }

    return ngx_http_error_abuse_set_variable(
        v, states[ctx->state].data, states[ctx->state].len);
}

static ngx_int_t
ngx_http_error_abuse_variable_count(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                              *p;
    ngx_http_error_abuse_req_ctx_t      *ctx;

    ctx = ngx_http_error_abuse_get_req_ctx(r);
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    return ngx_http_error_abuse_set_variable(v, p,
        ngx_sprintf(p, "%ui", ctx ? ctx->count : 0) - p);
}

static ngx_int_t
ngx_http_error_abuse_variable_blocked_until(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                              *p;
    ngx_http_error_abuse_req_ctx_t      *ctx;

    ctx = ngx_http_error_abuse_get_req_ctx(r);
    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    return ngx_http_error_abuse_set_variable(v, p,
        ngx_sprintf(p, "%T", ctx ? ctx->blocked_until : 0) - p);
}
