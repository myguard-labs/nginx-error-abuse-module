/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <hiredis/async.h>
#include <hiredis/adapters/poll.h>

#define NGX_HTTP_ERROR_ABUSE_VERSION       1
#define NGX_HTTP_ERROR_ABUSE_MAX_STATUS    599
#define NGX_HTTP_ERROR_ABUSE_STATUS_BYTES  75
#define NGX_HTTP_ERROR_ABUSE_MAX_THRESHOLD 1024
#define NGX_HTTP_ERROR_ABUSE_FILE_MAGIC    "NGEAB01"
#define NGX_HTTP_ERROR_ABUSE_FILE_MAGIC_LEN 8
#define NGX_HTTP_ERROR_ABUSE_REDIS_TICK     5
#define NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT 1000
#define NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_THRESHOLD 5
#define NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_DURATION 30

typedef struct {
    ngx_str_t   host;
    ngx_str_t   prefix;
    in_port_t   port;
    ngx_msec_t  timeout;
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
    ngx_msec_t                        persist_interval;
    ngx_event_t                       persist_event;
    ngx_flag_t                        redis;
};

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
    ngx_str_t                     key;
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

typedef struct {
    redisAsyncContext                   *context;
    ngx_http_error_abuse_redis_conf_t   *conf;
    ngx_event_t                          tick;
    ngx_event_t                          reconnect;
    ngx_log_t                           *log;
    ngx_uint_t                           sequence;
    uint64_t                             nonce;
    ngx_uint_t                           consecutive_failures;
    time_t                               circuit_breaker_until;
    unsigned                             ready:1;
    unsigned                             exiting:1;
} ngx_http_error_abuse_redis_worker_t;

typedef struct {
    u_char    magic[NGX_HTTP_ERROR_ABUSE_FILE_MAGIC_LEN];
    uint32_t  version;
    uint32_t  threshold;
    uint32_t  records;
    uint32_t  crc32;
} ngx_http_error_abuse_file_header_t;

typedef struct {
    uint16_t  key_len;
    uint16_t  event_count;
    int64_t   blocked_until;
    int64_t   last_seen;
} ngx_http_error_abuse_file_record_t;

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
static void ngx_http_error_abuse_redis_tick(ngx_event_t *ev);
static void ngx_http_error_abuse_redis_reconnect(ngx_event_t *ev);
static void ngx_http_error_abuse_redis_connect_callback(
    const redisAsyncContext *ac, int status);
static void ngx_http_error_abuse_redis_disconnect_callback(
    const redisAsyncContext *ac, int status);
static void ngx_http_error_abuse_redis_check_callback(
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
    "redis.call('SET',KEYS[2],'1','PX',ARGV[3]) "
    "redis.call('DEL',KEYS[1]) return {1,n} end "
    "return {0,n}";

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
        NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
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
        NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
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

static ngx_http_error_abuse_node_t *
ngx_http_error_abuse_create_node(ngx_http_error_abuse_zone_t *zone,
    uint32_t hash, ngx_str_t *key, time_t now)
{
    size_t                          size;
    ngx_http_error_abuse_node_t    *ean;

    size = ngx_http_error_abuse_node_size(key->len, zone->threshold);
    ean = ngx_slab_alloc_locked(zone->shpool, size);

    if (ean == NULL) {
        ngx_http_error_abuse_expire(zone, now, 0xffffffff);
        ean = ngx_slab_alloc_locked(zone->shpool, size);
        if (ean == NULL) {
            return NULL;
        }
    }

    ngx_memzero(ean, size);
    ean->node.key = hash;
    ean->key_len = (u_short) key->len;
    ean->last_seen = now;
    ngx_memcpy(ean->data, key->data, key->len);

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

    ngx_http_error_abuse_expire(zone, now, 2);
    ean = ngx_http_error_abuse_lookup(zone, hash, key);

    if (ean == NULL) {
        ean = ngx_http_error_abuse_create_node(zone, hash, key, now);
        if (ean == NULL) {
            ngx_shmtx_unlock(&zone->shpool->mutex);
            return NGX_ERROR;
        }
    }

    ean->last_seen = now;
    ngx_http_error_abuse_touch(zone, ean);

    if (ean->blocked_until > now) {
        *count = 0;
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
    ngx_http_error_abuse_expire(zone, now, 2);

    ean = ngx_http_error_abuse_lookup(zone, hash, key);
    if (ean == NULL) {
        *count = 0;
        *blocked_until = 0;
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return NGX_DECLINED;
    }

    ean->last_seen = now;
    ngx_http_error_abuse_touch(zone, ean);

    if (ean->blocked_until > now) {
        *count = 0;
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
                   &ctx->key, &ctx->zone->name);

    if (ctx->zone->redis && !ctx->redis_checked) {
        rc = ngx_http_error_abuse_redis_check(r, ctx);
        if (rc == NGX_AGAIN) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "error_abuse: waiting for Redis response");
            return NGX_AGAIN;
        }
    }
    if (ctx->redis_blocked) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: client \"%V\" blocked by Redis",
                       &ctx->key);
        if (conf->dry_run) {
            ctx->state = NGX_HTTP_ERROR_ABUSE_DRY_RUN;
            return NGX_DECLINED;
        }
        ctx->state = NGX_HTTP_ERROR_ABUSE_BLOCKED;
        ctx->own_rejection = 1;
        return conf->reject_status;
    }

    now = ngx_time();
    rc = ngx_http_error_abuse_is_blocked(conf->zone, &ctx->key, now,
                                         &ctx->count,
                                         &ctx->blocked_until);
    if (rc != NGX_OK) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: client \"%V\" in zone \"%V\" "
                       "currently blocked",
                       &ctx->key, &ctx->zone->name);
        if (conf->dry_run) {
            ctx->state = NGX_HTTP_ERROR_ABUSE_DRY_RUN;
            return NGX_DECLINED;
        }

        ctx->state = NGX_HTTP_ERROR_ABUSE_BLOCKED;
        ctx->own_rejection = 1;

        ngx_log_error(conf->log_level, r->connection->log, 0,
                      "error_abuse blocked client \"%V\" in zone \"%V\" until %T",
                      &r->connection->addr_text, &conf->zone->name,
                      ctx->blocked_until);

        return conf->reject_status;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "error_abuse: client \"%V\" in zone \"%V\" passed, "
                   "count=%ui",
                   &ctx->key, &ctx->zone->name, ctx->count);
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

    /* Optimization: early return for common case (200 OK) */
    conf = ngx_http_get_module_loc_conf(r, ngx_http_error_abuse_module);
    if (!conf->enabled || conf->zone == NULL) {
        return ngx_http_error_abuse_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_error_abuse_module);
    if (ctx == NULL) {
        if (conf->enabled && conf->zone != NULL) {
            ctx = ngx_http_error_abuse_prepare_ctx(r, conf);
        }
    }

    if (ctx == NULL || ctx->zone == NULL || ctx->response_seen
        || ctx->own_rejection)
    {
        return ngx_http_error_abuse_next_header_filter(r);
    }

    ctx->response_seen = 1;

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
                       r->headers_out.status, &ctx->zone->name, &ctx->key);
        return ngx_http_error_abuse_next_header_filter(r);
    }

    now = ngx_time();
    rc = ngx_http_error_abuse_record(ctx->zone, &ctx->key, now,
                                     &ctx->count, &ctx->blocked_until);
    if (ctx->zone->redis) {
        ngx_http_error_abuse_redis_record(r, ctx);
    }
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error_abuse zone \"%V\" has insufficient shared memory",
                      &ctx->zone->name);
    } else if (rc == NGX_BUSY) {
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: client \"%V\" blocked in zone \"%V\", "
                       "count=%ui, blocked_until=%T",
                       &ctx->key, &ctx->zone->name, ctx->count,
                       ctx->blocked_until);
        ctx->state = ctx->dry_run ? NGX_HTTP_ERROR_ABUSE_DRY_RUN
                                  : NGX_HTTP_ERROR_ABUSE_BLOCKED;
    } else {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: status %ui counted for client \"%V\" "
                       "in zone \"%V\", count=%ui",
                       r->headers_out.status, &ctx->key, &ctx->zone->name);
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

    if (key.len > 65535) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error_abuse key is too long: %uz bytes", key.len);
        return ctx;
    }

    ctx->key.data = ngx_pnalloc(r->pool, key.len);
    if (ctx->key.data == NULL) {
        return NULL;
    }

    ngx_memcpy(ctx->key.data, key.data, key.len);
    ctx->key.len = key.len;
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

        p = end + 1;
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
        NGX_HTTP_ERROR_ABUSE_SEEN_REDIS = 1 << 9
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
            ngx_str_t s = { value[i].len - 9, value[i].data + 9 };
            parsed_time = ngx_parse_time(&s, 1);
            if (parsed_time == (ngx_msec_t) NGX_ERROR || parsed_time == 0) {
                goto invalid;
            }
            zone->interval = (time_t) parsed_time;

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
            ngx_str_t s = { value[i].len - 6, value[i].data + 6 };
            parsed_time = ngx_parse_time(&s, 1);
            if (parsed_time == (ngx_msec_t) NGX_ERROR || parsed_time == 0) {
                goto invalid;
            }
            zone->block = (time_t) parsed_time;

        } else if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {
            if (seen & NGX_HTTP_ERROR_ABUSE_SEEN_INACTIVE) {
                goto duplicate;
            }
            seen |= NGX_HTTP_ERROR_ABUSE_SEEN_INACTIVE;
            ngx_str_t s = { value[i].len - 9, value[i].data + 9 };
            parsed_time = ngx_parse_time(&s, 1);
            if (parsed_time == (ngx_msec_t) NGX_ERROR || parsed_time == 0) {
                goto invalid;
            }
            zone->inactive = (time_t) parsed_time;

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

    if (zone->name.len == 0 || size == 0 || key.len == 0
        || statuses.len == 0 || zone->interval == 0
        || zone->threshold == 0 || zone->block == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "error_abuse_zone is missing a required parameter");
        return NGX_CONF_ERROR;
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

    if (cf->args->nelts == 2
        && value[1].len == 3
        && ngx_strncmp(value[1].data, "off", 3) == 0)
    {
        lcf->enabled = 0;
        lcf->zone = NULL;
        return NGX_CONF_OK;
    }

    if (lcf->enabled != NGX_CONF_UNSET) {
        return "is duplicate";
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
    ngx_int_t                         n;
    ngx_uint_t                        i, seen;
    ngx_msec_t                        timeout;
    ngx_str_t                        *value, host, prefix;
    ngx_http_error_abuse_main_conf_t *mcf;

    enum {
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_HOST = 1 << 0,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PORT = 1 << 1,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_PREFIX = 1 << 2,
        NGX_HTTP_ERROR_ABUSE_REDIS_SEEN_TIMEOUT = 1 << 3
    };

    mcf = conf;
    if (mcf->redis.configured) {
        return "is duplicate";
    }

    value = cf->args->elts;
    host.data = NULL;
    host.len = 0;
    ngx_str_set(&prefix, "error_abuse:");
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
        } else {
            goto invalid;
        }
    }

    if (host.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "error_abuse_redis requires host");
        return NGX_CONF_ERROR;
    }

    mcf->redis.host.data = ngx_pnalloc(cf->pool, host.len + 1);
    mcf->redis.prefix.data = ngx_pnalloc(cf->pool, prefix.len);
    if (mcf->redis.host.data == NULL || mcf->redis.prefix.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(mcf->redis.host.data, host.data, host.len);
    mcf->redis.host.data[host.len] = '\0';
    mcf->redis.host.len = host.len;
    ngx_memcpy(mcf->redis.prefix.data, prefix.data, prefix.len);
    mcf->redis.prefix.len = prefix.len;

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

    return NGX_OK;
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

    /* Circuit breaker: skip Redis if too many consecutive failures */
    now = ngx_time();
    if (ngx_http_error_abuse_redis_worker.circuit_breaker_until > now) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis circuit breaker active, "
                       "skipping check (recovers in %T seconds)",
                       ngx_http_error_abuse_redis_worker.circuit_breaker_until
                       - now);
        ctx->redis_checked = 1;
        return NGX_DECLINED;
    }

    if (!ngx_http_error_abuse_redis_worker.ready
        || ngx_http_error_abuse_redis_worker.context == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis not ready, skipping check");
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
                   &block, &ctx->key);

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
        ngx_http_error_abuse_redis_worker.consecutive_failures++;

        /* Trigger circuit breaker if threshold reached */
        if (ngx_http_error_abuse_redis_worker.consecutive_failures
            >= NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_THRESHOLD)
        {
            ngx_http_error_abuse_redis_worker.circuit_breaker_until =
                now + NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_DURATION;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "error_abuse: Redis circuit breaker triggered "
                          "after %ui consecutive failures, "
                          "suspending for %ui seconds",
                          ngx_http_error_abuse_redis_worker.consecutive_failures,
                          NGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_DURATION);
            ngx_http_error_abuse_redis_worker.consecutive_failures = 0;
        }

        ctx->redis_pending = 0;
        ctx->redis_checked = 1;
        return NGX_DECLINED;
    }

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
        return;
    }

    reply = data;
    ctx->redis_pending = 0;
    ctx->redis_checked = 1;
    ctx->redis_blocked = reply != NULL && reply->type == REDIS_REPLY_STRING;

    /* Reset circuit breaker on successful response */
    if (reply != NULL) {
        ngx_http_error_abuse_redis_worker.consecutive_failures = 0;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis check for client \"%V\" "
                       "returned %s",
                       &ctx->key,
                       ctx->redis_blocked ? "BLOCKED" : "not blocked");
    } else {
        ngx_http_error_abuse_redis_worker.consecutive_failures++;
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "error_abuse: Redis check failed (consecutive=%ui)",
                      ngx_http_error_abuse_redis_worker.consecutive_failures);
    }

    ngx_http_core_run_phases(r);
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

    /* Circuit breaker: skip Redis if too many consecutive failures */
    now = ngx_time();
    if (ngx_http_error_abuse_redis_worker.circuit_breaker_until > now) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis circuit breaker active, "
                       "skipping record");
        return;
    }

    if (!ngx_http_error_abuse_redis_worker.ready
        || ngx_http_error_abuse_redis_worker.context == NULL
        || ngx_http_error_abuse_redis_keys(r->pool, ctx, &events, &block)
           != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "error_abuse: Redis not available for record");
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "error_abuse: recording event to Redis for client \"%V\", "
                   "events_key=\"%V\", block_key=\"%V\"",
                   &ctx->key, &events, &block);

#define NGX_ERROR_ABUSE_REDIS_NUMBER(buf, value)                              \
    (size_t) (ngx_snprintf((u_char *) (buf), sizeof(buf), "%L",               \
                           (int64_t) (value)) - (u_char *) (buf))

    argv[0] = "EVAL";
    argvlen[0] = 4;
    argv[1] = ngx_http_error_abuse_redis_record_script;
    argvlen[1] = sizeof(ngx_http_error_abuse_redis_record_script) - 1;
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
                              NULL, NULL, 10, argv, argvlen) != REDIS_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "error_abuse could not queue Redis event");
    }

#undef NGX_ERROR_ABUSE_REDIS_NUMBER
}

static void
ngx_http_error_abuse_redis_tick(ngx_event_t *ev)
{
    ngx_http_error_abuse_redis_worker_t *worker;

    worker = ev->data;
    if (worker->context != NULL) {
        (void) redisPollTick(worker->context, 0.0);
    }
    if (!worker->exiting && worker->context != NULL) {
        ngx_add_timer(ev, NGX_HTTP_ERROR_ABUSE_REDIS_TICK);
    }
}

static void
ngx_http_error_abuse_redis_connect_callback(const redisAsyncContext *ac,
    int status)
{
    ngx_http_error_abuse_redis_worker_t *worker;

    worker = ac->data;
    if (status == REDIS_OK) {
        worker->ready = 1;
        ngx_log_error(NGX_LOG_NOTICE, worker->log, 0,
                      "error_abuse connected to Redis at \"%V:%ui\"",
                      &worker->conf->host, worker->conf->port);
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
    if (!worker->exiting && !worker->reconnect.timer_set) {
        ngx_add_timer(&worker->reconnect,
                      NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT);
    }
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
    if (ac->err || redisPollAttach(ac) != REDIS_OK) {
        redisAsyncFree(ac);
        return NGX_ERROR;
    }

    worker->context = ac;
    ac->data = worker;
    timeout.tv_sec = worker->conf->timeout / 1000;
    timeout.tv_usec = (worker->conf->timeout % 1000) * 1000;
    (void) redisAsyncSetTimeout(ac, timeout);
    (void) redisAsyncSetConnectCallback(
        ac, ngx_http_error_abuse_redis_connect_callback);
    (void) redisAsyncSetDisconnectCallback(
        ac, ngx_http_error_abuse_redis_disconnect_callback);
    if (!worker->tick.timer_set) {
        ngx_add_timer(&worker->tick, NGX_HTTP_ERROR_ABUSE_REDIS_TICK);
    }

    return NGX_OK;
}

static void
ngx_http_error_abuse_redis_reconnect(ngx_event_t *ev)
{
    ngx_http_error_abuse_redis_worker_t *worker;

    worker = ev->data;
    if (!worker->exiting && ngx_http_error_abuse_redis_connect() != NGX_OK)
    {
        ngx_add_timer(ev, NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT);
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

    if (mcf->redis.configured) {
        ngx_memzero(&ngx_http_error_abuse_redis_worker,
                    sizeof(ngx_http_error_abuse_redis_worker));
        ngx_http_error_abuse_redis_worker.conf = &mcf->redis;
        ngx_http_error_abuse_redis_worker.log = cycle->log;
        ngx_http_error_abuse_redis_worker.nonce =
            ((uint64_t) ngx_current_msec << 32)
            ^ (uint64_t) ngx_random()
            ^ (uint64_t) ngx_pid;
        ngx_http_error_abuse_redis_worker.tick.handler =
            ngx_http_error_abuse_redis_tick;
        ngx_http_error_abuse_redis_worker.tick.data =
            &ngx_http_error_abuse_redis_worker;
        ngx_http_error_abuse_redis_worker.tick.log = cycle->log;
        ngx_http_error_abuse_redis_worker.tick.cancelable = 1;
        ngx_http_error_abuse_redis_worker.reconnect.handler =
            ngx_http_error_abuse_redis_reconnect;
        ngx_http_error_abuse_redis_worker.reconnect.data =
            &ngx_http_error_abuse_redis_worker;
        ngx_http_error_abuse_redis_worker.reconnect.log = cycle->log;
        ngx_http_error_abuse_redis_worker.reconnect.cancelable = 1;
        if (ngx_http_error_abuse_redis_connect() != NGX_OK) {
            ngx_add_timer(&ngx_http_error_abuse_redis_worker.reconnect,
                          NGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT);
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
        if (ngx_http_error_abuse_redis_worker.tick.timer_set) {
            ngx_del_timer(&ngx_http_error_abuse_redis_worker.tick);
        }
        if (ngx_http_error_abuse_redis_worker.reconnect.timer_set) {
            ngx_del_timer(&ngx_http_error_abuse_redis_worker.reconnect);
        }
        if (ngx_http_error_abuse_redis_worker.context != NULL) {
            redisAsyncFree(ngx_http_error_abuse_redis_worker.context);
            ngx_http_error_abuse_redis_worker.context = NULL;
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
        }
    }
}

static void
ngx_http_error_abuse_persist_handler(ngx_event_t *ev)
{
    ngx_http_error_abuse_zone_t  *zone;

    zone = ev->data;
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

static ngx_int_t
ngx_http_error_abuse_save(ngx_http_error_abuse_zone_t *zone, ngx_log_t *log)
{
    u_char                              *buffer, *p, *last, *tmp;
    size_t                               capacity, key_len;
    uint32_t                             records;
    ngx_fd_t                             fd;
    ngx_uint_t                           i;
    ngx_queue_t                         *q;
    time_t                              *events;
    ngx_http_error_abuse_node_t         *ean;
    ngx_http_error_abuse_file_header_t  *header;
    ngx_http_error_abuse_file_record_t   record;

    capacity = zone->shm_zone->shm.size;
    buffer = ngx_alloc(capacity, log);
    if (buffer == NULL) {
        return NGX_ERROR;
    }

    p = buffer + sizeof(ngx_http_error_abuse_file_header_t);
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
            < sizeof(record) + key_len
              + ean->event_count * sizeof(int64_t))
        {
            break;
        }

        ngx_memzero(&record, sizeof(record));
        record.key_len = ean->key_len;
        record.event_count = (uint16_t) ean->event_count;
        record.blocked_until = (int64_t) ean->blocked_until;
        record.last_seen = (int64_t) ean->last_seen;
        p = ngx_cpymem(p, &record, sizeof(record));
        p = ngx_cpymem(p, ean->data, key_len);

        events = ngx_http_error_abuse_events(ean);
        for (i = 0; i < ean->event_count; i++) {
            int64_t when = (int64_t)
                events[(ean->event_head + i) % zone->threshold];
            p = ngx_cpymem(p, &when, sizeof(when));
        }
        records++;
    }

    ngx_shmtx_unlock(&zone->shpool->mutex);

    header = (ngx_http_error_abuse_file_header_t *) buffer;
    ngx_memzero(header, sizeof(*header));
    ngx_memcpy(header->magic, NGX_HTTP_ERROR_ABUSE_FILE_MAGIC,
               sizeof(NGX_HTTP_ERROR_ABUSE_FILE_MAGIC));
    header->version = NGX_HTTP_ERROR_ABUSE_VERSION;
    header->threshold = (uint32_t) zone->threshold;
    header->records = records;

    /* Compute CRC32 over payload (everything after header) */
    header->crc32 = ngx_crc32_long(buffer + sizeof(*header),
                                    p - buffer - sizeof(*header));

    tmp = ngx_alloc(zone->persist.len + 64, log);
    if (tmp == NULL) {
        ngx_free(buffer);
        return NGX_ERROR;
    }
    ngx_sprintf(tmp, "%V.tmp.%P%Z", &zone->persist, ngx_pid);

    fd = ngx_open_file(tmp, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                       NGX_FILE_OWNER_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", tmp);
        ngx_free(tmp);
        ngx_free(buffer);
        return NGX_ERROR;
    }

    if (ngx_http_error_abuse_write_all(fd, buffer, p - buffer) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      ngx_write_fd_n " \"%s\" failed", tmp);
        (void) ngx_close_file(fd);
        (void) ngx_delete_file(tmp);
        ngx_free(tmp);
        ngx_free(buffer);
        return NGX_ERROR;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", tmp);
        (void) ngx_delete_file(tmp);
        ngx_free(tmp);
        ngx_free(buffer);
        return NGX_ERROR;
    }

    if (ngx_rename_file(tmp, zone->persist.data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      ngx_rename_file_n " \"%s\" to \"%V\" failed",
                      tmp, &zone->persist);
        (void) ngx_delete_file(tmp);
        ngx_free(tmp);
        ngx_free(buffer);
        return NGX_ERROR;
    }

    ngx_free(tmp);
    ngx_free(buffer);
    return NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_load(ngx_http_error_abuse_zone_t *zone, ngx_log_t *log)
{
    u_char                              *buffer, *p, *last;
    off_t                                file_size;
    uint32_t                             hash, record_index;
    ngx_fd_t                             fd;
    ngx_file_info_t                      fi;
    ngx_uint_t                           i;
    time_t                               now, *events;
    int64_t                              stored_when;
    ngx_str_t                            key;
    ngx_http_error_abuse_node_t         *ean;
    ngx_http_error_abuse_file_header_t  *header;
    ngx_http_error_abuse_file_record_t   record;

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

    file_size = ngx_file_size(&fi);
    if (file_size < (off_t) sizeof(ngx_http_error_abuse_file_header_t)
        || file_size > (off_t) zone->shm_zone->shm.size)
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

    header = (ngx_http_error_abuse_file_header_t *) buffer;
    if (ngx_memcmp(header->magic, NGX_HTTP_ERROR_ABUSE_FILE_MAGIC,
                   sizeof(NGX_HTTP_ERROR_ABUSE_FILE_MAGIC)) != 0
        || header->version != NGX_HTTP_ERROR_ABUSE_VERSION
        || header->threshold != zone->threshold)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "error_abuse persistence file \"%V\" is incompatible",
                      &zone->persist);
        ngx_free(buffer);
        return NGX_OK;
    }

    p = buffer + sizeof(*header);
    last = buffer + file_size;

    /* Verify CRC32 checksum to detect corruption */
    if (header->crc32 != ngx_crc32_long(p, last - p)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "error_abuse persistence file \"%V\" is corrupted "
                      "(CRC32 mismatch), deleting",
                      &zone->persist);
        ngx_free(buffer);
        (void) ngx_delete_file((u_char *) zone->persist.data);
        return NGX_OK;
    }

    if (ngx_http_error_abuse_validate_snapshot(zone, p, last,
                                               header->records)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "error_abuse persistence file \"%V\" is malformed",
                      &zone->persist);
        ngx_free(buffer);
        return NGX_OK;
    }

    now = ngx_time();

    ngx_shmtx_lock(&zone->shpool->mutex);

    for (record_index = 0; record_index < header->records; record_index++) {
        if ((size_t) (last - p) < sizeof(record)) {
            break;
        }

        ngx_memcpy(&record, p, sizeof(record));
        p += sizeof(record);

        if (record.key_len == 0
            || record.event_count > zone->threshold
            || (size_t) (last - p)
               < record.key_len + record.event_count * sizeof(int64_t))
        {
            break;
        }

        key.data = p;
        key.len = record.key_len;
        p += record.key_len;

        if (record.blocked_until <= (int64_t) now
            && record.event_count == 0)
        {
            continue;
        }

        hash = ngx_crc32_short(key.data, key.len);
        ean = ngx_http_error_abuse_lookup(zone, hash, &key);
        if (ean == NULL) {
            ean = ngx_http_error_abuse_create_node(zone, hash, &key, now);
            if (ean == NULL) {
                break;
            }
        }

        ean->blocked_until = (record.blocked_until > (int64_t) now)
                             ? (time_t) record.blocked_until : 0;
        ean->last_seen = (record.last_seen > 0
                          && record.last_seen <= (int64_t) now)
                         ? (time_t) record.last_seen : now;
        ean->event_head = 0;
        ean->event_count = 0;
        events = ngx_http_error_abuse_events(ean);

        for (i = 0; i < record.event_count; i++) {
            ngx_memcpy(&stored_when, p, sizeof(stored_when));
            p += sizeof(int64_t);
            if (stored_when > (int64_t) (now - zone->interval)
                && stored_when <= (int64_t) now)
            {
                events[ean->event_count++] = (time_t) stored_when;
            }
        }
    }

    ngx_shmtx_unlock(&zone->shpool->mutex);
    ngx_free(buffer);
    return NGX_OK;
}

static ngx_int_t
ngx_http_error_abuse_validate_snapshot(ngx_http_error_abuse_zone_t *zone,
    u_char *p, u_char *last, uint32_t records)
{
    uint32_t                            i;
    size_t                              payload;
    ngx_http_error_abuse_file_record_t  record;

    for (i = 0; i < records; i++) {
        if ((size_t) (last - p) < sizeof(record)) {
            return NGX_ERROR;
        }

        ngx_memcpy(&record, p, sizeof(record));
        p += sizeof(record);

        if (record.key_len == 0 || record.event_count > zone->threshold) {
            return NGX_ERROR;
        }

        payload = (size_t) record.key_len
                  + (size_t) record.event_count * sizeof(int64_t);
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

    v->data = p;
    v->len = ngx_sprintf(p, "%ui", ctx ? ctx->count : 0) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
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

    v->data = p;
    v->len = ngx_sprintf(p, "%T", ctx ? ctx->blocked_until : 0) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}
