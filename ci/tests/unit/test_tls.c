/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <hiredis/hiredis.h>
#include <hiredis/hiredis_ssl.h>
#include <stdlib.h>
#include <stdio.h>
#include "ngx_http_error_abuse_tls.h"

int
main(int argc, char **argv)
{
    SSL_CTX       *ctx;
    SSL           *ssl;
    redisContext  *redis;
    int            rc;

    if (argc != 5) {
        return 2;
    }
    redisInitOpenSSL();
    if (ngx_http_error_abuse_tls_context(NULL) != NULL) {
        return 2;
    }
    ctx = ngx_http_error_abuse_tls_context(argv[1]);
    if (ctx == NULL) {
        return 2;
    }
    if (ngx_http_error_abuse_tls_session(ctx, NULL, 0) != NULL
        || ngx_http_error_abuse_tls_session(ctx, "", 0) != NULL
        || ngx_http_error_abuse_tls_session(ctx, ".example.com", 0) != NULL
        || (atoi(argv[3])
            && ngx_http_error_abuse_tls_session(ctx, "invalid-ip", 1) != NULL))
    {
        return 2;
    }
    ssl = ngx_http_error_abuse_tls_session(ctx, argv[2], atoi(argv[3]));
    redis = redisConnect("127.0.0.1", atoi(argv[4]));
    if (ssl == NULL || redis == NULL || redis->err) {
        return 2;
    }
    rc = redisInitiateSSL(redis, ssl);
    if (rc == REDIS_OK) {
        redisAppendCommand(redis, "AUTH fixture-only");
        redisAppendCommand(redis, "SELECT 1");
        redisAppendCommand(redis, "SCRIPT LOAD return(1)");
        {
            int done = 0;
            while (!done && rc == REDIS_OK) {
                rc = redisBufferWrite(redis, &done);
            }
        }
    } else {
        SSL_free(ssl);
    }
    redisFree(redis);
    SSL_CTX_free(ctx);
    return rc == REDIS_OK ? 0 : 1;
}
