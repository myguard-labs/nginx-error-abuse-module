/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <hiredis/hiredis.h>
#include <hiredis/hiredis_ssl.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include "ngx_http_error_abuse_tls.h"

int
main(int argc, char **argv)
{
    SSL_CTX       *ctx;
    SSL           *ssl;
    redisContext  *redis;
    unsigned char  address[16] = {0};
    char           oversized_dns[257];
    unsigned int   a, b, c, d;
    size_t         address_len = 0;
    int            rc, rejected = 0;

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
    memset(oversized_dns, 'a', sizeof(oversized_dns));
    oversized_dns[sizeof(oversized_dns) - 2] = '.';
    oversized_dns[sizeof(oversized_dns) - 1] = '\0';
    if (ngx_http_error_abuse_tls_session(ctx, NULL, NULL, 0) != NULL
        || ngx_http_error_abuse_tls_session(ctx, "", NULL, 0) != NULL
        || ngx_http_error_abuse_tls_session(ctx, ".example.com", NULL, 0) != NULL
        || ngx_http_error_abuse_tls_session(ctx, oversized_dns, NULL, 0) != NULL
        || ngx_http_error_abuse_tls_session(ctx, "127.0.0.1", address, 3) != NULL)
    {
        return 2;
    }
    if (atoi(argv[3])) {
        /* Supply parsed bytes, including nginx's decimal zero-padded IPv4. */
        if (sscanf(argv[2], "%u.%u.%u.%u", &a, &b, &c, &d) == 4
            && a <= 255 && b <= 255 && c <= 255 && d <= 255)
        {
            address[0] = (unsigned char) a;
            address[1] = (unsigned char) b;
            address[2] = (unsigned char) c;
            address[3] = (unsigned char) d;
            address_len = 4;
        } else if (inet_pton(AF_INET6, argv[2], address) == 1) {
            address_len = 16;
        } else {
            return 2;
        }
    }
    ssl = ngx_http_error_abuse_tls_session(ctx, argv[2], address, address_len);
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
        rejected = SSL_get_verify_result(ssl) != X509_V_OK;
        SSL_free(ssl);
    }
    redisFree(redis);
    SSL_CTX_free(ctx);
    return rc == REDIS_OK ? 0 : (rejected ? 3 : 1);
}
