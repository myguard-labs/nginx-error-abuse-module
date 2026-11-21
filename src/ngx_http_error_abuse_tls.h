/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NGX_HTTP_ERROR_ABUSE_TLS_H
#define NGX_HTTP_ERROR_ABUSE_TLS_H

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/* Identity verification was added in 1.0.2. Older libraries must fail the
 * build, rather than silently reducing TLS to chain verification and SNI. */
#ifdef OPENSSL_VERSION_NUMBER
#if OPENSSL_VERSION_NUMBER < 0x10002000L
#error "Redis TLS identity verification requires OpenSSL 1.0.2 or newer"
#endif
#endif

static SSL_CTX *
ngx_http_error_abuse_tls_context(const char *capath)
{
    SSL_CTX  *ctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = SSL_CTX_new(TLS_client_method());
#else
    ctx = SSL_CTX_new(SSLv23_client_method());
#endif
    if (ctx == NULL) {
        return NULL;
    }

    /* Preserve hiredis' TLS 1.2 minimum and mandatory chain verification. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
#else
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
                            | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, NULL, capath) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

static SSL *
ngx_http_error_abuse_tls_session(SSL_CTX *ctx, const char *identity,
    const unsigned char *address, size_t address_len)
{
    SSL                *ssl;
    X509_VERIFY_PARAM  *param;
    int                 rc;
    size_t              len;
    char                dns[256];

    /* Empty names disable the hostname check; a leading dot asks OpenSSL
     * to accept any subdomain instead of authenticating one endpoint. */
    if (identity == NULL || identity[0] == '\0' || identity[0] == '.') {
        return NULL;
    }

    /* Keep a DNS root dot for resolution only; SNI forbids it and certificate
     * matching omits that final dot. OpenSSL copies both names. */
    if (address_len == 0) {
        len = strlen(identity);
        if (identity[len - 1] == '.') {
            if (len >= sizeof(dns)) {
                return NULL;
            }
            memcpy(dns, identity, len - 1);
            dns[len - 1] = '\0';
            identity = dns;
        }
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        return NULL;
    }
    param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param,
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (address_len != 0) {
        /* Numeric identities require iPAddress SANs, never DNS SANs or CNs. */
        rc = X509_VERIFY_PARAM_set1_ip(param, address, address_len);
    } else {
        rc = X509_VERIFY_PARAM_set1_host(param, identity, 0);
        if (rc == 1) {
            rc = SSL_set_tlsext_host_name(ssl, identity);
        }
    }
    if (rc != 1) {
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

#endif /* NGX_HTTP_ERROR_ABUSE_TLS_H */
