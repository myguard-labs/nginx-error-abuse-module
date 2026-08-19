/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NGX_HTTP_ERROR_ABUSE_WIN32_H_INCLUDED_
#define _NGX_HTTP_ERROR_ABUSE_WIN32_H_INCLUDED_

/*
 * The Windows implementation lives behind this single seam.  Keep the header
 * empty on POSIX so including it cannot change Linux object code.
 */
#if (NGX_WIN32)

#if !defined(_MSC_VER) && !defined(__MINGW32__)
#error "error-abuse supports Windows through MSVC or MinGW-w64"
#endif

#include <aclapi.h>
#include <sddl.h>

typedef struct {
    HANDLE    mutex;
    unsigned  owned:1;
    unsigned  failed:1;
} ngx_http_error_abuse_win32_owner_t;

ngx_int_t ngx_http_error_abuse_win32_owner_try(
    ngx_http_error_abuse_win32_owner_t *owner, ngx_str_t *path,
    ngx_log_t *log);
void ngx_http_error_abuse_win32_owner_release(
    ngx_http_error_abuse_win32_owner_t *owner, ngx_log_t *log);
ngx_int_t ngx_http_error_abuse_win32_socket_readable(ngx_socket_t fd,
    ngx_log_t *log);
ngx_fd_t ngx_http_error_abuse_win32_create_temp(u_char *path,
    ngx_log_t *log);
ngx_int_t ngx_http_error_abuse_win32_flush_file(ngx_fd_t fd);
ngx_int_t ngx_http_error_abuse_win32_replace(u_char *from, ngx_str_t *to,
    ngx_log_t *log);
void ngx_http_error_abuse_win32_sync_parent(u_char *path, ngx_log_t *log);
ngx_uint_t ngx_http_error_abuse_win32_interrupted(ngx_err_t err);

#endif /* NGX_WIN32 */

#endif /* _NGX_HTTP_ERROR_ABUSE_WIN32_H_INCLUDED_ */
