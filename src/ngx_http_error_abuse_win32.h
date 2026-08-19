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
} ngx_http_error_abuse_win32_owner_t;

#endif /* NGX_WIN32 */

#endif /* _NGX_HTTP_ERROR_ABUSE_WIN32_H_INCLUDED_ */
