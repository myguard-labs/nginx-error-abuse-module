/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NGX_HTTP_ERROR_ABUSE_TIME_H
#define NGX_HTTP_ERROR_ABUSE_TIME_H

#include <stdint.h>
#include <time.h>


static inline time_t
ngx_http_error_abuse_time_max(void)
{
    if ((time_t) -1 > (time_t) 0) {
        return (time_t) -1;
    }

    if (sizeof(time_t) >= sizeof(int64_t)) {
        return (time_t) INT64_MAX;
    }

    if (sizeof(time_t) >= sizeof(int32_t)) {
        return (time_t) INT32_MAX;
    }

    if (sizeof(time_t) >= sizeof(int16_t)) {
        return (time_t) INT16_MAX;
    }

    return (time_t) INT8_MAX;
}


static inline time_t
ngx_http_error_abuse_time_add_saturate_at(time_t now, time_t duration,
    time_t ceiling)
{
    if (now >= ceiling) {
        return ceiling;
    }

    if (duration <= 0) {
        return now;
    }

    if (duration > ceiling - now) {
        return ceiling;
    }

    return now + duration;
}


static inline time_t
ngx_http_error_abuse_time_add_saturate(time_t now, time_t duration)
{
    return ngx_http_error_abuse_time_add_saturate_at(
        now, duration, ngx_http_error_abuse_time_max());
}

#endif /* NGX_HTTP_ERROR_ABUSE_TIME_H */
