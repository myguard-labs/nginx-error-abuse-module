/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for shared time arithmetic used by production deadline paths.
 */

#include "../../../src/ngx_http_error_abuse_time.h"

#include <stdint.h>
#include <stdio.h>


static int  failures;
static int  checks;


static void
check(int ok, const char *what)
{
    checks++;
    if (ok) {
        printf("ok   %s\n", what);
        return;
    }
    printf("FAIL %s\n", what);
    failures++;
}


static void
case_signed_time32_boundary(void)
{
    const time_t  t32_max = (time_t) INT32_MAX;
    const time_t  configured_duration_cap = 315360000;

    check(ngx_http_error_abuse_time_add_saturate_at(t32_max - 10,
                                                    configured_duration_cap,
                                                    t32_max)
          == t32_max,
          "configured duration cap saturates near signed time32 max");
    check(ngx_http_error_abuse_time_add_saturate_at(t32_max - 10, 9,
                                                    t32_max)
          == t32_max - 1,
          "non-overflowing signed time32 deadline is preserved");
    check(ngx_http_error_abuse_time_add_saturate_at(t32_max - 10, 10,
                                                    t32_max)
          == t32_max,
          "exact signed time32 ceiling is preserved");
    check(ngx_http_error_abuse_time_add_saturate_at(t32_max, 1, t32_max)
          == t32_max,
          "signed time32 ceiling stays saturated");
}


static void
case_host_time_t_boundary(void)
{
    time_t  maximum = ngx_http_error_abuse_time_max();

    check(ngx_http_error_abuse_time_add_saturate(maximum - 1, 2) == maximum,
          "host time_t addition saturates at the representable maximum");
    check(ngx_http_error_abuse_time_add_saturate((time_t) 100, (time_t) 0)
          == (time_t) 100,
          "zero duration leaves the timestamp unchanged");
}


int
main(void)
{
    case_signed_time32_boundary();
    case_host_time_t_boundary();

    if (failures != 0) {
        printf("FAILED: %d/%d time arithmetic checks failed\n",
               failures, checks);
        return 1;
    }

    printf("OK: %d time arithmetic checks passed\n", checks);
    return 0;
}
