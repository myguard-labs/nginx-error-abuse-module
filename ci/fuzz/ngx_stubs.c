/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Link stubs for the fuzz targets.
 *
 * The targets link nginx's real src/core/ngx_string.c so that ngx_atoi() and
 * ngx_strlchr() under test are production code. Before the scan seam existed,
 * fuzz/ngx_shim.h carried hand-written copies of both -- so a divergence
 * between the shim's ngx_atoi and nginx's own was invisible to the build, and
 * the status parser was fuzzed against a decoder it never runs with.
 *
 * But ngx_string.c is one translation unit: it also contains ngx_pstrdup(),
 * ngx_sort(), ngx_vslprintf() and friends, which reference the allocator and
 * the global cycle. The linker needs those symbols resolved even though neither
 * scan path calls them. Pulling in ngx_palloc.c + ngx_cycle.c to satisfy them
 * would drag in the whole core (pools need the log, the log needs the cycle,
 * the cycle needs the conf parser...). Stubbing is the smaller, honest option.
 *
 * These MUST stay unreachable from the scan path. Each aborts rather than
 * returning a plausible value: if a future change to the scan core starts
 * allocating or logging, the fuzzer fails loudly and immediately instead of
 * silently fuzzing against a fake allocator. Growth in this file is the tell
 * that decision logic drifted back toward nginx types -- fix the seam, not the
 * stub.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <stdlib.h>


volatile ngx_cycle_t  *ngx_cycle;


static void
ngx_stub_abort(const char *sym)
{
    fprintf(stderr,
            "\n*** fuzz stub reached: %s()\n"
            "*** The scan core must not allocate or log. Either the code under\n"
            "*** test changed, or the fuzz target is linking the wrong TU.\n\n",
            sym);
    abort();
}


void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) size; (void) log;
    ngx_stub_abort("ngx_alloc");
    return NULL;
}


void *
ngx_calloc(size_t size, ngx_log_t *log)
{
    (void) size; (void) log;
    ngx_stub_abort("ngx_calloc");
    return NULL;
}


void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    (void) pool; (void) size;
    ngx_stub_abort("ngx_palloc");
    return NULL;
}


void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool; (void) size;
    ngx_stub_abort("ngx_pnalloc");
    return NULL;
}


void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
    ngx_stub_abort("ngx_log_error_core");
}
