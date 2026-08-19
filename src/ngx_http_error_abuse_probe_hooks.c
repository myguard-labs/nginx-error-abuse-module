/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_error_abuse_probe_hooks.c -- this module's probe hooks (CI only).
 *
 * Two hooks, matching ngx_test_probe_hooks_t:
 *
 *   zone_render  adds the zone fields the generic probe cannot know -- how
 *                many identities are tracked, how many are currently blocked,
 *                and the fault-injector state.
 *   fault_set    arms the slab failure injector that reaches the zone-full
 *                path in ngx_http_error_abuse_create_node().
 *
 * The whole file compiles to nothing without NGX_TEST_HARNESS. See
 * ci/t/harness/README.md for the consumer contract.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_error_abuse_probe_hooks.h"

#ifdef NGX_TEST_HARNESS

#include "ngx_test_probe.h"

/*
 * The zone accessors below need the module's own zone and node layout, which
 * lives in the module translation unit. Rather than export those structs into
 * a header for a CI-only consumer, the module hands this file two small
 * accessors and keeps its layout private.
 */
ngx_uint_t ngx_http_error_abuse_probe_count_nodes(ngx_shm_zone_t *zone,
    ngx_uint_t *blocked);
void ngx_http_error_abuse_probe_fault_state(ngx_shm_zone_t *zone,
    ngx_int_t *nth, ngx_uint_t *seen);
ngx_int_t ngx_http_error_abuse_probe_arm_slab(ngx_shm_zone_t *zone,
    ngx_int_t nth);


/*
 * Append this module's fields to the probe's "zone" object.
 *
 * Contract (see ngx_test_probe_hooks_t): the generic members are already
 * rendered, so this appends with a LEADING comma and no closing brace, and
 * must respect `last` -- ngx_slprintf truncates there rather than overflowing.
 * The bound the caller reserved for this output is
 * NGX_HTTP_ERROR_ABUSE_PROBE_ZONE_MAX.
 *
 * `nodes` and `blocked` are counted under the zone mutex by walking the LRU
 * queue: the module keeps no running totals, and a count derived from two
 * unsynchronised reads could report a node as both present and blocked in the
 * same document.
 */
static u_char *
ngx_http_error_abuse_probe_zone_render(u_char *buf, u_char *last,
    ngx_shm_zone_t *zone)
{
    ngx_int_t   nth;
    ngx_uint_t  nodes, blocked, seen;

    if (zone == NULL) {
        return buf;
    }

    nodes = ngx_http_error_abuse_probe_count_nodes(zone, &blocked);
    ngx_http_error_abuse_probe_fault_state(zone, &nth, &seen);

    /* slab_nth/slab_seen are reported so a rule can assert that an arming
     * request took effect, and that a case which was SUPPOSED to trip the
     * injector actually reached an allocation -- a fault that never fires
     * would otherwise let the case pass for the wrong reason. */
    return ngx_slprintf(buf, last,
                        ",\"nodes\":%ui,\"blocked\":%ui"
                        ",\"fault\":{\"slab_nth\":%i,\"slab_seen\":%ui}",
                        nodes, blocked, nth, seen);
}


/*
 * Arm or clear fault injection for `fault` at `nth` (negative disarms).
 *
 * The harness has already matched the query argument, identified WHICH fault
 * site it names, rejected malformed and over-long values, and applied the
 * sign; this only has to store the result for a site this module actually
 * implements. There is exactly one fault site (slab allocation in
 * create_node), so every other value is declined -- the same answer as "no
 * fault site at all" -- so a query naming an unimplemented site is refused
 * rather than reported applied. See ngx_test_probe_hooks_t.fault_set.
 */
static ngx_int_t
ngx_http_error_abuse_probe_fault_set(ngx_shm_zone_t *zone,
    ngx_test_probe_fault_e fault, ngx_int_t nth)
{
    if (fault != NGX_TEST_PROBE_FAULT_SLAB) {
        return NGX_DECLINED;
    }

    if (zone == NULL) {
        return NGX_DECLINED;
    }

    return ngx_http_error_abuse_probe_arm_slab(zone, nth);
}


static const ngx_test_probe_hooks_t  ngx_http_error_abuse_probe_hooks = {
    ngx_http_error_abuse_probe_zone_render,
    ngx_http_error_abuse_probe_fault_set
};


void
ngx_http_error_abuse_probe_hooks_register(void)
{
    ngx_test_probe_register(&ngx_http_error_abuse_probe_hooks);
}

#else

/* ISO C forbids an empty translation unit, and angie's configure adds -Werror,
 * so the disabled build needs a declaration to stand on. */
typedef int ngx_http_error_abuse_probe_hooks_unused_t;

#endif /* NGX_TEST_HARNESS */
