/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_error_abuse_probe_hooks.h -- register the probe hooks (CI only).
 *
 * The probe itself lives in ci/t/harness (nginx-test-harness); this declares
 * the one call the HTTP module makes to hand it this module's zone semantics.
 * See ngx_http_error_abuse_probe_hooks.c for what the two hooks do, and
 * ci/t/harness/README.md for the consumer contract.
 */

#ifndef NGX_HTTP_ERROR_ABUSE_PROBE_HOOKS_H_INCLUDED_
#define NGX_HTTP_ERROR_ABUSE_PROBE_HOOKS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#ifdef NGX_TEST_HARNESS

/*
 * Upper bound on what ngx_http_error_abuse_probe_zone_render() appends to the
 * probe's "zone" object, on top of the harness's NGX_TEST_PROBE_JSON_MAX.
 *
 * The hook renders five fixed keys and five integers; the literal text is ~70
 * bytes, and 160 leaves room for every value to widen to a full 64-bit decimal
 * at once. The caller adds this to the harness bound when sizing the response
 * buffer. Undersizing truncates the JSON (ngx_slprintf stops at `last`), which
 * surfaces as a parse error on every case rather than a wrong assertion on one.
 */
#define NGX_HTTP_ERROR_ABUSE_PROBE_ZONE_MAX  160


/*
 * Register the zone_render and fault_set hooks with the harness probe.
 *
 * Call once, from module init or postconfiguration. Registering is what makes
 * the probe report zone.nodes / zone.blocked and accept fault_slab=; without it
 * the generic document still renders, so a missed call degrades to "the
 * module-specific assertions all fail" rather than to a crash.
 */
void ngx_http_error_abuse_probe_hooks_register(void);

#endif /* NGX_TEST_HARNESS */

#endif /* NGX_HTTP_ERROR_ABUSE_PROBE_HOOKS_H_INCLUDED_ */
