/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The scan core: the decision logic that walks untrusted bytes, isolated from
 * nginx's request and configuration machinery.
 *
 * Everything here takes plain (u_char *, size_t) buffers and scalars. That is
 * what makes the CI harness honest: ci/fuzz/fuzz_statuses.c and
 * ci/fuzz/fuzz_snapshot.c link THIS translation unit, so the fuzzer drives the
 * same bytes through the same code that serves live traffic.
 *
 * Before this seam existed the fuzz targets ran fuzz/extract_parser.sh, which
 * sliced the two function bodies out of the module .c with sed and compiled
 * them against a hand-written ngx_shim.h carrying re-typed copies of ngx_atoi()
 * and ngx_strlchr(). That fuzzed a textual copy of the parser against a copy
 * of the decoder -- two drift surfaces the build could not detect. Linking
 * the real TU removes both.
 *
 * The rule when extending this module: parsing and validation of attacker- or
 * operator-supplied bytes goes here; only the ngx_http_request_t / ngx_conf_t
 * plumbing stays in the module .c. Nothing in this file may take a request or
 * conf type, allocate from a request pool, or log -- the fuzz and unit builds
 * link it without those subsystems present.
 */

#ifndef _NGX_HTTP_ERROR_ABUSE_SCAN_H_INCLUDED_
#define _NGX_HTTP_ERROR_ABUSE_SCAN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* SEC-3: the identity stored in shared memory, Redis and snapshots is a fixed
 * 32-byte SHA-256 digest of the configured key, regardless of how large the raw
 * key variable is. Spelled as a literal rather than SHA256_DIGEST_LENGTH so the
 * scan TU stays free of the OpenSSL headers; the module .c static-asserts the
 * two agree. */
#define NGX_HTTP_ERROR_ABUSE_DIGEST_LEN    32

#define NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN  20 /* klen2+ecnt2+blk8+seen8 */
#define NGX_HTTP_ERROR_ABUSE_MAX_STATUS    599
#define NGX_HTTP_ERROR_ABUSE_STATUS_BYTES  75


/*
 * Status-list parse outcomes.
 *
 * parse_statuses() cannot log: it is linked into the fuzz and unit targets,
 * where ngx_conf_log_error() and the whole conf machinery do not exist. So it
 * returns WHICH rejection fired and the caller renders the message with the
 * ngx_conf_t it holds. That also makes the reject paths directly assertable
 * from a unit test -- previously they were distinguishable only by the log text
 * the fuzz shim threw away.
 */
typedef enum {
    NGX_HTTP_ERROR_ABUSE_STATUSES_OK = 0,
    NGX_HTTP_ERROR_ABUSE_STATUSES_EMPTY_ELEMENT,
    NGX_HTTP_ERROR_ABUSE_STATUSES_TRAILING_COMMA,
    NGX_HTTP_ERROR_ABUSE_STATUSES_RANGE
} ngx_http_error_abuse_statuses_rc_t;


/*
 * Parse a "403,404,500-599" status list into the caller's bitmap.
 *
 * `bitmap` must point at NGX_HTTP_ERROR_ABUSE_STATUS_BYTES writable bytes; on
 * any non-OK return it may have been partially written, so the caller must
 * treat the whole zone as rejected rather than keeping a half-applied list
 * (the module does: a non-OK return fails the config).
 *
 * The bitmap write `bitmap[status >> 3] |= 1U << (status & 7)` is the reason
 * this function is fuzzed: it is an OOB-write surface guarded only by the
 * (first < 100 / final < first / final > MAX_STATUS) range check above it.
 */
ngx_http_error_abuse_statuses_rc_t ngx_http_error_abuse_parse_statuses(
    u_char *data, size_t len, u_char *bitmap);


/*
 * Validate an on-disk snapshot payload before load() walks it.
 *
 * The security contract this gate exists to hold, and which
 * ci/fuzz/fuzz_snapshot.c asserts on every accepted input:
 *
 *   returns NGX_OK  =>  every byte load() will later read lies within
 *                       [p, last), and load()'s stride lands exactly on last.
 *
 * Takes `threshold` as a scalar rather than the zone, so the snapshot gate can
 * be driven with an arbitrary threshold without constructing a shared-memory
 * zone. Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_http_error_abuse_validate_snapshot(u_char *p, u_char *last,
    uint32_t records, ngx_uint_t threshold);


/*
 * RFC-3: explicit little-endian field codecs so a snapshot is portable across
 * endianness and compiler ABI, not a raw native struct dump.
 *
 * Declared here (and defined in the scan TU) rather than left as static inlines
 * in the module .c because the snapshot validator, the loader and the fuzz
 * harness's load()-stride replay must all decode with the SAME code. A second
 * copy in the harness is exactly the drift the seam removes.
 */
/*
 * Redis key construction, split out of the module's redis_keys() so the size
 * arithmetic and the write sequence can be checked against each other without
 * a pool.
 *
 * The two must agree exactly: the caller allocates key_len() bytes (plus a
 * suffix) and key_write() then fills them by a different route -- five summed
 * terms on one side, seven write steps with a *2 hex expansion on the other.
 * A wrong term overruns the pool by a few bytes, which is precisely the size
 * of overrun ASan does not see on an ngx_pnalloc'd block (cp10 10b). So the
 * agreement is asserted directly, with canaries, in ci/tests/unit/test_scan.c.
 *
 * Layout written is "<prefix>{<zone_name>:<hex digest>}", with the braces
 * making the two per-identity keys hash to one Redis Cluster slot. key_len()
 * returns the length of that base, excluding any suffix the caller appends.
 *
 * Precondition: the three lengths must be small enough that the sum below
 * cannot wrap size_t. The module's only caller passes a prefix and zone name
 * bounded by the config file and a digest_len fixed at
 * NGX_HTTP_ERROR_ABUSE_DIGEST_LEN, so this holds by construction there; a new
 * caller passing an attacker-influenced length would have to bound it first.
 * Stated rather than checked because a size_t return has no error value, and
 * inventing one would put a branch on the hot path for a condition the
 * allocation itself cannot survive anyway.
 */
size_t ngx_http_error_abuse_redis_key_len(size_t prefix_len,
    size_t zone_name_len, size_t digest_len);
u_char *ngx_http_error_abuse_redis_key_write(u_char *buf,
    const u_char *prefix, size_t prefix_len,
    const u_char *zone_name, size_t zone_name_len,
    const u_char *digest, size_t digest_len);


u_char *ngx_http_error_abuse_put_u16(u_char *p, uint16_t v);
u_char *ngx_http_error_abuse_put_u32(u_char *p, uint32_t v);
u_char *ngx_http_error_abuse_put_u64(u_char *p, uint64_t v);
uint16_t ngx_http_error_abuse_get_u16(const u_char *p);
uint32_t ngx_http_error_abuse_get_u32(const u_char *p);
uint64_t ngx_http_error_abuse_get_u64(const u_char *p);


#endif /* _NGX_HTTP_ERROR_ABUSE_SCAN_H_INCLUDED_ */
