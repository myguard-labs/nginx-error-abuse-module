/*
 * Minimal nginx shim for fuzzing ngx_http_error_abuse_validate_snapshot().
 *
 * The real ngx_http_error_abuse_module.c pulls in <ngx_config.h>/
 * <ngx_core.h>/<ngx_http.h> plus hiredis — the whole nginx tree. The
 * snapshot validator only touches a tiny, well-defined slice of that
 * surface (a couple of integer typedefs, the two on-disk struct layouts,
 * zone->threshold and ngx_memcpy), so we reproduce just that slice here
 * with the EXACT upstream semantics. The fuzz target then includes the
 * verbatim function body sliced out of the shipped .c, so we fuzz the
 * SHIPPED code — not a re-implementation.
 *
 * If the module ever changes these typedefs or the two on-disk struct
 * layouts, this shim must be updated to match (the .inc compile will fail
 * loudly if a referenced name disappears).
 */

#ifndef NGX_ERROR_ABUSE_FUZZ_SHIM_H
#define NGX_ERROR_ABUSE_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

#define NGX_OK     0
#define NGX_ERROR -1

#define ngx_memcpy(dst, src, n)  (void) memcpy(dst, src, n)

typedef struct {
    size_t  len;
    u_char *data;
} ngx_str_t;

/* Module constants used by parse_statuses — keep in sync with the .c. */
#define NGX_HTTP_ERROR_ABUSE_MAX_STATUS    599
#define NGX_HTTP_ERROR_ABUSE_STATUS_BYTES  75

/* Snapshot constants + LE getters used by validate_snapshot (RFC-3) —
 * keep in sync with the .c. */
#define NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN  20
/* SEC-3: identities are a fixed 32-byte SHA-256 digest; validate_snapshot
 * rejects any other key length. Mirror the .c constant for the sliced body. */
#define NGX_HTTP_ERROR_ABUSE_DIGEST_LEN    32

static inline uint16_t
ngx_http_error_abuse_get_u16(const u_char *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}

static inline uint32_t
ngx_http_error_abuse_get_u32(const u_char *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
           | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static inline uint64_t
ngx_http_error_abuse_get_u64(const u_char *p)
{
    uint64_t  v = 0;
    int       i;

    for (i = 0; i < 8; i++) {
        v |= (uint64_t) p[i] << (8 * i);
    }
    return v;
}

/*
 * ngx_strlchr() — verbatim upstream (src/core/ngx_string.h, inlined here):
 * find c in [p, last); return pointer or NULL.
 */
static inline u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return NULL;
}

/*
 * ngx_atoi() — faithful upstream copy (src/core/ngx_string.c). Returns the
 * non-negative value, or NGX_ERROR on empty/invalid/overflow input. The
 * status parser relies on exactly this contract (a bad token -> NGX_ERROR
 * -> rejected before the bitmap write), so the OOB-write guard depends on
 * it; reproduce it precisely.
 */
static inline ngx_int_t
ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t  value, cutoff, cutlim;

    if (n == 0) {
        return NGX_ERROR;
    }

    cutoff = ((ngx_uint_t) -1 >> 1) / 10;
    cutlim = ((ngx_uint_t) -1 >> 1) % 10;

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }
        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return NGX_ERROR;
        }
        value = value * 10 + (*line - '0');
    }

    return value;
}

/* parse_statuses only uses cf for the error log; make it a no-op sink so
 * the verbatim body compiles standalone. The variadic args are evaluated
 * but discarded. */
typedef struct { int unused; } ngx_conf_t;
#define NGX_LOG_EMERG 2
static inline void ngx_conf_log_error_noop(int level, ngx_conf_t *cf, ...) {
    (void) level; (void) cf;
}
#define ngx_conf_log_error(level, cf, err, ...) \
    ngx_conf_log_error_noop((level), (cf))

/* RFC-3: the on-disk record is now a fixed little-endian byte layout
 * (NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN + LE getters above), not a native
 * struct — the harness re-walk decodes it byte-for-byte. */

/*
 * Only the field the validator reads (zone->threshold) is reproduced;
 * its type (ngx_uint_t) matches production so the
 * `record.event_count > zone->threshold` comparison promotes identically.
 */
/*
 * Only the two fields the sliced parsers read/write are reproduced:
 * threshold (validate_snapshot) and the statuses[] bitmap that
 * parse_statuses sets bits in. The bitmap size MUST match production so
 * an off-by-one in the parser's bound shows up as an ASAN OOB write here.
 */
typedef struct {
    ngx_uint_t  threshold;
    u_char      statuses[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES];
} ngx_http_error_abuse_zone_t;

#endif /* NGX_ERROR_ABUSE_FUZZ_SHIM_H */
