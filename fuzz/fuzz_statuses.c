/*
 * libFuzzer harness for ngx_http_error_abuse_parse_statuses().
 *
 * Why this target: it parses a free-form "403,404,500-599"-style status
 * list with ngx_strlchr / ngx_atoi and pointer arithmetic, then for every
 * status in each [first,final] range sets a bit:
 *
 *     zone->statuses[status >> 3] |= 1U << (status & 7);
 *
 * That is an OOB-WRITE surface: if the (first<100 / final<first /
 * final>MAX_STATUS) guard is ever weakened, `status >> 3` walks past the
 * fixed-size statuses[] bitmap. ASAN turns that into an immediate, repro-
 * ducible heap-buffer-overflow. The fuzzer feeds the raw list bytes; the
 * harness places the bitmap right at the end of an exact-sized allocation
 * so any single-byte over-write is caught.
 *
 * The real function lives in ../ngx_http_error_abuse_scan.c and this target
 * LINKS it, together with nginx's real src/core/ngx_string.c -- so both the
 * parser and the ngx_atoi()/ngx_strlchr() it walks bytes with are production
 * code. (Until the scan seam landed, fuzz/extract_parser.sh sed-sliced the
 * function body into a generated .inc and ngx_shim.h supplied re-typed copies
 * of the two nginx helpers; that fuzzed a copy of the parser against a copy of
 * the decoder, with no build-time signal if either drifted.)
 *
 * Build (see fuzz/build.sh):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *       fuzz_statuses.c ngx_stubs.c ../ngx_http_error_abuse_scan.c \
 *       $NGX_SRC/src/core/ngx_string.c -o fuzz_statuses
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_error_abuse_scan.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /*
     * Put the statuses[] bitmap on the heap in an EXACT-sized allocation so
     * ASAN red-zones bracket it: any write past bitmap[STATUS_BYTES-1] is an
     * immediate heap-buffer-overflow rather than silent corruption of an
     * adjacent stack slot. (It used to sit in the tail of a shim zone struct,
     * where a small overflow could land in unrelated struct padding instead.)
     */
    u_char *bitmap = (u_char *) calloc(1, NGX_HTTP_ERROR_ABUSE_STATUS_BYTES);
    if (bitmap == NULL) {
        return 0;
    }

    /*
     * The list bytes are NOT NUL-terminated: the parser is fully length-
     * bounded (value->data .. value->data+value->len), so feed exactly
     * `size` bytes and let ASAN flag any read past the end. Allocate at
     * least one byte (never NULL) — in production value->data is always a
     * real config-string buffer, so a NULL here would only trip a bogus
     * "NULL + 0" UBSan report that cannot happen for real input.
     */
    size_t  alloc = size ? size : 1;
    u_char *buf = (u_char *) malloc(alloc);
    if (buf == NULL) { free(bitmap); return 0; }
    if (size) {
        memcpy(buf, data, size);
    }

    ngx_http_error_abuse_statuses_rc_t rc =
        ngx_http_error_abuse_parse_statuses(buf, size, bitmap);

    /* Contract: exactly one of the four declared outcomes. Anything else
     * means a path fell through somewhere it should not have. */
    switch (rc) {
    case NGX_HTTP_ERROR_ABUSE_STATUSES_OK:
    case NGX_HTTP_ERROR_ABUSE_STATUSES_EMPTY_ELEMENT:
    case NGX_HTTP_ERROR_ABUSE_STATUSES_TRAILING_COMMA:
    case NGX_HTTP_ERROR_ABUSE_STATUSES_RANGE:
        break;
    default:
        __builtin_trap();
    }

    free(buf);
    free(bitmap);
    return 0;
}
