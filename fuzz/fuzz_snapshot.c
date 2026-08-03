/*
 * libFuzzer harness for ngx_http_error_abuse_validate_snapshot().
 *
 * Why this target: it parses an untrusted on-disk snapshot file — bytes
 * an attacker (or corruption) can put under the persistence path — doing
 * raw pointer arithmetic against p / last and ngx_memcpy()ing a
 * fixed-size record straight off the buffer. It is the gate that load()
 * trusts: if validate returns NGX_OK, load() walks the SAME buffer with
 * the SAME stride and reads key_len + event_count*8 payload bytes without
 * re-deriving the bound. So the security contract is:
 *
 *   validate_snapshot() == NGX_OK  =>  every byte load() will later read
 *                                      lies within [orig_p, last).
 *
 * This harness fuzzes that gate two ways at once:
 *   1. ASAN/UBSAN on validate_snapshot itself catches any OOB read or
 *      overflow in the validator's own walk.
 *   2. When validate returns NGX_OK, the harness re-walks the buffer with
 *      load()'s exact stride and touches every payload byte through a
 *      volatile sink. ASAN then turns ANY gap between what validate
 *      accepts and what load() reads into an immediate heap-buffer-
 *      overflow — a hard regression gate on the two staying in lockstep.
 *
 * The real function lives in ../ngx_http_error_abuse_scan.c and this target
 * LINKS it -- including the LE getters it decodes records with, which the
 * replay below now shares instead of carrying its own copy. (Until the scan
 * seam landed, fuzz/extract_parser.sh sed-sliced the function body into a
 * generated .inc and ngx_shim.h reimplemented the getters and the on-disk
 * constants; a format change had to be mirrored in three places, and lessons.md
 * records the harness trap that followed when it was not.)
 *
 * Build (see fuzz/build.sh):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *       fuzz_snapshot.c ngx_stubs.c ../ngx_http_error_abuse_scan.c \
 *       $NGX_SRC/src/core/ngx_string.c -o fuzz_snapshot
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_error_abuse_scan.h"

/* Keep the loop count bounded so a 4-byte "records" field of 0xffffffff
 * cannot make the validator spin; the real header->records is bounded by
 * the file fitting in the shm zone, and each record consumes >= 20 bytes
 * so the walk is size-bounded anyway, but cap it explicitly for speed. */
#define FUZZ_MAX_RECORDS  100000u

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /*
     * Carve the fuzzer-controlled control fields off the front:
     *   [0..4)  records  (uint32, little-endian)
     *   [4]     threshold lever (mapped into a small range so the
     *           event_count > threshold reject path is reachable)
     * The remainder is the snapshot payload handed to the validator as
     * the [p, last) byte range — exactly what load() passes after the
     * file header.
     */
    if (size < 5) {
        return 0;
    }

    uint32_t records = (uint32_t) data[0]
                     | ((uint32_t) data[1] << 8)
                     | ((uint32_t) data[2] << 16)
                     | ((uint32_t) data[3] << 24);
    if (records > FUZZ_MAX_RECORDS) {
        records = FUZZ_MAX_RECORDS;
    }

    /* 0..255 threshold; covers event_count==0, the boundary, and reject. */
    ngx_uint_t threshold = (ngx_uint_t) data[4];

    size_t  payload_len = size - 5;
    /* Allocate EXACTLY payload_len (1 byte when zero) with no trailing
     * slack, so any read at or past `last` is an ASAN heap overflow. */
    size_t  alloc = payload_len ? payload_len : 1;
    u_char *buf = (u_char *) malloc(alloc);
    if (buf == NULL) {
        return 0;
    }
    if (payload_len) {
        memcpy(buf, data + 5, payload_len);
    }

    u_char *p    = buf;
    u_char *last = buf + payload_len;

    ngx_int_t rc = ngx_http_error_abuse_validate_snapshot(p, last, records,
                                                          threshold);

    if (rc != NGX_OK && rc != NGX_ERROR) {
        __builtin_trap();
    }

    if (rc == NGX_OK) {
        /*
         * Replay load()'s stride over the validated buffer and read every
         * byte it would read. If validate accepted a buffer that load()
         * would over-read, ASAN fires here. Mirrors the consumption loop
         * in ngx_http_error_abuse_load().
         */
        volatile uint8_t sink = 0;

        for (uint32_t i = 0; i < records; i++) {
            if ((size_t) (last - p) < NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN) {
                __builtin_trap();   /* validate said OK but record truncated */
            }
            /* RFC-3: little-endian record header, fixed 20-byte stride. */
            uint16_t rec_key_len = ngx_http_error_abuse_get_u16(p);
            uint16_t rec_event_count = ngx_http_error_abuse_get_u16(p + 2);
            p += NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN;

            size_t need = (size_t) rec_key_len
                        + (size_t) rec_event_count * sizeof(int64_t);
            if ((size_t) (last - p) < need) {
                __builtin_trap();   /* validate said OK but payload short */
            }
            for (size_t k = 0; k < need; k++) {
                sink ^= p[k];
            }
            p += need;
        }
        /* validate's contract: exact consumption, p lands on last. */
        if (p != last) {
            __builtin_trap();
        }
        (void) sink;
    }

    free(buf);
    return 0;
}
