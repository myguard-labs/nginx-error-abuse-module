/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the scan core (src/ngx_http_error_abuse_scan.c).
 *
 * WHY THIS EXISTS ALONGSIDE ci/t/ AND ci/fuzz/
 *
 *   ci/t, Test::Nginx    drives the module through a live nginx. It proves the
 *                        request/config plumbing, but the parse and bitmap
 *                        boundaries are awkward to hit precisely through HTTP
 *                        or a directive value, and the snapshot codec is not
 *                        addressable at all from there.
 *   ci/fuzz targets      drive the same code with random bytes. They prove the
 *                        core does not CRASH and does not read/write out of
 *                        bounds -- but a fuzzer asserts invariants, not VALUES.
 *                        "500-599 alone sets exactly bits 500..599" or "put_u32
 *                        writes little-endian" are not things it can state.
 *   this file            states values, at named boundaries, with no nginx
 *                        process and no network, in well under a second.
 *
 * It links the REAL src/ngx_http_error_abuse_scan.c and the REAL nginx
 * src/core/ngx_string.c (via ci/tests/unit/run.sh), exactly as the fuzz
 * targets do. There is deliberately NO shim reimplementation of ngx_atoi() or
 * ngx_strlchr(): they are the exact surface the status-list parser walks
 * untrusted bytes with, and a test that asserted against a private copy would
 * assert only that the copy is self-consistent. ci/fuzz/ngx_stubs.c supplies
 * the allocator/log symbols that ngx_string.c drags in, and aborts if the scan
 * path ever actually reaches one -- which is also why a stray ngx_conf_t or
 * request-pool allocation in the scan core would fail this build loudly rather
 * than silently.
 *
 * Extend: add a CASE() function and one line in main(). Keep each case
 * asserting a value the CORRECT implementation produces and a BROKEN one does
 * not -- ci/tests/unit/run.sh's header lists the mutations every case here was
 * seen red against.
 */

#include "ngx_http_error_abuse_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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


/* Parse a NUL-terminated C literal. The core takes (u_char *, len) and never
 * looks for a terminator, so the length is the string length -- never
 * sizeof(), which would feed the NUL in as a scanned byte. */
static ngx_http_error_abuse_statuses_rc_t
parse_str(const char *s, u_char *bitmap)
{
    return ngx_http_error_abuse_parse_statuses((u_char *) s, strlen(s),
                                                bitmap);
}


static int
bit_set(const u_char *bitmap, ngx_uint_t status)
{
    return (bitmap[status >> 3] & (1U << (status & 7))) != 0;
}


/* Count set bits over the whole NGX_HTTP_ERROR_ABUSE_STATUS_BYTES zone, so a
 * write that lands one bit past where it should is visible even when that bit
 * happens to fall inside the allocated bitmap (an OOB *value* corruption, as
 * opposed to an OOB *memory* write, which the canary case below covers
 * separately). */
static int
popcount_bitmap(const u_char *bitmap)
{
    int  i, n;

    n = 0;
    for (i = 0; i < NGX_HTTP_ERROR_ABUSE_STATUS_BYTES; i++) {
        u_char  b = bitmap[i];

        while (b) {
            n += b & 1;
            b >>= 1;
        }
    }
    return n;
}


/* --- parse_statuses() ------------------------------------------------- */

/*
 * The reject paths, each asserted against its SPECIFIC enum rc -- not just
 * "non-OK". Before the scan seam existed these were distinguishable only by
 * the log text the fuzz shim threw away; the header now documents them as an
 * assertable contract.
 */
static void
case_parse_reject_rcs(void)
{
    u_char  bitmap[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES];

    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("404,,500", bitmap)
              == NGX_HTTP_ERROR_ABUSE_STATUSES_EMPTY_ELEMENT,
          "double comma (\"404,,500\") is EMPTY_ELEMENT");

    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str(",404", bitmap)
              == NGX_HTTP_ERROR_ABUSE_STATUSES_EMPTY_ELEMENT,
          "leading empty element (\",404\") is EMPTY_ELEMENT");

    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("404,", bitmap)
              == NGX_HTTP_ERROR_ABUSE_STATUSES_TRAILING_COMMA,
          "single trailing comma (\"404,\") is TRAILING_COMMA");

    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("403,404,", bitmap)
              == NGX_HTTP_ERROR_ABUSE_STATUSES_TRAILING_COMMA,
          "trailing comma after a valid element is TRAILING_COMMA");

    /* first < 100 floor. */
    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("99", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_RANGE,
          "status 99 alone is rejected (floor)");
    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("0", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_RANGE,
          "status 0 alone is rejected (floor)");

    /* final > MAX_STATUS ceiling. */
    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("600", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_RANGE,
          "status 600 alone is rejected (ceiling)");

    /* final < first (inverted range). */
    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("500-404", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_RANGE,
          "inverted range (500-404) is rejected");

    /* ngx_atoi() rejects non-digit input, which surfaces as -1 -> RANGE via
     * the first < 100 check -- exercised here as an explicit rc, not merely
     * "did not crash". */
    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("abc", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_RANGE,
          "non-numeric element is rejected (ngx_atoi -1 -> RANGE floor)");
}


/*
 * Boundary values at NGX_HTTP_ERROR_ABUSE_MAX_STATUS (599) and the floor
 * (100), plus the OK path for a normal list and a range.
 */
static void
case_parse_boundaries_and_ok(void)
{
    u_char  bitmap[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES];

    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("599", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_OK,
          "status 599 alone is accepted (ceiling boundary)");
    check(bit_set(bitmap, 599), "bit 599 is set");
    check(popcount_bitmap(bitmap) == 1, "exactly one bit set for \"599\"");

    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("100", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_OK,
          "status 100 alone is accepted (floor boundary)");
    check(bit_set(bitmap, 100), "bit 100 is set");

    memset(bitmap, 0, sizeof(bitmap));
    check(parse_str("403,404,500-599", bitmap)
              == NGX_HTTP_ERROR_ABUSE_STATUSES_OK,
          "\"403,404,500-599\" is accepted");

    /* len == 0: the `while (p < last)` loop body never runs (the loop's
     * false-on-entry arm, otherwise unreached -- every other case here
     * enters the loop at least once). Falls straight through to OK without
     * touching the bitmap; not a reject path.
     *
     * Seeded with a non-zero pattern rather than zeroed, so this asserts
     * "the parser wrote nothing" rather than the weaker "the result is
     * all-zero" -- a parser that cleared the bitmap on entry would satisfy
     * the zeroed form and still be wrong. */
    {
        u_char before[sizeof(bitmap)];

        memset(bitmap, 0xa5, sizeof(bitmap));
        memcpy(before, bitmap, sizeof(bitmap));

        check(parse_str("", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_OK,
              "empty status list is accepted as OK (loop never entered)");
        check(memcmp(bitmap, before, sizeof(bitmap)) == 0,
              "empty status list leaves the bitmap byte-for-byte untouched");
    }
}


/*
 * The bitmap write itself: `bitmap[status >> 3] |= 1U << (status & 7)` is the
 * OOB-write surface documented in the header. Assert the EXACT bitmap
 * contents for a known list (not just "some bits got set"), and assert
 * nothing was written past NGX_HTTP_ERROR_ABUSE_STATUS_BYTES using a canary
 * byte immediately after the caller's buffer.
 */
static void
case_bitmap_contents_and_no_overrun(void)
{
    u_char      buf[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES + 1];
    u_char     *bitmap = buf;
    ngx_uint_t  s;

    /* Canary immediately past the bitmap the caller is contractually allowed
     * to write. A one-off in the shift/index arithmetic (status 599 needs
     * byte index 599>>3 == 74, i.e. exactly the last of the 75 allocated
     * bytes) would corrupt this. */
    memset(buf, 0, sizeof(buf));
    buf[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES] = 0xAA;

    check(parse_str("100,200,403,404,599", bitmap)
              == NGX_HTTP_ERROR_ABUSE_STATUSES_OK,
          "known list parses OK for bitmap-contents check");

    for (s = 0; s <= NGX_HTTP_ERROR_ABUSE_MAX_STATUS; s++) {
        int  expect = (s == 100 || s == 200 || s == 403 || s == 404
                        || s == 599);

        if (bit_set(bitmap, s) != expect) {
            printf("     bit %lu: expected %d, got %d\n",
                   (unsigned long) s, expect, bit_set(bitmap, s));
            failures++;
        }
    }
    checks++;
    printf("ok   bitmap contents match {100,200,403,404,599} exactly (or a "
           "mismatch line was printed above)\n");

    check(buf[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES] == 0xAA,
          "canary byte immediately past the bitmap is untouched");

    /* A full-width range must fill every allocated bit and still leave the
     * canary alone -- the densest write this function can produce. */
    memset(buf, 0, sizeof(buf));
    buf[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES] = 0xAA;
    check(parse_str("100-599", bitmap) == NGX_HTTP_ERROR_ABUSE_STATUSES_OK,
          "full-width range 100-599 is accepted");
    check(popcount_bitmap(bitmap) == 500,
          "100-599 sets exactly 500 bits (599-100+1)");
    check(buf[NGX_HTTP_ERROR_ABUSE_STATUS_BYTES] == 0xAA,
          "canary untouched after the densest possible write");
}


/* --- validate_snapshot() ------------------------------------------------ */

/*
 * The header's contract: NGX_OK => every byte load() reads lies within
 * [p, last) AND the stride lands EXACTLY on last. Assert accept and every
 * reject case named in the checkpoint brief.
 */
static void
case_snapshot_accept(void)
{
    u_char  buf[NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN + 32];
    u_char *p;

    memset(buf, 0, sizeof(buf));
    p = buf;
    p = ngx_http_error_abuse_put_u16(p, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN);
    p = ngx_http_error_abuse_put_u16(p, 2);           /* event_count */
    p = ngx_http_error_abuse_put_u64(p, 0);           /* blk */
    p = ngx_http_error_abuse_put_u64(p, 0);           /* seen */
    /* 32-byte digest payload + 2 events * 8 bytes */
    p += NGX_HTTP_ERROR_ABUSE_DIGEST_LEN;
    p += 2 * 8;

    check(ngx_http_error_abuse_validate_snapshot(buf, p, 1, 10) == NGX_OK,
          "one well-formed record with stride landing exactly on last is OK");
}


static void
case_snapshot_reject_truncated_header(void)
{
    u_char  buf[NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN - 1];
    u_char *p;

    /* The header fields themselves must be VALID (matching digest length,
     * event_count within threshold) so a zeroed buffer's key-length check
     * cannot be the thing that rejects this.
     *
     * SURVIVED MUTATION, recorded here rather than hidden: weakening the
     * record-length bound from `< FILE_REC_LEN` to `< FILE_REC_LEN - 1` still
     * leaves this case green, because the resulting 1-byte pointer overshoot
     * is independently caught by the final `p == last` stride check a few
     * lines later in ngx_http_error_abuse_validate_snapshot(). That is not a
     * gap this test can close: for records=1 the two checks are redundant on
     * exactly this input shape (a header short by 1 byte, event_count=0), so
     * no case built from this shape can isolate the length bound from the
     * stride bound. It IS still a meaningful assertion -- it proves the
     * truncated buffer is rejected -- just not proof that this SPECIFIC line
     * is what does it. See run.sh's SEEN RED / SURVIVED lists.
     *
     * A multi-record construction does NOT close this gap either -- see the
     * investigation note on case_snapshot_accept_two_records() below: `p` is
     * monotonic, so once this bound is weakened enough to let `p` overshoot
     * `last`, no later record's advance can bring it back to equal `last`,
     * and the function's own final stride check independently rejects every
     * such overshoot regardless of record count. Verified by building the
     * mutation and running the full multi-record suite: still 41/41 green. */
    p = buf;
    p = ngx_http_error_abuse_put_u16(p, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN);
    p = ngx_http_error_abuse_put_u16(p, 0);          /* event_count */
    p = ngx_http_error_abuse_put_u64(p, 0);
    ngx_http_error_abuse_put_u32(p, 0);       /* only 3 bytes of `seen` fit */

    check(ngx_http_error_abuse_validate_snapshot(
              buf, buf + sizeof(buf), 1, 10) == NGX_ERROR,
          "truncated header (19 bytes, otherwise well-formed) is rejected");
}


static void
case_snapshot_reject_bad_key_len(void)
{
    u_char  buf[NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN + NGX_HTTP_ERROR_ABUSE_DIGEST_LEN];
    u_char *p;

    memset(buf, 0, sizeof(buf));
    p = buf;
    p = ngx_http_error_abuse_put_u16(p, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN - 1);
    p = ngx_http_error_abuse_put_u16(p, 0);
    p = ngx_http_error_abuse_put_u64(p, 0);
    ngx_http_error_abuse_put_u64(p, 0);

    check(ngx_http_error_abuse_validate_snapshot(
              buf, buf + sizeof(buf), 1, 10) == NGX_ERROR,
          "key length other than the fixed digest length is rejected");
}


static void
case_snapshot_reject_event_count_over_threshold(void)
{
    u_char  buf[NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN
                + NGX_HTTP_ERROR_ABUSE_DIGEST_LEN + 11 * 8];
    u_char *p;

    memset(buf, 0, sizeof(buf));
    p = buf;
    p = ngx_http_error_abuse_put_u16(p, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN);
    p = ngx_http_error_abuse_put_u16(p, 11);   /* event_count > threshold 10 */
    p = ngx_http_error_abuse_put_u64(p, 0);
    ngx_http_error_abuse_put_u64(p, 0);

    check(ngx_http_error_abuse_validate_snapshot(
              buf, buf + sizeof(buf), 1, 10) == NGX_ERROR,
          "event_count above the caller's threshold is rejected");
}


static void
case_snapshot_reject_payload_overrun(void)
{
    /* Header claims 2 events (16 bytes of event payload) plus the 32-byte
     * digest, but the buffer stops right after the digest -- the payload
     * bound must catch this before validate_snapshot would read past `last`.
     *
     * SURVIVED MUTATION, recorded rather than hidden: deleting the payload
     * bound entirely (`if ((size_t) (last - p) < payload) return NGX_ERROR;`)
     * still leaves this case, and every other case in this file, green. On a
     * 64-bit size_t, `p += payload` for any event_count that fits in the
     * on-disk uint16_t field cannot wrap the address space, so the function's
     * OWN final `p == last` stride check independently catches every overrun
     * this test can construct -- single-record or chained across records.
     * The payload bound is still worth keeping (defense in depth, and the
     * property this proves is host/ABI-dependent -- a 32-bit build's pointer
     * arithmetic has far less headroom before wrapping), but no case reachable
     * from this harness can prove IT specifically is load-bearing. See
     * run.sh's SURVIVED list.
     *
     * A multi-record construction does NOT close this gap: `p` is monotonic
     * non-decreasing, so once this bound is weakened enough to let `p`
     * overshoot `last`, no later record's advance can bring it back to equal
     * `last`. See the investigation note on case_snapshot_accept_two_records()
     * below for the full argument; verified by building the mutation and
     * running the full multi-record suite -- still 41/41 green. */
    u_char  buf[NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN
                + NGX_HTTP_ERROR_ABUSE_DIGEST_LEN];
    u_char *p;

    memset(buf, 0, sizeof(buf));
    p = buf;
    p = ngx_http_error_abuse_put_u16(p, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN);
    p = ngx_http_error_abuse_put_u16(p, 2);
    p = ngx_http_error_abuse_put_u64(p, 0);
    ngx_http_error_abuse_put_u64(p, 0);

    check(ngx_http_error_abuse_validate_snapshot(
              buf, buf + sizeof(buf), 1, 10) == NGX_ERROR,
          "record payload longer than the buffer is rejected");
}


static void
case_snapshot_reject_off_by_one_stride(void)
{
    u_char  buf[NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN + NGX_HTTP_ERROR_ABUSE_DIGEST_LEN
                + 1];
    u_char *p;

    /* Well-formed record (0 events) that ends one byte SHORT of `last` -- the
     * stride must land EXACTLY on last, not merely at-or-before it. */
    memset(buf, 0, sizeof(buf));
    p = buf;
    p = ngx_http_error_abuse_put_u16(p, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN);
    p = ngx_http_error_abuse_put_u16(p, 0);
    p = ngx_http_error_abuse_put_u64(p, 0);
    ngx_http_error_abuse_put_u64(p, 0);

    check(ngx_http_error_abuse_validate_snapshot(
              buf, buf + sizeof(buf), 1, 10) == NGX_ERROR,
          "stride short of last by one byte is rejected (off-by-one)");
}


/* Two-record helper: encodes a record with the given event_count at `p`,
 * returns the advanced pointer. Digest bytes are left zeroed -- the function
 * never inspects digest content, only rec_key_len. */
static u_char *
put_record(u_char *p, uint16_t event_count)
{
    p = ngx_http_error_abuse_put_u16(p, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN);
    p = ngx_http_error_abuse_put_u16(p, event_count);
    p = ngx_http_error_abuse_put_u64(p, 0);           /* blk */
    p = ngx_http_error_abuse_put_u64(p, 0);           /* seen */
    memset(p, 0, NGX_HTTP_ERROR_ABUSE_DIGEST_LEN);     /* digest payload */
    p += NGX_HTTP_ERROR_ABUSE_DIGEST_LEN;
    p += (size_t) event_count * 8;                    /* event payload */
    return p;
}


static void
case_snapshot_accept_two_records(void)
{
    /* Two well-formed records, 0 events each, stride landing exactly on
     * last. Must pass unmutated -- proves the multi-record shape itself
     * parses correctly.
     *
     * INVESTIGATED AND NOT ADDED, recorded so the next person does not
     * redo this work: a multi-record case that KILLS the record-length or
     * payload-bound mutations (see run.sh's SURVIVED list) does not exist,
     * on any 64-bit build, for any record count. Both bounds guard
     * `p += <fixed or attacker-influenced amount>`, and `p` is monotonic
     * non-decreasing across the whole function. Once a weakened/missing
     * bound lets `p` overshoot `last` on some record, no later record's
     * (strictly positive) advance can bring `p` back down to equal `last`
     * again -- so the final `return (p == last) ? NGX_OK : NGX_ERROR;`
     * check independently rejects every overshoot the two per-record bounds
     * would have caught, regardless of how many records precede or follow
     * it. This was verified both by exhaustive simulation (sweeping event
     * counts 0-10 and byte offsets across 1-3 records, see the reasoning
     * left in this commit's message) and by building the mutated source and
     * running: `checks stay 41/41 green under both mutations, same as the
     * single-record cases above. The only real difference the mutations
     * introduce is the OOB READ itself (one to a few bytes past `last`,
     * still normally within the same heap/stack allocation on typical
     * inputs) -- not the function's return value -- which is exactly why
     * the fuzz targets under ci/fuzz/ (built with ASan) are the layer that
     * catches this class of bug, not this unit-test file. A unit case
     * asserting NGX_ERROR here would therefore be asserting something that
     * does NOT distinguish correct from mutated code -- see the "control
     * that hardcodes a verdict" rule. */
    u_char  buf[2 * (NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN
                      + NGX_HTTP_ERROR_ABUSE_DIGEST_LEN)];
    u_char *p;

    memset(buf, 0, sizeof(buf));
    p = buf;
    p = put_record(p, 0);
    p = put_record(p, 0);

    check(ngx_http_error_abuse_validate_snapshot(buf, p, 2, 10) == NGX_OK,
          "two well-formed records with stride landing exactly on last is OK");
}


static void
case_snapshot_reject_records_zero_with_bytes_left(void)
{
    u_char  buf[8];

    /* records == 0 but bytes remain -- the loop body never runs, so only the
     * final `p == last` check can catch this. Exercises that check
     * independently of the per-record bound checks above it. */
    memset(buf, 0, sizeof(buf));
    check(ngx_http_error_abuse_validate_snapshot(
              buf, buf + sizeof(buf), 0, 10) == NGX_ERROR,
          "records=0 with leftover bytes is rejected (p != last)");
}


/* --- LE codecs ------------------------------------------------------------ */

/*
 * Round-trip AND explicit byte-order assertions. A round-trip test alone
 * (decode(encode(v)) == v) passes even on a native-endian dump: swapping which
 * byte lands at p[0] vs p[3] is invisible to a round trip on a
 * little-endian CI host, since encode and decode would both be wrong the same
 * way. Only asserting the actual on-wire bytes catches that class of bug --
 * see the "LE encode byte order flipped" mutation in run.sh's SEEN RED list.
 */
static void
case_codec_u16(void)
{
    u_char  buf[2];
    u_char *end;

    end = ngx_http_error_abuse_put_u16(buf, 0x1234);
    check(end == buf + 2, "put_u16 returns p + 2");
    check(buf[0] == 0x34 && buf[1] == 0x12,
          "put_u16 writes little-endian bytes (0x1234 -> 34 12)");
    check(ngx_http_error_abuse_get_u16(buf) == 0x1234,
          "get_u16 round-trips 0x1234");

    check(ngx_http_error_abuse_get_u16((u_char *) "\xff\xff") == 0xffff,
          "get_u16 round-trips the max value");
}


static void
case_codec_u32(void)
{
    u_char  buf[4];
    u_char *end;

    end = ngx_http_error_abuse_put_u32(buf, 0x12345678U);
    check(end == buf + 4, "put_u32 returns p + 4");
    check(buf[0] == 0x78 && buf[1] == 0x56 && buf[2] == 0x34 && buf[3] == 0x12,
          "put_u32 writes little-endian bytes (0x12345678 -> 78 56 34 12)");
    check(ngx_http_error_abuse_get_u32(buf) == 0x12345678U,
          "get_u32 round-trips 0x12345678");
}


static void
case_codec_u64(void)
{
    u_char      buf[8];
    u_char     *end;
    uint64_t    v = 0x0123456789abcdefULL;
    int         i;
    static const u_char expect[8] =
        { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };

    end = ngx_http_error_abuse_put_u64(buf, v);
    check(end == buf + 8, "put_u64 returns p + 8");

    for (i = 0; i < 8; i++) {
        if (buf[i] != expect[i]) {
            printf("     byte %d: expected 0x%02x, got 0x%02x\n",
                   i, expect[i], buf[i]);
            failures++;
        }
    }
    checks++;
    printf("ok   put_u64 writes little-endian bytes (or a mismatch line was "
           "printed above)\n");

    check(ngx_http_error_abuse_get_u64(buf) == v,
          "get_u64 round-trips a full 64-bit value");
}


int
main(void)
{
    case_parse_reject_rcs();
    case_parse_boundaries_and_ok();
    case_bitmap_contents_and_no_overrun();

    case_snapshot_accept();
    case_snapshot_reject_truncated_header();
    case_snapshot_reject_bad_key_len();
    case_snapshot_reject_event_count_over_threshold();
    case_snapshot_reject_payload_overrun();
    case_snapshot_reject_off_by_one_stride();
    case_snapshot_reject_records_zero_with_bytes_left();
    case_snapshot_accept_two_records();

    case_codec_u16();
    case_codec_u32();
    case_codec_u64();

    printf("\n%d check(s), %d failure(s)\n", checks, failures);

    /* A run that asserted NOTHING is a failure, not a pass. */
    if (checks == 0) {
        printf("FAIL: no checks ran\n");
        return 1;
    }

    return failures ? 1 : 0;
}
