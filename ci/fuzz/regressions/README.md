# Regression corpus

One file per past crash or proven-real bug shape in
[`ngx_http_error_abuse_validate_snapshot()`](../../../src/ngx_http_error_abuse_scan.c),
replayed against both fuzz targets **before** the fresh time-boxed run in
[`fuzzing.yml`](../../../.github/workflows/fuzzing.yml). A crash that returns
must fail in seconds, not after the fresh-run budget.

## Naming

`<target>-<bug-slug>.bin`, prefixed with the fuzz target it should run against:
- `snapshot-*` for fixtures replayed through `fuzz_snapshot`
- `statuses-*` for fixtures replayed through `fuzz_statuses`

The `<bug-slug>` portion names the defect it reproduces — not the date or a hash.
A fixture matching no known prefix (`snapshot-`, `statuses-`) must FAIL the replay
step loudly, never be silently skipped.

## Contract

- Every file here must be **clean** (no crash, no ASan/UBSan report) against
  the current, unmutated target function it is destined for. A file that crashes
  production code belongs in `ci/fuzz/corpus/` as a seed for discovery, not here
  — this directory is a negative-control replay set.
- Adding a file here after a real crash requires the minimized reproducer
  (`libFuzzer -minimize_crash=1`), not the raw fuzzer-generated blob.
- `fuzzing.yml`'s replay step dispatches each file to its declared target binary
  based on the filename prefix (e.g., `snapshot-*.bin` runs through `fuzz_snapshot`,
  `statuses-*.bin` through `fuzz_statuses`). A fixture with no matching prefix
  causes the replay step to exit non-zero and fail the gate. A regression that
  starts crashing again fails the PR gate in seconds.

## Provenance of the current set

Both entries below are **synthetic-but-real**: no live crash from this exact
shape has been filed in
[`memory/labs/nginx-error-abuse-module/issues.md`](../../../../../memory/labs/nginx-error-abuse-module/issues.md)
or `lessons.md`. They encode the two `validate_snapshot()` bound-check gaps
recorded in `TODO.md` item 1 (cp5, PR #18) — both confirmed as **real
one-past-`last` OOB reads**, but each is invisible to a black-box unit test
because the function's own final `p == last` stride check happens to reject
the corrupted state anyway on every reachable shape *except* when ASan
observes the intermediate out-of-bounds read directly. cp6 verified each
mutation is caught, then reverted it — evidence below and in
`memory/labs/nginx-error-abuse-module/lessons.md`.

- **`snapshot-record-length-bound-exact.bin`** — three records: one full valid
  record, then a second record whose remaining buffer is exactly
  `NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN - 1` (19) bytes, with header bytes that
  parse as a *valid* key_len/event_count. Weakening the guard at
  `ngx_http_error_abuse_scan.c` (`(last - p) < FILE_REC_LEN`) by one byte lets
  `p` advance past `last`; the next `(size_t)(last - p)` computation then
  underflows to a huge unsigned value, defeating the payload bound too, and
  the following iteration's `ngx_http_error_abuse_get_u16()` reads past the
  allocated buffer. Confirmed 2026-08-04: mutating the bound to `< FILE_REC_LEN
  - 1` reproduces `heap-buffer-overflow ... ngx_http_error_abuse_get_u16` at
  `ngx_http_error_abuse_scan.c:56`; mutation reverted after confirmation.

- **`snapshot-payload-overrun-bound-exact.bin`** — two records: the first declares
  `key_len=32, event_count=1` (a 40-byte payload) but only 5 payload bytes are
  actually present in the buffer. Deleting the guard at
  `(last - p) < payload` lets `p += payload` overshoot `last` by 35 bytes;
  the second record's header read then dereferences past the allocation.
  Confirmed 2026-08-04: deleting the check reproduces the same
  `heap-buffer-overflow` signature at `ngx_http_error_abuse_get_u16`;
  mutation reverted after confirmation.

Both fixtures are clean (no crash) against unmutated
`ngx_http_error_abuse_validate_snapshot()` — verified with a fresh rebuild of
`fuzz_snapshot` before and after each mutation test.
