# Fuzzing

Coverage-guided fuzzing of the two untrusted-input parsers in
[`../ngx_http_error_abuse_module.c`](../ngx_http_error_abuse_module.c):

- **`fuzz_snapshot`** → `ngx_http_error_abuse_validate_snapshot()` — the
  gate that walks the untrusted on-disk persistence snapshot before
  `ngx_http_error_abuse_load()` reads it back into shared memory.
- **`fuzz_statuses`** → `ngx_http_error_abuse_parse_statuses()` — the
  `"403,404,500-599"` status-list parser. It walks the list with
  `ngx_strlchr`/`ngx_atoi` and, for each status in each range, sets a bit
  in `zone->statuses[status >> 3]` — an **OOB-write** surface if the
  `first<100 / final<first / final>MAX_STATUS` guard is ever weakened.
  The harness puts the bitmap at the tail of an exact-sized heap object
  so any single-byte over-write is an immediate ASAN failure.

Both parsers are sliced verbatim into `generated_parser.inc`; the section
below describes the snapshot target in detail and the no-copy-drift setup
that applies to both.

## Why this target

The validator parses bytes an attacker (or disk corruption) can place at the
`error_abuse_zone … persist=` path. It does raw pointer arithmetic against
`p`/`last` and `ngx_memcpy()`s a fixed-size record straight off the buffer,
then trusts `record.key_len` / `record.event_count` to advance. `load()`
relies on it: if validate returns `NGX_OK`, load walks the **same** buffer
with the **same** stride and reads `key_len + event_count*8` payload bytes
**without re-deriving the bound**. That length-bounded record/payload walk is
exactly the truncation / over-read bug class the Perl suite cannot reach.

## The contract under test

```
validate_snapshot() == NGX_OK  =>  every byte load() later reads is < last
```

The harness ([`fuzz_snapshot.c`](fuzz_snapshot.c)) fuzzes it two ways at once:

1. **ASAN/UBSAN on the validator** catches any OOB read or overflow in its
   own walk.
2. **Lockstep replay** — when validate returns `NGX_OK`, the harness re-walks
   the buffer with `load()`'s exact stride and touches every payload byte. Any
   gap between what validate accepts and what load reads becomes an immediate
   heap-buffer-overflow. Hard regression gate on the two staying in sync.

The first 5 input bytes are control levers (`records` u32 + a `threshold`
byte); the rest is the snapshot payload handed in as `[p, last)`.

## No copy drift

There is **no hand-maintained copy** of the validator.
[`extract_parser.sh`](extract_parser.sh) slices its verbatim body out of the
shipped `.c` into `generated_parser.inc` at build time and fails loudly if it
cannot find it. [`ngx_shim.h`](ngx_shim.h) supplies only the tiny nginx
surface the function needs (`ngx_int_t`, the two on-disk struct layouts,
`zone->threshold`, `ngx_memcpy`) with faithful upstream semantics.

## Run locally

```bash
bash fuzz/build.sh          # needs clang with libFuzzer
cd fuzz
./fuzz_snapshot -max_total_time=60 corpus/
```

A crash drops a `crash-*` reproducer. Replay it with:

```bash
./fuzz_snapshot crash-<hash>
```

## CI

[`.github/workflows/fuzzing.yml`](../.github/workflows/fuzzing.yml), kept
separate from the build/test pipeline so it never slows PR feedback:

- **Monthly** — 15-min discovery run, merges + uploads the grown corpus
- **PR** — 2-min bounded regression run, *only* when the source, `fuzz/`, or
  the workflow changes (`paths:` filter)
- **Manual** — `workflow_dispatch` with a custom duration

ASAN+UBSAN are compiled in, so memory and undefined-behaviour bugs abort the
run and fail the job. The harness also traps if the validator ever returns a
value other than `NGX_OK`/`NGX_ERROR`, or breaks its lockstep contract with
`load()`.
