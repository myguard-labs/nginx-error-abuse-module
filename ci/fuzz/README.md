# Fuzzing

Coverage-guided fuzzing of the two untrusted-input parsers in the scan core,
[`../ngx_http_error_abuse_scan.c`](../ngx_http_error_abuse_scan.c):

- **`fuzz_snapshot`** → `ngx_http_error_abuse_validate_snapshot()` — the
  gate that walks the untrusted on-disk persistence snapshot before
  `ngx_http_error_abuse_load()` reads it back into shared memory.
- **`fuzz_statuses`** → `ngx_http_error_abuse_parse_statuses()` — the
  `"403,404,500-599"` status-list parser. It walks the list with
  `ngx_strlchr`/`ngx_atoi` and, for each status in each range, sets a bit
  in `zone->statuses[status >> 3]` — an **OOB-write** surface if the
  `first<100 / final<first / final>MAX_STATUS` guard is ever weakened.
  The harness allocates the bitmap as an exact-sized heap object so any
  single-byte over-write is an immediate ASAN failure.

Both targets link the real scan TU; the section below describes the snapshot
target in detail and the no-copy-drift setup that applies to both.

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

Both targets **link** [`../ngx_http_error_abuse_scan.c`](../ngx_http_error_abuse_scan.c)
— the same translation unit the shipped module links — together with nginx's
real `src/core/ngx_string.c`. So the parsers under test *and* the
`ngx_atoi()`/`ngx_strlchr()` they walk bytes with are production code, and the
snapshot harness's load()-stride replay decodes records through the same LE
getters the loader uses. There is no generated, sliced or re-typed copy anywhere
in the build.

That is why an ASAN report from these targets names
`ngx_http_error_abuse_scan.c:<line>` directly: the stack frame is the shipped
function, not a harness duplicate of it.

Earlier revisions sliced the two function bodies out of the module `.c` with
`extract_parser.sh` and compiled them against an `ngx_shim.h` that reimplemented
`ngx_atoi`, `ngx_strlchr` and the on-disk constants. Three copies, none of them
checked by the build — and a persistence-format change did once break the
harness's hand-maintained stride rather than the validator (see
`memory/labs/nginx-error-abuse-module/lessons.md`). Do not reintroduce that
pattern: if a parser cannot be linked directly, that is a signal to move it into
the scan TU, not to slice it.

[`ngx_stubs.c`](ngx_stubs.c) resolves the allocator/log symbols `ngx_string.c`
drags in. Every stub **aborts** rather than returning a plausible value, so the
scan core silently starting to allocate or log fails the fuzzer loudly. Growth
in that file means decision logic drifted back toward nginx types — fix the
seam, not the stub.

## Run locally

The targets need a configured nginx tree for its headers and `ngx_string.c`:

```bash
bash ci/tools/ci-build.sh             # once; uses the central nginx pin
bash ci/fuzz/build.sh                 # needs clang with libFuzzer
cd ci/fuzz
./fuzz_snapshot -max_total_time=60 corpus/
./fuzz_statuses -max_total_time=60 -dict=fuzz.dict corpus_statuses/
```

`build.sh` fails with an explicit message if no configured tree is present,
rather than falling back to anything stubbed.

A crash drops a `crash-*` reproducer. Replay it with:

```bash
./fuzz_snapshot crash-<hash>
```

## CI

[`.github/workflows/fuzzing.yml`](../../.github/workflows/fuzzing.yml) is the
reusable PR member called by `ci.yml`; the long campaign belongs to
[`ci-deep.yml`](../../.github/workflows/ci-deep.yml):

- **PR** — 2-min bounded regression run on every pull request through `ci.yml`
- **Deep monthly** — long discovery run on the 4th, with corpus upload
- **Manual** — `workflow_dispatch` on either workflow (the deep workflow accepts
  a custom duration)

ASAN+UBSAN are compiled in, so memory and undefined-behaviour bugs abort the
run and fail the job. The harness also traps if the validator ever returns a
value other than `NGX_OK`/`NGX_ERROR`, or breaks its lockstep contract with
`load()`.
