# Fuzzing

Coverage-guided fuzzing of the module's untrusted-input parsers:

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
- **`fuzz_accept`** → `ngx_http_error_abuse_stats_query_format()` and
  `ngx_http_error_abuse_accept_field()` — raw `?format=` queries and repeated
  Accept fields, including quoted pairs and the request-wide item/byte budgets.
  Curated seeds retain positive, boundary and malformed oracles in every replay.

The snapshot and status targets link the real scan TU. The Accept target
includes the same production stats header as the module. The section below
describes the snapshot target in detail and the no-copy-drift setup.

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

```text
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

The snapshot and status targets **link**
[`../ngx_http_error_abuse_scan.c`](../ngx_http_error_abuse_scan.c)
— the same translation unit the shipped module links — together with nginx's
real `src/core/ngx_string.c`. So the parsers under test *and* the
`ngx_atoi()`/`ngx_strlchr()` they walk bytes with are production code, and the
snapshot harness's load()-stride replay decodes records through the same LE
getters the loader uses. There is no generated, sliced or re-typed copy anywhere
in the build.

That is why an ASAN report from these targets names
`ngx_http_error_abuse_scan.c:<line>` directly: the stack frame is the shipped
function, not a harness duplicate of it.

`fuzz_accept` compiles
[`../ngx_http_error_abuse_stats.h`](../ngx_http_error_abuse_stats.h) directly.
Its repeated-field path calls the same `ngx_http_error_abuse_accept_field()`
helper as the request handler, so byte and item accumulation stay production
code rather than a harness copy.

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
./fuzz_accept -max_total_time=60 -dict=fuzz_accept.dict corpus_accept/
```

`build.sh` fails with an explicit message if no configured tree is present,
rather than falling back to anything stubbed.

A crash drops a `crash-*` reproducer. Replay it with:

```bash
./fuzz_snapshot crash-<hash>
```

## CI

[`.github/workflows/fuzzing.yml`](../../.github/workflows/fuzzing.yml) is the
manual regression diagnostic; the monthly regression and long campaign belong to
[`ci-deep.yml`](../../.github/workflows/ci-deep.yml):

- **PR** — deterministic parser/runtime tests and sanitizers remain in `ci.yml`;
  fuzz campaigns run monthly/manual
- **Deep monthly** — regression replay + 120s/target, then 3600s/target discovery
  on the 4th, sharing one sanitizer build, with crash/corpus upload
- **Manual** — `workflow_dispatch` on either workflow (the deep workflow accepts
  a custom duration)

ASAN+UBSAN are compiled in, so memory and undefined-behaviour bugs abort the
run and fail the job. The harnesses also trap if a parser returns outside its
declared result domain, the snapshot validator breaks its lockstep contract
with `load()`, or a curated Accept/query oracle changes.

`build.sh` and `run.py` discover every `fuzz_*.c`, including future targets.
Target binary names must not end in `.dict`, `.c`, or `.h`, which are reserved
for input files. Dotted source names such as `fuzz_headers.v2.c` remain valid.
Each target requires a matching executable and `corpus_<name>/` directory;
`fuzz_snapshot` retains `corpus/`. `fuzz_statuses` retains `fuzz.dict`;
other targets may provide `<binary-name>.dict` (for example,
`fuzz_accept.dict`). A target named `fuzz_fuzz` uses `fuzz_fuzz.dict`,
leaving the statuses dictionary exclusive to `fuzz_statuses`. Regression fixtures
use
`regressions/<full-target-name>-<suffix>.bin` with a nonempty suffix. Exactly one
registered target name followed by `-` must match. Ambiguous prefixes fail before
any execution, so adding `snapshot-record-length` cannot steal an existing
`snapshot-record-length-bound-exact.bin` fixture from `snapshot`. Bare target
names, unknown prefixes and missing suffixes also fail; missing targets/corpora
fail visibly. Existing `snapshot-<suffix>.bin` names remain valid.

The deep job has a total admission budget of **360 minutes on GitHub-hosted
runners** and **600 minutes on self-hosted runners**. Before building,
`python3 ci/fuzz/run.py "$FUZZ_SECS" --runner-class "$RUNNER_ENVIRONMENT"
--check-budget` counts all `fuzz_*.c`
sources and regression fixtures, without needing binaries. Every normal runner
invocation repeats the check before starting any replay or campaign. The requested
per-target duration remains unchanged; an oversized request fails with the target
count, required total and maximum discovery duration.

Admission reserves 3600 seconds for setup, build, uploads and runner overhead;
for each target it includes the requested discovery duration, the default
120-second regression campaign, 60 seconds of exit grace for each campaign, and
600 seconds for minimization. Each fixture reserves 60 seconds in each of the
two replay passes. Thus, with the current three targets and two fixtures,
GitHub-hosted runners accept the 3600-second default and at most 5080 seconds per
target. Self-hosted runners accept the same default and at most 9880 seconds per
target. Adding a target or fixture reduces each maximum automatically. These
are admission allowances, not measured execution guarantees: the workflow's
600-minute timeout remains an independent hard upper bound on self-hosted
runners. GitHub-hosted jobs stop after **360 minutes**, even when the workflow
allows 600 minutes. Either cutoff can end an overrun before corpus upload.
See [GitHub Actions limits](https://docs.github.com/en/actions/reference/limits).

The budget preflight and `--merge` discovery include both passes. A standalone
regression invocation admits its own campaign and replay once, without charging
the discovery or merge allowance again. Each campaign has a wrapper deadline of
its target duration plus 60 seconds of exit grace.

Discovered target stems must match `fuzz_[A-Za-z0-9_][A-Za-z0-9_.-]*`.
Spaces and shell metacharacters cannot be passed safely to libFuzzer merge
workers; dotted names such as `fuzz_headers.v2.c` remain supported.
