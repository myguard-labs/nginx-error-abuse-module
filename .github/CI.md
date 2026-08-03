# Continuous integration

The CI pipeline is intentionally split by failure class:

PR/push gates:

| Workflow | Check | Coverage |
|---|---|---|
| `build-test.yml` | `Validation` | workflow lint, shellcheck, Python syntax, cppcheck |
| `build-test.yml` | `Build` | nginx 1.31.1, strict warnings-as-errors compile |
| `build-test.yml` | `Runtime` | multi-worker behavior, two-host Redis aggregation, snapshots and restart restore |
| `build-test.yml` | `ASan and UBSan` | memory safety and undefined behavior |
| `fuzzing.yml` | `Fuzz regression (120s/target)` | short libFuzzer regression run of the parse targets, with corpus and dictionary |
| `valgrind.yml` | `Memcheck lite (60s soak)` | uninitialized reads, invalid memory access, and definite/indirect leaks (`--errors-for-leak-kinds=definite,indirect`) |
| `security-scanners.yml` | `Security scanners` | flawfinder (high-severity gate), clang-tidy (`cert-*`, `bugprone-*`, `clang-analyzer-security.*`), Semgrep (`p/c`, `p/security-audit`) |

Deep pass (`ci-deep.yml`, monthly cron on the 1st + `workflow_dispatch`):

| Job | Coverage |
|---|---|
| `Fuzz (all targets, long)` | long libFuzzer run of all targets |
| `Valgrind Memcheck soak` | full memcheck soak |
| `Valgrind Helgrind soak` | thread-error detection soak |
| `Security scanners` | same scanner set as the PR gate |

All third-party actions are pinned to immutable commit SHAs. Workflows use
read-only repository permissions.

## Divergence from the skeleton reference (checkpoint 4b, rule 2)

This repo's workflow set differs from `nginx-skeleton-module`'s in both
directions. Per-item keep-or-fold call, with evidence:

- **`ci-deep.yml` — KEPT.** Schedule-only (`cron` on the 1st +
  `workflow_dispatch`), not a `pull_request` member. Runs the long fuzz +
  full memcheck + helgrind sweep that the PR-lane `fuzzing.yml`/`valgrind.yml`
  intentionally keep short. Gates something the PR lane does not: see
  `ci-deep.yml` job list above. Matches the reference's own `ci-deep.yml`
  pattern — same role, not a duplicate.
- **`asan.yml` — ABSENT, due checkpoint 6.** ASan/UBSan currently runs as a
  job inside `build-test.yml` (see the `Build&Test` row above and the
  `ASan and UBSan` local command). The reference splits it into its own
  workflow for an independent request-storm soak; this repo has not split it
  out yet. No badge added for it now — see the `<!-- A/UBSan badge -->`
  placeholder comment in README.md.
- **`lint.yml` — ABSENT, due checkpoint 7.** The reference's `ci/linter/`
  gate has not been ported to this module yet; `build-test.yml`'s
  `Validation` job (workflow lint, shellcheck, Python syntax, cppcheck, see
  above) covers a subset in the meantime.
- **`bump.yml` — ABSENT, decision: port at checkpoint 4b follow-up /
  whenever `versions.env` needs its first live bump.** This checkpoint ports
  the version-pin *machinery* (`versions.env`, `load-versions.sh`,
  `compute-versions.sh`, `fetch-verify.sh`) but explicitly does not wire it
  into the existing workflows or add the weekly bump workflow — that is a
  separate, later checkpoint per the cp4b task scope. Until `bump.yml` lands,
  `versions.env` in this repo is inert (present, not yet consumed) and pins
  must be advanced by hand.

**Known pin discrepancy:** the ported `.github/versions.env` is an unmodified
copy of the skeleton's, which pins `NGINX_VERSION=1.31.3`. This repo's actual
build/CI version is `1.31.1` (see `ci/tools/ci-build.sh nginx 1.31.1` in the
local commands below and in `build-test.yml`). Per task scope, the skeleton's
sha256 digests were kept as-is rather than fabricated for 1.31.1 — the file
is landed inert (see `bump.yml` note above) and does not yet drive any build
step, so the mismatch does not affect current CI. Reconcile when `bump.yml`
and the workflow rewiring land.

## Local commands

```bash
# Build nginx mainline and the dynamic module.
bash ci/tools/ci-build.sh nginx 1.31.1

# Native multi-worker runtime suite.
python3 ci/tools/test_runtime.py \
  --nginx-binary .build/nginx-1.31.1/objs/nginx \
  --module .build/nginx-1.31.1/objs/ngx_http_error_abuse_module.so \
  --redis-server /usr/bin/redis-server

# ASan and UBSan.
bash ci/tools/ci-build.sh nginx 1.31.1 asan
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
python3 ci/tools/test_runtime.py --single-process \
  --redis-server /usr/bin/redis-server \
  --nginx-binary .build/nginx-1.31.1/objs/nginx

# Valgrind.
python3 ci/tools/test_runtime.py --single-process \
  --runner "valgrind --tool=memcheck --track-origins=yes --error-exitcode=99" \
  --redis-server /usr/bin/redis-server \
  --nginx-binary .build/nginx-1.31.1/objs/nginx \
  --module .build/nginx-1.31.1/objs/ngx_http_error_abuse_module.so
```
