# Continuous integration

The CI pipeline is intentionally split by failure class:

PR/push gates:

| Workflow | Check | Coverage |
|---|---|---|
| `build-test.yml` | `Validation` | workflow lint, shellcheck, Python syntax, cppcheck |
| `build-test.yml` | `Build` | pinned nginx mainline, strict compile |
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
- **`bump.yml` — ABSENT.** Version pins are maintained manually in
  `.github/versions.env`. Workflows load that file and `ci-build.sh` accepts
  only its pinned nginx and Angie versions. Every restored or downloaded source
  archive is SHA-256 verified before extraction; `NO_CACHE=1` forces a fresh
  download but does not bypass verification.

## Local commands

```bash
# Build nginx mainline and the dynamic module.
source .github/versions.env
bash ci/tools/ci-build.sh nginx "$NGINX_VERSION"
build=".build/nginx-${NGINX_VERSION}-debug/objs"

# Native multi-worker runtime suite.
python3 ci/tools/test_runtime.py \
  --nginx-binary "$build/nginx" \
  --module "$build/ngx_http_error_abuse_module.so" \
  --redis-server /usr/bin/redis-server

# ASan and UBSan.
bash ci/tools/ci-build.sh nginx "$NGINX_VERSION" asan
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
python3 ci/tools/test_runtime.py --single-process \
  --redis-server /usr/bin/redis-server \
  --nginx-binary ".build/nginx-${NGINX_VERSION}-asan/objs/nginx"

# Valgrind.
python3 ci/tools/test_runtime.py --single-process \
  --runner "valgrind --tool=memcheck --track-origins=yes --error-exitcode=99" \
  --redis-server /usr/bin/redis-server \
  --nginx-binary "$build/nginx" \
  --module "$build/ngx_http_error_abuse_module.so"
```
