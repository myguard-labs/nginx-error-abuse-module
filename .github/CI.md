# Continuous integration

The CI pipeline is intentionally split by failure class:

Pull-request gate:

| Workflow | Check | Coverage |
|---|---|---|
| `ci.yml` | Orchestrator | The only `pull_request` entry point; calls the seven reusable PR members below. |
| `build-test.yml` | `Validation` | workflow lint, shellcheck, Python syntax, cppcheck |
| `build-test.yml` | `Build` | pinned nginx mainline, strict compile |
| `build-test.yml` | `Runtime` | multi-worker behavior, two-host Redis aggregation, snapshots and restart restore |
| `build-test.yml` | `Coverage report` | bounded runtime and parser coverage for both module translation units; report artifact only, no percentage threshold |
| `asan.yml` | `ASan and UBSan` | static module build plus single-process and multi-worker request-storm/reload lanes |
| `valgrind.yml` | `Memcheck lite (60s soak)` | uninitialized reads, invalid memory access, and definite/indirect leaks (`--errors-for-leak-kinds=definite,indirect`) |
| `security-scanners.yml` | `Security scanners` | flawfinder (high-severity gate), clang-tidy (`cert-*`, `bugprone-*`, `clang-analyzer-security.*`), Semgrep (`p/c`, `p/security-audit`) |
| `codeql.yml` | `CodeQL` | CodeQL analysis over the module translation unit |
| `lint.yml` | `Lint` | shell, Python, Perl, YAML/workflow, spelling, runner, port, cadence, secret, sync-stamp and docs-drift checks |
| `windows.yml` | `MinGW-w64 static module` | fast native Windows compiler check |

The seven PR members enter through `ci.yml` once. Lint and build-test start
immediately. Lint → CodeQL → scanners forms the static chain. Build-test
retains validation, strict build → runtime, and Test::Nginx → coverage;
after build-test, ASan → reload, Memcheck lite and MinGW run independently.
The conservative expanded dependency graph has width four, counting all
reusable children and matrix entries, including failure diagnostic paths.
Members retain manual dispatch for diagnostics.

Deep pass (`ci-deep.yml`, monthly cron on the 4th + `workflow_dispatch`, not a
PR-lane member):

| Job | Coverage |
|---|---|
| A: `Fuzz (all targets, long)` | replay every regression, 120s/target then 3600s/target discovery, one compatible sanitizer build; all corpora and dictionaries |
| B: `windows-msvc.yml` → `Valgrind Memcheck soak` | unchanged complete MSVC build/native controls, then 600s @ 4 concurrency Memcheck |
| C: `Valgrind Helgrind soak` | 600s @ 4 concurrency thread-error soak |
| D: `Security scanners` → `codeql.yml` | deep scanner commands and reports, then the unchanged CodeQL analysis |

The sole scheduled entry is `ci-deep.yml` at `30 3 4 * *` UTC. CodeQL retains
its PR gate and manual diagnostics; its former separate monthly cron is removed.
`fuzzing.yml` remains a manual/reusable 120s diagnostic and is unreachable from
PRs; CI Deep uses the same runner command before discovery without rebuilding.
`windows-msvc.yml` is monthly/manual only. Fuzz and MSVC failures therefore have
the explicitly selected monthly/manual detection cadence.

Coverage mapping: build-test validation/build/runtime/Test::Nginx/coverage,
ASan/UBSan/reload, Memcheck lite, linters, MinGW, PR scanners and PR CodeQL
retain their original commands, assertions and artifact contracts. The complete
MSVC job moves unchanged from `windows.yml` to `windows-msvc.yml`. Both 600s
soaks, deep scanners, Discord scheduled-failure notifications, error exits and
14-day scanner reports stay in CI Deep. Fuzz discovery retains sanitizer flags,
replays all fixtures, runs every target for 120s then the full selected duration,
merges each corpus into `ci/fuzz/minimized/<corpus-name>/`, and keeps fast
crash (14 days), deep crash and minimized
corpus (30 days) artifacts. New `fuzz_*.c` targets are automatically built and
run; a missing corpus/binary or unroutable regression fails visibly. Manual
`fuzz_seconds` remains strictly bounded to 1..86400; scheduled runs use 3600.

### Required-check migration before delivery

Current protection requires `fuzzing / Fuzz regression (120s/target)`. Before
pushing the cadence change, remove that context and retain the other ten real
PR contexts: `build-test / Validation`, `build-test / Runtime`,
`build-test / Test::Nginx`, `build-test / Build (nginx / gcc)`,
`security-scanners / Security scanners`, `valgrind / Memcheck lite (60s soak)`,
`codeql / Analyze C`, `asan / ASan and UBSan`,
`asan / ASan multi-worker + reload`, and `lint / Linters`.
No replacement check is fabricated: parser/runtime/sanitizer checks continue
to gate PRs; fuzzing and MSVC are required monthly operational coverage.
Ordering: inspect live protection and rulesets; update only the retired fuzz
context while old PR checks still exist; read back and verify the ten-context
contract; push this workflow candidate; verify all ten contexts run on the
current PR head and the monthly/manual graph passes before merge. Repository
settings are a delivery action, not performed by local workflow preparation.

All third-party actions are pinned to immutable commit SHAs. Workflows use
read-only contents permissions, with CodeQL alone granted security-events write
for its analysis upload. Every job loads `.github/versions.env` via
`.github/scripts/load-versions.sh` before using a toolchain or source pin.

## Default versions

`.github/versions.env` is the single source of truth. `NGINX_VERSION` is the
default for every single-version PR job and currently tracks mainline
(`NGINX_MAINLINE`); `NGINX_STABLE` and `ANGIE_VERSION` are used only by the
deep-pass matrix. Each version has an adjacent SHA-256 pin, and
`load-versions.sh` validates and exports the file into `$GITHUB_ENV`.
There is no automatic bump workflow: update the file with
`compute-versions.sh`, verify the digest, and run the linter.

## Local commands

Local `ci/tools/ci-build.sh` runs require Debian dpkg tooling with `dpkg-query`
on `PATH` and a readable package database. The installed package fingerprint is
required for every local build, including `CI_BUILD_IDENTITY_ONLY=1` and
`NO_CACHE=1`; these modes fail before fetching or building if the probe is
unavailable or fails. Importing a verified producer artifact with
`ci/tools/ci-build-artifact.sh import` does not probe the consumer's packages.

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

# Generate HTML, text and JSON coverage reports under .build/coverage/.
# This runs the bounded runtime suite against the static coverage build.
ci/tools/coverage.sh "$NGINX_VERSION"

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

The PR orchestrator starts lint and build-test immediately. Later phases retain
all existing checks and run after predecessors finish, including on failure.
`ci/tools/check_ci_graph.py` conservatively bounds the expanded PR graph to four
runner jobs, including reusable workflows and matrix entries. It rejects graph
features it cannot bound. `ci/tools/check_ci_cadence.py` also bounds the monthly/manual graph and
rejects PR-reachable fuzz/MSVC and lost coverage. Independent workflow runs
are outside this per-run limit.
