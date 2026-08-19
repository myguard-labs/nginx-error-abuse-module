# Continuous integration

The CI pipeline is intentionally split by failure class:

Pull-request gate:

| Workflow | Check | Coverage |
|---|---|---|
| `ci.yml` | Orchestrator | The only `pull_request` entry point; calls the eight reusable members below. |
| `build-test.yml` | `Validation` | workflow lint, shellcheck, Python syntax, cppcheck |
| `build-test.yml` | `Build` | pinned nginx mainline, strict compile |
| `build-test.yml` | `Runtime` | multi-worker behavior, two-host Redis aggregation, snapshots and restart restore |
| `build-test.yml` | `Coverage report` | bounded runtime and parser coverage for both module translation units; report artifact only, no percentage threshold |
| `asan.yml` | `ASan and UBSan` | static module build plus single-process and multi-worker request-storm/reload lanes |
| `fuzzing.yml` | `Fuzz regression (120s/target)` | short libFuzzer regression run of the parse targets, with corpus and dictionary |
| `valgrind.yml` | `Memcheck lite (60s soak)` | uninitialized reads, invalid memory access, and definite/indirect leaks (`--errors-for-leak-kinds=definite,indirect`) |
| `security-scanners.yml` | `Security scanners` | flawfinder (high-severity gate), clang-tidy (`cert-*`, `bugprone-*`, `clang-analyzer-security.*`), Semgrep (`p/c`, `p/security-audit`) |
| `codeql.yml` | `CodeQL` | CodeQL analysis over the module translation unit |
| `lint.yml` | `Lint` | shell, Python, Perl, YAML/workflow, spelling, runner, port, cadence, secret, sync-stamp and docs-drift checks |
| `windows.yml` | `MSVC static module and runtime`; `MinGW-w64 static module` | native Windows builds, directive controls, two-worker persistence ownership and restart restore |

The eight reusable members are called by `ci.yml`; the seven Linux members use four runner lanes. `build-test`
precedes `asan`; `codeql` precedes `security-scanners`; `valgrind` precedes
`lint`; `fuzzing` and the hosted Windows workflow run independently. Members
carry `workflow_call` and do not have their own pull-request or push trigger,
so each change enters the lane once.

Deep pass (`ci-deep.yml`, monthly cron on the 4th + `workflow_dispatch`, not a
PR-lane member):

| Job | Coverage |
|---|---|
| `Fuzz (all targets, long)` | long libFuzzer run of all targets |
| `Valgrind Memcheck soak` | full memcheck soak |
| `Valgrind Helgrind soak` | thread-error detection soak |
| `Security scanners` | same scanner set as the PR gate |

All third-party actions are pinned to immutable commit SHAs. Workflows use
read-only repository permissions. Every job loads `.github/versions.env` via
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
