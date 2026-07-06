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

## Local commands

```bash
# Build nginx mainline and the dynamic module.
bash tools/ci-build.sh nginx 1.31.1

# Native multi-worker runtime suite.
python3 tools/test_runtime.py \
  --nginx-binary .build/nginx-1.31.1/objs/nginx \
  --module .build/nginx-1.31.1/objs/ngx_http_error_abuse_module.so \
  --redis-server /usr/bin/redis-server

# ASan and UBSan.
bash tools/ci-build.sh nginx 1.31.1 asan
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
python3 tools/test_runtime.py --single-process \
  --redis-server /usr/bin/redis-server \
  --nginx-binary .build/nginx-1.31.1/objs/nginx

# Valgrind.
python3 tools/test_runtime.py --single-process \
  --runner "valgrind --tool=memcheck --track-origins=yes --error-exitcode=99" \
  --redis-server /usr/bin/redis-server \
  --nginx-binary .build/nginx-1.31.1/objs/nginx \
  --module .build/nginx-1.31.1/objs/ngx_http_error_abuse_module.so
```
