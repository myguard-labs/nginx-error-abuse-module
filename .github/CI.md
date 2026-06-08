# Continuous integration

The CI pipeline is intentionally split by failure class:

| Workflow | Required check | Coverage |
|---|---|---|
| `build-test.yml` | `Validation` | workflow lint, shellcheck, Python syntax, cppcheck |
| `build-test.yml` | `Build (nginx-mainline)` | nginx 1.31.1, strict warnings-as-errors compile |
| `build-test.yml` | `Build (nginx-stable)` | nginx 1.30.2 compatibility |
| `build-test.yml` | `Build (angie)` | Angie 1.11.6 compatibility |
| `build-test.yml` | `Runtime` | multi-worker behavior, reload and persistence |
| `build-test.yml` | `ASan and UBSan` | memory safety and undefined behavior |
| `valgrind.yml` | `Memcheck` | uninitialized reads and invalid memory access |
| `codeql.yml` | `Analyze C` | CodeQL security-extended C/C++ queries |

All third-party actions are pinned to immutable commit SHAs. Workflows use
read-only repository permissions except CodeQL, which additionally receives
`security-events: write`.

## Local commands

```bash
# Build nginx mainline and the dynamic module.
bash tools/ci-build.sh nginx 1.31.1

# Native multi-worker runtime suite.
python3 tools/test_runtime.py \
  --nginx-binary .build/nginx-1.31.1/objs/nginx \
  --module .build/nginx-1.31.1/objs/ngx_http_error_abuse_module.so

# ASan and UBSan.
bash tools/ci-build.sh nginx 1.31.1 asan
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
python3 tools/test_runtime.py --single-process \
  --nginx-binary .build/nginx-1.31.1/objs/nginx

# Valgrind.
python3 tools/test_runtime.py --single-process \
  --runner "valgrind --tool=memcheck --track-origins=yes --error-exitcode=99" \
  --nginx-binary .build/nginx-1.31.1/objs/nginx \
  --module .build/nginx-1.31.1/objs/ngx_http_error_abuse_module.so
```
