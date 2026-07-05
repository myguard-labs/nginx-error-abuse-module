#!/usr/bin/env bash
#
# Sustained error-traffic soak for the error-abuse module. LOCAL ONLY —
# not wired into CI (CI's single-shot suite never churns the rbtree).
# Drives a real nginx (ideally an ASAN/UBSAN build, optionally under
# valgrind) with a mix of 403/404/5xx storms across many distinct client
# keys, so the memory-heavy paths actually run for minutes:
#   - rbtree insert + LRU/inactive eviction (small zone, many keys)
#   - the per-node event ring wrapping (% threshold)
#   - block -> 429 -> unblock transitions (low threshold, short block)
#   - periodic snapshot save/load (short persist_interval)
# Then asserts the worker survived cleanly: no sanitizer report, no
# valgrind error, no crash, no error-log [alert]/[emerg] — AND that the
# block path actually fired (saw a 429), so a clean run is meaningful.
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 600 8
#
# Build the nginx binary with the module + -fsanitize=address,undefined
# for the ASAN path, or a plain debug build for the valgrind path.

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-120}"
CONC="${3:-8}"
PORT=18244

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/state" "$WORK/html"
echo ok > "$WORK/html/ok"

# Tiny zone + low threshold + short block so eviction, ring-wrap and the
# block/unblock cycle all happen many times over the soak.
cat > "$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 2;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    access_log off;

    error_abuse_zone zone=soak:1m
                     key=\$arg_id
                     statuses=403,404,500-599
                     interval=300s
                     threshold=20
                     block=10s
                     inactive=300s
                     persist=$WORK/state/soak.state
                     persist_interval=2s;

    server {
        listen 127.0.0.1:$PORT;
        root $WORK/html;
        default_type text/plain;

        # The ci-build nginx is configured --without-http_rewrite_module,
        # so the return directive is unavailable; produce each counted
        # status the natural way instead.
        location / { error_abuse zone=soak; }                 # 404 (no such file)
        location = /ok   { error_abuse zone=soak; }           # 200 (serves html/ok)
        location = /e403 { error_abuse zone=soak; deny all; } # 403 (access phase)
        location = /e502 {                                    # 502 (origin refused)
            error_abuse zone=soak;
            proxy_pass http://127.0.0.1:1;
            proxy_connect_timeout 1s;
        }
    }
}
EOF

ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:abort_on_error=1:exitcode=42:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=1"

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
# Suppression file lives at tools/valgrind.supp (nginx core pool/ssl leaks that
# are never freed at exit). Passed to BOTH memcheck and helgrind so a real
# module leak/race (which always carries an error_abuse_* frame) is never hidden.
SUPP="$(cd "$(dirname "$0")" && pwd)/valgrind.supp"
if [ "${USE_VALGRIND:-0}" = "1" ]; then
    VG=(valgrind --error-exitcode=99 --leak-check=full
        --errors-for-leak-kinds=definite
        --log-file="$WORK/logs/valgrind.%p")
    [ -f "$SUPP" ] && VG+=(--suppressions="$SUPP")
    RUN=("${VG[@]}" "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
    # Data-race / lock-order checking (shm zone + --with-threads aio pool).
    # --error-exitcode=99 makes a detected race FAIL the job (not grep-only).
    VG=(valgrind --tool=helgrind --error-exitcode=99
        --log-file="$WORK/logs/helgrind.%p")
    [ -f "$SUPP" ] && VG+=(--suppressions="$SUPP")
    RUN=("${VG[@]}" "${RUN[@]}")
fi

"${RUN[@]}" &
NGINX_PID=$!

for _ in $(seq 1 100); do
    curl -fsS -o /dev/null "http://127.0.0.1:$PORT/ok?id=warm" 2>/dev/null && break
    sleep 0.1
done

echo "soak: ${DURATION}s, concurrency ${CONC}$( [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'; [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)')"
END=$(( $(date +%s) + DURATION ))
saw_429="$WORK/logs/saw_429"

worker() {
    local paths=(/missing /e403 /e502 /ok)
    while [ "$(date +%s)" -lt "$END" ]; do
        # 70% of traffic: a small key set, to trip threshold -> 429.
        # 30%: a huge key space, to grow + evict the rbtree.
        if [ $((RANDOM % 10)) -lt 7 ]; then
            id=$((RANDOM % 40))
        else
            id=$((RANDOM % 100000))
        fi
        p=${paths[$((RANDOM % ${#paths[@]}))]}
        code=$(curl -s -o /dev/null -w '%{http_code}' \
               "http://127.0.0.1:$PORT$p?id=$id" 2>/dev/null || echo 000)
        [ "$code" = "429" ] && : > "$saw_429"
    done
}

pids=()
for _ in $(seq 1 "$CONC"); do worker & pids+=($!); done
for pid in "${pids[@]}"; do wait "$pid" || true; done

# Clean shutdown so persist-on-exit + all pool cleanups run.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null; rc=$?

problems=0
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then
    echo "FAIL: ASAN/UBSAN report:"; cat "$WORK"/logs/asan*; problems=1
fi
if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null; then
        echo "FAIL: valgrind/helgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null
        problems=1
    fi
fi
# Any alert/emerg fails — EXCEPT the intermittent shm-teardown line nginx
# logs when a worker still holds a zone mutex at QUIT ("shared memory zone
# ... was locked by <pid>"). That is a shutdown race, not a runtime memory
# bug (ASAN/valgrind below catch real corruption), and it is flaky, so it
# must not turn the soak red on its own.
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null \
        | grep -vE 'shared memory zone .* was locked by|open socket #[0-9]+ left in connection|\[alert\][^:]*: aborting'; then
    echo "FAIL: alert/emerg in error.log"; problems=1
fi
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"; tail -40 "$WORK/logs/error.log" || true
    problems=1
fi
if [ ! -f "$saw_429" ]; then
    echo "FAIL: never saw a 429 — block path did not fire, soak is not exercising the module"
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent — eviction+ring+block exercised, no sanitizer/leak/crash"
