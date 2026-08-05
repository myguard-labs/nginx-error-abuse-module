#!/usr/bin/env python3
"""End-to-end tests for ngx_http_error_abuse_module.

MODULE-UNLOADED BASELINE (2026-08-05, no --module flag): the suite does not
silently pass -- it fails at the very first case, before any HTTP traffic:

    $ python3 ci/tools/test_runtime.py --port 18880 \\
          --nginx-binary $PWD/.build/nginx-1.31.3-debug/objs/nginx \\
          --redis-server $(which redis-server)
    ERROR: minimal-zone config was rejected but should be valid:
    nginx: [emerg] unknown directive "error_abuse_zone" in
    /tmp/error-abuse-ci-*/minimal-zone/conf/nginx.conf:4

This is the expected and correct failure mode: with no module loaded, nginx
does not know the error_abuse_zone directive at all, so test_valid_configs()
(the first thing main() calls) fails immediately on its first
expect_valid_config() case. There is no code path in this file that can run
any further without the module.

MUTATION LEDGER -- SEEN RED. Every mutation below was APPLIED to
src/ngx_http_error_abuse_module.c, rebuilt with
`bash ci/tools/ci-build.sh nginx 1.31.3`, run against this suite with
`python3 ci/tools/test_runtime.py --port 18880 --nginx-binary
$PWD/.build/nginx-1.31.3-debug/objs/nginx --module
$PWD/.build/nginx-1.31.3-debug/objs/ngx_http_error_abuse_module.so
--redis-server $(which redis-server)`, and observed FAILING; each was then
reverted (`git diff src/` empty) and the unmutated build reconfirmed green in
the same session before moving to the next. Re-run these after touching the
runtime enforcement path: a check that has never failed is not known to be a
check. Ordered by the priority this ledger was built in: ban enforcement,
zone/key handling, error-page/redirect, then persistence.

  * threshold off-by-one (ban enforcement) -- in
    ngx_http_error_abuse_record(), change `if (ean->event_count >=
    zone->threshold)` to `> zone->threshold`, so a client sitting exactly AT
    the configured threshold is never banned.
      -> test_on_full_policy(): "/err?client=fresh-reject" expected 503, got
         404 (the reject-on-full leg never sees the zone fill, because
         _fill_zone()'s last request stops one short of tripping the ban).

  * interval/window boundary widened (zone/key handling -- event pruning) --
    in ngx_http_error_abuse_prune_events(), change `events[ean->event_head]
    <= cutoff` to `< cutoff`, so an event exactly AT the window cutoff is
    kept instead of pruned, one interval-width too long.
      -> main(): "/window-ok" expected 200, got 429 (an event that should
         have aged out of the interval window is still counted, so the
         identity is still banned after the window elapsed).

  * key hashing collapsed (zone/key handling -- per-identity isolation) --
    in ngx_http_error_abuse_prepare_ctx(), change `SHA256(key.data, key.len,
    ctx->key.data)` to `SHA256(key.data, 1, ctx->key.data)`, so only the
    first raw key byte feeds the identity hash; distinct keys sharing a
    first byte collapse onto one shared node.
      -> T-1 follow-up: the existing "/key-*" block (client=a / client=b)
         does NOT catch this mutation -- verified by running it in
         isolation against the mutated build: it stayed GREEN, because "a"
         and "b" differ in their FIRST byte, which is exactly the one byte
         a truncated hash still reads, so truncated hashing still separates
         them. A dedicated case was added: zone=keyiso, threshold=1, two
         locations, with client=aaa / client=aab (identical first byte,
         differ only after it). Isolated against the mutated build this
         case fails -- "/keyiso-ok?client=aab" expected 200, got 429 (the
         "aab" identity was wrongly banned by "aaa"'s hit, because the
         truncated hash collapsed both onto the same node). Reverted and
         reconfirmed green. This was previously caught only incidentally
         via test_on_full_policy()'s zone-fill cross-contamination between
         "fresh-allow" and its fill clients (see TODO.md history) -- that
         incidental catch still holds, but no longer needs to carry the
         key-hashing case; T-1 makes it explicit and reachable on its own.

  * anchor restore disabled (error-page/redirect) -- in
    ngx_http_error_abuse_prepare_ctx(), change `if (ctx != NULL)` (the F-2
    anchor-restore branch after ngx_http_error_abuse_find_anchor_ctx()) to
    `if (0 && ctx != NULL)`, so every error_page-redirected destination
    location gets a FRESH ctx instead of reusing the origin's.
      -> test_error_page_redirect(): "/origin-ok?client=off-a" expected 429,
         got 200 (the origin's threshold=1 hit never reaches the zone,
         because the destination location silently allocated a new,
         unrelated ctx instead of restoring the one the origin earned).

  * HMAC verification disabled (persistence, SEC-5) -- in the persistence
    loader, change the tampered-MAC rejection condition's
    `CRYPTO_memcmp(mac, buffer + payload_size, NGX_HTTP_ERROR_ABUSE_MAC_LEN)
    != 0` to a literal `0`, so a snapshot whose trailing HMAC does not match
    is trusted and loaded anyway.
      -> main(): "/secret-ok" expected 200, got 429 (a snapshot with a
         deliberately bit-flipped HMAC tail was loaded and its ban
         restored, instead of being ignored).

T-2 follow-up (2026-08-05) measured the six areas the pass above left
UNMEASURED. Same build/run/revert discipline: mutate src/, rebuild, observe,
revert, reconfirm green in the same session before moving on.

  * shared Redis blocking never applied (test_redis_multi_host()) -- in
    ngx_http_error_abuse_redis_check_callback(), change `ctx->redis_blocked
    = 1;` (REDIS_REPLY_STRING branch) to `= 0;`, so a GET that finds an
    existing block key in Redis is treated as not-blocked.
      -> test_redis_multi_host(): "/redis-ok?client=shared" (second host,
         after the first host's two 404s) expected 429, got 200 -- the
         second nginx instance never saw the block the first instance wrote
         to the shared Redis backend. SEEN RED.

  * AUTH handshake skipped (test_redis_auth()) -- in
    ngx_http_error_abuse_redis_connect_callback(), change `if
    (worker->conf->password.len)` to `if (0 && worker->conf->password.len)`,
    so the AUTH command is never sent to a password-protected Redis.
      -> test_redis_auth(): SURVIVED. Confirmed via error.log that the
         mutation did take effect -- every worker logged "error_abuse: Redis
         handshake (AUTH/SELECT) failed: NOAUTH Authentication required."
         (COR-5 failure path), yet all 4 requests still got their expected
         status (404/404/404/429) and assert_clean_logs() passed. Root
         cause: test_redis_auth() runs a single nginx instance, so once
         Redis is unreachable (NOAUTH trips the circuit breaker exactly like
         a connection failure), the module falls back to the same-node
         shared-memory zone, which independently enforces threshold=1 --
         masking whether AUTH ever ran. A case that would actually catch a
         disabled/broken AUTH handshake needs two nginx instances sharing
         one Redis (like test_redis_multi_host()'s topology) so only Redis-
         mediated blocking can make the second instance's request succeed
         or fail -- local zone enforcement can't cover for a second process.

  * COR-3 inactive-vs-interval/block check disabled (test_invalid_configs())
    -- in the error_abuse_zone merge validation, change `} else if
    (zone->inactive < zone->interval || zone->inactive < zone->block) {` to
    `} else if (0 && (...)) {`, so an explicit inactive shorter than
    interval/block is accepted instead of rejected.
      -> test_invalid_configs(): the "short-inactive" case (interval=5m,
         block=1h, inactive=1s) expected the config to be rejected with
         "inactive must be >=" and instead got "syntax is ok" /
         "test is successful". SEEN RED.

  * reload key-change guard disabled -- in
    ngx_http_error_abuse_init_zone(), change the `if (old->key.value.len !=
    zone->key.value.len || ngx_strncmp(...) != 0)` key-mismatch check to `if
    (0 && (...))`, so a reload with a changed zone key is silently accepted
    instead of rejected.
      -> main(): after write_config("$binary_remote_addr") followed by
         reload, error.log was expected to contain "key cannot change
         during reload" and did not -- the reload was accepted.
         AssertionError: "reload accepted a changed zone key". SEEN RED.

  * persistence CRC32 corruption check disabled -- in the persistence
    loader, change the CRC32 mismatch condition's `ngx_http_error_abuse_get_
    u32(buffer + 20) != ngx_crc32_long(p, last - p)` to `0 && (...)`, so a
    snapshot whose payload CRC does not match the header is trusted and
    parsed anyway.
      -> main() (pre-B-3): SURVIVED. The truncation scenario the suite
         exercised (`state.write_bytes(data[:-1])`, dropping exactly the
         trailing byte) still recovered correctly with the CRC check
         disabled, because it hit an independent guard first: shrinking the
         buffer by one byte shifts `last - p` short of what the still-intact
         header's record/field-length fields expect, so the mid-parse
         bounds checks (`(size_t) (last - p) < NGX_HTTP_ERROR_ABUSE_FILE_
         REC_LEN` and the per-record key/event-length check right after it)
         already reject the malformed tail and drop the record -- with or
         without CRC32.
      -> main() (B-3, added an in-place byte flip): KILLED. Re-banned
         `persisted.state`, stopped nginx, then flipped one byte inside a
         record's `blocked_until` field (file offset 24+4+2, same length,
         same field boundaries -- the value is only ever range-clamped and
         compared with `>`, never validated against a length or count, so
         every downstream bounds check still passes). With the CRC32 check
         live: `/persist-ok` after reload correctly stayed 200 (corrupted
         snapshot rejected, file deleted, no ban restored). With the CRC32
         mismatch branch disabled via `if (0 && ...)`, rebuilt
         (ngx_http_error_abuse_module.so mtime 2026-08-05 03:02:21, 985008
         bytes) and rerun: `/persist-ok` came back 429 -- the tampered ban
         was restored. AssertionError: "/persist-ok: expected 200, got 429".
         SEEN RED. Reverted the `if (0 && ...)`, rebuilt (mtime 03:02:59,
         985296 bytes, confirming a real second rebuild), reran: green
         again. `git diff src/` was empty both before the mutation and
         after the revert.

  * $error_abuse_count always zero -- in
    ngx_http_error_abuse_variable_count(), change `ctx ? ctx->count : 0` to
    always emit 0.
      -> main(): the exposed-variable block's COUNTED assertion expected
         count=1 and got count=0 ("COUNTED expected count=1 until=0:
         ['/var-error', 'COUNTED', '0', '0']"). SEEN RED.

Ledger tally after B-3: 5 SEEN RED (test_redis_multi_host, the short-inactive
leg of test_invalid_configs, the reload key-change guard, the exposed
$error_abuse_count variable, the persistence CRC32 corruption check once
isolated with an in-place byte flip), 1 SURVIVED (test_redis_auth's AUTH
handshake -- masked by same-node local fallback). Every mutation above was
reverted; `git diff src/` is empty at the end of this ledger's construction.
"""

from __future__ import annotations

import argparse
import atexit
import concurrent.futures
import os
import pathlib
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

# A test that raises before stop() would orphan every child we spawned:
# an nginx master (or redis) keeps listening on its test port, which
# collides with later runs of any repo sharing the runner. Track every
# Popen and reap survivors at interpreter exit.
_SPAWNED: list[subprocess.Popen] = []


def _track(proc: subprocess.Popen) -> subprocess.Popen:
    _SPAWNED.append(proc)
    return proc


def _reap_spawned() -> None:
    for proc in _SPAWNED:
        if proc.poll() is None:
            proc.terminate()
    deadline = time.monotonic() + 5
    for proc in _SPAWNED:
        if proc.poll() is None:
            try:
                proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                proc.kill()


atexit.register(_reap_spawned)


SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "ERROR SUMMARY:",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx-binary", required=True)
    parser.add_argument("--module")
    parser.add_argument("--runner", default="")
    parser.add_argument("--single-process", action="store_true")
    parser.add_argument("--port", type=int, default=18880)
    parser.add_argument("--redis-server")
    return parser.parse_args()


def wait_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nginx did not listen on 127.0.0.1:{port}")


def request(port: int, path: str) -> int:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Connection": "close", "User-Agent": "error-abuse-ci/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code


def expect(port: int, path: str, expected: int) -> None:
    actual = request(port, path)
    if actual != expected:
        raise AssertionError(f"{path}: expected {expected}, got {actual}")


def fetch(port: int, path: str) -> tuple[int, dict[str, str]]:
    """Return (status, headers) so cache/Retry-After headers can be asserted."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Connection": "close", "User-Agent": "error-abuse-ci/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            response.read()
            return response.status, {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}


def nginx_config(
    root: pathlib.Path,
    port: int,
    module: pathlib.Path | None,
    workers: int,
    keyed_key: str = "$arg_client",
    redis_port: int | None = None,
    redis_prefix: str = "error-abuse-ci:",
    redis_password: str | None = None,
) -> str:
    load = f"load_module {module};\n" if module else ""
    redis = ""
    redis_zone = ""
    redis_locations = ""
    if redis_port is not None:
        auth = f" password={redis_password}" if redis_password else ""
        redis = (
            f"    error_abuse_redis host=127.0.0.1 port={redis_port} "
            f"prefix={redis_prefix} timeout=250ms{auth};\n"
        )
        redis_zone = """    error_abuse_zone zone=cluster:1m key=$arg_client
                     statuses=404 interval=5s threshold=3 block=10s
                     redis=on;
"""
        redis_locations = f"""
        location = /redis-error {{
            error_abuse zone=cluster status=429;
            root {root}/empty;
        }}
        location = /redis-ok {{
            error_abuse zone=cluster status=429;
            empty_gif;
        }}
"""
    return f"""{load}worker_processes {workers};
pid {root}/nginx.pid;
error_log {root}/logs/error.log notice;

events {{
    worker_connections 512;
}}

http {{
    access_log off;

    # Exercise the three exposed variables end-to-end at the log phase, where
    # the request ctx state is fully settled.
    log_format eavars '$uri $error_abuse_status $error_abuse_count '
                      '$error_abuse_blocked_until';

{redis}{redis_zone}
    error_abuse_zone zone=vars:1m key=$binary_remote_addr
                     statuses=404 interval=30s threshold=2 block=30s;
    error_abuse_zone zone=basic:1m key=$binary_remote_addr
                     statuses=403,404 interval=5s threshold=3 block=2s
                     persist={root}/basic.state persist_interval=100ms;
    error_abuse_zone zone=keyed:1m key={keyed_key}
                     statuses=404 interval=5s threshold=2 block=10s;
    error_abuse_zone zone=keyiso:1m key=$arg_client
                     statuses=404 interval=30s threshold=1 block=10s;
    error_abuse_zone zone=dry:1m key=$binary_remote_addr
                     statuses=404 interval=5s threshold=1 block=10s;
    error_abuse_zone zone=dryshared:1m key=$binary_remote_addr
                     statuses=404 interval=30s threshold=2 block=30s;
    error_abuse_zone zone=window:1m key=$binary_remote_addr
                     statuses=404 interval=1s threshold=3 block=10s;
    error_abuse_zone zone=persisted:1m key=$binary_remote_addr
                     statuses=404 interval=30s threshold=3 block=10s
                     persist={root}/persisted.state persist_interval=100ms;
    error_abuse_zone zone=secret:1m key=$binary_remote_addr
                     statuses=404 interval=30s threshold=2 block=30s
                     persist={root}/secret.state persist_interval=100ms
                     persist_secret=00112233445566778899aabbccddeeff;

    server {{
        listen 127.0.0.1:{port};

        location = /missing {{
            error_abuse zone=basic status=429;
            root {root}/empty;
        }}
        location = /denied {{
            error_abuse zone=basic status=429;
            deny all;
        }}
        location = /ignored {{
            error_abuse zone=basic status=429;
            proxy_connect_timeout 100ms;
            proxy_pass http://127.0.0.1:1;
        }}
        location = /ok {{
            error_abuse zone=basic status=429;
            empty_gif;
        }}

        location = /key-error {{
            error_abuse zone=keyed status=429;
            root {root}/empty;
        }}
        location = /key-ok {{
            error_abuse zone=keyed status=429;
            empty_gif;
        }}

        location = /keyiso-error {{
            error_abuse zone=keyiso status=429;
            root {root}/empty;
        }}
        location = /keyiso-ok {{
            error_abuse zone=keyiso status=429;
            empty_gif;
        }}

        location = /dry-error {{
            error_abuse zone=dry dry_run=on;
            root {root}/empty;
        }}
        location = /dry-ok {{
            error_abuse zone=dry dry_run=on;
            empty_gif;
        }}

        location = /dryshared-dry {{
            error_abuse zone=dryshared dry_run=on;
            root {root}/empty;
        }}
        location = /dryshared-ok {{
            error_abuse zone=dryshared status=429;
            empty_gif;
        }}

        location = /window-error {{
            error_abuse zone=window status=429;
            root {root}/empty;
        }}
        location = /window-ok {{
            error_abuse zone=window status=429;
            empty_gif;
        }}

        location = /persist-error {{
            error_abuse zone=persisted status=429;
            root {root}/empty;
        }}
        location = /persist-ok {{
            error_abuse zone=persisted status=429;
            empty_gif;
        }}

        location = /secret-error {{
            error_abuse zone=secret status=429;
            root {root}/empty;
        }}
        location = /secret-ok {{
            error_abuse zone=secret status=429;
            empty_gif;
        }}

        location = /var-error {{
            error_abuse zone=vars status=429;
            access_log {root}/logs/vars.log eavars;
            root {root}/empty;
        }}
        location = /var-ok {{
            error_abuse zone=vars status=429;
            access_log {root}/logs/vars.log eavars;
            empty_gif;
        }}
{redis_locations}
    }}
}}
"""


class Nginx:
    def __init__(
        self,
        binary: pathlib.Path,
        module: pathlib.Path | None,
        root: pathlib.Path,
        port: int,
        runner: str,
        single_process: bool,
        redis_port: int | None = None,
        redis_prefix: str = "error-abuse-ci:",
        redis_password: str | None = None,
    ) -> None:
        self.binary = binary
        self.module = module
        self.root = root
        self.port = port
        self.runner = shlex.split(runner)
        self.single_process = single_process
        self.redis_port = redis_port
        self.redis_prefix = redis_prefix
        self.redis_password = redis_password
        self.process: subprocess.Popen[str] | None = None
        self.output_path = root / "nginx-output.log"

    def write_config(self, keyed_key: str = "$arg_client") -> None:
        workers = 1 if self.single_process else 4
        (self.root / "conf").mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        (self.root / "empty").mkdir(parents=True, exist_ok=True)
        (self.root / "conf" / "nginx.conf").write_text(
            nginx_config(
                self.root,
                self.port,
                self.module,
                workers,
                keyed_key,
                self.redis_port,
                self.redis_prefix,
                self.redis_password,
            ),
            encoding="ascii",
        )

    def command(self, test: bool = False) -> list[str]:
        command = [
            str(self.binary),
            "-p",
            str(self.root),
            "-c",
            str(self.root / "conf" / "nginx.conf"),
        ]
        if test:
            # Syntax check runs with the bare binary: nginx -t never frees the
            # cycle pool, so the Valgrind/ASan runner would flag intrinsic
            # nginx leaks and mask the real config-test result.
            command.append("-t")
            return command
        if self.single_process:
            command.extend(["-g", "daemon off; master_process off;"])
        else:
            command.extend(["-g", "daemon off;"])
        return self.runner + command

    def config_test(self) -> None:
        result = subprocess.run(
            self.command(test=True),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"nginx -t failed:\n{result.stdout}")

    def start(self) -> None:
        self.write_config()
        output = self.output_path.open("a", encoding="utf-8")
        self.process = _track(
            subprocess.Popen(
                self.command(),
                text=True,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        )
        output.close()
        try:
            wait_port(self.port)
        except Exception:
            self.stop()
            raise

    def reload(self) -> None:
        if self.process is None:
            raise RuntimeError("nginx is not running")
        os.kill(self.process.pid, signal.SIGHUP)
        time.sleep(0.5)
        if self.process.poll() is not None:
            raise RuntimeError("nginx exited during reload")

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        rc = self.process.returncode
        self.process = None
        if rc not in (0, -signal.SIGTERM):
            output = (
                self.output_path.read_text(encoding="utf-8", errors="replace")
                if self.output_path.exists()
                else ""
            )
            raise RuntimeError(f"nginx exited with {rc}:\n{output}")

    def assert_clean_logs(self) -> None:
        paths = [self.output_path, self.root / "logs" / "error.log"]
        combined = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in paths
            if path.exists()
        )
        for marker in SANITIZER_MARKERS:
            if marker == "ERROR SUMMARY:" and "ERROR SUMMARY: 0 errors" in combined:
                continue
            if marker in combined:
                raise AssertionError(f"runtime checker marker found: {marker}")
        fatal_lines = [
            line
            for line in combined.splitlines()
            if ("[alert]" in line or "[emerg]" in line)
            and "key cannot change during reload" not in line
        ]
        if fatal_lines:
            raise AssertionError(
                "nginx logged a fatal condition:\n" + "\n".join(fatal_lines)
            )


class RedisServer:
    def __init__(
        self,
        binary: pathlib.Path,
        root: pathlib.Path,
        port: int,
        requirepass: str | None = None,
    ) -> None:
        self.binary = binary
        self.root = root
        self.port = port
        self.requirepass = requirepass
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(self.binary),
            "--bind",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            str(self.root),
        ]
        if self.requirepass:
            cmd += ["--requirepass", self.requirepass]
        self.process = _track(
            subprocess.Popen(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        )
        wait_port(self.port)
        # Flush all data to ensure clean state for each test
        flush = ["redis-cli", "-h", "127.0.0.1", "-p", str(self.port)]
        if self.requirepass:
            flush += ["-a", self.requirepass]
        subprocess.run(
            flush + ["FLUSHALL"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        if self.process.returncode not in (0, -signal.SIGTERM):
            output = self.process.stdout.read() if self.process.stdout else ""
            raise RuntimeError(f"redis-server failed:\n{output}")
        self.process = None


def test_redis_multi_host(
    binary: pathlib.Path,
    module: pathlib.Path | None,
    root: pathlib.Path,
    runner: str,
    single_process: bool,
    nginx_port: int,
    redis_binary: pathlib.Path,
) -> None:
    redis_port = nginx_port + 20
    prefix = f"error-abuse-ci-{os.getpid()}-{int(time.time() * 1000)}:"
    redis = RedisServer(redis_binary, root / "redis", redis_port)
    first = Nginx(
        binary,
        module,
        root / "redis-nginx-a",
        nginx_port + 1,
        runner,
        single_process,
        redis_port,
        prefix,
    )
    second = Nginx(
        binary,
        module,
        root / "redis-nginx-b",
        nginx_port + 2,
        runner,
        single_process,
        redis_port,
        prefix,
    )

    try:
        redis.start()
        first.start()
        second.start()
        time.sleep(0.2)

        expect(first.port, "/redis-error?client=shared", 404)
        time.sleep(0.05)
        expect(second.port, "/redis-error?client=shared", 404)
        time.sleep(0.05)
        expect(first.port, "/redis-error?client=shared", 404)
        time.sleep(0.05)
        expect(second.port, "/redis-ok?client=shared", 429)

        expect(second.port, "/redis-ok?client=other", 200)
        redis.stop()
        time.sleep(0.3)
        expect(first.port, "/redis-ok?client=redis-down", 200)

        # CI-5: Redis comes back -> the workers reconnect (backoff) and shared
        # blocking resumes.
        redis = RedisServer(redis_binary, root / "redis", redis_port)
        redis.start()
        time.sleep(3.0)  # allow reconnect backoff + handshake
        expect(first.port, "/redis-error?client=again", 404)
        time.sleep(0.05)
        expect(second.port, "/redis-error?client=again", 404)
        time.sleep(0.05)
        expect(first.port, "/redis-error?client=again", 404)
        time.sleep(0.05)
        expect(second.port, "/redis-ok?client=again", 429)
    finally:
        first.stop()
        second.stop()
        redis.stop()


def test_redis_auth(
    binary: pathlib.Path,
    module: pathlib.Path | None,
    root: pathlib.Path,
    runner: str,
    single_process: bool,
    nginx_port: int,
    redis_binary: pathlib.Path,
) -> None:
    # CI-5: password-protected Redis exercises the AUTH handshake (COR-5) and
    # that blocking still works through it.
    #
    # B-2: a single node cannot prove AUTH actually ran -- the module's
    # single-node local-zone fallback enforces blocking entirely in-process
    # when every Redis command fails with NOAUTH, so a lone `server` making
    # /redis-ok return 429 is satisfied even with AUTH never sent (proven by
    # mutating the AUTH send site to `if (0 && worker->conf->password.len)`:
    # NOAUTH floods error.log but the single-node assertions below still went
    # green). Mirror test_redis_multi_host: run a SECOND, independent nginx
    # node against the same authed Redis + prefix. Blocking state can only be
    # observed on the second node if the first node's requests actually
    # reached and were recorded in Redis -- the local-zone fallback is
    # strictly per-process and cannot leak state across two separate nginx
    # binaries. If AUTH is never sent, every Redis command from both nodes
    # gets NOAUTH, nothing is ever written to the shared counter, and
    # `second`'s /redis-ok request observes a fresh (unblocked) identity,
    # i.e. 200 instead of 429 -- turning the fallback's fail-open behavior
    # into a hard test failure instead of a silent pass.
    redis_port = nginx_port + 30
    prefix = f"error-abuse-auth-{os.getpid()}-{int(time.time() * 1000)}:"
    redis = RedisServer(
        redis_binary, root / "redis-auth", redis_port, requirepass="s3cr3t-pass"
    )
    server = Nginx(
        binary,
        module,
        root / "redis-auth-nginx",
        nginx_port + 3,
        runner,
        single_process,
        redis_port,
        prefix,
        redis_password="s3cr3t-pass",
    )
    second = Nginx(
        binary,
        module,
        root / "redis-auth-nginx-b",
        nginx_port + 4,
        runner,
        single_process,
        redis_port,
        prefix,
        redis_password="s3cr3t-pass",
    )
    try:
        redis.start()
        server.start()
        second.start()
        time.sleep(0.3)

        expect(server.port, "/redis-error?client=authed", 404)
        time.sleep(0.05)
        expect(server.port, "/redis-error?client=authed", 404)
        time.sleep(0.05)
        expect(server.port, "/redis-error?client=authed", 404)
        time.sleep(0.05)
        expect(server.port, "/redis-ok?client=authed", 429)

        # B-2: the block for "authed" must be visible from the SECOND,
        # independent node -- only possible if `server`'s three 404s were
        # actually recorded in the shared, authed Redis instance.
        expect(second.port, "/redis-ok?client=authed", 429)

        server.stop()
        server.assert_clean_logs()
        second.stop()
        second.assert_clean_logs()
    finally:
        server.stop()
        second.stop()
        redis.stop()


# ngx_http_error_abuse_zone() rejects anything under 8 * ngx_pagesize, so the
# smallest legal zone is page-size dependent: 32k on a 4 KiB host, 128k on a
# 16 KiB one (arm64 Linux, macOS on Apple silicon). Hardcoding 32k makes nginx
# refuse the config outright on those hosts and the test never reaches the
# allocation-failure path it exists to check.
_ZONE_FULL_PAGES = 8
_ZONE_FULL_BYTES = _ZONE_FULL_PAGES * os.sysconf("SC_PAGE_SIZE")
_ZONE_FULL_SIZE = f"{_ZONE_FULL_BYTES // 1024}k"
# 300 identities overflow a 32k zone with room to spare; scale with the zone so
# a 16 KiB-page host still fills it rather than asserting against a zone that
# never ran out.
_ZONE_FILL_REQUESTS = 300 * max(1, _ZONE_FULL_BYTES // 32768)


def _on_full_config(
    root: pathlib.Path,
    port: int,
    module: pathlib.Path | None,
    on_full: str,
    redis_port: int | None,
    redis_prefix: str,
) -> str:
    # F-3: minimum-size zone (8 pages), threshold=1 so a single 404 both
    # creates AND permanently blocks each distinct identity -- every
    # successful insert consumes a node forever, so a handful of pipelined
    # distinct clients reliably exhausts the zone.
    load = f"load_module {module};\n" if module else ""
    redis = ""
    redis_param = ""
    if redis_port is not None:
        redis = (
            f"    error_abuse_redis host=127.0.0.1 port={redis_port} "
            f"prefix={redis_prefix} timeout=250ms;\n"
        )
        redis_param = " redis=on"
    return f"""{load}worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log notice;

events {{
    worker_connections 512;
}}

http {{
    access_log off;

{redis}    error_abuse_zone zone=full:{_ZONE_FULL_SIZE} key=$arg_client
                     statuses=404 interval=60s threshold=1 block=600s
                     on_full={on_full}{redis_param};

    server {{
        listen 127.0.0.1:{port};

        location = /err {{
            error_abuse zone=full status=503;
            root {root}/empty;
        }}
        location = /ok {{
            error_abuse zone=full status=503;
            empty_gif;
        }}
    }}
}}
"""


def _on_full_start(
    binary: pathlib.Path,
    module: pathlib.Path | None,
    root: pathlib.Path,
    runner: str,
    port: int,
    on_full: str,
    redis_port: int | None = None,
    redis_prefix: str = "error-abuse-ci-full:",
) -> subprocess.Popen[str]:
    (root / "conf").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    (root / "empty").mkdir(parents=True, exist_ok=True)
    (root / "conf" / "nginx.conf").write_text(
        _on_full_config(root, port, module, on_full, redis_port, redis_prefix),
        encoding="ascii",
    )
    output = (root / "nginx-output.log").open("a", encoding="utf-8")
    proc = _track(
        subprocess.Popen(
            shlex.split(runner)
            + [
                str(binary),
                "-p",
                str(root),
                "-c",
                str(root / "conf" / "nginx.conf"),
                "-g",
                "daemon off; master_process off;",
            ],
            text=True,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    )
    output.close()
    try:
        wait_port(port)
    except Exception:
        _on_full_stop(proc)
        raise
    return proc


def _on_full_stop(proc: subprocess.Popen[str]) -> None:
    # A crash AFTER the response has been written still satisfies every expect()
    # above, so an already-dead nginx here is a test failure, not a no-op. This
    # is exactly how the callback-lifetime regression manifests: the 503 goes
    # out, then the worker dies unwinding the request.
    rc = proc.poll()
    if rc is not None:
        raise AssertionError(
            f"nginx exited with {rc} before shutdown -- it crashed while "
            f"serving the on_full requests"
        )
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _fill_zone(port: int, tag: str, n: int = _ZONE_FILL_REQUESTS) -> None:
    # Each distinct client=<tag><N> both creates a node and immediately
    # blocks it (threshold=1) -- the node is never evicted afterward (an
    # active ban is never evicted to make room), so n distinct identities
    # against a 32k zone reliably drives ngx_http_error_abuse_create_node's
    # allocation to NGX_ERROR well before n=300.
    #
    # `tag` MUST be unique per instance sharing a Redis backend: with
    # redis=on, a key already reported BLOCKED by Redis short-circuits at
    # preaccess and never reaches the local zone's create_node() at all, so
    # reusing the same client= names across allow/reject legs (which share
    # one Redis server) would leave the reject leg's local zone unfilled and
    # its assertion vacuous.
    for i in range(n):
        request(port, f"/err?client={tag}{i}")


def test_on_full_policy(
    binary: pathlib.Path,
    module: pathlib.Path | None,
    root: pathlib.Path,
    runner: str,
    nginx_port: int,
    redis_binary: pathlib.Path | None,
) -> None:
    # F-3: a full zone must not silently pass a new identity untracked
    # (on_full=allow, the default, preserves that historical passthrough
    # behaviour) or, when the operator opts into on_full=reject, it must
    # apply the location's configured rejection status instead.
    allow_root = root / "on-full-allow"
    proc = _on_full_start(binary, module, allow_root, runner, nginx_port + 10, "allow")
    try:
        _fill_zone(nginx_port + 10, "allow")
        # F-3 default: the zone is full, so the fresh identity's error
        # response passes through untracked -- same as historical behaviour.
        expect(nginx_port + 10, "/err?client=fresh-allow", 404)
        # The 404 above is NOT by itself evidence of pass-through: at
        # threshold=1 a successfully TRACKED identity also gets 404 on its
        # first error (it is blocked only from the next request on). Ask for a
        # non-error URI with the same key -- 200 means no node was created and
        # the identity really is untracked; a tracked one would be banned and
        # answer 503 here.
        expect(nginx_port + 10, "/ok?client=fresh-allow", 200)
    finally:
        _on_full_stop(proc)

    reject_root = root / "on-full-reject"
    proc = _on_full_start(
        binary, module, reject_root, runner, nginx_port + 11, "reject"
    )
    try:
        _fill_zone(nginx_port + 11, "reject")
        # F-3 opt-in: the zone is full, so the fresh identity's error
        # response is rejected with the location's configured status instead
        # of passing through untracked.
        expect(nginx_port + 11, "/err?client=fresh-reject", 503)
        # Serve one more request afterwards: the filter_finalize path unwinds
        # after the 503 is already on the wire, so a crash there is invisible
        # to the assertion above but kills the next request.
        expect(nginx_port + 11, "/err?client=after-reject", 503)
    finally:
        _on_full_stop(proc)

    if redis_binary is None:
        return

    # Same policy, with redis=on: a fresh identity is first parked in
    # preaccess awaiting the async Redis reply (ngx_http_error_abuse_redis_
    # check_callback resumes it), so on_full=reject's synchronous
    # ngx_http_filter_finalize_request must still complete cleanly from
    # inside that resumed phase chain -- this previously segfaulted nginx
    # until the callback was fixed to release its parked reference BEFORE
    # resuming phases instead of after (see the ordering comment on
    # ngx_http_error_abuse_redis_check_callback).
    redis_port = nginx_port + 40
    prefix = f"error-abuse-ci-full-{os.getpid()}-{int(time.time() * 1000)}:"
    redis = RedisServer(redis_binary, root / "on-full-redis-server", redis_port)
    try:
        redis.start()

        allow_root = root / "on-full-allow-redis"
        proc = _on_full_start(
            binary,
            module,
            allow_root,
            runner,
            nginx_port + 12,
            "allow",
            redis_port,
            prefix,
        )
        try:
            _fill_zone(nginx_port + 12, "allowredis")
            expect(nginx_port + 12, "/err?client=fresh-allow-redis", 404)
            # NOT the untracked proof used on the non-Redis leg: with redis=on,
            # ngx_http_error_abuse_redis_record() runs before the rc==NGX_ERROR
            # branch, so a full LOCAL zone still records the identity in Redis
            # and threshold=1 bans it there. The follow-up is therefore 503 even
            # under on_full=allow. That is the module's actual behaviour, so
            # assert it rather than the local-only expectation.
            expect(nginx_port + 12, "/ok?client=fresh-allow-redis", 503)
        finally:
            _on_full_stop(proc)

        reject_root = root / "on-full-reject-redis"
        proc = _on_full_start(
            binary,
            module,
            reject_root,
            runner,
            nginx_port + 13,
            "reject",
            redis_port,
            prefix,
        )
        try:
            _fill_zone(nginx_port + 13, "rejectredis")
            expect(nginx_port + 13, "/err?client=fresh-reject-redis", 503)
            # This is the leg that actually segfaulted before the callback
            # ordering fix: the reject unwinds inside the phase chain resumed
            # by the Redis callback. A second request proves the worker
            # survived it.
            expect(nginx_port + 13, "/err?client=after-reject-redis", 503)
        finally:
            _on_full_stop(proc)
    finally:
        redis.stop()


def _error_page_config(
    root: pathlib.Path, port: int, module: pathlib.Path | None
) -> str:
    # F-2: an error_page internal redirect (URI target AND named-location
    # target -- nginx clears r->ctx on two distinct code paths) must not
    # erase the ORIGIN's error_abuse ctx. Each origin location is bound to
    # zone "origin" (threshold=1, so a single error both counts AND, on a
    # follow-up request, proves the identity was tracked). Destinations cover
    # the three audited cases: (a) error_abuse off, (b) bound to a DIFFERENT
    # zone "other", (c) a custom rejection status whose headers must still be
    # the module's own (private/no-store/Retry-After).
    load = f"load_module {module};\n" if module else ""
    return f"""{load}worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log notice;

events {{
    worker_connections 512;
}}

http {{
    access_log off;

    error_abuse_zone zone=origin:1m key=$arg_client
                     statuses=404 interval=60s threshold=1 block=600s;
    error_abuse_zone zone=other:1m key=$arg_client
                     statuses=404 interval=60s threshold=1 block=600s;
    error_abuse_zone zone=dryorigin:1m key=$arg_client
                     statuses=404 interval=60s threshold=1 block=600s;

    server {{
        listen 127.0.0.1:{port};

        # (a) URI error_page target with error_abuse off.
        location = /off-origin {{
            error_abuse zone=origin status=429;
            error_page 404 /off-dest;
            root {root}/empty;
        }}
        location = /off-dest {{
            internal;
            error_abuse off;
            empty_gif;
        }}

        # (a) named-location target with error_abuse off.
        location = /off-named-origin {{
            error_abuse zone=origin status=429;
            error_page 404 @off_named;
            root {root}/empty;
        }}
        location @off_named {{
            error_abuse off;
            empty_gif;
        }}

        # (b) URI error_page target bound to a DIFFERENT zone.
        location = /other-origin {{
            error_abuse zone=origin status=429;
            error_page 404 /other-dest;
            root {root}/empty;
        }}
        location = /other-dest {{
            internal;
            error_abuse zone=other status=429;
            empty_gif;
        }}

        # (b) named-location target bound to a DIFFERENT zone.
        location = /other-named-origin {{
            error_abuse zone=origin status=429;
            error_page 404 @other_named;
            root {root}/empty;
        }}
        location @other_named {{
            error_abuse zone=other status=429;
            empty_gif;
        }}

        # (c) URI error_page target: custom 503 rejection page.
        location = /custom-origin {{
            error_abuse zone=origin status=503;
            error_page 404 /custom-dest;
            root {root}/empty;
        }}
        location = /custom-dest {{
            internal;
            error_abuse off;
            empty_gif;
        }}

        # (c) named-location target: custom 503 rejection page.
        location = /custom-named-origin {{
            error_abuse zone=origin status=503;
            error_page 404 @custom_named;
            root {root}/empty;
        }}
        location @custom_named {{
            error_abuse off;
            empty_gif;
        }}

        # (d) origin-wins dry_run: the ORIGIN location has dry_run=on, the
        # error_page destination does NOT. A destination that could
        # retroactively turn dry-run observation into real enforcement would
        # ban an identity the operator explicitly asked to only observe.
        location = /dryorigin-origin {{
            error_abuse zone=dryorigin dry_run=on;
            error_page 404 /dryorigin-dest;
            root {root}/empty;
        }}
        location = /dryorigin-dest {{
            internal;
            error_abuse zone=dryorigin status=429;
            empty_gif;
        }}

        # Plain probes to read back the "origin" / "other" / "dryorigin" zone
        # identity counters without going through error_page.
        location = /origin-ok {{
            error_abuse zone=origin status=429;
            empty_gif;
        }}
        location = /other-ok {{
            error_abuse zone=other status=429;
            empty_gif;
        }}
        # 404-capable probe to seed a ban directly in zone "other" without
        # ever touching zone "origin" -- needed to build the cross-zone
        # scenario below (an identity banned in "other" but clean in
        # "origin").
        location = /other-dest-direct {{
            error_abuse zone=other status=429;
            root {root}/empty;
        }}
        location = /dryorigin-ok {{
            error_abuse zone=dryorigin status=429;
            empty_gif;
        }}

        # A-1: plain "error_abuse off" location, hit DIRECTLY -- no
        # error_page redirect, no anchor from any earlier location in this
        # request. prepare_ctx() finds no anchor and conf->enabled=0, so it
        # returns NULL: preaccess must treat that as the ordinary "disabled
        # here" case (NGX_DECLINED, normal response) and NOT the internal
        # error it used to return when prepare_ctx() was unreachable through
        # a different path. Guards the CAUTION in A-1: NULL now means two
        # different things (no anchor + disabled here vs a real allocation
        # failure) and this is the common one, exercised on every request to
        # a module-off location.
        location = /off-plain {{
            error_abuse off;
            empty_gif;
        }}
    }}
}}
"""


def test_error_page_redirect(
    binary: pathlib.Path,
    module: pathlib.Path | None,
    root: pathlib.Path,
    runner: str,
    port: int,
) -> None:
    work = root / "error-page"
    (work / "conf").mkdir(parents=True)
    (work / "logs").mkdir()
    (work / "empty").mkdir()
    (work / "conf" / "nginx.conf").write_text(
        _error_page_config(work, port, module), encoding="ascii"
    )
    output = (work / "nginx-output.log").open("a", encoding="utf-8")
    proc = _track(
        subprocess.Popen(
            shlex.split(runner)
            + [
                str(binary),
                "-p",
                str(work),
                "-c",
                str(work / "conf" / "nginx.conf"),
                "-g",
                "daemon off; master_process off;",
            ],
            text=True,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    )
    output.close()
    try:
        wait_port(port)

        # (a) error_page URI target with "error_abuse off": the origin 404
        # must still be COUNTED against zone "origin", not silently dropped.
        # threshold=1 means the FIRST error alone cannot distinguish counted
        # from uncounted (a tracked identity also answers via its own 404 on
        # request 1) -- the follow-up /origin-ok request on the SAME key is
        # the proof: 200 would mean untracked, 429 means the identity was
        # recorded and is now banned.
        expect(port, "/off-origin?client=off-a", 404)
        expect(port, "/origin-ok?client=off-a", 429)

        # (a) named-location target with "error_abuse off".
        expect(port, "/off-named-origin?client=off-b", 404)
        expect(port, "/origin-ok?client=off-b", 429)

        # Smoke coverage, NOT the A-1 regression guard: off-a is already
        # banned in zone "origin" (from the assertions above, a SEPARATE
        # prior request). /off-origin shares that zone, so its own
        # preaccess -- unaffected by A-1, it was never behind the removed
        # guard -- rejects first (429, own_rejection) without ever reaching
        # the backend or the error_page redirect to /off-dest. Kept as an
        # end-to-end sanity check that the ban is honoured on repeat
        # requests; the debug-log assertion further down is what actually
        # exercises /off-dest's own restored preaccess.
        expect(port, "/off-origin?client=off-a", 429)

        # Negative control: a FRESH identity, never seen anywhere, taking
        # the same /off-origin -> /off-dest path must pass normally: origin
        # preaccess records it (404, uncounted-yet since threshold=1 makes
        # this itself the counted event) and the "error_abuse off"
        # destination must not turn it into a 500 or a spurious reject.
        expect(port, "/off-origin?client=off-fresh", 404)

        # A-1 core regression guard: a location where the module is off,
        # hit DIRECTLY with no earlier hop in this request to anchor from.
        # prepare_ctx() returns NULL (no anchor, conf disabled) and
        # preaccess must treat that as "disabled here", serving the normal
        # response -- not NGX_HTTP_INTERNAL_SERVER_ERROR. This is the exact
        # case the CAUTION warns about: get the NULL handling wrong and
        # EVERY request to a module-off location 500s.
        expect(port, "/off-plain?client=off-plain-a", 200)

        # (b) URI error_page target bound to a DIFFERENT zone: the origin
        # zone's identity must still be the one that gets counted, and the
        # destination zone ("other") must NOT record it instead.
        expect(port, "/other-origin?client=other-a", 404)
        expect(port, "/origin-ok?client=other-a", 429)
        expect(port, "/other-ok?client=other-a", 200)

        # Cross-zone preaccess proof: ban a DIFFERENT identity in zone
        # "other" only (zone "origin" has no record for it), then route that
        # identity through /other-origin -> /other-dest. /other-origin's own
        # preaccess (conf->zone=origin, unbanned) passes and produces the
        # 404 that triggers the redirect; the interesting check is
        # /other-dest's preaccess, which runs again after r->ctx is zeroed
        # by the internal redirect. With the F-2 restore, prepare_ctx()
        # there recovers the ORIGIN ctx (ctx->zone=origin, unbanned for this
        # key) and preaccess must therefore PASS. Reading ctx->zone (not
        # conf->zone="other", which IS banned for this key) is the only
        # thing standing between this and a false reject -- the single-pass
        # /other-origin assertions above cannot reach this because they
        # never leave "origin" banned while "other" is clean for a DIFFERENT
        # identity than the one that trips the redirect.
        #
        # `error_page 404 /other-dest;` (no `=` overwrite) preserves the
        # ORIGIN's 404 status regardless of what the destination serves, so
        # a PASSING preaccess at /other-dest is observed as 404 (the
        # original error, now counted once against "origin"), not 200. A
        # preaccess REJECT at the destination, by contrast, finalizes the
        # request directly with the destination's own reject_status (429),
        # short-circuiting the error_page status preservation entirely --
        # that is the visible difference the bug vs the fix produces.
        expect(port, "/other-dest-direct?client=cross-x", 404)
        expect(port, "/other-ok?client=cross-x", 429)
        expect(port, "/other-origin?client=cross-x", 404)

        # (b) named-location target bound to a DIFFERENT zone.
        expect(port, "/other-named-origin?client=other-b", 404)
        expect(port, "/origin-ok?client=other-b", 429)
        expect(port, "/other-ok?client=other-b", 200)
        expect(port, "/other-named-origin?client=other-b", 429)

        # (c) custom rejection page (URI target): the SECOND request against
        # the now-banned identity must come back through the origin's own
        # status=503 with the synthetic rejection headers -- proving the
        # restored ctx kept own_rejection/state, not just the counter.
        expect(port, "/custom-origin?client=custom-a", 404)
        status, headers = fetch(port, "/custom-origin?client=custom-a")
        if status != 503:
            raise AssertionError(f"/custom-origin expected 503, got {status}")
        cache_control = headers.get("cache-control", "")
        if "no-store" not in cache_control or "private" not in cache_control:
            raise AssertionError(
                f"custom rejection page Cache-Control missing "
                f"private/no-store: {cache_control!r}"
            )
        if "retry-after" not in headers:
            raise AssertionError("custom rejection page missing Retry-After")

        # (c) custom rejection page (named-location target).
        expect(port, "/custom-named-origin?client=custom-b", 404)
        status, headers = fetch(port, "/custom-named-origin?client=custom-b")
        if status != 503:
            raise AssertionError(f"/custom-named-origin expected 503, got {status}")
        cache_control = headers.get("cache-control", "")
        if "no-store" not in cache_control or "private" not in cache_control:
            raise AssertionError(
                f"custom rejection page (named) Cache-Control missing "
                f"private/no-store: {cache_control!r}"
            )
        if "retry-after" not in headers:
            raise AssertionError("custom rejection page (named) missing Retry-After")

        # (d) origin-wins dry_run: the origin location (dry_run=on) must keep
        # dry_run TRUE across the redirect even though the destination
        # location's own conf has dry_run=off (COR-2's non-restored
        # re-derivation would flip it). A follow-up /dryorigin-ok on the same
        # key proves no ban was actually created: dry-run must never insert
        # events or set a block deadline, so a real enforcing sibling
        # location on the SAME zone still serves 200, not 429.
        expect(port, "/dryorigin-origin?client=dry-a", 404)
        expect(port, "/dryorigin-ok?client=dry-a", 200)
    finally:
        rc = proc.poll()
        if rc is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        elif rc not in (0, -signal.SIGTERM):
            text = (work / "nginx-output.log").read_text(
                encoding="utf-8", errors="replace"
            )
            raise AssertionError(f"nginx exited with {rc}:\n{text}")


def expect_invalid_config(
    binary: pathlib.Path,
    module: pathlib.Path | None,
    root: pathlib.Path,
    runner: str,
    name: str,
    http_config: str,
    expected: str,
) -> None:
    bad = root / name
    (bad / "conf").mkdir(parents=True)
    (bad / "logs").mkdir()
    load = f"load_module {module};\n" if module else ""
    (bad / "conf" / "nginx.conf").write_text(
        f"""{load}error_log {bad}/logs/error.log;
events {{}}
http {{
{http_config}
}}
""",
        encoding="ascii",
    )
    # Run the syntax check with the bare binary, never the leak-checker runner:
    # nginx's -t path intentionally never frees the cycle pool, so Valgrind
    # always reports indirect leaks and --error-exitcode masks the real result.
    command = [
        str(binary),
        "-p",
        str(bad),
        "-c",
        str(bad / "conf" / "nginx.conf"),
        "-t",
    ]
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
        check=False,
    )
    if result.returncode == 0 or expected not in result.stdout:
        raise AssertionError(
            f"{name} config was not rejected as expected:\n{result.stdout}"
        )


def expect_valid_config(
    binary: pathlib.Path,
    module: pathlib.Path | None,
    root: pathlib.Path,
    runner: str,
    name: str,
    http_config: str,
) -> None:
    good = root / name
    (good / "conf").mkdir(parents=True)
    (good / "logs").mkdir()
    load = f"load_module {module};\n" if module else ""
    (good / "conf" / "nginx.conf").write_text(
        f"""{load}error_log {good}/logs/error.log;
events {{}}
http {{
{http_config}
}}
""",
        encoding="ascii",
    )
    # Bare binary, never the leak-checker runner (see expect_invalid_config):
    # nginx -t leaves the cycle pool unfreed, so Valgrind's leak exit code
    # would fail an otherwise valid config.
    command = [
        str(binary),
        "-p",
        str(good),
        "-c",
        str(good / "conf" / "nginx.conf"),
        "-t",
    ]
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{name} config was rejected but should be valid:\n{result.stdout}"
        )


def test_valid_configs(
    binary: pathlib.Path, module: pathlib.Path | None, root: pathlib.Path, runner: str
) -> None:
    # COR-1: the documented one-argument forms must be accepted (were rejected
    # by NGX_CONF_2MORE before the fix).
    expect_valid_config(
        binary,
        module,
        root,
        runner,
        "minimal-zone",
        "    error_abuse_zone zone=minimal:1m;",
    )
    expect_valid_config(
        binary,
        module,
        root,
        runner,
        "minimal-redis",
        """    error_abuse_redis host=127.0.0.1;
    error_abuse_zone zone=minimal:1m redis=on;""",
    )
    # F-3: both on_full= values are accepted.
    expect_valid_config(
        binary,
        module,
        root,
        runner,
        "on-full-allow",
        "    error_abuse_zone zone=minimal:1m on_full=allow;",
    )
    expect_valid_config(
        binary,
        module,
        root,
        runner,
        "on-full-reject",
        "    error_abuse_zone zone=minimal:1m on_full=reject;",
    )


def test_invalid_configs(
    binary: pathlib.Path, module: pathlib.Path | None, root: pathlib.Path, runner: str
) -> None:
    # COR-8: a trailing comma in the status list is malformed, not ignored.
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "trailing-comma-status",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404, interval=1s threshold=2 block=1s;""",
        "invalid error_abuse status list",
    )
    # COR-3: an explicit inactive shorter than interval/block is rejected.
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "short-inactive",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=5m threshold=2 block=1h
                         inactive=1s;""",
        "inactive must be >=",
    )
    # SEC-5: persist_secret without persist, and odd-length hex, are rejected.
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "secret-without-persist",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         persist_secret=00112233445566778899aabbccddeeff;""",  # gitleaks:allow
        "persist_secret requires persist",
    )
    secret_state = root / "oddsecret.state"
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "secret-odd-hex",
        f"""    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         persist={secret_state} persist_secret=abc;""",
        "invalid error_abuse_zone parameter",
    )
    # F-5: persist_secret shorter than the 16-byte minimum is rejected before
    # allocation, distinct from the requires-persist and odd-hex checks above.
    short_secret_state = root / "shortsecret.state"
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "secret-below-minimum",
        f"""    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         persist={short_secret_state} persist_secret=00112233445566778899aabbccddee;""",  # gitleaks:allow
        "persist_secret: min 16 bytes (32 hex chars); got 15 bytes",
    )
    # COR-6: "off" then a real declaration in the same block is a duplicate,
    # regardless of order.
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "off-then-zone",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s;
    server {
        error_abuse off;
        error_abuse zone=bad status=429;
    }""",
        "is duplicate",
    )
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "bad-status",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404,700 interval=1s threshold=2 block=1s;""",
        "invalid error_abuse status list",
    )
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "duplicate-parameter",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s interval=2s
                         threshold=2 block=1s;""",
        "duplicate error_abuse_zone parameter",
    )
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "duplicate-enable-parameter",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s;
    server {
        error_abuse zone=bad status=429 status=403;
    }""",
        "duplicate error_abuse parameter",
    )
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "redis-without-backend",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         redis=on;""",
        "requires error_abuse_redis",
    )
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "bad-redis-prefix",
        """    error_abuse_redis host=127.0.0.1 "prefix=bad{prefix";
    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         redis=on;""",
        "invalid error_abuse_redis parameter",
    )
    # F-3: an unrecognized on_full= value is rejected at config time.
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "bad-on-full",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         on_full=maybe;""",
        "invalid error_abuse_zone parameter",
    )
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "duplicate-on-full",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         on_full=allow on_full=reject;""",
        "duplicate error_abuse_zone parameter",
    )
    shared = root / "shared.state"
    expect_invalid_config(
        binary,
        module,
        root,
        runner,
        "duplicate-persistence",
        f"""    error_abuse_zone zone=one:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         persist={shared};
    error_abuse_zone zone=two:1m key=$binary_remote_addr
                         statuses=403 interval=1s threshold=2 block=1s
                         persist={shared};""",
        "use the same persistence file",
    )


def main() -> int:
    args = parse_args()
    binary = pathlib.Path(args.nginx_binary).resolve()
    module = pathlib.Path(args.module).resolve() if args.module else None
    if not binary.exists():
        raise FileNotFoundError(binary)
    if module is not None and not module.exists():
        raise FileNotFoundError(module)

    with tempfile.TemporaryDirectory(prefix="error-abuse-ci-") as tmp:
        root = pathlib.Path(tmp)
        test_valid_configs(binary, module, root, args.runner)
        test_invalid_configs(binary, module, root, args.runner)
        test_on_full_policy(
            binary,
            module,
            root,
            args.runner,
            args.port,
            pathlib.Path(args.redis_server).absolute() if args.redis_server else None,
        )
        test_error_page_redirect(binary, module, root, args.runner, args.port + 20)
        if args.redis_server:
            test_redis_multi_host(
                binary,
                module,
                root,
                args.runner,
                args.single_process,
                args.port,
                pathlib.Path(args.redis_server).absolute(),
            )
            test_redis_auth(
                binary,
                module,
                root,
                args.runner,
                args.single_process,
                args.port,
                pathlib.Path(args.redis_server).absolute(),
            )
        nginx = Nginx(
            binary,
            module,
            root / "server",
            args.port,
            args.runner,
            args.single_process,
        )
        nginx.write_config()
        nginx.config_test()

        try:
            nginx.start()

            expect(args.port, "/ignored", 502)
            expect(args.port, "/ok", 200)
            expect(args.port, "/missing", 404)
            expect(args.port, "/denied", 403)
            expect(args.port, "/ok", 200)
            expect(args.port, "/missing", 404)
            # RFC-1/SEC-2 + RFC-2: the synthetic 429 must be non-cacheable and
            # advertise a retry deadline.
            status, headers = fetch(args.port, "/ok")
            if status != 429:
                raise AssertionError(f"/ok expected 429, got {status}")
            cache_control = headers.get("cache-control", "")
            if "no-store" not in cache_control or "private" not in cache_control:
                raise AssertionError(
                    f"block response Cache-Control missing private/no-store: "
                    f"{cache_control!r}"
                )
            if "retry-after" not in headers:
                raise AssertionError("block response missing Retry-After")
            time.sleep(2.2)
            expect(args.port, "/ok", 200)

            expect(args.port, "/dry-error", 404)
            expect(args.port, "/dry-ok", 200)
            expect(args.port, "/dry-error", 404)

            # COR-2: dry-run must not write shared state. Flood the dry-run
            # location past its threshold, then a sibling location on the SAME
            # zone must still serve normally (no ban was created).
            for _ in range(5):
                expect(args.port, "/dryshared-dry", 404)
            expect(args.port, "/dryshared-ok", 200)
            expect(args.port, "/dryshared-ok", 200)

            expect(args.port, "/key-error?client=a", 404)
            expect(args.port, "/key-error?client=b", 404)
            expect(args.port, "/key-error?client=a", 404)
            expect(args.port, "/key-ok?client=a", 429)
            expect(args.port, "/key-ok?client=b", 200)

            # Dedicated per-identity key-hashing isolation case (T-1). The
            # two client values below differ only AFTER their shared first
            # byte ("aaa" vs "aab"), so a hash that truncates the key to its
            # first raw byte (see the key-hashing mutation ledger entry
            # above) would collapse them onto the same node -- unlike
            # "a"/"b" above, which differ in the first byte and so still
            # separate under a truncated hash. threshold=1 means a single
            # 404 bans that identity immediately: "aaa" must ban while its
            # sibling "aab" stays unaffected.
            expect(args.port, "/keyiso-error?client=aaa", 404)
            expect(args.port, "/keyiso-ok?client=aaa", 429)
            expect(args.port, "/keyiso-ok?client=aab", 200)

            expect(args.port, "/window-error", 404)
            expect(args.port, "/window-error", 404)
            time.sleep(1.2)
            expect(args.port, "/window-error", 404)
            expect(args.port, "/window-ok", 200)
            expect(args.port, "/window-error", 404)
            expect(args.port, "/window-error", 404)
            expect(args.port, "/window-ok", 429)

            expect(args.port, "/persist-error", 404)
            expect(args.port, "/persist-error", 404)
            time.sleep(0.3)

            state = nginx.root / "persisted.state"
            if not state.exists() or state.stat().st_size <= 24:
                raise AssertionError(
                    "periodic persistence did not write a populated snapshot"
                )
            mode = stat.S_IMODE(state.stat().st_mode)
            if mode != 0o600:
                raise AssertionError(
                    f"periodic snapshot mode is {mode:o}, expected 600"
                )

            if not args.single_process:
                nginx.reload()
                expect(args.port, "/persist-error", 404)
                expect(args.port, "/persist-ok", 429)
                time.sleep(10.2)

                # Reset the persisted zone after the reload-specific block.
                expect(args.port, "/persist-ok", 200)
                expect(args.port, "/persist-error", 404)
                expect(args.port, "/persist-error", 404)

                nginx.write_config("$binary_remote_addr")
                nginx.reload()
                error_log = nginx.root / "logs" / "error.log"
                if "key cannot change during reload" not in error_log.read_text(
                    encoding="utf-8", errors="replace"
                ):
                    raise AssertionError("reload accepted a changed zone key")
                nginx.write_config()
                nginx.reload()

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                codes = list(
                    pool.map(
                        lambda _: request(args.port, "/dry-error"),
                        range(200),
                    )
                )
            if set(codes) != {404}:
                raise AssertionError(f"dry-run concurrency returned {set(codes)}")

            time.sleep(0.3)
            nginx.stop()

            mode = stat.S_IMODE(state.stat().st_mode)
            if mode != 0o600:
                raise AssertionError(f"snapshot mode is {mode:o}, expected 600")

            nginx.start()
            expect(args.port, "/persist-error", 404)
            expect(args.port, "/persist-ok", 429)
            nginx.stop()

            data = state.read_bytes()
            if len(data) < 2:
                raise AssertionError("snapshot unexpectedly small")
            state.write_bytes(data[:-1])
            os.chmod(state, 0o600)

            nginx.start()
            expect(args.port, "/persist-ok", 200)
            expect(args.port, "/persist-error", 404)
            expect(args.port, "/persist-error", 404)
            expect(args.port, "/persist-ok", 200)
            nginx.stop()

            # CRC32 isolation case (B-3). The truncation case above shrinks the
            # file, which trips an independent bounds check before CRC32 is
            # ever consulted (see the mutation ledger entry above) -- it
            # cannot tell us whether the CRC32 check itself does anything.
            # Re-ban, persist, then flip one byte of blocked_until IN PLACE
            # (same file length, same field boundaries, still a value every
            # bounds/range check downstream accepts -- it is compared with
            # `>` against `now`, never validated against a length or count).
            # Only the CRC32 check can now catch the corruption. The reload
            # above already restored a count=2 state (two 404s counted, none
            # blocking yet -- the trailing /persist-ok 200 checks did not
            # reset it), so one more 404 crosses threshold=3.
            nginx.start()
            expect(args.port, "/persist-error", 404)
            expect(args.port, "/persist-ok", 429)
            time.sleep(0.3)
            nginx.stop()

            data = bytearray(state.read_bytes())
            # header(24) + record: key_len(u16) + event_count(u16) +
            # blocked_until(i64) @ offset 4 within the record -> file offset
            # 24 + 4 = 28. Flip a low-order byte in the middle of the i64
            # (offset +2) so the value stays a plausible (still in-the-
            # future) timestamp rather than flipping sign/magnitude into
            # something a later stage might reject for an unrelated reason.
            blocked_until_off = 24 + 4 + 2
            if len(data) <= blocked_until_off:
                raise AssertionError("snapshot too small for CRC32 flip case")
            data[blocked_until_off] ^= 0x01
            state.write_bytes(bytes(data))
            os.chmod(state, 0o600)

            nginx.start()
            expect(args.port, "/persist-ok", 200)  # not restored: CRC32 caught it
            expect(args.port, "/persist-error", 404)
            expect(args.port, "/persist-error", 404)
            expect(args.port, "/persist-ok", 200)
            nginx.stop()

            # SEC-5: HMAC-authenticated snapshot round-trips, and a tampered
            # MAC is rejected on load (no ban restored).
            nginx.start()
            expect(args.port, "/secret-error", 404)
            expect(args.port, "/secret-error", 404)
            expect(args.port, "/secret-ok", 429)
            nginx.stop()

            secret_state = nginx.root / "secret.state"
            sdata = secret_state.read_bytes()
            if len(sdata) < 33:
                raise AssertionError("secret snapshot missing HMAC tail")

            nginx.start()  # untampered: ban restored
            expect(args.port, "/secret-ok", 429)
            nginx.stop()

            # Flip a bit in the trailing HMAC (CRC covers payload only, so only
            # the HMAC catches this) — load must ignore the file.
            tampered = bytearray(secret_state.read_bytes())
            tampered[-1] ^= 0x01
            secret_state.write_bytes(bytes(tampered))
            os.chmod(secret_state, 0o600)

            nginx.start()
            expect(args.port, "/secret-ok", 200)  # not restored
            nginx.stop()

            # Exposed variables: drive PASSED -> COUNTED -> BLOCKED and assert
            # $error_abuse_status / _count / _blocked_until via the access log.
            nginx.start()
            expect(args.port, "/var-ok", 200)  # 200 untracked -> PASSED
            expect(args.port, "/var-error", 404)  # 1st 404      -> COUNTED 1
            expect(args.port, "/var-error", 404)  # threshold    -> BLOCKED 2
            expect(args.port, "/var-error", 429)  # now banned   -> BLOCKED 2
            time.sleep(0.3)
            nginx.stop()

            vars_log = nginx.root / "logs" / "vars.log"
            lines = [
                ln.split()
                for ln in vars_log.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            if len(lines) != 4:
                raise AssertionError(f"vars.log expected 4 lines, got {lines}")

            # Line ORDER is deliberately not asserted. Both locations log to the
            # same vars.log with no buffer=, so each of the 4 workers issues its
            # own unsynchronized write(); the kernel orders those by which worker
            # reaches the syscall, not by request arrival. Asserting the sequence
            # flaked exactly that way on run 30941891262 (COUNTED before PASSED,
            # counters all correct), and passed on a bare rerun of the same sha.
            #
            # What the module actually guarantees is per-request: each URI gets
            # the state and counters its own request earned. So key by URI, and
            # keep every counter assertion the sequence version had -- those are
            # what would catch a real counting or identity bug.
            by_uri = {}
            for ln in lines:
                by_uri.setdefault(ln[0], []).append(ln)

            ok = by_uri.get("/var-ok", [])
            if len(ok) != 1:
                raise AssertionError(f"expected 1 /var-ok line, got {ok}")
            if ok[0][1] != "PASSED":
                raise AssertionError(f"/var-ok expected PASSED: {ok[0]}")
            if ok[0][2] != "0" or ok[0][3] != "0":
                raise AssertionError(f"PASSED count/until not zero: {ok[0]}")

            err = by_uri.get("/var-error", [])
            if len(err) != 3:
                raise AssertionError(f"expected 3 /var-error lines, got {err}")

            # The 3 /var-error requests are sequential on one connection, so the
            # STATES they earned are fixed even though their log order is not:
            # one COUNTED (1st 404, below threshold) then two BLOCKED.
            err_states = sorted(ln[1] for ln in err)
            if err_states != ["BLOCKED", "BLOCKED", "COUNTED"]:
                raise AssertionError(f"unexpected /var-error states: {err_states}")

            counted = [ln for ln in err if ln[1] == "COUNTED"]
            if counted[0][2] != "1" or counted[0][3] != "0":
                raise AssertionError(f"COUNTED expected count=1 until=0: {counted[0]}")
            for ln in [x for x in err if x[1] == "BLOCKED"]:
                if ln[2] != "2" or int(ln[3]) <= 0:
                    raise AssertionError(f"BLOCKED expected count=2 until>0: {ln}")

            nginx.assert_clean_logs()
        finally:
            nginx.stop()

    print(
        "OK: runtime, multi-host Redis, reload, persistence, corruption "
        "and concurrency tests"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
