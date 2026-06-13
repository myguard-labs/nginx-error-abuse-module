#!/usr/bin/env python3
"""End-to-end tests for ngx_http_error_abuse_module."""

from __future__ import annotations

import argparse
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
            return response.status, {k.lower(): v
                                     for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}


def nginx_config(root: pathlib.Path, port: int, module: pathlib.Path | None,
                 workers: int, keyed_key: str = "$arg_client",
                 redis_port: int | None = None,
                 redis_prefix: str = "error-abuse-ci:",
                 redis_password: str | None = None) -> str:
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
    def __init__(self, binary: pathlib.Path, module: pathlib.Path | None,
                 root: pathlib.Path, port: int, runner: str,
                 single_process: bool, redis_port: int | None = None,
                 redis_prefix: str = "error-abuse-ci:",
                 redis_password: str | None = None) -> None:
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
                self.root, self.port, self.module, workers, keyed_key,
                self.redis_port, self.redis_prefix, self.redis_password,
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
        elif self.single_process:
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
        )
        if result.returncode != 0:
            raise RuntimeError(f"nginx -t failed:\n{result.stdout}")

    def start(self) -> None:
        self.write_config()
        output = self.output_path.open("a", encoding="utf-8")
        self.process = subprocess.Popen(
            self.command(),
            text=True,
            stdout=output,
            stderr=subprocess.STDOUT,
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
            output = self.output_path.read_text(
                encoding="utf-8", errors="replace"
            ) if self.output_path.exists() else ""
            raise RuntimeError(f"nginx exited with {rc}:\n{output}")

    def assert_clean_logs(self) -> None:
        paths = [self.output_path, self.root / "logs" / "error.log"]
        combined = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in paths if path.exists()
        )
        for marker in SANITIZER_MARKERS:
            if marker == "ERROR SUMMARY:" and "ERROR SUMMARY: 0 errors" in combined:
                continue
            if marker in combined:
                raise AssertionError(f"runtime checker marker found: {marker}")
        fatal_lines = [
            line for line in combined.splitlines()
            if ("[alert]" in line or "[emerg]" in line)
            and "key cannot change during reload" not in line
        ]
        if fatal_lines:
            raise AssertionError(
                "nginx logged a fatal condition:\n" + "\n".join(fatal_lines)
            )


class RedisServer:
    def __init__(self, binary: pathlib.Path, root: pathlib.Path,
                 port: int, requirepass: str | None = None) -> None:
        self.binary = binary
        self.root = root
        self.port = port
        self.requirepass = requirepass
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(self.binary),
            "--bind", "127.0.0.1",
            "--port", str(self.port),
            "--save", "",
            "--appendonly", "no",
            "--dir", str(self.root),
        ]
        if self.requirepass:
            cmd += ["--requirepass", self.requirepass]
        self.process = subprocess.Popen(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
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


def test_redis_multi_host(binary: pathlib.Path,
                          module: pathlib.Path | None,
                          root: pathlib.Path, runner: str,
                          single_process: bool, nginx_port: int,
                          redis_binary: pathlib.Path) -> None:
    redis_port = nginx_port + 20
    prefix = f"error-abuse-ci-{os.getpid()}-{int(time.time()*1000)}:"
    redis = RedisServer(redis_binary, root / "redis", redis_port)
    first = Nginx(
        binary, module, root / "redis-nginx-a", nginx_port + 1, runner,
        single_process, redis_port, prefix,
    )
    second = Nginx(
        binary, module, root / "redis-nginx-b", nginx_port + 2, runner,
        single_process, redis_port, prefix,
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
        time.sleep(3.0)   # allow reconnect backoff + handshake
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


def test_redis_auth(binary: pathlib.Path, module: pathlib.Path | None,
                    root: pathlib.Path, runner: str, single_process: bool,
                    nginx_port: int, redis_binary: pathlib.Path) -> None:
    # CI-5: password-protected Redis exercises the AUTH handshake (COR-5) and
    # that blocking still works through it.
    redis_port = nginx_port + 30
    prefix = f"error-abuse-auth-{os.getpid()}-{int(time.time()*1000)}:"
    redis = RedisServer(redis_binary, root / "redis-auth", redis_port,
                        requirepass="s3cr3t-pass")
    server = Nginx(
        binary, module, root / "redis-auth-nginx", nginx_port + 3, runner,
        single_process, redis_port, prefix, redis_password="s3cr3t-pass",
    )
    try:
        redis.start()
        server.start()
        time.sleep(0.3)

        expect(server.port, "/redis-error?client=authed", 404)
        time.sleep(0.05)
        expect(server.port, "/redis-error?client=authed", 404)
        time.sleep(0.05)
        expect(server.port, "/redis-error?client=authed", 404)
        time.sleep(0.05)
        expect(server.port, "/redis-ok?client=authed", 429)

        server.stop()
        server.assert_clean_logs()
    finally:
        server.stop()
        redis.stop()


def expect_invalid_config(binary: pathlib.Path, module: pathlib.Path | None,
                          root: pathlib.Path, runner: str, name: str,
                          http_config: str, expected: str) -> None:
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
        str(binary), "-p", str(bad), "-c", str(bad / "conf" / "nginx.conf"),
        "-t",
    ]
    result = subprocess.run(
        command, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=20,
    )
    if result.returncode == 0 or expected not in result.stdout:
        raise AssertionError(
            f"{name} config was not rejected as expected:\n{result.stdout}"
        )


def expect_valid_config(binary: pathlib.Path, module: pathlib.Path | None,
                        root: pathlib.Path, runner: str, name: str,
                        http_config: str) -> None:
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
        str(binary), "-p", str(good), "-c", str(good / "conf" / "nginx.conf"),
        "-t",
    ]
    result = subprocess.run(
        command, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{name} config was rejected but should be valid:\n{result.stdout}"
        )


def test_valid_configs(binary: pathlib.Path, module: pathlib.Path | None,
                       root: pathlib.Path, runner: str) -> None:
    # COR-1: the documented one-argument forms must be accepted (were rejected
    # by NGX_CONF_2MORE before the fix).
    expect_valid_config(
        binary, module, root, runner, "minimal-zone",
        "    error_abuse_zone zone=minimal:1m;",
    )
    expect_valid_config(
        binary, module, root, runner, "minimal-redis",
        """    error_abuse_redis host=127.0.0.1;
    error_abuse_zone zone=minimal:1m redis=on;""",
    )


def test_invalid_configs(binary: pathlib.Path, module: pathlib.Path | None,
                         root: pathlib.Path, runner: str) -> None:
    # COR-8: a trailing comma in the status list is malformed, not ignored.
    expect_invalid_config(
        binary, module, root, runner, "trailing-comma-status",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404, interval=1s threshold=2 block=1s;""",
        "invalid error_abuse status list",
    )
    # COR-3: an explicit inactive shorter than interval/block is rejected.
    expect_invalid_config(
        binary, module, root, runner, "short-inactive",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=5m threshold=2 block=1h
                         inactive=1s;""",
        "inactive must be >=",
    )
    # SEC-5: persist_secret without persist, and odd-length hex, are rejected.
    expect_invalid_config(
        binary, module, root, runner, "secret-without-persist",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         persist_secret=00ff;""",
        "persist_secret requires persist",
    )
    secret_state = root / "oddsecret.state"
    expect_invalid_config(
        binary, module, root, runner, "secret-odd-hex",
        f"""    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         persist={secret_state} persist_secret=abc;""",
        "invalid error_abuse_zone parameter",
    )
    # COR-6: "off" then a real declaration in the same block is a duplicate,
    # regardless of order.
    expect_invalid_config(
        binary, module, root, runner, "off-then-zone",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s;
    server {
        error_abuse off;
        error_abuse zone=bad status=429;
    }""",
        "is duplicate",
    )
    expect_invalid_config(
        binary, module, root, runner, "bad-status",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404,700 interval=1s threshold=2 block=1s;""",
        "invalid error_abuse status list",
    )
    expect_invalid_config(
        binary, module, root, runner, "duplicate-parameter",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s interval=2s
                         threshold=2 block=1s;""",
        "duplicate error_abuse_zone parameter",
    )
    expect_invalid_config(
        binary, module, root, runner, "duplicate-enable-parameter",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s;
    server {
        error_abuse zone=bad status=429 status=403;
    }""",
        "duplicate error_abuse parameter",
    )
    expect_invalid_config(
        binary, module, root, runner, "redis-without-backend",
        """    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         redis=on;""",
        "requires error_abuse_redis",
    )
    expect_invalid_config(
        binary, module, root, runner, "bad-redis-prefix",
        """    error_abuse_redis host=127.0.0.1 "prefix=bad{prefix";
    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                         statuses=404 interval=1s threshold=2 block=1s
                         redis=on;""",
        "invalid error_abuse_redis parameter",
    )
    shared = root / "shared.state"
    expect_invalid_config(
        binary, module, root, runner, "duplicate-persistence",
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
        if args.redis_server:
            test_redis_multi_host(
                binary, module, root, args.runner, args.single_process,
                args.port, pathlib.Path(args.redis_server).absolute(),
            )
            test_redis_auth(
                binary, module, root, args.runner, args.single_process,
                args.port, pathlib.Path(args.redis_server).absolute(),
            )
        nginx = Nginx(
            binary, module, root / "server", args.port, args.runner,
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
                codes = list(pool.map(
                    lambda _: request(args.port, "/dry-error"),
                    range(200),
                ))
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

            nginx.start()                       # untampered: ban restored
            expect(args.port, "/secret-ok", 429)
            nginx.stop()

            # Flip a bit in the trailing HMAC (CRC covers payload only, so only
            # the HMAC catches this) — load must ignore the file.
            tampered = bytearray(secret_state.read_bytes())
            tampered[-1] ^= 0x01
            secret_state.write_bytes(bytes(tampered))
            os.chmod(secret_state, 0o600)

            nginx.start()
            expect(args.port, "/secret-ok", 200)   # not restored
            nginx.stop()

            # Exposed variables: drive PASSED -> COUNTED -> BLOCKED and assert
            # $error_abuse_status / _count / _blocked_until via the access log.
            nginx.start()
            expect(args.port, "/var-ok", 200)       # 200 untracked -> PASSED
            expect(args.port, "/var-error", 404)    # 1st 404      -> COUNTED 1
            expect(args.port, "/var-error", 404)    # threshold    -> BLOCKED 2
            expect(args.port, "/var-error", 429)    # now banned   -> BLOCKED 2
            time.sleep(0.3)
            nginx.stop()

            vars_log = nginx.root / "logs" / "vars.log"
            lines = [ln.split() for ln in
                     vars_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if len(lines) != 4:
                raise AssertionError(f"vars.log expected 4 lines, got {lines}")
            states = [ln[1] for ln in lines]
            if states != ["PASSED", "COUNTED", "BLOCKED", "BLOCKED"]:
                raise AssertionError(f"unexpected $error_abuse_status: {states}")
            if lines[0][2] != "0" or lines[0][3] != "0":
                raise AssertionError(f"PASSED count/until not zero: {lines[0]}")
            if lines[1][2] != "1" or lines[1][3] != "0":
                raise AssertionError(f"COUNTED expected count=1 until=0: {lines[1]}")
            for ln in lines[2:]:
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
