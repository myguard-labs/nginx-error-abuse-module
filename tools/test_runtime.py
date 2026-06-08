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


def nginx_config(root: pathlib.Path, port: int, module: pathlib.Path | None,
                 workers: int) -> str:
    load = f"load_module {module};\n" if module else ""
    return f"""{load}worker_processes {workers};
pid {root}/nginx.pid;
error_log {root}/logs/error.log notice;

events {{
    worker_connections 512;
}}

http {{
    access_log off;

    error_abuse_zone zone=basic:1m key=$binary_remote_addr
                     statuses=403,404 interval=5s threshold=3 block=2s
                     persist={root}/basic.state persist_interval=100ms;
    error_abuse_zone zone=keyed:1m key=$arg_client
                     statuses=404 interval=5s threshold=2 block=10s;
    error_abuse_zone zone=dry:1m key=$binary_remote_addr
                     statuses=404 interval=5s threshold=1 block=10s;
    error_abuse_zone zone=window:1m key=$binary_remote_addr
                     statuses=404 interval=1s threshold=3 block=10s;
    error_abuse_zone zone=persisted:1m key=$binary_remote_addr
                     statuses=404 interval=30s threshold=3 block=10s
                     persist={root}/persisted.state persist_interval=100ms;

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
    }}
}}
"""


class Nginx:
    def __init__(self, binary: pathlib.Path, module: pathlib.Path | None,
                 root: pathlib.Path, port: int, runner: str,
                 single_process: bool) -> None:
        self.binary = binary
        self.module = module
        self.root = root
        self.port = port
        self.runner = shlex.split(runner)
        self.single_process = single_process
        self.process: subprocess.Popen[str] | None = None
        self.output_path = root / "nginx-output.log"

    def write_config(self) -> None:
        workers = 1 if self.single_process else 4
        (self.root / "conf").mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        (self.root / "empty").mkdir(parents=True, exist_ok=True)
        (self.root / "conf" / "nginx.conf").write_text(
            nginx_config(self.root, self.port, self.module, workers),
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
            command.append("-t")
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
        if "[alert]" in combined or "[emerg]" in combined:
            raise AssertionError(f"nginx logged a fatal condition:\n{combined}")


def test_invalid_config(binary: pathlib.Path, module: pathlib.Path | None,
                        root: pathlib.Path, runner: str) -> None:
    bad = root / "bad"
    (bad / "conf").mkdir(parents=True)
    (bad / "logs").mkdir()
    load = f"load_module {module};\n" if module else ""
    (bad / "conf" / "nginx.conf").write_text(
        f"""{load}error_log {bad}/logs/error.log;
events {{}}
http {{
    error_abuse_zone zone=bad:1m key=$binary_remote_addr
                     statuses=404,700 interval=1s threshold=2 block=1s;
}}
""",
        encoding="ascii",
    )
    command = shlex.split(runner) + [
        str(binary), "-p", str(bad), "-c", str(bad / "conf" / "nginx.conf"),
        "-t",
    ]
    result = subprocess.run(
        command, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=20,
    )
    if result.returncode == 0 or "invalid error_abuse status list" not in result.stdout:
        raise AssertionError(f"invalid status config was accepted:\n{result.stdout}")


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
        test_invalid_config(binary, module, root, args.runner)
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
            expect(args.port, "/ok", 429)
            time.sleep(2.2)
            expect(args.port, "/ok", 200)

            expect(args.port, "/dry-error", 404)
            expect(args.port, "/dry-ok", 200)
            expect(args.port, "/dry-error", 404)

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

            if not args.single_process:
                nginx.reload()
                expect(args.port, "/persist-error", 404)
                expect(args.port, "/persist-ok", 429)
                time.sleep(10.2)

                # Reset the persisted zone after the reload-specific block.
                expect(args.port, "/persist-ok", 200)
                expect(args.port, "/persist-error", 404)
                expect(args.port, "/persist-error", 404)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                codes = list(pool.map(
                    lambda _: request(args.port, "/dry-error"),
                    range(200),
                ))
            if set(codes) != {404}:
                raise AssertionError(f"dry-run concurrency returned {set(codes)}")

            time.sleep(0.3)
            nginx.stop()

            state = nginx.root / "persisted.state"
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
            nginx.assert_clean_logs()
        finally:
            nginx.stop()

    print("OK: runtime, reload, persistence, corruption and concurrency tests")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
