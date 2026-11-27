#!/usr/bin/env python3
"""EA-02 live GET whole/split and request-cancellation controls.

Build the module with NGX_HTTP_ERROR_ABUSE_TEST_GET_TRACE=1. The peer only
releases a suffix after the runner observes the LIVE hiredis reader retaining
the exact prefix with one pending callback/token/park reference. No private
decoder is called, and no TCP write boundary is treated as a receive boundary.
The cancellation case closes the HTTP client while that prefix is retained,
then requires cleanup and the later Redis callback to settle both observers.
"""

import argparse
import ast
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import re
import select
import signal
import socket
import socketserver
import struct
import threading
import time
from unittest import mock

from test_runtime import Nginx, fetch

TIMEOUT = 1.0
PREFIX = b"ea02-get:"
ZONE = b"get"


def scripts(source: pathlib.Path) -> tuple[bytes, bytes]:
    text = source.read_text(encoding="utf-8")
    result = []
    for name in ("check", "record"):
        declaration = re.search(
            rf"static const char ngx_http_error_abuse_redis_{name}_script\[\] =\s*"
            r"((?:\s*\"[^\"]*\")+);",
            text,
        )
        if declaration is None:
            raise AssertionError(f"missing exact {name} script declaration")
        result.append(
            "".join(
                ast.literal_eval(s) for s in re.findall(r'"[^\"]*"', declaration[1])
            ).encode("ascii")
        )
    return result[0], result[1]


def digest(script: bytes) -> bytes:
    return hashlib.sha1(script, usedforsecurity=False).hexdigest().encode("ascii")


def block_key(identity: str) -> bytes:
    key = hashlib.sha256(identity.encode("ascii")).hexdigest().encode("ascii")
    return PREFIX + b"{" + ZONE + b":" + key + b"}:block"


def read_command(stream: io.BufferedIOBase) -> list[bytes] | None:
    """Strict, bounded fixture RESP parser; reject invalid lengths and EOF."""
    line = stream.readline(32)
    if not line:
        return None
    if not re.fullmatch(rb"\*[1-4]\r\n", line):
        raise ValueError("malformed RESP command array")
    command = []
    for _ in range(int(line[1:-2])):
        line = stream.readline(32)
        if not re.fullmatch(rb"\$(0|[1-9][0-9]{0,3})\r\n", line):
            raise ValueError("malformed RESP command length")
        length = int(line[1:-2])
        if length > 4096:
            raise ValueError("RESP command element too large")
        value = stream.read(length)
        if len(value) != length or stream.read(2) != b"\r\n":
            raise ValueError("truncated RESP command")
        command.append(value)
    return command


@dataclasses.dataclass
class Reply:
    identity: str
    wire: bytes
    split: int = 0
    deadline: int | None = None
    received: threading.Event = dataclasses.field(default_factory=threading.Event)
    release: threading.Event = dataclasses.field(default_factory=threading.Event)
    finished: threading.Event = dataclasses.field(default_factory=threading.Event)

    def __post_init__(self) -> None:
        if not 0 <= self.split < len(self.wire):
            raise ValueError("bad split index")

    def assert_fresh(self) -> None:
        if self.deadline is not None and self.deadline <= time.time() + 3:
            raise AssertionError("expired deadline fixture")


class GetPeer:
    """One session, exact SCRIPT/check vectors and explicit progress ack.

    The runner prepares one reply under the condition lock before requesting
    it. The server owns the socket and history, and signals receipt/completion.
    Only the runner may release a suffix; timeout/exception is a failed test.
    Stop unblocks waits and closes the owned connection before joining threads.
    """

    def __init__(self, check: bytes, record: bytes, ack_timeout: float = 2.0):
        self.expected_scripts = (check, record)
        self.ack_timeout = ack_timeout
        self.history: list[list[bytes]] = []
        self.sessions = 0
        self.current: Reply | None = None
        self.error: Exception | None = None
        self.condition = threading.Condition()
        self.stopping = threading.Event()
        self.connections: set[socket.socket] = set()

    def prepare(self, reply: Reply) -> None:
        with self.condition:
            self.check()
            if self.current is not None and not self.current.finished.is_set():
                raise AssertionError("overlapping GET replies")
            self.current = reply

    def check(self) -> None:
        if self.error is not None:
            raise AssertionError("GET peer failed") from self.error

    def wait(self, event: threading.Event, label: str, timeout: float = 2.0) -> None:
        until = time.monotonic() + timeout
        with self.condition:
            while not event.is_set():
                self.check()
                remaining = until - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"missing {label}")
                self.condition.wait(remaining)
            self.check()

    def notify(self, event: threading.Event) -> None:
        with self.condition:
            event.set()
            self.condition.notify_all()

    def serve(self, stream: io.BufferedIOBase) -> None:
        while not self.stopping.is_set():
            command = read_command(stream)
            if command is None:
                if not self.stopping.is_set():
                    raise AssertionError("unexpected Redis EOF")
                return
            with self.condition:
                index = len(self.history)
                self.history.append(command)
                self.condition.notify_all()
            if index < 2:
                script = self.expected_scripts[index]
                if command != [b"SCRIPT", b"LOAD", script]:
                    raise AssertionError(f"wrong SCRIPT vector/lengths: {command!r}")
                response = b"$40\r\n" + digest(script) + b"\r\n"
                stream.write(response)
                stream.flush()
                continue
            with self.condition:
                reply = self.current
            if reply is None:
                raise AssertionError("unexpected check without prepared reply")
            if reply.finished.is_set():
                raise AssertionError("duplicate GET for completed reply")
            expected = [
                b"EVALSHA",
                digest(self.expected_scripts[0]),
                b"1",
                block_key(reply.identity),
            ]
            if command != expected:
                raise AssertionError(f"wrong check vector/lengths: {command!r}")
            reply.assert_fresh()
            self.notify(reply.received)
            if reply.split:
                stream.write(reply.wire[: reply.split])
                stream.flush()
                if not reply.release.wait(self.ack_timeout):
                    raise AssertionError("missing prefix-consumed acknowledgement")
                if self.stopping.is_set():
                    return
                reply.assert_fresh()
                response = reply.wire[reply.split :]
            else:
                response = reply.wire
            stream.write(response)
            stream.flush()
            self.notify(reply.finished)

    def start(self) -> None:
        parent = self

        class Handler(socketserver.StreamRequestHandler):
            def setup(self) -> None:
                self.connection = self.request
                self.rfile = self.request.makefile("rwb")
                self.wfile = self.rfile

            def handle(self) -> None:
                with parent.condition:
                    parent.sessions += 1
                    parent.connections.add(self.request)
                try:
                    if parent.sessions != 1:
                        raise AssertionError("unexpected Redis reconnect")
                    parent.serve(self.rfile)
                except Exception as error:  # noqa: BLE001 - fail foreground on any peer error
                    if not parent.stopping.is_set():
                        with parent.condition:
                            parent.error = error
                            parent.condition.notify_all()
                finally:
                    with parent.condition:
                        parent.connections.discard(self.request)

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def stop(self) -> None:
        self.stopping.set()
        if self.current is not None:
            self.current.release.set()
        with self.condition:
            connections = tuple(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                # A concurrent peer close already completed this stop step.
                continue
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise AssertionError("GET peer did not stop")


STATE = re.compile(
    r"EA_GET state=(\w+) len=(\d+) pos=(\d+) task=(-?\d+) pending=(\d+) "
    r"tokens=(\d+) parked=(\d+) timer=(\d+) bytes=([0-9a-f]*)"
)


def states(log: str) -> list[dict]:
    return [
        dict(
            zip(
                (
                    "where",
                    "length",
                    "pos",
                    "task",
                    "pending",
                    "tokens",
                    "parked",
                    "timer",
                    "bytes",
                ),
                (m[1], *(int(m[i]) for i in range(2, 9)), m[9]),
                strict=True,
            )
        )
        for m in STATE.finditer(log)
    ]


def wait_until(predicate, label: str, peer: GetPeer, timeout: float = 2.0):
    until = time.monotonic() + timeout
    while True:
        peer.check()
        value = predicate()
        if value:
            return value
        if time.monotonic() >= until:
            raise AssertionError(label)
        time.sleep(0.002)


def events(log: str) -> list[tuple[str, str]]:
    return re.findall(r"EA_GET (park|cleanup|callback|release|resume) id=(\d+)", log)


def assert_completion(log: str) -> None:
    observed = events(log)
    if [kind for kind, _ in observed] != ["park", "callback", "release", "resume"]:
        raise AssertionError(f"GET unique callback/release/resume ordering: {observed}")
    if len({identity for _, identity in observed}) != 1:
        raise AssertionError("GET lifecycle events changed request identity")


def cancellation_state(log: str) -> dict | None:
    matches = list(re.finditer(r"EA_GET cancelled tokens=(\d+) parked=(\d+)", log))
    if not matches:
        return None
    match = matches[-1]
    return {
        "tokens": int(match[1]),
        "parked": int(match[2]),
        "offset": match.start(),
    }


def assert_cancellation(log: str) -> dict:
    observed = events(log)
    if [kind for kind, _ in observed] != ["park", "cleanup"]:
        raise AssertionError(f"GET unique park/cleanup ordering: {observed}")
    if len({identity for _, identity in observed}) != 1:
        raise AssertionError("GET cancellation events changed request identity")
    cleanup_at = log.find("EA_GET cleanup id=")
    final = cancellation_state(log)
    if final is None or final["offset"] <= cleanup_at:
        raise AssertionError("GET cancelled callback did not follow cleanup")
    if final["tokens"] != 0:
        raise AssertionError("GET cancellation callback token did not settle")
    if final["parked"] != 0:
        raise AssertionError(f"GET cancellation stale parked reference: {final}")
    return final


def assert_one_completion(lines: list[str], identity: str, status: str) -> None:
    completions = [line for line in lines if line.startswith(f"{identity} ")]
    if completions != [f"{identity} {status}"]:
        raise AssertionError("GET repeated HTTP completion")


def prefix_consumed(log: str, reply: Reply) -> bool:
    return any(
        s["where"] == "read"
        and s["task"] >= 0
        and s["pending"] == s["tokens"] == s["parked"] == 1
        and s["bytes"].endswith(reply.wire[: reply.split].hex())
        for s in states(log)
    )


def worker_fds(proc: pathlib.Path, http_port: int) -> dict[str, str] | None:
    """Snapshot only worker descriptors, after accepted HTTP sockets close.

    Reading an HTTP response body can precede nginx closing its descriptor.
    Join the worker's socket inodes to the kernel TCP table so that warmup
    cannot accidentally include that transient client socket in the baseline.
    TIME_WAIT entries without an owned descriptor do not affect this test.
    """
    try:
        descriptors = {fd.name: str(fd.readlink()) for fd in (proc / "fd").iterdir()}
        rows = (proc / "net/tcp").read_text(encoding="ascii").splitlines()[1:]
    except FileNotFoundError:
        return None  # A descriptor closed while the snapshot was being read.
    owned = set(descriptors.values())
    for row in rows:
        fields = row.split()
        if (
            int(fields[1].split(":")[1], 16) == http_port
            and fields[3] != "0A"
            and f"socket:[{fields[9]}]" in owned
        ):
            return None
    return descriptors


def test_redis_get(
    binary: pathlib.Path,
    module: pathlib.Path,
    root: pathlib.Path,
    port: int,
    selection: str = "all",
) -> None:
    check, record = scripts(
        pathlib.Path(__file__).resolve().parents[2]
        / "src/ngx_http_error_abuse_module.c"
    )
    peer = GetPeer(check, record)
    peer.start()
    slow_listener = None
    slow_client = None
    upstream = None
    nginx = None
    try:
        slow_listener = socket.socket()
        slow_listener.bind(("127.0.0.1", 0))
        slow_listener.listen()
        slow_listener.settimeout(5)
        slow_port = slow_listener.getsockname()[1]
        nginx = Nginx(binary, module, root, port, "", selection != "cancel", peer.port)
        (root / "conf").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "conf/nginx.conf").write_text(
            f"""load_module {module};
worker_processes 1;
worker_shutdown_timeout 100ms;
pid {root}/nginx.pid;
error_log {root}/logs/error.log debug;
events {{ worker_connections 64; }}
http {{
    log_format get '$arg_client $status';
    access_log {root}/access.log get;
    error_abuse_redis host=127.0.0.1 port={peer.port} prefix=ea02-get: timeout=1s;
    error_abuse_zone zone=get:1m key=$arg_client statuses=404
                     interval=60s threshold=10 block=60s redis=on;
    server {{
        listen 127.0.0.1:{port};
        location = /get.gif {{ error_abuse zone=get; empty_gif; }}
        location = /health.gif {{ empty_gif; }}
        location = /hold {{ proxy_pass http://127.0.0.1:{slow_port}; }}
    }}
}}
""",
            encoding="ascii",
        )
    except BaseException:
        if slow_listener is not None:
            with contextlib.suppress(OSError):
                slow_listener.close()
        if nginx is not None:
            with contextlib.suppress(Exception):
                nginx.stop()
        with contextlib.suppress(Exception):
            peer.stop()
        raise
    assert slow_listener is not None
    assert nginx is not None
    error_path = root / "logs/error.log"
    access_path = root / "access.log"

    def log() -> str:
        return error_path.read_text(encoding="ascii", errors="replace")

    def idle(offset: int) -> bool:
        return any(
            s["pending"] == s["tokens"] == s["parked"] == s["timer"] == 0
            for s in states(log()[offset:])
        )

    records = []
    try:
        with mock.patch.object(nginx, "write_config"):
            nginx.start()
        wait_until(lambda: idle(0), "GET handshake did not reach drained idle", peer)
        fetch(port, "/health.gif")
        process = nginx.process
        assert process is not None
        proc = pathlib.Path(f"/proc/{process.pid}")
        baseline = wait_until(
            lambda: worker_fds(proc, port), "GET warmup HTTP socket did not close", peer
        )

        def run(reply: Reply) -> float:
            reply.assert_fresh()
            peer.prepare(reply)
            offset = len(log())
            begun = time.monotonic()
            prefix_witness = None
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(
                    f"GET /get.gif?client={reply.identity} HTTP/1.0\r\n"
                    "Host: localhost\r\n\r\n".encode("ascii")
                )
                peer.wait(reply.received, "GET command")
                if reply.split:
                    wait_until(
                        lambda: prefix_consumed(log()[offset:], reply),
                        "GET prefix was not consumed by live hiredis",
                        peer,
                        timeout=TIMEOUT * 0.6,
                    )
                    if [kind for kind, _ in events(log()[offset:])] != ["park"]:
                        raise AssertionError("GET prefix delivered callback/resume")
                    if select.select([client], [], [], 0)[0]:
                        raise AssertionError("GET prefix delivered HTTP bytes/EOF")
                    if (
                        access_path.exists()
                        and reply.identity in access_path.read_text()
                    ):
                        raise AssertionError("GET prefix completed HTTP")
                    if time.monotonic() - begun >= TIMEOUT * 0.8:
                        raise AssertionError(
                            "GET prefix fixture missed command deadline"
                        )
                    prefix_witness = {
                        "state": states(log()[offset:])[-1],
                        "events": events(log()[offset:]),
                        "http_bytes": 0,
                        "observed_at": time.monotonic(),
                    }
                    reply.release.set()
                    prefix_witness["suffix_released_at"] = time.monotonic()
                response = b""
                try:
                    while chunk := client.recv(65536):
                        response += chunk
                except TimeoutError as error:
                    raise AssertionError(
                        "GET suffix did not complete HTTP after resumption"
                    ) from error
            peer.wait(reply.finished, "GET reply completion")
            assert_completion(log()[offset:])
            status = b"429" if reply.deadline else b"200"
            if (
                response.split(b" ", 2)[1:2] != [status]
                or response.count(b"HTTP/1.") != 1
            ):
                raise AssertionError(
                    f"GET exactly-once HTTP status {status!r}: {response!r}"
                )
            if reply.deadline:
                match = re.search(rb"\r\nRetry-After: ([0-9]+)\r\n", response)
                if match is None or not 1 <= int(match[1]) <= 60:
                    raise AssertionError(
                        "GET deadline Retry-After outside block bounds"
                    )
            wait_until(
                lambda: (
                    access_path.exists()
                    and f"{reply.identity} {status.decode()}\n"
                    in access_path.read_text()
                ),
                "GET missing HTTP completion",
                peer,
            )
            assert_one_completion(
                access_path.read_text().splitlines(), reply.identity, status.decode()
            )
            wait_until(
                lambda: worker_fds(proc, port) == baseline,
                "GET worker fd snapshot did not return to baseline",
                peer,
            )

            def drained():
                observed = states(log()[offset:])
                if observed and not any(
                    observed[-1][key] for key in ("pending", "tokens", "parked")
                ):
                    return observed[-1]
                return None

            final = wait_until(drained, "GET stale command/token/park reference", peer)
            if time.monotonic() - begun >= TIMEOUT * 0.8:
                raise AssertionError("GET reply did not precede command deadline")
            records.append(
                {
                    "identity": reply.identity,
                    "wire_hex": reply.wire.hex(),
                    "split": reply.split,
                    "prefix_witness": prefix_witness,
                    "events": events(log()[offset:]),
                    "final": final,
                    "fd_baseline": baseline,
                }
            )
            return begun

        def cancel(reply: Reply) -> None:
            nonlocal slow_client, upstream
            reply.assert_fresh()
            peer.prepare(reply)
            offset = len(log())
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            try:
                client.sendall(
                    f"GET /get.gif?client={reply.identity} HTTP/1.0\r\n"
                    "Host: localhost\r\n\r\n".encode("ascii")
                )
                peer.wait(reply.received, "cancellation GET command")
                wait_until(
                    lambda: prefix_consumed(log()[offset:], reply),
                    "cancellation GET prefix was not consumed by live hiredis",
                    peer,
                    timeout=TIMEOUT * 0.6,
                )
                if [kind for kind, _ in events(log()[offset:])] != ["park"]:
                    raise AssertionError("cancellation GET prefix advanced lifecycle")
                if select.select([client], [], [], 0)[0]:
                    raise AssertionError(
                        "cancellation GET prefix delivered HTTP bytes/EOF"
                    )
                client.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
            finally:
                client.close()
            if reply.release.is_set() or reply.finished.is_set():
                raise AssertionError("cancellation GET reply completed before shutdown")
            slow_client = socket.create_connection(("127.0.0.1", port), timeout=2)
            slow_client.sendall(b"GET /hold HTTP/1.0\r\nHost: localhost\r\n\r\n")
            upstream, _ = slow_listener.accept()
            process = nginx.process
            if process is None:
                raise AssertionError("cancellation GET nginx is not running")
            os.kill(process.pid, signal.SIGQUIT)
            process.wait(timeout=5)
            wait_until(
                lambda: (
                    [kind for kind, _ in events(log()[offset:])] == ["park", "cleanup"]
                ),
                "cancellation GET shutdown did not run request cleanup",
                peer,
            )
            final = wait_until(
                lambda: cancellation_state(log()[offset:]),
                "GET cancellation callback did not settle",
                peer,
            )
            assert_cancellation(log()[offset:])
            if reply.release.is_set() or reply.finished.is_set():
                raise AssertionError(
                    "cancellation GET suffix completed during shutdown"
                )
            lines = [
                line
                for line in access_path.read_text().splitlines()
                if line.startswith(f"{reply.identity} ")
            ]
            if len(lines) != 1:
                raise AssertionError("cancellation GET repeated HTTP completion")
            records.append(
                {
                    "identity": reply.identity,
                    "wire_hex": reply.wire.hex(),
                    "split": reply.split,
                    "events": events(log()[offset:]),
                    "final": final,
                    "http_status": int(lines[0].split()[1]),
                    "worker_exit": process.returncode,
                    "suffix_completed": False,
                }
            )
            peer.stopping.set()
            reply.release.set()

        # Whole cases are prerequisite baselines; k=0 represents both endpoints.
        for kind in ("nil", "blocked"):
            length = 5 if kind == "nil" else 17  # ten-digit Unix deadline bulk
            for split in range(length):
                label = f"{kind}:{split}"
                if selection == "cancel":
                    continue
                if selection != "all" and selection != label:
                    continue
                deadline = int(time.time()) + 30 if kind == "blocked" else None
                wire = (
                    b"$-1\r\n"
                    if deadline is None
                    else b"$10\r\n" + str(deadline).encode() + b"\r\n"
                )
                if len(wire) != length:
                    raise AssertionError("GET frozen reply byte count changed")
                identity = f"{kind}-{split}"
                settle = len(log())
                started = run(Reply(identity, wire, split, deadline))
                # A distinct key must use the same session before the original
                # command's timer deadline; then await the real idle timer wake.
                run(Reply(identity + "-before", b"$-1\r\n"))
                if time.monotonic() >= started + TIMEOUT:
                    raise AssertionError("GET same-session reuse missed prior deadline")
                wait_until(
                    lambda settle=settle: idle(settle),
                    "GET adapter timer did not settle",
                    peer,
                )
                if time.monotonic() < started + TIMEOUT:
                    raise AssertionError("GET idle witness preceded prior deadline")
                settle = len(log())
                run(Reply(identity + "-after", b"$-1\r\n"))
                wait_until(
                    lambda settle=settle: idle(settle),
                    "GET reuse timer did not settle",
                    peer,
                )
                print(
                    f"OK: GET {'WHOLE' if split == 0 else 'SPLIT'} {label}", flush=True
                )
        if selection == "cancel":
            cancel(Reply("cancel", b"$-1\r\n", 1))
            print("OK: GET CANCEL split:1", flush=True)
        peer.check()
        if not records:
            raise ValueError("GET selection matched no cases")
        if peer.sessions != 1 or len(peer.history) != len(records) + 2:
            raise AssertionError("GET unexpected command/session history")
        (root / "get-evidence.json").write_text(
            json.dumps(
                {
                    "cases": records,
                    "sessions": peer.sessions,
                    "vectors_hex": [
                        [v.hex() for v in vector] for vector in peer.history
                    ],
                    "scripts_sha1": [digest(s).decode() for s in (check, record)],
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        for stream in (slow_client, upstream, slow_listener):
            if stream is not None:
                stream.close()
        try:
            nginx.stop()
        finally:
            peer.stop()
    nginx.assert_clean_logs()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx-binary", type=pathlib.Path, required=True)
    parser.add_argument("--module", type=pathlib.Path, required=True)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--port", type=int, default=18967)
    parser.add_argument("--case", default="all")
    args = parser.parse_args()
    test_redis_get(
        args.nginx_binary.resolve(),
        args.module.resolve(),
        args.root.resolve(),
        args.port,
        args.case,
    )


if __name__ == "__main__":
    main()
