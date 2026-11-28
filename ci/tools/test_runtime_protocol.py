#!/usr/bin/env python3
"""Live initial SCRIPT and record protocol controls.

Only the existing GET helpers decode commands and witness request ownership.
SCRIPT replies are released one at a time after the previous live callback is
acknowledged. Error cases close the peer only after the post-branch witness,
settling the remaining callbacks via hiredis's actual NULL-failure drain.
Record commands use a separate bounded ten-element decoder and hold their
callbacks until the counted HTTP response has completed.
"""

import argparse
import dataclasses
import io
import json
import os
import pathlib
import re
import select
import signal
import socket
import threading
import time
from unittest import mock

from test_runtime import Nginx, fetch, http_call
from test_runtime_get import (
    TIMEOUT,
    GetPeer,
    Reply,
    assert_completion,
    assert_one_completion,
    block_key,
    digest,
    events,
    read_command,
    scripts,
    states,
    wait_until,
    worker_fds,
)

ERROR = b"-ERR script fixture\r\n"
FIELDS = (
    "gen",
    "slot",
    "queued",
    "called",
    "outstanding",
    "ready",
    "connected",
    "timer",
    "disconnecting",
    "reconnect",
    "cleanup",
    "kind",
    "length",
)
SCRIPT_STATE = re.compile(
    r"EA_SCRIPT state=(\w+) "
    + " ".join(rf"{name}=(\d+)" for name in FIELDS)
    + r" bytes=([0-9a-f]*)"
)


def script_states(log: str) -> list[dict]:
    return [
        {
            "where": m[1],
            **dict(zip(FIELDS, map(int, m.groups()[1:-1]), strict=True)),
            "bytes": m.groups()[-1],
        }
        for m in SCRIPT_STATE.finditer(log)
    ]


def assert_ledger(log: str, expected: list[tuple[int, int, bytes]]) -> None:
    rows = script_states(log)
    queues = [r for r in rows if r["where"] == "queue"]
    if [(r["slot"], r["queued"], r["called"], r["outstanding"]) for r in queues] != [
        (1, 1, 0, 1),
        (2, 2, 0, 2),
    ]:
        raise AssertionError("SCRIPT exact queue identity/order/count")
    callbacks = [r for r in rows if r["where"] == "callback"]
    if [
        (r["slot"], r["kind"], bytes.fromhex(r["bytes"])) for r in callbacks
    ] != expected:
        raise AssertionError("SCRIPT unique FIFO callbacks/reply values")
    if [r["length"] for r in callbacks] != [len(e[2]) for e in expected]:
        raise AssertionError("SCRIPT exact callback reply length")
    if [(r["called"], r["outstanding"]) for r in callbacks] != [(1, 1), (2, 0)]:
        raise AssertionError("SCRIPT callback outstanding count")
    if re.findall(r"EA_SCRIPT callback_gen=(\d+)", log) != ["1", "1"]:
        raise AssertionError("SCRIPT callback token generation")
    if any(r["gen"] != 1 for r in rows if r["where"] != "previous"):
        raise AssertionError("SCRIPT connection generation")
    posts = [r for r in rows if r["where"] == "post"]
    if [(r["slot"], r["kind"], bytes.fromhex(r["bytes"])) for r in posts] != [
        e for e in expected if e[1] != 0
    ]:
        raise AssertionError("SCRIPT post callback identity/order")
    if any(
        not 0 <= r["called"] <= r["queued"] <= 2
        or r["outstanding"] != r["queued"] - r["called"]
        for r in rows
    ):
        raise AssertionError("SCRIPT stale snapshot count")
    previous = [r for r in rows if r["where"] == "previous"]
    if len(previous) != 1 or previous[0]["outstanding"] != 0:
        raise AssertionError("SCRIPT stale previous generation")


def assert_error_post(log: str, slot: int) -> dict:
    rows = [r for r in script_states(log) if r["where"] == "post" and r["slot"] == slot]
    if len(rows) != 1 or rows[0]["kind"] != 6:
        raise AssertionError("missing SCRIPT error post-branch witness")
    row = rows[0]
    if row["ready"] != 0:
        raise AssertionError("SCRIPT error callback left ready")
    if row["disconnecting"] != 1:
        raise AssertionError("SCRIPT error callback did not enter disconnect")
    return row


def assert_resources(row: dict, connected: bool) -> None:
    if any(row[k] for k in ("outstanding", "timer")):
        raise AssertionError("SCRIPT stale outstanding/command timer")
    if row["connected"] != int(connected) or row["cleanup"] != int(not connected):
        raise AssertionError("SCRIPT adapter cleanup/connection count")


def assert_fds(actual: dict | None, expected: dict) -> None:
    if actual != expected:
        raise AssertionError("SCRIPT worker fd drift")


@dataclasses.dataclass(frozen=True)
class ErrorContext:
    begun: float
    offset: int
    identity: str
    scripts: tuple[bytes, bytes]
    disconnected_fds: tuple[tuple[str, str], ...]
    slot: int
    worker: str


@dataclasses.dataclass(frozen=True)
class ErrorSnapshot:
    context: ErrorContext
    log: str
    output: str
    access: tuple[str, ...]
    response: bytes
    sessions: int
    vectors: tuple[tuple[bytes, ...], ...]
    peer_error: str | None
    fds: tuple[tuple[str, str], ...] | None
    captured_at: float


def capture_error_snapshot(context, read_live, clock=time.monotonic):
    """Freeze every live witness before checking the original capture deadline."""
    live = read_live()
    snapshot = ErrorSnapshot(
        context=context,
        log=live["log"],
        output=live["output"],
        access=tuple(live["access"]),
        response=bytes(live["response"]),
        sessions=live["sessions"],
        vectors=tuple(
            tuple(bytes(value) for value in vector) for vector in live["vectors"]
        ),
        peer_error=live["peer_error"],
        fds=None if live["fds"] is None else tuple(sorted(live["fds"].items())),
        captured_at=clock(),
    )
    if snapshot.captured_at >= context.begun + TIMEOUT:
        raise AssertionError("SCRIPT failure cleanup waited for command timeout")
    return snapshot


def error_snapshot_evidence(snapshot):
    """Validate only frozen old-generation data, even if validation runs late."""
    context = snapshot.context
    check, record = context.scripts
    expected = (
        [(1, 6, ERROR[1:-2]), (2, 0, b"")]
        if context.slot == 1
        else [(1, 1, digest(check)), (2, 6, ERROR[1:-2])]
    )
    assert_error_post(snapshot.log, context.slot)
    assert_ledger(snapshot.log, expected)
    rows = script_states(snapshot.log)
    if rows[-1]["where"] != "drained":
        raise AssertionError("SCRIPT error snapshot missing final drain")
    final = rows[-1]
    assert_resources(final, False)
    if final["ready"] != 0 or final["reconnect"] != 1:
        raise AssertionError("SCRIPT error snapshot lost scheduled reconnect")
    delays = re.findall(
        r"error_abuse test reconnect delay=(\d+) next=(\d+)", snapshot.log
    )
    if len(delays) != 1 or int(delays[0][1]) != 30000:
        raise AssertionError("SCRIPT missing capped reconnect delay witness")
    delay = int(delays[0][0])
    if delay <= TIMEOUT * 1000:
        raise AssertionError("SCRIPT reconnect delay overlaps error-capture window")
    if re.findall(r"EA_SCRIPT settled tokens=(\d+) parked=(\d+)", snapshot.log) != [
        ("0", "0")
    ]:
        raise AssertionError("SCRIPT failure left GET token/park reference")
    if re.findall(r"EA_SCRIPT get_kind=(\d+)", snapshot.log) != ["0"]:
        raise AssertionError("SCRIPT sentinel missing NULL failure callback")
    assert_completion(snapshot.log[context.offset :])
    if (
        snapshot.response.split(b" ", 2)[1:2] != [b"200"]
        or snapshot.response.count(b"HTTP/1.") != 1
    ):
        raise AssertionError("SCRIPT GET exactly-once HTTP 200")
    assert_one_completion(list(snapshot.access), context.identity, "200")
    if snapshot.fds != context.disconnected_fds:
        raise AssertionError("SCRIPT worker fd drift")
    expected_vectors = (
        (b"SCRIPT", b"LOAD", check),
        (b"SCRIPT", b"LOAD", record),
        (b"EVALSHA", digest(check), b"1", block_key(context.identity)),
    )
    if snapshot.sessions != 1 or snapshot.vectors != expected_vectors:
        raise AssertionError("SCRIPT unexpected session/command history")
    if snapshot.peer_error is not None:
        raise AssertionError("SCRIPT captured peer failure: " + snapshot.peer_error)
    clean_logs(snapshot.log + snapshot.output, True)
    return {
        "sessions": snapshot.sessions,
        "worker": context.worker,
        "vectors_hex": [[v.hex() for v in vector] for vector in snapshot.vectors],
        "scripts_sha1": [digest(script).decode() for script in context.scripts],
        "script_states": rows,
        "get_states": states(snapshot.log),
        "get_cases": [
            {
                "identity": context.identity,
                "events": events(snapshot.log[context.offset :]),
                "response_hex": snapshot.response.hex(),
            }
        ],
        "fd_disconnected": dict(context.disconnected_fds),
        "elapsed": snapshot.captured_at - context.begun,
        "capture_monotonic": snapshot.captured_at,
        "capture_deadline_monotonic": context.begun + TIMEOUT,
        "reconnect_delay_ms": delay,
        "captured_access": list(snapshot.access),
        "captured_output": snapshot.output,
        "captured_log": snapshot.log,
        "captured_peer_error": snapshot.peer_error,
        "captured_fds": dict(snapshot.fds),
    }


class ScriptPeer(GetPeer):
    """One exact session with runner-acknowledged SCRIPT callback boundaries."""

    def __init__(
        self, check: bytes, record: bytes, case: str, ack_timeout: float = 2.0
    ):
        super().__init__(check, record, ack_timeout)
        self.case = case
        self.queued = threading.Event()
        self.send = [threading.Event(), threading.Event()]
        self.sent = [threading.Event(), threading.Event()]
        self.ack = [threading.Event(), threading.Event()]
        self.suffix = threading.Event()
        self.close = threading.Event()

    def gate(self, event: threading.Event, label: str) -> None:
        if not event.wait(self.ack_timeout):
            raise AssertionError(f"missing {label}")

    def script_vector(self, command: list[bytes] | None, slot: int) -> None:
        if command != [b"SCRIPT", b"LOAD", self.expected_scripts[slot]]:
            raise AssertionError("wrong SCRIPT vector/order/script")

    def get_vector(self, command: list[bytes] | None, reply: Reply) -> None:
        if command != [
            b"EVALSHA",
            digest(self.expected_scripts[0]),
            b"1",
            block_key(reply.identity),
        ]:
            raise AssertionError("wrong SCRIPT sentinel SHA/key/vector")

    def serve(self, stream) -> None:
        for slot in range(2):
            command = read_command(stream)
            self.script_vector(command, slot)
            self.history.append(command)
        self.notify(self.queued)
        reply = self.current
        if reply is None:
            raise AssertionError("missing prepared SCRIPT sentinel")
        command = read_command(stream)
        self.get_vector(command, reply)
        self.history.append(command)
        self.notify(reply.received)
        for slot, script in enumerate(self.expected_scripts):
            self.gate(self.send[slot], "SCRIPT release")
            if self.stopping.is_set():
                return
            is_error = (
                self.case in ("error-check", "error-split")
                and slot == 0
                or self.case == "error-record"
                and slot == 1
            )
            wire = ERROR if is_error else b"$40\r\n" + digest(script) + b"\r\n"
            if not is_error and len(wire) != 47:
                raise AssertionError("SCRIPT frozen whole frame length changed")
            if self.case == "error-split" and is_error:
                stream.write(wire[:-1])
                stream.flush()
                self.notify(self.sent[slot])
                self.gate(self.suffix, "error-prefix-consumed acknowledgement")
                if self.stopping.is_set():
                    return
                wire = wire[-1:]
            stream.write(wire)
            stream.flush()
            self.notify(self.sent[slot])
            self.gate(self.ack[slot], "SCRIPT callback acknowledgement")
            if is_error:
                self.gate(self.close, "SCRIPT disconnect acknowledgement")
                return
        stream.write(reply.wire)
        stream.flush()
        self.notify(reply.finished)
        super().serve(stream)

    def stop(self) -> None:
        self.stopping.set()
        for event in (*self.send, *self.ack, self.suffix, self.close):
            event.set()
        super().stop()


RECORD_FIELDS = (
    "gen",
    "id",
    "queued",
    "called",
    "outstanding",
    "nulls",
    "local",
    "type",
    "elements",
    "armed",
    "bans",
    "delta",
    "ready",
    "connected",
    "timer",
)
RECORD_STATE = re.compile(
    r"EA_RECORD state=(\w+) "
    + " ".join(
        rf"{name}=(-?\d+)" if name == "armed" else rf"{name}=(\d+)"
        for name in RECORD_FIELDS
    )
)


def record_states(log: str) -> list[dict]:
    return [
        {
            "where": match[1],
            **dict(zip(RECORD_FIELDS, map(int, match.groups()[1:]), strict=True)),
        }
        for match in RECORD_STATE.finditer(log)
    ]


def read_record_command(stream: io.BufferedIOBase) -> list[bytes] | None:
    """Decode exactly one bounded ten-element record EVALSHA command."""
    line = stream.readline(32)
    if not line:
        return None
    if line != b"*10\r\n":
        raise ValueError("malformed record RESP command array")
    command = []
    total = 0
    for _ in range(10):
        line = stream.readline(32)
        if not re.fullmatch(rb"\$(0|[1-9][0-9]{0,3})\r\n", line):
            raise ValueError("malformed record RESP command length")
        length = int(line[1:-2])
        total += length
        if length > 4096 or total > 16384:
            raise ValueError("record RESP command element too large")
        value = stream.read(length)
        if len(value) != length or stream.read(2) != b"\r\n":
            raise ValueError("truncated record RESP command")
        command.append(value)
    return command


def record_keys(identity: str) -> tuple[bytes, bytes]:
    block = block_key(identity)
    return block.rsplit(b":", 1)[0] + b":events", block


def integer_reply(*values: int) -> bytes:
    return f"*{len(values)}\r\n".encode() + b"".join(
        f":{value}\r\n".encode() for value in values
    )


@dataclasses.dataclass
class RecordReply:
    identity: str
    wire: bytes | None
    local: int
    delta: int
    elements: int
    request_id: str = ""
    split: int = 0
    after_idle: bool = False
    suffix: threading.Event = dataclasses.field(default_factory=threading.Event)
    armed: int = -1
    reply_type: int = 2
    reload: bool = False
    unexpected: bool = False
    received: threading.Event = dataclasses.field(default_factory=threading.Event)
    release: threading.Event = dataclasses.field(default_factory=threading.Event)
    sent: threading.Event = dataclasses.field(default_factory=threading.Event)
    reloaded: threading.Event = dataclasses.field(default_factory=threading.Event)
    finished: threading.Event = dataclasses.field(default_factory=threading.Event)


class RecordPeer(GetPeer):
    """One connection with strict record vectors and held callbacks."""

    def __init__(
        self, check: bytes, record: bytes, threshold: int, ack_timeout: float = 2.0
    ):
        super().__init__(check, record, ack_timeout)
        self.threshold = threshold
        self.primed = threading.Event()
        self.record_vectors: list[list[bytes]] = []
        self.nonce_prefix: bytes | None = None

    def record_vector(self, command: list[bytes] | None, reply: RecordReply) -> None:
        event_key, blocked_key = record_keys(reply.identity)
        if command is None or len(command) != 10:
            raise AssertionError("wrong RECORD vector arity")
        expected = [
            b"EVALSHA",
            digest(self.expected_scripts[1]),
            b"2",
            event_key,
            blocked_key,
            b"60000",
            str(self.threshold).encode(),
            b"60000",
            b"120000",
        ]
        if command[:9] != expected:
            raise AssertionError("wrong RECORD SHA/keys/units/vector")
        match = re.fullmatch(rb"([0-9]+):([1-9][0-9]*)", command[9])
        if match is None:
            raise AssertionError("wrong RECORD nonce format")
        if self.nonce_prefix is None:
            self.nonce_prefix = match[1]
        if match[1] != self.nonce_prefix:
            raise AssertionError("RECORD nonce worker prefix changed")
        if int(match[2]) != len(self.record_vectors) + 1:
            raise AssertionError("RECORD nonce unique ordered sequence")
        tag = b"{get:" + blocked_key.split(b"{get:", 1)[1].split(b"}", 1)[0] + b"}"
        if tag not in event_key or tag not in blocked_key:
            raise AssertionError("RECORD keys do not share exact hash tag")

    def serve(self, stream) -> None:
        for script in self.expected_scripts:
            command = read_command(stream)
            if command != [b"SCRIPT", b"LOAD", script]:
                raise AssertionError("wrong RECORD initial SCRIPT vector")
            self.history.append(command)
            stream.write(b"$40\r\n" + digest(script) + b"\r\n")
            stream.flush()
        self.notify(self.primed)

        while not self.stopping.is_set():
            command = read_record_command(stream)
            if command is None:
                if not self.stopping.is_set():
                    raise AssertionError("unexpected RECORD Redis EOF")
                return
            with self.condition:
                reply = self.current
            if not isinstance(reply, RecordReply) or reply.finished.is_set():
                raise AssertionError("unexpected RECORD without prepared reply")
            self.record_vector(command, reply)
            self.record_vectors.append(command)
            self.history.append(command)
            self.notify(reply.received)
            if not reply.release.wait(self.ack_timeout):
                raise AssertionError("missing RECORD callback release")
            if self.stopping.is_set():
                return
            if reply.wire is None:
                self.notify(reply.sent)
                self.notify(reply.finished)
                return
            if reply.split:
                record_reader_position(reply.wire, reply.split)
                stream.write(reply.wire[: reply.split])
                stream.flush()
                self.notify(reply.sent)
                if not reply.suffix.wait(self.ack_timeout):
                    raise AssertionError(
                        "missing RECORD prefix-consumed acknowledgement"
                    )
                if self.stopping.is_set():
                    return
                stream.write(reply.wire[reply.split :])
            else:
                stream.write(reply.wire)
            stream.flush()
            self.notify(reply.sent)
            if reply.reload:
                command = read_command(stream)
                expected = [b"SCRIPT", b"LOAD", self.expected_scripts[1]]
                if command != expected:
                    raise AssertionError("NOSCRIPT loaded other than record script")
                self.history.append(command)
                stream.write(b"$40\r\n" + digest(self.expected_scripts[1]) + b"\r\n")
                stream.flush()
                self.notify(reply.reloaded)
            self.notify(reply.finished)

    def stop(self) -> None:
        self.stopping.set()
        if isinstance(self.current, RecordReply):
            self.current.suffix.set()
        super().stop()


def record_reader_position(wire: bytes, split: int) -> tuple[int, int]:
    """Pinned hiredis integer-array decoder: type byte, then CRLF line.

    Do not derive consumed position from the observed reader. At an incomplete
    line hiredis has consumed its type byte, and leaves the line unconsumed.
    The array header uses task 0; integer children use task 1.
    """
    if not 0 < split < len(wire) or not re.fullmatch(
        rb"\*[234]\r\n(?::[0-9]+\r\n){2,4}", wire
    ):
        raise AssertionError("invalid RECORD frame/internal split")
    if int(wire[1:2]) != wire.count(b":"):
        raise AssertionError("invalid RECORD integer-array arity")
    offset = 0
    task = 0
    while offset < split:
        end = wire.index(b"\r\n", offset) + 2
        if end > split:
            return offset + 1, task
        offset = end
        task = 1
    return offset, task


def record_prefix_state(log: str, reply: RecordReply, identity: int) -> dict | None:
    """Require a fresh record-owned decoder epoch and exact consumed prefix."""
    if reply.wire is None:
        raise AssertionError("RECORD NULL has no prefix")
    position, task = record_reader_position(reply.wire, reply.split)
    readers = states(log)
    bases = [state for state in readers if state["where"] == "record_queue"]
    if len(bases) != 1:
        raise AssertionError("RECORD unique frame reader baseline")
    base = bases[0]
    if (
        base["length"] != base["pos"]
        or base["task"] != 0
        or base["pending"] != 1
        or base["tokens"] != 0
        or base["parked"] != 0
    ):
        raise AssertionError("RECORD previous frame not acknowledged complete")
    rows = record_states(log)
    if len(rows) != 1 or (
        rows[0]["where"],
        rows[0]["gen"],
        rows[0]["id"],
        rows[0]["queued"],
        rows[0]["called"],
        rows[0]["outstanding"],
        rows[0]["nulls"],
    ) != ("queue", 1, identity, identity, identity - 1, 1, 0):
        raise AssertionError("RECORD prefix must retain one pending callback")
    if events(log):
        raise AssertionError("RECORD prefix acquired request lifecycle")
    prefix = reply.wire[: reply.split]
    for state in readers:
        if (
            state["where"] == "read"
            and state["length"] - base["length"] == len(prefix)
            and state["pos"] - base["pos"] == position
            and state["task"] == task
            and state["pending"] == state["timer"] == 1
            and state["tokens"] == state["parked"] == 0
            and state["bytes"].endswith(prefix[-32:].hex())
        ):
            return {
                "base": base,
                "prefix": state,
                "frame_pos": position,
                "split": reply.split,
                "wire_hex": reply.wire.hex(),
            }
    return None


def record_split_frames() -> list[RecordReply]:
    """Frozen two/three/four-integer boundary frames and accounting owners."""
    maximum = 9_223_372_036_854_775_807
    return [
        RecordReply("two-unarmed", integer_reply(0, maximum), 0, 0, 2),
        RecordReply("two-local", integer_reply(1, maximum), 1, 1, 2),
        RecordReply("three-unarmed", integer_reply(0, maximum, maximum), 0, 0, 3),
        RecordReply("three-local", integer_reply(1, maximum, maximum), 1, 1, 3),
        RecordReply("four-unarmed", integer_reply(0, maximum, 0, 0), 0, 0, 4, armed=0),
        RecordReply(
            "four-remote", integer_reply(1, maximum, maximum, 1), 0, 1, 4, armed=1
        ),
        RecordReply(
            "four-local-zero", integer_reply(1, maximum, maximum, 0), 1, 0, 4, armed=0
        ),
        RecordReply(
            "four-local-one", integer_reply(1, maximum, maximum, 1), 1, 1, 4, armed=1
        ),
    ]


def test_record_splits(binary, module, root, port):
    root.mkdir(parents=True)
    census = []
    for frame in record_split_frames():
        assert frame.wire is not None
        for split in range(1, len(frame.wire)):
            selected = RecordReply(
                frame.identity,
                frame.wire,
                frame.local,
                frame.delta,
                frame.elements,
                armed=frame.armed,
                split=split,
            )
            case_root = root / f"{frame.identity}-{split}"
            test_record(binary, module, case_root, port, "splits", selected)
            census.append(
                {
                    "frame": frame.identity,
                    "split": split,
                    "wire_hex": frame.wire.hex(),
                    "root": str(case_root),
                }
            )
    (root / "split-census.json").write_text(json.dumps(census, indent=2) + "\n")
    print(f"OK: RECORD every internal split ({len(census)} cases)", flush=True)


def assert_record_callback(log: str, reply: RecordReply, identity: int) -> dict:
    rows = record_states(log)
    queues = [row for row in rows if row["where"] == "queue" and row["id"] == identity]
    callbacks = [
        row for row in rows if row["where"] == "callback" and row["id"] == identity
    ]
    if len(queues) != 1 or len(callbacks) != 1:
        raise AssertionError("RECORD unique queue/callback identity")
    queue = queues[0]
    callback = callbacks[0]
    if (
        queue["gen"] != 1
        or callback["gen"] != 1
        or (queue["queued"], queue["called"], queue["outstanding"])
        != (identity, identity - 1, 1)
        or (callback["queued"], callback["called"], callback["outstanding"])
        != (identity, identity, 0)
    ):
        raise AssertionError("RECORD FIFO generation/settlement")
    if queue["local"] != reply.local or callback["local"] != reply.local:
        raise AssertionError("RECORD local-armed callback wrapper")
    if callback["delta"] != reply.delta:
        if reply.armed == 1:
            raise AssertionError("RECORD armed_now ban-counter effect")
        raise AssertionError("RECORD exact ban-counter effect")
    expected_nulls = 1 if reply.wire is None else 0
    if callback["nulls"] != expected_nulls:
        raise AssertionError("RECORD NULL callback settlement")
    if (
        callback["type"] != reply.reply_type
        or callback["elements"] != reply.elements
        or callback["armed"] != reply.armed
    ):
        raise AssertionError("RECORD reply shape observer")
    return callback


def clean_logs(log: str, error: bool) -> None:
    expected = [
        r"error_abuse: Redis handshake \(AUTH/SELECT\) failed \(type=6, detail_len=18\); disconnecting$",
        r'error_abuse: Redis check failed \(consecutive=1\), client: 127\.0\.0\.1, server: , request: "GET /get\.gif\?client=script-sentinel HTTP/1\.0", host: "localhost"$',
    ]
    matched = [0, 0]
    for line in log.splitlines():
        if re.search(
            r"AddressSanitizer|runtime error:|LeakSanitizer|\[(?:emerg|alert|crit|error|warn)\]",
            line,
        ):
            for index, pattern in enumerate(expected):
                if error and re.search(pattern, line):
                    matched[index] += 1
                    break
            else:
                raise AssertionError(f"unexpected SCRIPT error log: {line}")
    if error and matched != [1, 1]:
        raise AssertionError(f"SCRIPT expected error log counts: {matched}")


def test_script(
    binary: pathlib.Path, module: pathlib.Path, root: pathlib.Path, port: int, case: str
) -> None:
    check, record = scripts(
        pathlib.Path(__file__).resolve().parents[2]
        / "src/ngx_http_error_abuse_module.c"
    )
    peer = ScriptPeer(check, record, case)
    sentinel = Reply("script-sentinel", b"$-1\r\n")
    peer.prepare(sentinel)
    peer.start()
    nginx = Nginx(binary, module, root, port, "", False, peer.port)
    client = None
    error_case = case != "whole"
    error_slot = 2 if case == "error-record" else 1
    records = []
    try:
        (root / "conf").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "conf/nginx.conf").write_text(
            f"""load_module {module};
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log debug;
events {{ worker_connections 64; }}
http {{
    log_format protocol '$arg_client $status';
    access_log {root}/access.log protocol;
    error_abuse_redis host=127.0.0.1 port={peer.port} prefix=ea02-get: timeout=1s;
    error_abuse_zone zone=get:1m key=$arg_client statuses=404 interval=60s threshold=10 block=60s redis=on;
    server {{
        listen 127.0.0.1:{port};
        location = /get.gif {{ error_abuse zone=get; empty_gif; }}
        location = /health.gif {{ empty_gif; }}
    }}
}}
""",
            encoding="ascii",
        )
        error_path = root / "logs/error.log"
        access_path = root / "access.log"

        def log():
            return error_path.read_text(encoding="ascii", errors="replace")

        begun = time.monotonic()
        with mock.patch.object(nginx, "write_config"):
            nginx.start()
        peer.wait(peer.queued, "two SCRIPT commands")
        fetch(port, "/health.gif")
        assert nginx.process is not None
        children = (
            pathlib.Path(f"/proc/{nginx.process.pid}/task/{nginx.process.pid}/children")
            .read_text()
            .split()
        )
        if len(children) != 1:
            raise AssertionError("SCRIPT fixture requires exactly one normal worker")
        proc = pathlib.Path(f"/proc/{children[0]}")
        baseline = wait_until(
            lambda: worker_fds(proc, port), "SCRIPT warmup socket did not close", peer
        )
        redis_inodes = set()
        for line in (proc / "net/tcp").read_text().splitlines()[1:]:
            fields = line.split()
            if int(fields[2].split(":")[1], 16) == peer.port:
                redis_inodes.add(f"socket:[{fields[9]}]")
        redis_fds = [fd for fd, value in baseline.items() if value in redis_inodes]
        if len(redis_fds) != 1:
            raise AssertionError("SCRIPT connected Redis fd identity")
        disconnected = {
            fd: value for fd, value in baseline.items() if fd not in redis_fds
        }

        def request(reply):
            connection = socket.create_connection(("127.0.0.1", port), timeout=2)
            connection.sendall(
                f"GET /get.gif?client={reply.identity} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode(
                    "ascii"
                )
            )
            peer.wait(reply.received, "sentinel GET command")
            return connection

        def complete(connection, reply, offset, expected_fds, capture_only=False):
            response = b""
            while chunk := connection.recv(65536):
                response += chunk
            connection.close()
            if capture_only:
                return response
            assert_completion(log()[offset:])
            if (
                response.split(b" ", 2)[1:2] != [b"200"]
                or response.count(b"HTTP/1.") != 1
            ):
                raise AssertionError("SCRIPT GET exactly-once HTTP 200")
            wait_until(
                lambda reply=reply: (
                    access_path.exists()
                    and f"{reply.identity} 200\n" in access_path.read_text()
                ),
                "SCRIPT GET access completion",
                peer,
            )
            assert_one_completion(
                access_path.read_text().splitlines(), reply.identity, "200"
            )
            wait_until(
                lambda: worker_fds(proc, port) == expected_fds,
                "SCRIPT worker fd drift",
                peer,
            )
            records.append(
                {
                    "identity": reply.identity,
                    "events": events(log()[offset:]),
                    "response_hex": response.hex(),
                }
            )
            return None

        offset = len(log())
        client = request(sentinel)
        if [kind for kind, _ in events(log()[offset:])] != ["park"] or select.select(
            [client], [], [], 0
        )[0]:
            raise AssertionError("SCRIPT pending sentinel completed early")
        parked = states(log())[-1]
        if (parked["pending"], parked["tokens"], parked["parked"]) != (1, 1, 1):
            raise AssertionError("SCRIPT sentinel pending token/park state")
        initial = script_states(log())[-1]
        if (initial["queued"], initial["called"], initial["outstanding"]) != (2, 0, 2):
            raise AssertionError("SCRIPT sentinel not behind both commands")
        for slot in range(2):
            peer.send[slot].set()
            peer.wait(peer.sent[slot], "SCRIPT reply write")
            if case == "error-split" and slot == 0:
                wait_until(
                    lambda: any(
                        s["where"] == "read"
                        and s["task"] >= 0
                        and s["pending"] == s["tokens"] == s["parked"] == 1
                        and s["bytes"] == ERROR[:-1].hex()
                        for s in states(log())
                    ),
                    "SCRIPT error delimiter prefix not consumed",
                    peer,
                    TIMEOUT * 0.6,
                )
                if (
                    any(r["where"] == "callback" for r in script_states(log()))
                    or select.select([client], [], [], 0)[0]
                ):
                    raise AssertionError(
                        "SCRIPT error delimiter prefix completed callback/HTTP"
                    )
                peer.suffix.set()
            wait_until(
                lambda slot=slot: any(
                    r["where"] == "post" and r["slot"] == slot + 1
                    for r in script_states(log())
                ),
                "SCRIPT callback post witness missing",
                peer,
                TIMEOUT * 0.6,
            )
            if error_case and slot + 1 == error_slot:
                assert_error_post(log(), error_slot)
                if time.monotonic() >= begun + TIMEOUT:
                    raise AssertionError("SCRIPT error branch missed command deadline")
                peer.ack[slot].set()
                peer.close.set()
                break
            peer.ack[slot].set()
        response = complete(client, sentinel, offset, baseline, capture_only=error_case)
        client = None
        if error_case:
            wait_until(
                lambda: any(r["where"] == "drained" for r in script_states(log())),
                "SCRIPT adapter cleanup missing",
                peer,
            )
            wait_until(
                lambda: worker_fds(proc, port) == disconnected,
                "SCRIPT worker fd drift",
                peer,
            )
            wait_until(
                lambda: (
                    access_path.exists()
                    and f"{sentinel.identity} 200\n" in access_path.read_text()
                ),
                "SCRIPT GET access completion",
                peer,
            )

            def read_error_live():
                captured_log = log()
                captured_output = nginx.output_path.read_text()
                captured_access = access_path.read_text().splitlines()
                with peer.condition:
                    sessions = peer.sessions
                    vectors = tuple(tuple(vector) for vector in peer.history)
                    peer_error = None if peer.error is None else repr(peer.error)
                return {
                    "log": captured_log,
                    "output": captured_output,
                    "access": captured_access,
                    "response": response,
                    "sessions": sessions,
                    "vectors": vectors,
                    "peer_error": peer_error,
                    "fds": worker_fds(proc, port),
                }

            context = ErrorContext(
                begun,
                offset,
                sentinel.identity,
                (check, record),
                tuple(sorted(disconnected.items())),
                error_slot,
                children[0],
            )
            snapshot = capture_error_snapshot(context, read_error_live)
            evidence = error_snapshot_evidence(snapshot)
            evidence["fd_connected"] = baseline
        else:

            def reuse(identity):
                reply = Reply(identity, b"$-1\r\n")
                peer.prepare(reply)
                mark = len(log())
                connection = request(reply)
                complete(connection, reply, mark, baseline)

            reuse("script-before")
            if time.monotonic() >= begun + TIMEOUT:
                raise AssertionError("SCRIPT reuse missed original deadline")

            def idle():
                rows = script_states(log())
                get = states(log())
                return (
                    rows
                    and get
                    and rows[-1]["where"] == "timeout"
                    and not any(
                        get[-1][k] for k in ("pending", "tokens", "parked", "timer")
                    )
                    and rows[-1]
                )

            final = wait_until(idle, "SCRIPT adapter idle timer did not settle", peer)
            if time.monotonic() < begun + TIMEOUT:
                raise AssertionError("SCRIPT idle timer preceded original deadline")
            assert_resources(final, True)
            reuse("script-after")
            wait_until(idle, "SCRIPT reuse timer did not settle", peer)
            assert_resources(script_states(log())[-1], True)
            expected = [(1, 1, digest(check)), (2, 1, digest(record))]
            if re.findall(r"EA_SCRIPT get_kind=(\d+)", log()) != ["4", "4", "4"]:
                raise AssertionError("SCRIPT GET reuse missing exact NIL callbacks")
            if len({row["events"][0][1] for row in records}) != 3:
                raise AssertionError("SCRIPT GET reused request identity")
            assert_ledger(log(), expected)
            if peer.sessions != 1 or len(peer.history) != 5:
                raise AssertionError("SCRIPT unexpected session/command history")
            peer.check()
            clean_logs(log() + nginx.output_path.read_text(), False)
            evidence = {
                "sessions": peer.sessions,
                "worker": children[0],
                "vectors_hex": [[v.hex() for v in c] for c in peer.history],
                "scripts_sha1": [digest(check).decode(), digest(record).decode()],
                "script_states": script_states(log()),
                "get_states": states(log()),
                "get_cases": records,
                "fd_connected": baseline,
                "fd_disconnected": disconnected,
                "elapsed": time.monotonic() - begun,
            }
        evidence["case"] = case
        (root / "script-evidence.json").write_text(
            json.dumps(evidence, indent=2) + "\n"
        )
    finally:
        if client is not None:
            client.close()
        try:
            nginx.stop()
        finally:
            peer.stop()
    if not error_case:
        clean_logs(log() + nginx.output_path.read_text(), False)
    print(f"OK: SCRIPT {case}", flush=True)


def raw_reply(*atoms: bytes) -> bytes:
    return f"*{len(atoms)}\r\n".encode() + b"".join(atoms)


def record_scenario(case: str) -> tuple[int, list[RecordReply], int, int]:
    deadline = 2_000_000_000
    if case == "whole":
        replies = [
            RecordReply("whole-a", integer_reply(0, 1, 0, 0), 0, 0, 4, armed=0),
            RecordReply("whole-b", integer_reply(1, 1, deadline, 1), 0, 1, 4, armed=1),
            RecordReply("whole-a", integer_reply(1, 2, deadline, 0), 1, 0, 4, armed=0),
            RecordReply("whole-b", integer_reply(1, 2, deadline, 1), 1, 1, 4, armed=1),
            RecordReply("legacy-two", integer_reply(0, 1), 0, 0, 2),
            RecordReply("legacy-two", integer_reply(1, 2), 1, 1, 2),
            RecordReply("legacy-three", integer_reply(0, 1, 0), 0, 0, 3),
            RecordReply("legacy-three", integer_reply(1, 2, deadline), 1, 1, 3),
        ]
        return 2, replies, 0, 0
    if case == "noscript":
        return (
            1,
            [
                RecordReply(
                    "noscript-lost",
                    b"-NOSCRIPT record fixture\r\n",
                    1,
                    1,
                    0,
                    reply_type=6,
                    reload=True,
                ),
                RecordReply(
                    "noscript-recovered",
                    integer_reply(1, 1, deadline, 1),
                    1,
                    1,
                    4,
                    armed=1,
                ),
            ],
            0,
            1,
        )
    if case == "null":
        return (
            1,
            [RecordReply("null-settlement", None, 1, 1, 0, reply_type=0)],
            0,
            0,
        )
    if case != "errors":
        raise AssertionError(f"unknown RECORD case: {case}")

    def integer(value: int) -> bytes:
        return f":{value}\r\n".encode()

    malformed = [
        (raw_reply(integer(0)), 1, -1),
        (raw_reply(*(integer(value) for value in (0, 1, 0, 0, 0))), 5, -1),
        (raw_reply(b"$1\r\nx\r\n", integer(1), integer(0), integer(0)), 4, 0),
        (raw_reply(integer(0), b"$1\r\nx\r\n", integer(0), integer(0)), 4, 0),
        (integer_reply(-1, 1, 0, 0), 4, 0),
        (integer_reply(0, -1, 0, 0), 4, 0),
        (integer_reply(0, 1, -1, 0), 4, 0),
        (integer_reply(1, 1, 0, -1), 4, -1),
        (integer_reply(1, 1, 0, 2), 4, 2),
        (integer_reply(0, 1, 0, 1), 4, 1),
    ]
    replies = []
    for index, (wire, elements, armed) in enumerate(malformed, 1):
        replies.append(
            RecordReply(
                f"malformed-{index}",
                wire,
                1,
                1,
                elements,
                armed=armed,
                unexpected=True,
            )
        )
        replies.append(
            RecordReply(
                f"error-reset-{index}",
                integer_reply(0, 1, 0, 0),
                1,
                0,
                4,
                armed=0,
            )
        )
    return 1, replies, len(malformed), 0


def record_fd_baseline(proc: pathlib.Path, port: int) -> dict[str, str] | None:
    """Reject an HTTP fd closed between descriptor and TCP-table snapshots."""
    first = worker_fds(proc, port)
    if first is not None and first == worker_fds(proc, port):
        return first
    return None


def record_stats(port: int) -> dict[str, int]:
    status, _, body = http_call(port, "/stats")
    if status != 200:
        raise AssertionError(f"RECORD stats endpoint returned {status}")
    return json.loads(body)


def clean_record_logs(log: str, unexpected: int, noscript: int) -> None:
    counts = {"unexpected": 0, "noscript": 0}
    for line in log.splitlines():
        if re.search(r"AddressSanitizer|runtime error:|LeakSanitizer", line):
            raise AssertionError(f"unexpected RECORD sanitizer log: {line}")
        if not re.search(r"\[(?:emerg|alert|crit|error|warn)\]", line):
            continue
        if "Redis EVAL returned unexpected reply" in line:
            counts["unexpected"] += 1
        elif "Redis script cache miss (NOSCRIPT); reloading record script" in line:
            counts["noscript"] += 1
        else:
            raise AssertionError(f"unexpected RECORD error log: {line}")
    if counts != {"unexpected": unexpected, "noscript": noscript}:
        raise AssertionError(f"RECORD expected error log counts: {counts}")


def test_record(
    binary: pathlib.Path,
    module: pathlib.Path,
    root: pathlib.Path,
    port: int,
    case: str,
    selected: RecordReply | None = None,
) -> None:
    check, record = scripts(
        pathlib.Path(__file__).resolve().parents[2]
        / "src/ngx_http_error_abuse_module.c"
    )
    if selected is None:
        threshold, replies, unexpected_logs, noscript_logs = record_scenario(case)
    else:
        threshold, unexpected_logs, noscript_logs = 2, 0, 0
        replies = []
        if selected.local:
            replies.append(
                RecordReply(
                    selected.identity, integer_reply(0, 1, 0, 0), 0, 0, 4, armed=0
                )
            )
        replies.extend(
            [
                selected,
                RecordReply(
                    "reuse-before", integer_reply(0, 1, 0, 0), 0, 0, 4, armed=0
                ),
                RecordReply(
                    "reuse-after",
                    integer_reply(0, 1, 0, 0),
                    0,
                    0,
                    4,
                    armed=0,
                    after_idle=True,
                ),
            ]
        )
    for identity, reply in enumerate(replies, 1):
        reply.request_id = f"record-{identity}"
    peer = RecordPeer(check, record, threshold)
    peer.start()
    nginx = Nginx(binary, module, root, port, "", False, peer.port)
    try:
        (root / "conf").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "conf/nginx.conf").write_text(
            f"""load_module {module};
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log debug;
events {{ worker_connections 64; }}
http {{
    log_format protocol '$arg_request $status';
    access_log {root}/access.log protocol;
    error_abuse_redis host=127.0.0.1 port={peer.port} prefix=ea02-get: timeout=1s;
    error_abuse_zone zone=get:1m key=$arg_client statuses=404 interval=60s
        threshold={threshold} block=60s inactive=120s redis=on;
    server {{
        listen 127.0.0.1:{port};
        location = /record.gif {{ error_abuse zone=get; return 404; }}
        location = /health.gif {{ empty_gif; }}
        location = /stats {{ error_abuse_stats get; }}
    }}
}}
""",
            encoding="ascii",
        )
        error_path = root / "logs/error.log"
        access_path = root / "access.log"

        def log():
            return error_path.read_text(encoding="ascii", errors="replace")

        with mock.patch.object(nginx, "write_config"):
            nginx.start()
        peer.wait(peer.primed, "initial RECORD SCRIPT LOAD pair")
        fetch(port, "/health.gif")
        wait_until(
            lambda: any(
                row["where"] == "post" and row["slot"] == 2
                for row in script_states(log())
            ),
            "RECORD initial SCRIPT callbacks not acknowledged",
            peer,
        )
        assert nginx.process is not None
        children = (
            pathlib.Path(f"/proc/{nginx.process.pid}/task/{nginx.process.pid}/children")
            .read_text(encoding="ascii")
            .split()
        )
        if len(children) != 1:
            raise AssertionError("RECORD fixture requires exactly one normal worker")
        proc = pathlib.Path(f"/proc/{children[0]}")
        baseline = wait_until(
            lambda: record_fd_baseline(proc, port),
            "RECORD warmup socket did not close",
            peer,
        )
        redis_inodes = set()
        for line in (proc / "net/tcp").read_text().splitlines()[1:]:
            fields = line.split()
            if int(fields[2].split(":")[1], 16) == peer.port:
                redis_inodes.add(f"socket:[{fields[9]}]")
        redis_fds = [fd for fd, value in baseline.items() if value in redis_inodes]
        if len(redis_fds) != 1:
            raise AssertionError("RECORD connected Redis fd identity")
        disconnected = {
            fd: value for fd, value in baseline.items() if fd not in redis_fds
        }

        def idle():
            script = script_states(log())
            get = states(log())
            return (
                script
                and get
                and script[-1]["where"] == "timeout"
                and not any(
                    get[-1][key] for key in ("pending", "tokens", "parked", "timer")
                )
                and script[-1]
            )

        evidence_rows = []
        for identity, reply in enumerate(replies, 1):
            if reply.after_idle:
                final = wait_until(
                    idle, "RECORD pre-reuse idle timer did not settle", peer
                )
                assert_resources(final, True)
                assert_fds(worker_fds(proc, port), baseline)
            peer.prepare(reply)
            before = record_stats(port)
            offset = len(log())
            status, _ = fetch(
                port,
                f"/record.gif?client={reply.identity}&request={reply.request_id}",
            )
            if status != 404:
                raise AssertionError(f"RECORD counted response status: {status}")
            peer.wait(reply.received, "ten-element RECORD EVALSHA")
            wait_until(
                lambda reply=reply: (
                    access_path.exists()
                    and f"{reply.request_id} 404\n" in access_path.read_text()
                ),
                "RECORD HTTP completion before callback",
                peer,
            )
            assert_one_completion(
                access_path.read_text().splitlines(), reply.request_id, "404"
            )
            wait_until(
                lambda: worker_fds(proc, port) == baseline,
                "RECORD worker fd drift before callback",
                peer,
            )
            rows = record_states(log())
            if not any(
                row["where"] == "queue" and row["id"] == identity for row in rows
            ):
                raise AssertionError("RECORD queue observer missing")
            if any(
                row["where"] == "callback" and row["id"] == identity for row in rows
            ):
                raise AssertionError("RECORD callback preceded HTTP completion")
            if events(log()[offset:]):
                raise AssertionError("RECORD callback acquired request lifecycle")

            reply.release.set()
            peer.wait(reply.sent, "RECORD reply release")
            prefix = None
            if reply.split:
                prefix = wait_until(
                    lambda offset=offset, reply=reply, identity=identity: (
                        record_prefix_state(log()[offset:], reply, identity)
                    ),
                    "RECORD exact frame-relative prefix not consumed",
                    peer,
                    TIMEOUT * 0.6,
                )
                assert_fds(worker_fds(proc, port), baseline)
                if record_stats(port)["bans"] != before["bans"]:
                    raise AssertionError("RECORD prefix changed ban counter")
                assert_one_completion(
                    access_path.read_text().splitlines(), reply.request_id, "404"
                )
                reply.suffix.set()
            wait_until(
                lambda identity=identity: any(
                    row["where"] == "callback" and row["id"] == identity
                    for row in record_states(log())
                ),
                "RECORD callback observer missing",
                peer,
            )
            callback = assert_record_callback(log(), reply, identity)
            if prefix is not None:

                def consumed_frame(prefix=prefix, offset=offset, reply=reply):
                    base = prefix["base"]
                    return next(
                        (
                            state
                            for state in states(log()[offset:])
                            if state["where"] == "read"
                            and state["length"] - base["length"] == len(reply.wire)
                            and state["pos"] == state["length"]
                            and state["task"] == 0
                            and state["pending"] == 0
                            and state["tokens"] == state["parked"] == 0
                        ),
                        None,
                    )

                prefix["complete"] = wait_until(
                    consumed_frame, "RECORD suffix not consumed", peer
                )
            if events(log()[offset:]):
                raise AssertionError("RECORD callback resumed or finalized request")
            peer.wait(reply.finished, "RECORD callback/reload settlement")
            if reply.reload:
                peer.wait(reply.reloaded, "record-only NOSCRIPT reload")
            assert_one_completion(
                access_path.read_text().splitlines(), reply.request_id, "404"
            )
            wait_until(
                lambda reply=reply: (
                    worker_fds(proc, port) == baseline
                    if reply.wire is not None
                    else worker_fds(proc, port) == disconnected
                ),
                "RECORD worker fd drift after callback",
                peer,
            )
            after = record_stats(port)
            if after["bans"] - before["bans"] != reply.delta:
                if reply.armed == 1:
                    raise AssertionError("RECORD armed_now ban-counter effect")
                raise AssertionError("RECORD exact ban-counter effect")
            evidence_rows.append(
                {
                    "identity": reply.identity,
                    "request": reply.request_id,
                    "local": reply.local,
                    "delta": reply.delta,
                    "callback": callback,
                    "prefix": prefix,
                    "after_idle": reply.after_idle,
                    "vector_hex": [value.hex() for value in peer.record_vectors[-1]],
                }
            )

        if case == "null":
            wait_until(
                lambda: worker_fds(proc, port) == disconnected,
                "RECORD NULL fd settlement",
                peer,
            )
            final = wait_until(
                lambda: next(
                    (
                        row
                        for row in reversed(script_states(log()))
                        if row["where"] == "drained"
                    ),
                    None,
                ),
                "RECORD NULL adapter drain",
                peer,
            )
            assert_resources(final, False)
        else:
            final = wait_until(idle, "RECORD idle timer did not settle", peer)
            assert_resources(final, True)
            wait_until(
                lambda: worker_fds(proc, port) == baseline,
                "RECORD final worker fd drift",
                peer,
            )
        if peer.sessions != 1:
            raise AssertionError("RECORD same-session reuse")
        if len(peer.record_vectors) != len(replies):
            raise AssertionError("RECORD exact FIFO command count")
        expected_history = 2 + len(replies) + sum(reply.reload for reply in replies)
        if len(peer.history) != expected_history:
            raise AssertionError("RECORD lost-event no-replay history")
        peer.check()
        combined_log = log() + nginx.output_path.read_text()
        clean_record_logs(combined_log, unexpected_logs, noscript_logs)
        evidence = {
            "case": case,
            "sessions": peer.sessions,
            "worker": children[0],
            "history_hex": [[value.hex() for value in row] for row in peer.history],
            "record_states": record_states(log()),
            "get_states": states(log()),
            "rows": evidence_rows,
            "fd_connected": baseline,
            "fd_disconnected": disconnected,
        }
        (root / "record-evidence.json").write_text(
            json.dumps(evidence, indent=2) + "\n"
        )
    finally:
        try:
            nginx.stop()
        finally:
            peer.stop()
    clean_record_logs(
        log() + nginx.output_path.read_text(), unexpected_logs, noscript_logs
    )
    print(f"OK: RECORD {case}", flush=True)


@dataclasses.dataclass
class CoalescedFrame:
    kind: str
    identity: str
    wire: bytes
    status: int = 200
    delta: int = 0


@dataclasses.dataclass
class CoalescedBatch:
    frames: list[CoalescedFrame]
    split: int = 0
    queued: threading.Event = dataclasses.field(default_factory=threading.Event)
    release: threading.Event = dataclasses.field(default_factory=threading.Event)
    sent: threading.Event = dataclasses.field(default_factory=threading.Event)
    suffix: threading.Event = dataclasses.field(default_factory=threading.Event)
    ack: threading.Event = dataclasses.field(default_factory=threading.Event)


class CoalescedPeer(RecordPeer):
    """Read every exact vector before one write, then require live settlement ack."""

    def __init__(self, check, record, batches, ack_timeout=2.0):
        super().__init__(check, record, 10, ack_timeout)
        self.batches = batches

    def gate(self, event, label):
        if not event.wait(self.ack_timeout):
            raise AssertionError(f"missing COALESCE {label} acknowledgement")

    def serve(self, stream):
        for batch in self.batches:
            if (
                not batch.frames
                or batch.split
                and not 0 < batch.split < len(batch.frames[-1].wire)
            ):
                raise AssertionError("invalid COALESCE batch/split")
            for frame in batch.frames:
                if frame.kind == "record":
                    command = read_record_command(stream)
                    reply = RecordReply(frame.identity, frame.wire, 0, frame.delta, 4)
                    self.record_vector(command, reply)
                    self.record_vectors.append(command)
                else:
                    command = read_command(stream)
                    if frame.kind == "script":
                        expected = [
                            b"SCRIPT",
                            b"LOAD",
                            self.expected_scripts[int(frame.identity)],
                        ]
                    else:
                        expected = [
                            b"EVALSHA",
                            digest(self.expected_scripts[0]),
                            b"1",
                            block_key(frame.identity),
                        ]
                    if command != expected:
                        raise AssertionError("wrong COALESCE exact vector/FIFO")
                self.history.append(command)
                with self.condition:
                    self.condition.notify_all()
            self.notify(batch.queued)
            self.gate(batch.release, "release")
            if self.stopping.is_set():
                return
            wire = b"".join(frame.wire for frame in batch.frames)
            if batch.split:
                cut = len(wire) - len(batch.frames[-1].wire) + batch.split
                stream.write(wire[:cut])
                stream.flush()
                self.notify(batch.sent)
                self.gate(batch.suffix, "prefix-consumed")
                if self.stopping.is_set():
                    return
                stream.write(wire[cut:])
                stream.flush()
            else:
                stream.write(wire)
                stream.flush()
                self.notify(batch.sent)
            self.gate(batch.ack, "settlement")
            if self.stopping.is_set():
                return
        # Keep the original connection alive for the adapter's idle timer.
        if stream.read(1) and not self.stopping.is_set():
            raise AssertionError("unexpected COALESCE extra command")

    def stop(self):
        self.stopping.set()
        for batch in self.batches:
            for event in (batch.release, batch.suffix, batch.ack):
                event.set()
        super().stop()


def coalesced_callbacks(log):
    """One unified ordered ledger, including native reply type and failure state."""
    rows = []
    pattern = re.compile(
        r"EA_SCRIPT state=callback gen=\d+ slot=(\d+).*? kind=(\d+)"
        r"|EA_COALESCE (get|record) id=(\d+) kind=(\d+) failures=(\d+)"
    )
    for match in pattern.finditer(log):
        if match[1] is not None:
            rows.append(("script", match[1], int(match[2]), 0))
        else:
            rows.append((match[3], match[4], int(match[5]), int(match[6])))
    return rows


def coalesced_drain(log, expected, require_partial=False):
    """Require the complete ordered callbacks inside one actual read handler."""
    for match in re.finditer(
        r"EA_DRAIN begin id=(\d+) fd=(\d+) command=(\S+) timer=([01]) due=(\d+) reconnect=(\S+) retry=([01])",
        log,
    ):
        end = re.search(
            rf"EA_DRAIN end id={match[1]} fd=-1 command=(\S+) timer=([01]) due=(\d+) reconnect=(\S+) retry=([01])",
            log[match.end() :],
        )
        if end is None:
            continue
        body = log[match.end() : match.end() + end.start()]
        if "EA_DRAIN begin" in body or coalesced_callbacks(body) != expected:
            continue
        begin_timer, begin_due = int(match[4]), int(match[5])
        end_timer, end_due = int(end[2]), int(end[3])
        if (
            (match[3], match[6]) != (end[1], end[4])
            or begin_timer != end_timer
            or begin_due > end_due
            or match[7] != end[5]
            or end[5] != "0"
        ):
            raise AssertionError("COALESCE drain timer/due transition drift")
        readers = [row for row in states(body) if row["where"] == "read"]
        if not readers:
            raise AssertionError("COALESCE missing post-hiredis drain witness")
        # Each post-hiredis snapshot ends one redisAsyncHandleRead/recv call.
        # A callback-only handler witness cannot prove a native read boundary.
        iterations = []
        start = 0
        for reader in re.finditer(r"EA_GET state=read[^\n]*", body):
            iterations.append(coalesced_callbacks(body[start : reader.start()]))
            start = reader.end()
        if coalesced_callbacks(body[start:]):
            continue
        if require_partial:
            if (
                len(readers) < 2
                or iterations[0]
                or readers[0]["length"] <= readers[0]["pos"]
                or readers[0]["pending"] != 1
                or expected not in iterations[1:]
            ):
                continue
        elif expected not in iterations:
            continue
        return {
            "id": int(match[1]),
            "fd": int(match[2]),
            "command": match[3],
            "begin_timer": begin_timer,
            "begin_due": begin_due,
            "timer": end_timer,
            "due": end_due,
            "reconnect": match[6],
            "readers": readers,
        }
    return None


def coalesced_final_idle(log, drain_id):
    """Return paired GET/SCRIPT timeout state after the final drain only."""
    marker = re.search(rf"EA_DRAIN end id={drain_id} fd=-1 .*", log)
    if marker is None:
        return None
    tail = log[marker.end() :]
    # Snapshot emits GET then SCRIPT in the same timeout callback. Pair before
    # filtering, so a stale latest GET cannot borrow an earlier clean state.
    latest = None
    pending = None
    for line in tail.splitlines():
        if "EA_GET state=timeout " in line:
            pending = states(line)[0]
        elif "EA_SCRIPT state=timeout " in line and pending is not None:
            latest = {"get": pending, "script": script_states(line)[0]}
            pending = None
    if (
        latest is None
        or pending is not None
        or any(latest["get"][key] for key in ("pending", "tokens", "parked", "timer"))
    ):
        return None
    return latest


def coalesced_drain_order(previous, current):
    if previous is not None and current <= previous:
        raise AssertionError("COALESCE drain IDs must increase strictly")
    return current


def coalesced_receive_queue(proc, inode, expected):
    """Observe the full batch on the exact worker-owned Redis socket."""
    for line in (proc / "net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if f"socket:[{fields[9]}]" == inode and fields[3] == "01":
            queued = int(fields[4].split(":")[1], 16)
            if queued > expected:
                raise AssertionError("COALESCE unexpected receive queue bytes")
            if queued == expected:
                return {"inode": inode, "queued": queued}
    return None


def coalesced_release(proc, inode, batch, peer):
    """Hold the owned worker until TCP has delivered the whole unsplit batch."""
    pid = int(proc.name)
    if not 1 < pid <= 2147483647:
        raise AssertionError("COALESCE invalid owned worker PID")
    os.kill(pid, signal.SIGSTOP)
    try:
        wait_until(
            lambda: re.search(
                r"^State:\s+T", (proc / "status").read_text(), re.MULTILINE
            ),
            "COALESCE worker did not stop",
            peer,
            0.6,
        )
        batch.release.set()
        peer.wait(batch.sent, "COALESCE one write")
        return wait_until(
            lambda: coalesced_receive_queue(
                proc, inode, sum(len(frame.wire) for frame in batch.frames)
            ),
            "COALESCE full receive queue missing",
            peer,
            0.6,
        )
    finally:
        os.kill(pid, signal.SIGCONT)


def coalesced_fds(actual, baseline, pending):
    if actual is None or any(actual.get(fd) != value for fd, value in baseline.items()):
        return False
    extra = {fd: value for fd, value in actual.items() if fd not in baseline}
    return len(extra) == pending and all(
        value.startswith("socket:[") for value in extra.values()
    )


def coalesced_position(wire, split):
    if not 0 < split < len(wire):
        raise AssertionError("invalid COALESCE internal prefix")
    if wire.startswith(b"*"):
        return record_reader_position(wire, split)
    if wire.startswith(b"$"):
        # hiredis processBulkItem commits its line only with the entire payload.
        return 1, 0
    if wire.startswith(b"-"):
        return 1, 0
    raise AssertionError("unsupported COALESCE prefix frame")


def coalesced_prefix(log, base, first, last, split, expected, remaining_gets):
    if coalesced_callbacks(log) != expected:
        raise AssertionError("COALESCE prefix callback ownership/count")
    position, task = coalesced_position(last, split)
    prefix = first + last[:split]
    for row in states(log):
        if row["where"] == "read" and (
            row["length"] - base["length"],
            row["pos"] - base["pos"],
            row["task"],
            row["pending"],
            row["tokens"],
            row["parked"],
            row["timer"],
            row["bytes"],
        ) == (
            len(prefix),
            len(first) + position,
            task,
            1,
            remaining_gets,
            remaining_gets,
            1,
            (bytes.fromhex(base["bytes"]) + prefix)[-32:].hex(),
        ):
            return row
    return None


def coalesced_scenarios(check, record, case, split=0):
    script = CoalescedBatch(
        [
            CoalescedFrame("script", str(i), b"$40\r\n" + digest(s) + b"\r\n")
            for i, s in enumerate((check, record))
        ],
        split,
    )
    nil = b"$-1\r\n"
    deadline = str(int(time.time()) + 45).encode()
    blocked = b"$" + str(len(deadline)).encode() + b"\r\n" + deadline + b"\r\n"

    def get(name, wire=nil):
        return CoalescedFrame(
            "get", name, wire, 429 if wire == blocked or len(wire) > 16384 else 200
        )

    def rec(name, armed=0, error=False):
        return CoalescedFrame(
            "record",
            name,
            ERROR
            if error
            else integer_reply(
                1 if armed else 0,
                10 if armed else 1,
                int(deadline) if armed else 0,
                armed,
            ),
            404,
            armed,
        )

    if case == "drain":
        large = b"$20000\r\n" + b"9" * 20000 + b"\r\n"
        return [
            CoalescedBatch(script.frames),
            CoalescedBatch([get("large", large), get("after-large")]),
        ]
    if case == "errors":
        return [
            script,
            CoalescedBatch(
                [get("good-a"), get("error-b", ERROR), get("blocked-c", blocked)]
            ),
            CoalescedBatch(
                [rec("record-a"), rec("record-error", error=True), rec("record-c", 1)]
            ),
            CoalescedBatch(
                [
                    get("mixed-a"),
                    rec("mixed-error", error=True),
                    get("mixed-c", blocked),
                ]
            ),
            CoalescedBatch(
                [rec("reverse-a"), get("reverse-error", ERROR), rec("reverse-c", 1)]
            ),
        ]
    return [
        script,
        CoalescedBatch([get("allow"), get("blocked", blocked)], split),
        CoalescedBatch([rec("normal"), rec("armed", 1)], split),
        CoalescedBatch([get("mixed"), rec("mixed-record", 1)], split),
        CoalescedBatch([rec("reverse"), get("reverse-get", blocked)], split),
    ]


def coalesced_http(client, frame):
    client.settimeout(0.6)
    response = b""
    while True:
        chunk = client.recv(4096)
        if not chunk:
            break
        response += chunk
    try:
        header, body = response.split(b"\r\n\r\n", 1)
        lines = header.split(b"\r\n")
        status = lines[0].split(b" ", 2)
        lengths = [
            line.split(b":", 1)[1].strip()
            for line in lines[1:]
            if line.lower().startswith(b"content-length:")
        ]
        if (
            len(status) != 3
            or status[0] not in (b"HTTP/1.0", b"HTTP/1.1")
            or status[1] != str(frame.status).encode()
            or len(lengths) != 1
            or not lengths[0].isdigit()
            or len(body) != int(lengths[0])
            or any(line.lower().startswith(b"transfer-encoding:") for line in lines[1:])
        ):
            raise ValueError("invalid response framing/status")
    except ValueError as error:
        raise AssertionError("COALESCE GET FIFO HTTP outcome/framing") from error
    finally:
        client.close()


def test_coalesced(binary, module, root, port, case, split=0):
    if case == "splits":
        # Type-only and final-delimiter boundaries for every pair family.
        # -1 is converted per frame rather than imposing a common length.
        for boundary in (1, -1):
            test_coalesced(
                binary, module, root / f"prefix-{boundary}", port, "partial", boundary
            )
        return
    check, record = scripts(
        pathlib.Path(__file__).resolve().parents[2]
        / "src/ngx_http_error_abuse_module.c"
    )
    batches = coalesced_scenarios(check, record, case)
    if split:
        for batch in batches:
            batch.split = split if split > 0 else len(batch.frames[-1].wire) - 1
    peer = CoalescedPeer(check, record, batches)
    peer.start()
    nginx = Nginx(binary, module, root, port, "", False, peer.port)
    clients = []
    evidence = []
    try:
        (root / "conf").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "conf/nginx.conf").write_text(
            f"""load_module {module};
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log debug;
events {{ worker_connections 64; }}
http {{
 log_format protocol '$arg_client $status';
 access_log {root}/access.log protocol;
 error_abuse_redis host=127.0.0.1 port={peer.port} prefix=ea02-get: timeout=1s;
 error_abuse_zone zone=get:1m key=$arg_client statuses=404 interval=60s threshold=10 block=60s inactive=120s redis=on;
 server {{ listen 127.0.0.1:{port};
 location = /get.gif {{ error_abuse zone=get; empty_gif; }}
 location = /record.gif {{ error_abuse zone=get; return 404; }}
 location = /health.gif {{ empty_gif; }}
 location = /stats {{ error_abuse_stats get; }}
 }}
}}
""",
            encoding="ascii",
        )
        log_path = root / "logs/error.log"
        access = root / "access.log"

        def log():
            return log_path.read_text(encoding="ascii", errors="replace")

        with mock.patch.object(nginx, "write_config"):
            nginx.start()
        fetch(port, "/health.gif")
        assert nginx.process is not None
        children = (
            pathlib.Path(f"/proc/{nginx.process.pid}/task/{nginx.process.pid}/children")
            .read_text()
            .split()
        )
        if len(children) != 1:
            raise AssertionError("COALESCE requires one normal worker")
        proc = pathlib.Path(f"/proc/{children[0]}")
        peer.wait(batches[0].queued, "COALESCE initial SCRIPT vectors")
        baseline = wait_until(
            lambda: record_fd_baseline(proc, port), "COALESCE initial fd baseline", peer
        )
        redis_inodes = {
            f"socket:[{fields[9]}]"
            for row in (proc / "net/tcp").read_text().splitlines()[1:]
            if (fields := row.split()) and int(fields[2].split(":")[1], 16) == peer.port
        }
        redis_fds = [int(fd) for fd, value in baseline.items() if value in redis_inodes]
        if len(redis_fds) != 1:
            raise AssertionError("COALESCE connected Redis inode identity")
        record_id = 0
        all_expected = []
        connection_identity = None
        timer_identity = None
        previous_drain = None
        get_ids = []
        for batch in batches:
            offset = len(log())
            sockets = []
            expected = []
            before = record_stats(port)["bans"]
            for frame in batch.frames:
                if frame.kind == "script":
                    expected.append(("script", str(int(frame.identity) + 1), 1, 0))
                    continue
                if frame.kind == "record":
                    record_id += 1
                    expected.append(
                        (
                            "record",
                            str(record_id),
                            6 if frame.wire == ERROR else 2,
                            1 if frame.wire == ERROR else 0,
                        )
                    )
                    status, _, _ = http_call(
                        port, f"/record.gif?client={frame.identity}"
                    )
                    if status != 404:
                        raise AssertionError("COALESCE record HTTP status")
                else:
                    client = socket.create_connection(("127.0.0.1", port))
                    clients.append(client)
                    client.sendall(
                        f"GET /get.gif?client={frame.identity} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode()
                    )
                    sockets.append((client, frame))
                    count = len(get_ids) + 1
                    wait_until(
                        lambda count=count: (
                            len([e for e in events(log()) if e[0] == "park"]) >= count
                        ),
                        "COALESCE GET did not park",
                        peer,
                    )
                    identity = [e[1] for e in events(log()) if e[0] == "park"][-1]
                    get_ids.append(identity)
                    expected.append(
                        (
                            "get",
                            identity,
                            6
                            if frame.wire == ERROR
                            else 1
                            if frame.status == 429
                            else 4,
                            1 if frame.wire == ERROR else 0,
                        )
                    )
            peer.wait(batch.queued, "COALESCE full queued vectors")
            segment = log()[offset:]
            if coalesced_callbacks(segment):
                raise AssertionError("COALESCE callback before release")
            base = (
                states(log())[-1]
                if states(log())
                else {"length": 0, "pos": 0, "bytes": ""}
            )
            if base["length"] != base["pos"]:
                raise AssertionError("COALESCE prior reader not at frame boundary")
            receive = None
            if batch.split:
                batch.release.set()
                peer.wait(batch.sent, "COALESCE one write")
            else:
                receive = coalesced_release(
                    proc, baseline[str(redis_fds[0])], batch, peer
                )
            prefix = None
            drains = []
            if batch.split:
                prior = expected[:-1]
                first = b"".join(f.wire for f in batch.frames[:-1])
                remaining = int(batch.frames[-1].kind == "get")

                def prefix_witness(
                    offset=offset,
                    base=base,
                    first=first,
                    batch=batch,
                    prior=prior,
                    remaining=remaining,
                ):
                    return coalesced_prefix(
                        log()[offset:],
                        base,
                        first,
                        batch.frames[-1].wire,
                        batch.split,
                        prior,
                        remaining,
                    )

                # The first frame callback must arrive before testing the exact prefix ledger.
                wait_until(
                    lambda offset=offset, prior=prior: (
                        len(coalesced_callbacks(log()[offset:])) >= len(prior)
                    ),
                    "COALESCE first callback missing",
                    peer,
                    0.6,
                )
                prefix = wait_until(
                    prefix_witness,
                    "COALESCE exact frame-relative prefix not consumed",
                    peer,
                    0.6,
                )
                prefix_drain = wait_until(
                    lambda offset=offset, prior=prior: coalesced_drain(
                        log()[offset:], prior
                    ),
                    "COALESCE prefix outside single readable drain",
                    peer,
                    0.6,
                )
                if prefix not in prefix_drain["readers"]:
                    raise AssertionError(
                        "COALESCE prefix reader outside callback drain"
                    )
                drains.append(prefix_drain)
                # Settle every complete GET before permitting the next frame suffix.
                complete_sockets = sockets if not remaining else sockets[:-1]
                for client, frame in complete_sockets:
                    coalesced_http(client, frame)
                    assert_one_completion(
                        access.read_text().splitlines(),
                        frame.identity,
                        str(frame.status),
                    )
                sockets = sockets[-1:] if remaining else []
                if remaining and select.select([sockets[0][0]], [], [], 0)[0]:
                    raise AssertionError("COALESCE partial next GET completed early")
                prefix_delta = sum(f.delta for f in batch.frames[:-1])
                if record_stats(port)["bans"] - before != prefix_delta:
                    raise AssertionError("COALESCE partial next record changed bans")
                wait_until(
                    lambda remaining=remaining: coalesced_fds(
                        record_fd_baseline(proc, 0), baseline, remaining
                    ),
                    "COALESCE prefix fd identity baseline drift",
                    peer,
                )
                batch.suffix.set()
                # Remaining frame must have its own observed readable drain.
                wait_until(
                    lambda offset=offset, expected=expected: (
                        len(coalesced_callbacks(log()[offset:])) == len(expected)
                    ),
                    "COALESCE suffix callback missing",
                    peer,
                    0.6,
                )
                drain = wait_until(
                    lambda offset=offset, expected=expected: coalesced_drain(
                        log()[offset:], expected[-1:]
                    ),
                    "COALESCE suffix drain witness missing",
                    peer,
                    0.6,
                )
            else:
                drain = wait_until(
                    lambda offset=offset, expected=expected: coalesced_drain(
                        log()[offset:],
                        expected,
                        require_partial=case == "drain" and len(evidence) == 1,
                    ),
                    "COALESCE single-drain FIFO progress missing",
                    peer,
                    0.6,
                )
            if drain is None:
                raise AssertionError("COALESCE suffix drain witness missing")
            drains.append(drain)
            for observed in drains:
                previous_drain = coalesced_drain_order(previous_drain, observed["id"])
                identity = (
                    observed["fd"],
                    observed["command"],
                    observed["reconnect"],
                )
                if connection_identity is None:
                    connection_identity = identity
                if identity != connection_identity or observed["fd"] != redis_fds[0]:
                    raise AssertionError("COALESCE fd/command/reconnect identity drift")
                begin_identity = (observed["begin_timer"], observed["begin_due"])
                if timer_identity is not None and (
                    begin_identity[0] != timer_identity[0]
                    or begin_identity[1] < timer_identity[1]
                ):
                    raise AssertionError("COALESCE command timer/due continuity drift")
                timer_identity = (observed["timer"], observed["due"])
            completed = drain["readers"][-1]
            if completed["length"] != completed["pos"] or any(
                completed[k] for k in ("pending", "tokens", "parked", "task")
            ):
                raise AssertionError("COALESCE completed batch retained reader/owner")
            if batch.split and completed["length"] - base["length"] != sum(
                len(f.wire) for f in batch.frames
            ):
                raise AssertionError("COALESCE suffix frame-relative completion drift")
            for client, frame in sockets:
                coalesced_http(client, frame)
            for frame in batch.frames:
                if frame.kind != "script":
                    wait_until(
                        lambda frame=frame: (
                            f"{frame.identity} {frame.status}"
                            in access.read_text().splitlines()
                        ),
                        "COALESCE HTTP completion missing",
                        peer,
                    )
                    assert_one_completion(
                        access.read_text().splitlines(),
                        frame.identity,
                        str(frame.status),
                    )
            all_expected.extend(expected)
            expected_records = [
                f
                for b in batches[: len(evidence) + 1]
                for f in b.frames
                if f.kind == "record"
            ]
            callbacks = [r for r in record_states(log()) if r["where"] == "callback"]
            if [
                (r["id"], r["gen"], r["local"], r["nulls"], r["delta"])
                for r in callbacks
            ] != [(i, 1, 0, 0, f.delta) for i, f in enumerate(expected_records, 1)]:
                raise AssertionError("COALESCE record callback FIFO ban ownership")
            if len(events(log())) != 4 * len(get_ids) or {
                i for _, i in events(log())
            } != set(get_ids):
                raise AssertionError("COALESCE non-GET callback acquired lifecycle")
            if coalesced_callbacks(log()) != all_expected:
                raise AssertionError("COALESCE duplicate or wrong FIFO callback")
            for identity in get_ids:
                assert_completion(
                    "\n".join(
                        f"EA_GET {kind} id={i}"
                        for kind, i in events(log())
                        if i == identity
                    )
                )
            if record_stats(port)["bans"] - before != sum(
                f.delta for f in batch.frames
            ):
                raise AssertionError("COALESCE record FIFO ban effect")
            wait_until(
                lambda: worker_fds(proc, port) == baseline,
                "COALESCE fd baseline drift",
                peer,
            )
            evidence.append(
                {
                    "expected": expected,
                    "drain": drain,
                    "prefix": prefix,
                    "receive": receive,
                    "split": batch.split,
                }
            )
            batch.ack.set()
        final = wait_until(
            lambda drain_id=drain["id"]: coalesced_final_idle(log(), drain_id),
            "COALESCE idle resources did not settle",
            peer,
        )
        assert_resources(final["script"], True)
        assert_fds(worker_fds(proc, port), baseline)
        if coalesced_callbacks(log()) != all_expected or peer.sessions != 1:
            raise AssertionError("COALESCE duplicate settlement/reconnect")
        # Error neighbours must traverse the real native failure branch exactly once.
        failures = sum(
            frame.wire == ERROR for batch in batches for frame in batch.frames
        )
        if (
            len(re.findall(r"Redis (?:check|EVAL) returned unexpected reply", log()))
            != failures
        ):
            raise AssertionError("COALESCE real error-owner failure path")
        for line in log().splitlines():
            if (
                re.search(r"\[(?:emerg|alert|crit|error|warn)\]", line)
                and "returned unexpected reply" not in line
            ):
                raise AssertionError(f"unexpected COALESCE error log: {line}")
        assert_ledger(
            log(),
            [(i, 1, digest(script)) for i, script in enumerate((check, record), 1)],
        )
        peer.check()
        (root / "coalesced-evidence.json").write_text(
            json.dumps(
                {
                    "case": case,
                    "worker": children[0],
                    "rows": evidence,
                    "final": final,
                    "fd_baseline": baseline,
                    "history_hex": [[v.hex() for v in c] for c in peer.history],
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        for client in clients:
            client.close()
        try:
            nginx.stop()
        finally:
            peer.stop()
    print(f"OK: COALESCE {case} split={split}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx-binary", type=pathlib.Path, required=True)
    parser.add_argument("--module", type=pathlib.Path, required=True)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--port", type=int, default=18968)
    parser.add_argument(
        "--family", choices=("script", "record", "coalesced"), required=True
    )
    parser.add_argument(
        "--case",
        choices=(
            "whole",
            "drain",
            "splits",
            "errors",
            "noscript",
            "null",
            "error-check",
            "error-record",
            "error-split",
        ),
        required=True,
    )
    args = parser.parse_args()
    if args.family == "coalesced":
        if args.case not in ("whole", "splits", "errors", "drain"):
            parser.error(f"case {args.case} is not valid for COALESCE")
        test_coalesced(
            args.nginx_binary.resolve(),
            args.module.resolve(),
            args.root.resolve(),
            args.port,
            args.case,
        )
    elif args.family == "script":
        if args.case in ("splits", "errors", "noscript", "null", "drain"):
            parser.error(f"case {args.case} is not valid for SCRIPT")
        test_script(
            args.nginx_binary.resolve(),
            args.module.resolve(),
            args.root.resolve(),
            args.port,
            args.case,
        )
    else:
        if args.case.startswith("error-") or args.case == "drain":
            parser.error(f"case {args.case} is not valid for RECORD")
        arguments = (
            args.nginx_binary.resolve(),
            args.module.resolve(),
            args.root.resolve(),
            args.port,
        )
        if args.case == "splits":
            test_record_splits(*arguments)
        else:
            test_record(*arguments, args.case)


if __name__ == "__main__":
    main()
