#!/usr/bin/env python3
"""Positive, boundary and hostile controls for the EA-02 GET fixture/oracles."""

import io
import pathlib
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from test_runtime_get import (
    GetPeer,
    Reply,
    assert_cancellation,
    assert_completion,
    block_key,
    digest,
    prefix_consumed,
    read_command,
    scripts,
    worker_fds,
)


def command(*values: bytes) -> bytes:
    return b"*%d\r\n" % len(values) + b"".join(
        b"$%d\r\n%s\r\n" % (len(value), value) for value in values
    )


class Parser(unittest.TestCase):
    def test_positive_binary_and_boundaries(self):
        for values in ((b"",), (b"a\x00b\r\nc", b""), (b"x" * 4096, b"b", b"c", b"d")):
            self.assertEqual(read_command(io.BytesIO(command(*values))), list(values))
        self.assertIsNone(read_command(io.BytesIO()))

    def test_malformed_and_every_truncation(self):
        valid = command(b"EVALSHA", b"a" * 40, b"1", b"key")
        for prefix in range(1, len(valid)):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                read_command(io.BytesIO(valid[:prefix]))
        for wire in (
            b"*0\r\n",
            b"*-1\r\n",
            b"*5\r\n",
            b"*01\r\n",
            b"*1\n",
            b"*1\r\n$-1\r\n",
            b"*1\r\n$+1\r\n",
            b"*1\r\n$01\r\n",
            b"*1\r\n$4097\r\n",
            b"*1\r\n$1\r\nxXX",
        ):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                read_command(io.BytesIO(wire))

    def test_bad_split_and_expired_deadline_fail(self):
        for split in (-1, 5, 6):
            with self.assertRaisesRegex(ValueError, "bad split index"):
                Reply("key", b"$-1\r\n", split)
        for split in range(5):
            Reply("key", b"$-1\r\n", split).assert_fresh()
        with self.assertRaisesRegex(AssertionError, "expired deadline fixture"):
            Reply("key", b"$-1\r\n", deadline=int(time.time())).assert_fresh()

    def test_actual_scripts_and_key(self):
        check, record = scripts(
            pathlib.Path(__file__).resolve().parents[2]
            / "src/ngx_http_error_abuse_module.c"
        )
        self.assertTrue(check.startswith(b"local active=redis.pcall('GET',KEYS[1]) "))
        self.assertTrue(record.startswith(b"local t=redis.call('TIME') "))
        self.assertNotEqual(digest(check), digest(record))
        self.assertEqual(len(digest(check)), 40)
        self.assertEqual(
            block_key("a"),
            b"ea02-get:{get:ca978112ca1bbdcafac231b39a23dc4d"
            b"a786eff8147c4e72b9807785afee48bb}:block",
        )


class Peer(unittest.TestCase):
    def setUp(self):
        self.peer = GetPeer(b"check", b"record", ack_timeout=0.05)
        self.peer.start()
        self.addCleanup(self.peer.stop)
        self.client = socket.create_connection(("127.0.0.1", self.peer.port), 1)
        self.addCleanup(self.client.close)
        self.stream = self.client.makefile("rb")
        self.addCleanup(self.stream.close)

    def handshake(self):
        for script in (b"check", b"record"):
            self.client.sendall(command(b"SCRIPT", b"LOAD", script))
            self.assertEqual(
                self.stream.read(47), b"$40\r\n" + digest(script) + b"\r\n"
            )

    def get(self, reply):
        self.peer.prepare(reply)
        self.client.sendall(
            command(b"EVALSHA", digest(b"check"), b"1", block_key(reply.identity))
        )

    def failure(self, message):
        with self.assertRaisesRegex(AssertionError, "GET peer failed") as caught:
            self.peer.wait(threading.Event(), "failure", timeout=1)
        self.assertIn(message, str(caught.exception.__cause__))

    def test_exact_handshake_and_same_session_split_reuse(self):
        self.handshake()
        for split in (0, 1, 4):
            reply = Reply(str(split), b"$-1\r\n", split)
            self.get(reply)
            self.peer.wait(reply.received, "command")
            if split:
                self.assertEqual(self.stream.read(split), reply.wire[:split])
                self.assertFalse(reply.finished.is_set())
                reply.release.set()
            self.assertEqual(
                self.stream.read(len(reply.wire) - split), reply.wire[split:]
            )
            self.peer.wait(reply.finished, "reply")
        self.assertEqual(self.peer.sessions, 1)
        self.assertEqual(len(self.peer.history), 5)

    def test_missing_ack_propagates(self):
        self.handshake()
        reply = Reply("missing", b"$-1\r\n", 1)
        self.get(reply)
        self.assertEqual(self.stream.read(1), b"$")
        self.failure("missing prefix-consumed acknowledgement")
        self.assertFalse(reply.finished.is_set())

    def test_wrong_script_vector(self):
        self.client.sendall(command(b"SCRIPT", b"LOAD", b"wrong"))
        self.failure("wrong SCRIPT vector/lengths")

    def test_wrong_check_key_or_sha(self):
        self.handshake()
        self.peer.prepare(Reply("key", b"$-1\r\n"))
        self.client.sendall(command(b"EVALSHA", b"0" * 40, b"1", b"wrong-key"))
        self.failure("wrong check vector/lengths")

    def test_malformed_command_propagates(self):
        self.client.sendall(b"*9\r\n")
        self.failure("malformed RESP command array")

    def test_truncated_command_propagates(self):
        self.client.sendall(b"*1\r\n$4\r\nab")
        self.client.shutdown(socket.SHUT_WR)
        self.failure("truncated RESP command")

    def test_arbitrary_peer_exception_propagates(self):
        with mock.patch(
            "test_runtime_get.read_command", side_effect=RuntimeError("injected")
        ):
            self.client.sendall(command(b"SCRIPT", b"LOAD", b"check"))
            # First read may already be blocked before the patch; wake it,
            # then its next read must reach the injected exception.
            self.failure("injected")

    def test_missing_event_cannot_pass(self):
        with self.assertRaisesRegex(AssertionError, "missing progress"):
            self.peer.wait(threading.Event(), "progress", timeout=0)

    def test_duplicate_check_rejected(self):
        self.handshake()
        reply = Reply("duplicate", b"$-1\r\n")
        self.get(reply)
        self.assertEqual(self.stream.read(5), reply.wire)
        self.peer.wait(reply.finished, "reply")
        self.client.sendall(
            command(b"EVALSHA", digest(b"check"), b"1", block_key(reply.identity))
        )
        self.failure("duplicate GET for completed reply")

    def test_reconnect_rejected_and_all_sessions_stopped(self):
        self.handshake()
        with socket.create_connection(("127.0.0.1", self.peer.port), 1):
            self.failure("unexpected Redis reconnect")

    def test_overlapping_replies_fail(self):
        self.peer.prepare(Reply("one", b"$-1\r\n"))
        with self.assertRaisesRegex(AssertionError, "overlapping GET replies"):
            self.peer.prepare(Reply("two", b"$-1\r\n"))


class Oracles(unittest.TestCase):
    PREFIX = (
        "EA_GET state=read len=1 pos=1 task=0 pending=1 "
        "tokens=1 parked=1 timer=1 bytes=24"
    )
    CANCELLED = (
        "EA_GET park id=7\n"
        "EA_GET cleanup id=7\n"
        "EA_GET cancelled tokens=0 parked=0\n"
        "error_abuse: Redis check completed after cleanup (null=1)"
    )

    def test_prefix_requires_exact_bytes_live_decoder_and_ownership(self):
        reply = Reply("key", b"$-1\r\n", 1)
        self.assertTrue(prefix_consumed(self.PREFIX, reply))
        for field, replacement in (
            ("bytes=24", "bytes=2d"),
            ("pending=1", "pending=0"),
            ("tokens=1", "tokens=0"),
            ("parked=1", "parked=0"),
            ("task=0", "task=-1"),
            ("state=read", "state=timeout"),
        ):
            self.assertFalse(
                prefix_consumed(self.PREFIX.replace(field, replacement), reply)
            )
        self.assertFalse(prefix_consumed("", reply))

    def test_each_lifecycle_event_is_unique_and_ordered(self):
        lines = [
            f"EA_GET {kind} id=7\n"
            for kind in ("park", "callback", "release", "resume")
        ]
        good = "".join(lines)
        assert_completion(good)
        for index in range(4):
            for bad in (
                "".join(lines[:index] + lines[index + 1 :]),
                good + lines[index],
                "".join(reversed(lines)),
            ):
                with self.assertRaisesRegex(AssertionError, "ordering"):
                    assert_completion(bad)
        with self.assertRaisesRegex(AssertionError, "request identity"):
            assert_completion(good.replace("resume id=7", "resume id=8"))

    def test_cancellation_requires_cleanup_then_callback_settlement(self):
        self.assertEqual(assert_cancellation(self.CANCELLED)["parked"], 0)
        for bad, message in (
            (self.CANCELLED.replace("EA_GET cleanup id=7\n", ""), "ordering"),
            (
                self.CANCELLED.replace("EA_GET cleanup id=7", "EA_GET cleanup id=8"),
                "request identity",
            ),
            (
                self.CANCELLED.replace("EA_GET cancelled tokens=0 parked=0\n", ""),
                "cancelled callback",
            ),
            (self.CANCELLED.replace("tokens=0", "tokens=1"), "callback token"),
            (self.CANCELLED.replace("parked=0", "parked=1"), "stale parked"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(AssertionError, message),
            ):
                assert_cancellation(bad)

    def test_fd_baseline_waits_for_owned_http_socket_close(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = pathlib.Path(directory)
            (proc / "fd").mkdir()
            (proc / "net").mkdir()
            descriptor = proc / "fd/9"
            descriptor.symlink_to("socket:[42]")
            table = proc / "net/tcp"
            for state in ("01", "08", "04"):
                table.write_text(f"header\n0: 0100007F:4A17 x {state} x x x x x 42\n")
                self.assertIsNone(worker_fds(proc, 18967))
            table.write_text("header\n0: 0100007F:4A17 x 0A x x x x x 42\n")
            self.assertEqual(worker_fds(proc, 18967), {"9": "socket:[42]"})
            self.assertEqual(worker_fds(proc, 18968), {"9": "socket:[42]"})
            # A peer/fixture socket inode is not a worker descriptor.
            table.write_text("header\n0: 0100007F:4A17 x 01 x x x x x 99\n")
            self.assertEqual(worker_fds(proc, 18967), {"9": "socket:[42]"})
            descriptor.unlink()
            self.assertEqual(worker_fds(proc, 18967), {})


if __name__ == "__main__":
    unittest.main()
