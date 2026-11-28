#!/usr/bin/env python3
"""Causal malformed/negative controls for SCRIPT and RECORD fixtures."""

import copy
import dataclasses
import io
import math
import pathlib
import re
import sys
import threading
import unittest
from unittest import mock

from test_redis_get_controls import command
from test_runtime_get import Reply, block_key, digest, scripts
from test_runtime_protocol import (
    ERROR,
    FIELDS,
    RECORD_FIELDS,
    CoalescedBatch,
    CoalescedFrame,
    CoalescedPeer,
    ErrorContext,
    RecordPeer,
    RecordReply,
    ScriptPeer,
    assert_error_post,
    assert_fds,
    assert_ledger,
    assert_record_callback,
    assert_resources,
    capture_error_snapshot,
    clean_logs,
    coalesced_callbacks,
    coalesced_drain,
    coalesced_fds,
    coalesced_final_idle,
    coalesced_position,
    coalesced_prefix,
    error_snapshot_evidence,
    integer_reply,
    read_record_command,
    record_fd_baseline,
    record_keys,
    record_prefix_state,
    record_reader_position,
    record_scenario,
    record_split_frames,
    record_states,
    script_states,
)
from test_runtime_protocol import (
    main as protocol_main,
)


def row(where, **changes):
    values = dict.fromkeys(FIELDS, 0)
    values.update(gen=1, queued=2, called=2, ready=1, connected=1)
    values.update(changes)
    payload = values.pop("payload", b"")
    if "length" not in changes:
        values["length"] = len(payload)
    return (
        "EA_SCRIPT state="
        + where
        + " "
        + " ".join(f"{key}={values[key]}" for key in FIELDS)
        + " bytes="
        + payload.hex()
        + "\n"
    )


def whole():
    return (
        row("previous", gen=0, queued=0, called=0)
        + row("queue", slot=1, queued=1, called=0, outstanding=1)
        + row("queue", slot=2, called=0, outstanding=2)
        + "EA_SCRIPT callback_gen=1\n"
        + row("callback", slot=1, called=1, outstanding=1, kind=1, payload=b"a" * 40)
        + row("post", slot=1, called=1, outstanding=1, kind=1, payload=b"a" * 40)
        + "EA_SCRIPT callback_gen=1\n"
        + row("callback", slot=2, kind=1, payload=b"b" * 40)
        + row("post", slot=2, kind=1, payload=b"b" * 40)
    )


EXPECTED = [(1, 1, b"a" * 40), (2, 1, b"b" * 40)]


def record_row(where, **changes):
    values = dict.fromkeys(RECORD_FIELDS, 0)
    values.update(gen=1, ready=1, connected=1, armed=-1)
    values.update(changes)
    return (
        "EA_RECORD state="
        + where
        + " "
        + " ".join(f"{key}={values[key]}" for key in RECORD_FIELDS)
        + "\n"
    )


class Oracles(unittest.TestCase):
    def test_complete_exact_ledger(self):
        assert_ledger(whole(), EXPECTED)
        self.assertEqual(len(script_states(whole())), 7)

    def test_wrong_missing_duplicate_order_generation_and_stale_counts(self):
        baseline = whole()
        mutations = [
            baseline.replace("61" * 40, "63" * 40),
            baseline.replace("slot=1 queued=2", "slot=2 queued=2"),
            baseline.replace("callback_gen=1", "callback_gen=2", 1),
            baseline.replace("gen=1", "gen=2", 1),
            baseline.replace("outstanding=1", "outstanding=0", 1),
            baseline.replace("called=1", "called=2", 1),
            baseline.replace("queued=1", "queued=2", 1),
            baseline.replace("length=40", "length=41", 1),
            baseline.replace("state=queue", "state=missing", 1),
            baseline.replace("state=callback", "state=missing", 1),
            baseline.replace("state=post", "state=missing", 1),
            baseline + row("callback", slot=2, kind=1, payload=b"b" * 40),
            baseline + row("post", slot=2, kind=1, payload=b"b" * 40),
            baseline + row("read", outstanding=1),
        ]
        for mutated in mutations:
            with self.subTest(mutated=mutated), self.assertRaises(AssertionError):
                assert_ledger(mutated, EXPECTED)

    def test_error_post_branch_is_causal(self):
        valid = row("post", slot=1, kind=6, ready=0, disconnecting=1)
        self.assertEqual(assert_error_post(valid, 1)["ready"], 0)
        for altered, message in (
            (valid.replace("ready=0", "ready=1"), "SCRIPT error callback left ready"),
            (
                valid.replace("disconnecting=1", "disconnecting=0"),
                "did not enter disconnect",
            ),
            (valid.replace("slot=1", "slot=2"), "missing SCRIPT"),
            (valid.replace("kind=6", "kind=1"), "missing SCRIPT"),
            (valid + valid, "missing SCRIPT"),
            ("", "missing SCRIPT"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(AssertionError, message),
            ):
                assert_error_post(altered, 1)

    def test_resources_and_fd_drift_reject(self):
        connected = script_states(row("timeout"))[0]
        assert_resources(connected, True)
        disconnected = {**connected, "connected": 0, "cleanup": 1}
        assert_resources(disconnected, False)
        for key, value in (
            ("outstanding", 1),
            ("timer", 1),
            ("cleanup", 1),
            ("connected", 0),
        ):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                assert_resources({**connected, key: value}, True)
        with self.assertRaises(AssertionError):
            assert_resources({**disconnected, "cleanup": 2}, False)
        baseline = {"0": "/dev/null", "4": "socket:[123]"}
        assert_fds(dict(baseline), baseline)
        for actual in (
            None,
            {},
            {**baseline, "5": "socket:[456]"},
            {**baseline, "4": "socket:[124]"},
        ):
            with (
                self.subTest(actual=actual),
                self.assertRaisesRegex(AssertionError, "fd drift"),
            ):
                assert_fds(actual, baseline)

    def test_narrow_error_logs(self):
        handshake = "[error] error_abuse: Redis handshake (AUTH/SELECT) failed (type=6, detail_len=18); disconnecting\n"
        check = '[warn] error_abuse: Redis check failed (consecutive=1), client: 127.0.0.1, server: , request: "GET /get.gif?client=script-sentinel HTTP/1.0", host: "localhost"\n'
        clean_logs(handshake + check, True)
        clean_logs("[notice] healthy\n", False)
        for log in (
            handshake,
            check,
            handshake + check + handshake,
            handshake + check + "[error] unknown",
            handshake + check + "AddressSanitizer",
            handshake + check.replace("consecutive=1", "consecutive=2"),
            handshake + check + "runtime error:",
        ):
            with self.subTest(log=log), self.assertRaises(AssertionError):
                clean_logs(log, True)
        with self.assertRaises(AssertionError):
            clean_logs(handshake + check, False)


class ErrorCapture(unittest.TestCase):
    def setUp(self):
        script_pair = scripts(
            pathlib.Path(__file__).resolve().parents[2]
            / "src/ngx_http_error_abuse_module.c"
        )
        self.context = ErrorContext(
            10.0,
            0,
            "script-sentinel",
            script_pair,
            (("0", "/dev/null"),),
            1,
            "worker-fixture",
        )
        self.live = {
            "log": (
                row("previous", gen=0, queued=0, called=0)
                + row("queue", slot=1, queued=1, called=0, outstanding=1)
                + row("queue", slot=2, called=0, outstanding=2)
                + "EA_GET park id=3\nEA_SCRIPT callback_gen=1\n"
                + row(
                    "callback",
                    slot=1,
                    called=1,
                    outstanding=1,
                    kind=6,
                    payload=ERROR[1:-2],
                )
                + row(
                    "post",
                    slot=1,
                    called=1,
                    outstanding=1,
                    kind=6,
                    payload=ERROR[1:-2],
                    ready=0,
                    disconnecting=1,
                )
                + "[error] error_abuse: Redis handshake (AUTH/SELECT) failed (type=6, detail_len=18); disconnecting\n"
                + row(
                    "cleanup", called=1, outstanding=1, ready=0, connected=0, cleanup=1
                )
                + "EA_SCRIPT callback_gen=1\n"
                + row("callback", slot=2, ready=0, connected=0, cleanup=1)
                + "EA_SCRIPT get_kind=0\nEA_GET callback id=3\n"
                + '[warn] error_abuse: Redis check failed (consecutive=1), client: 127.0.0.1, server: , request: "GET /get.gif?client=script-sentinel HTTP/1.0", host: "localhost"\n'
                + "EA_GET release id=3\nEA_GET resume id=3\n"
                + "error_abuse test reconnect delay=22500 next=30000\n"
                + "EA_SCRIPT settled tokens=0 parked=0\n"
                + row("drained", ready=0, connected=0, cleanup=1, reconnect=1)
            ),
            "output": "",
            "access": ["script-sentinel 200"],
            "response": bytearray(b"HTTP/1.0 200 OK\r\n\r\nbody"),
            "sessions": 1,
            "vectors": [[b"SCRIPT", b"LOAD", script] for script in script_pair]
            + [
                [b"EVALSHA", digest(script_pair[0]), b"1", block_key("script-sentinel")]
            ],
            "peer_error": None,
            "fds": {"0": "/dev/null"},
        }

    def capture(self, at=10.5):
        return capture_error_snapshot(self.context, lambda: self.live, clock=lambda: at)

    def test_deadline_boundary_after_all_live_reads(self):
        read = mock.Mock(return_value=self.live)
        clock = mock.Mock(return_value=math.nextafter(11.0, -math.inf))
        order = mock.Mock()
        order.attach_mock(read, "read")
        order.attach_mock(clock, "clock")
        snapshot = capture_error_snapshot(self.context, read, clock)
        self.assertEqual([call[0] for call in order.mock_calls], ["read", "clock"])
        self.assertLess(error_snapshot_evidence(snapshot)["capture_monotonic"], 11.0)
        for at in (11.0, math.nextafter(11.0, math.inf), 12.0):
            with (
                self.subTest(at=at),
                self.assertRaisesRegex(AssertionError, "waited for command timeout"),
            ):
                self.capture(at)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snapshot.sessions = 2

    def test_delay_window_missing_and_uncapped_witness_reject(self):
        original = self.live["log"]
        for delay in (1001, 22500, 37500):
            self.live["log"] = original.replace("delay=22500", f"delay={delay}")
            self.assertEqual(
                error_snapshot_evidence(self.capture())["reconnect_delay_ms"], delay
            )
        for delay in (0, 999, 1000):
            self.live["log"] = original.replace("delay=22500", f"delay={delay}")
            with (
                self.subTest(delay=delay),
                self.assertRaisesRegex(AssertionError, "overlaps error-capture"),
            ):
                error_snapshot_evidence(self.capture())
        for altered in (
            original.replace("error_abuse test reconnect delay=22500 next=30000\n", ""),
            original.replace("next=30000", "next=2000"),
            original + "error_abuse test reconnect delay=22500 next=30000\n",
        ):
            self.live["log"] = altered
            with self.assertRaisesRegex(AssertionError, "missing capped reconnect"):
                error_snapshot_evidence(self.capture())

    def test_late_scheduler_mutation_cannot_change_frozen_generation(self):
        # Exercise the very capture/validation pair used by the live runner.
        read = mock.Mock(return_value=self.live)
        clock = mock.Mock(return_value=10.9)
        snapshot = capture_error_snapshot(self.context, read, clock)
        accepted = error_snapshot_evidence(snapshot)
        self.live["log"] += row("previous", gen=2) + row("queue", gen=2, slot=1)
        self.live["sessions"] = 2
        self.live["vectors"].append([b"SCRIPT", b"LOAD", b"later-script"])
        self.live["vectors"][0][2] = b"later-generation"
        self.live["peer_error"] = "later reconnect is forbidden by this peer"
        self.live["fds"]["4"] = "socket:[later]"
        self.live["access"].append("script-sentinel 500")
        self.live["response"][:] = b"HTTP/1.0 500 Later\r\n\r\n"
        self.live["output"] = "later worker output"
        # Validation deliberately happens after a simulated long deschedule.
        clock.return_value = 100.0
        self.assertEqual(error_snapshot_evidence(snapshot), accepted)
        read.assert_called_once_with()
        clock.assert_called_once_with()
        # The same new-generation state, when captured before the deadline,
        # is a defect in the capture and must still be rejected.
        with self.assertRaisesRegex(AssertionError, "exact queue identity/order/count"):
            error_snapshot_evidence(self.capture(at=10.9))

    def test_stale_evidence_captured_before_boundary_rejects(self):
        baseline = copy.deepcopy(self.live)
        alterations = (
            (
                "log",
                baseline["log"].replace("gen=1", "gen=2", 1),
                "connection generation",
            ),
            ("sessions", 2, "session/command history"),
            ("fds", {"0": "/dev/null", "4": "socket:[old-redis]"}, "fd drift"),
            ("access", [], "HTTP completion"),
            ("response", b"HTTP/1.0 500 Bad\r\n\r\n", "HTTP 200"),
            ("peer_error", "early peer exception", "captured peer failure"),
            (
                "log",
                baseline["log"].replace("tokens=0 parked=0", "tokens=1 parked=0"),
                "token/park",
            ),
            (
                "log",
                baseline["log"].replace("tokens=0 parked=0", "tokens=0 parked=1"),
                "token/park",
            ),
            (
                "log",
                baseline["log"].replace("cleanup=1", "cleanup=2"),
                "cleanup/connection count",
            ),
            (
                "log",
                baseline["log"].replace("state=drained", "state=notdrained"),
                "missing final drain",
            ),
            ("log", baseline["log"].replace("timer=0", "timer=1"), "command timer"),
            (
                "log",
                baseline["log"].replace("reconnect=1", "reconnect=0"),
                "lost scheduled reconnect",
            ),
            (
                "log",
                baseline["log"].replace(
                    "called=2 outstanding=0", "called=1 outstanding=1"
                ),
                "outstanding count",
            ),
        )
        for key, value, message in alterations:
            self.live = {**copy.deepcopy(baseline), key: value}
            with (
                self.subTest(key=key, message=message),
                self.assertRaisesRegex(AssertionError, message),
            ):
                error_snapshot_evidence(self.capture(at=10.99))
        self.live = copy.deepcopy(baseline)
        self.live["vectors"][2][-1] = b"stale-key"
        with self.assertRaisesRegex(AssertionError, "session/command history"):
            error_snapshot_evidence(self.capture(at=10.99))


class Fixture(unittest.TestCase):
    def setUp(self):
        self.scripts = scripts(
            pathlib.Path(__file__).resolve().parents[2]
            / "src/ngx_http_error_abuse_module.c"
        )
        self.peer = ScriptPeer(*self.scripts, "whole", ack_timeout=0.01)
        self.reply = Reply("script-sentinel", b"$-1\r\n")
        self.peer.prepare(self.reply)

    def test_exact_vectors_and_script_extraction(self):
        self.assertEqual(len(self.scripts), 2)
        self.assertNotEqual(*self.scripts)
        self.assertNotEqual(*(digest(s) for s in self.scripts))
        for slot, script in enumerate(self.scripts):
            self.peer.script_vector([b"SCRIPT", b"LOAD", script], slot)
        for command_values in (
            None,
            [b"SCRIPT", b"LOAD", b"wrong"],
            [b"SCRIPT", b"LOAD", self.scripts[1]],
            [b"SCRIPT", b"LOAD"],
            [b"AUTH", b"LOAD", self.scripts[0]],
        ):
            with (
                self.subTest(command=command_values),
                self.assertRaisesRegex(AssertionError, "wrong SCRIPT"),
            ):
                self.peer.script_vector(command_values, 0)
        valid = [b"EVALSHA", digest(self.scripts[0]), b"1", b"key"]
        for command_values in (
            valid,
            [*valid[:1], b"wrong", *valid[2:]],
            [*valid[:2], b"2", *valid[3:]],
            [*valid[:3]],
            None,
        ):
            with (
                self.subTest(command=command_values),
                self.assertRaisesRegex(AssertionError, "SHA/key/vector"),
            ):
                self.peer.get_vector(command_values, self.reply)

    def test_missing_release_callback_ack_and_peer_exception(self):
        with self.assertRaisesRegex(AssertionError, "missing SCRIPT release"):
            self.peer.gate(threading.Event(), "SCRIPT release")
        event = threading.Event()
        event.set()
        self.peer.gate(event, "release")
        self.peer.error = ValueError("peer exception control")
        with self.assertRaisesRegex(AssertionError, "GET peer failed"):
            self.peer.wait(threading.Event(), "callback", 0.01)
        self.peer.error = None
        self.peer.send[0].set()
        with (
            mock.patch(
                "test_runtime_protocol.read_command",
                side_effect=[[b"SCRIPT", b"LOAD", script] for script in self.scripts]
                + [[b"bad"]],
            ),
            self.assertRaisesRegex(AssertionError, "SHA/key/vector"),
        ):
            self.peer.serve(io.BytesIO())
        from test_runtime_get import block_key

        wire = b"".join(
            command(b"SCRIPT", b"LOAD", script) for script in self.scripts
        ) + command(
            b"EVALSHA", digest(self.scripts[0]), b"1", block_key(self.reply.identity)
        )
        with self.assertRaisesRegex(
            AssertionError, "missing SCRIPT callback acknowledgement"
        ):
            self.peer.serve(io.BytesIO(wire))

    def test_malformed_truncated_commands_and_missing_prefix_ack(self):
        for wire in (
            b"*0\r\n",
            b"*3\r\n$6\r\nSCRIPT\r\n$4\r\nLOAD\r\n$5\r\na",
            b"*3\r\n$+6\r\nSCRIPT\r\n",
        ):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                self.peer.serve(io.BytesIO(wire))
        self.peer.case = "error-split"
        self.peer.send[0].set()
        from test_runtime_get import block_key

        commands = [[b"SCRIPT", b"LOAD", script] for script in self.scripts] + [
            [b"EVALSHA", digest(self.scripts[0]), b"1", block_key(self.reply.identity)]
        ]
        with (
            mock.patch("test_runtime_protocol.read_command", side_effect=commands),
            self.assertRaisesRegex(
                AssertionError, "missing error-prefix-consumed acknowledgement"
            ),
        ):
            self.peer.serve(io.BytesIO())


class RecordOracles(unittest.TestCase):
    def setUp(self):
        self.reply = RecordReply(
            "armed", integer_reply(1, 1, 2_000_000_000, 1), 0, 1, 4, armed=1
        )
        self.valid = record_row(
            "queue", id=1, queued=1, called=0, outstanding=1, local=0
        ) + record_row(
            "callback",
            id=1,
            queued=1,
            called=1,
            local=0,
            type=2,
            elements=4,
            armed=1,
            bans=1,
            delta=1,
        )

    def test_armed_now_ban_counter_control_is_named_and_causal(self):
        self.assertEqual(assert_record_callback(self.valid, self.reply, 1)["delta"], 1)
        with self.assertRaisesRegex(
            AssertionError, "RECORD armed_now ban-counter effect"
        ):
            assert_record_callback(
                self.valid.replace("delta=1", "delta=0"), self.reply, 1
            )

    def test_record_ledger_rejects_identity_generation_wrapper_and_shape(self):
        alterations = (
            self.valid.replace("state=queue", "state=missing", 1),
            self.valid.replace("state=callback", "state=missing", 1),
            self.valid + self.valid.splitlines(keepends=True)[1],
            self.valid.replace("gen=1", "gen=2", 1),
            self.valid.replace("outstanding=1", "outstanding=0", 1),
            self.valid.replace("called=1", "called=0", 1),
            self.valid.replace("local=0", "local=1", 1),
            self.valid.replace("type=2", "type=6", 1),
            self.valid.replace("elements=4", "elements=3", 1),
            self.valid.replace("armed=1", "armed=0", 1),
        )
        for altered in alterations:
            with self.subTest(altered=altered), self.assertRaises(AssertionError):
                assert_record_callback(altered, self.reply, 1)
        self.assertEqual(len(record_states(self.valid)), 2)

    def test_record_scenarios_cover_current_legacy_error_noscript_and_null(self):
        threshold, whole_replies, unexpected, noscript = record_scenario("whole")
        self.assertEqual((threshold, unexpected, noscript), (2, 0, 0))
        self.assertEqual(
            [reply.elements for reply in whole_replies], [4, 4, 4, 4, 2, 2, 3, 3]
        )
        self.assertEqual({reply.local for reply in whole_replies}, {0, 1})
        self.assertEqual({reply.armed for reply in whole_replies[:4]}, {0, 1})
        threshold, errors, unexpected, _ = record_scenario("errors")
        self.assertEqual(threshold, 1)
        self.assertEqual(sum(reply.unexpected for reply in errors), unexpected)
        self.assertGreater(unexpected, 0)
        _, noscript_replies, _, noscript = record_scenario("noscript")
        self.assertEqual(noscript, 1)
        self.assertTrue(noscript_replies[0].reload)
        self.assertIsNone(record_scenario("null")[1][0].wire)


def reader_row(where, **changes):
    values = {
        "length": 94,
        "pos": 94,
        "task": 0,
        "pending": 1,
        "tokens": 0,
        "parked": 0,
        "timer": 1,
        "bytes": "",
    }
    values.update(changes)
    return (
        f"EA_GET state={where} len={values['length']} pos={values['pos']} "
        + " ".join(
            f"{key}={values[key]}"
            for key in ("task", "pending", "tokens", "parked", "timer", "bytes")
        )
        + "\n"
    )


class RecordPrefixes(unittest.TestCase):
    def setUp(self):
        self.reply = RecordReply(
            "prefix",
            integer_reply(1, 9223372036854775807, 9223372036854775807, 1),
            0,
            1,
            4,
            armed=1,
            split=35,
        )
        self.queue = record_row("queue", id=2, queued=2, called=1, outstanding=1)
        self.base = reader_row("record_queue")

    def prefix(self, reply):
        position, task = record_reader_position(reply.wire, reply.split)
        return reader_row(
            "read",
            length=94 + reply.split,
            pos=94 + position,
            task=task,
            bytes=reply.wire[: reply.split][-32:].hex(),
        )

    def test_frozen_frames_every_internal_position_and_tail(self):
        frames = record_split_frames()
        self.assertEqual({frame.elements for frame in frames}, {2, 3, 4})
        self.assertEqual(
            {(frame.local, frame.armed) for frame in frames if frame.elements == 4},
            {(0, 0), (0, 1), (1, 0), (1, 1)},
        )
        for frame in frames:
            for split in range(1, len(frame.wire)):
                frame.split = split
                accepted = record_prefix_state(
                    self.queue + self.base + self.prefix(frame), frame, 2
                )
                self.assertEqual(accepted["split"], split)
                self.assertEqual(accepted["wire_hex"], frame.wire.hex())
        wire = integer_reply(0, 1)
        for split, expected in (
            (1, (1, 0)),
            (3, (1, 0)),
            (4, (4, 1)),
            (5, (5, 1)),
            (7, (5, 1)),
            (8, (8, 1)),
            (9, (9, 1)),
            (11, (9, 1)),
        ):
            self.assertEqual(record_reader_position(wire, split), expected)
        for split in (-1, 0, len(wire), len(wire) + 1):
            with self.assertRaisesRegex(AssertionError, "invalid RECORD"):
                record_reader_position(wire, split)
        for wire in (b"*2\r\n:0\r\n", b"*1\r\n:0\r\n", b"*2\r\n+x\r\n:1\r\n"):
            with self.assertRaisesRegex(AssertionError, "invalid RECORD"):
                record_reader_position(wire, 1)

    def test_aggregate_tail_without_exact_epoch_and_reader_state_rejects(self):
        prefix = self.prefix(self.reply)
        for key, value in (
            ("length", 35),
            ("length", 130),
            ("pos", 94),
            ("task", -1),
            ("pending", 0),
            ("timer", 0),
            ("tokens", 1),
            ("parked", 1),
            ("bytes", "00"),
        ):
            # Change only the named field of the genuine live-reader-shaped row.
            field = "len" if key == "length" else key
            altered = re.sub(rf"{field}=[^ \n]*", f"{field}={value}", prefix)
            with self.subTest(key=key, value=value):
                self.assertIsNone(
                    record_prefix_state(self.queue + self.base + altered, self.reply, 2)
                )
        self.assertIsNone(record_prefix_state(self.queue + self.base, self.reply, 2))
        for base in (
            "",
            self.base + self.base,
            self.base.replace("pos=94", "pos=93"),
            self.base.replace("task=0", "task=1"),
            self.base.replace("pending=1", "pending=0"),
            self.base.replace("tokens=0", "tokens=1"),
            self.base.replace("parked=0", "parked=1"),
        ):
            with self.subTest(base=base), self.assertRaises(AssertionError):
                record_prefix_state(self.queue + base + prefix, self.reply, 2)

    def test_pending_owner_generation_callback_and_lifecycle_controls(self):
        prefix = self.base + self.prefix(self.reply)
        for queue in (
            self.queue.replace("id=2", "id=1"),
            self.queue.replace("gen=1", "gen=2"),
            self.queue.replace("called=1", "called=2"),
            self.queue.replace("outstanding=1", "outstanding=0"),
            self.queue.replace("nulls=0", "nulls=1"),
            self.queue + record_row("callback"),
            self.queue + self.queue,
        ):
            with (
                self.subTest(queue=queue),
                self.assertRaisesRegex(AssertionError, "pending callback"),
            ):
                record_prefix_state(queue + prefix, self.reply, 2)
        with self.assertRaisesRegex(AssertionError, "request lifecycle"):
            record_prefix_state(
                self.queue + prefix + "EA_GET resume id=1\n", self.reply, 2
            )


class RecordBaseline(unittest.TestCase):
    def test_stale_then_settled_baseline(self):
        settled = {"4": "socket:[redis]", "6": "socket:[listener]"}
        stale = {**settled, "3": "socket:[closed-http]"}
        with mock.patch(
            "test_runtime_protocol.worker_fds",
            side_effect=[stale, settled, settled, settled],
        ) as snapshots:
            self.assertIsNone(
                record_fd_baseline(pathlib.Path("/worker"), 1234),
                "RECORD phantom HTTP fd became baseline",
            )
            self.assertEqual(record_fd_baseline(pathlib.Path("/worker"), 1234), settled)
        self.assertEqual(snapshots.call_count, 4)

    def test_incomplete_or_never_settled_baseline_rejects(self):
        settled = {"4": "socket:[redis]"}
        stale = {**settled, "3": "socket:[closed-http]"}
        for observations in (
            [None],
            [settled, None],
            [stale, settled],
            [settled, stale],
        ):
            with (
                self.subTest(observations=observations),
                mock.patch(
                    "test_runtime_protocol.worker_fds", side_effect=observations
                ),
            ):
                self.assertIsNone(
                    record_fd_baseline(pathlib.Path("/worker"), 1234),
                    "RECORD unstable fd baseline accepted",
                )


class ProtocolSelectors(unittest.TestCase):
    def test_family_case_dispatch(self):
        for family, case, selected in (
            ("record", "splits", "test_record_splits"),
            ("record", "whole", "test_record"),
            ("script", "whole", "test_script"),
        ):
            with (
                self.subTest(family=family, case=case),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "protocol",
                        "--nginx-binary",
                        "/binary",
                        "--module",
                        "/module",
                        "--root",
                        "/case",
                        "--family",
                        family,
                        "--case",
                        case,
                    ],
                ),
                mock.patch("test_runtime_protocol.test_record") as record,
                mock.patch("test_runtime_protocol.test_record_splits") as splits,
                mock.patch("test_runtime_protocol.test_script") as script,
            ):
                protocol_main()
                methods = {
                    "test_record": record,
                    "test_record_splits": splits,
                    "test_script": script,
                }
                methods.pop(selected).assert_called_once()
                for other in methods.values():
                    other.assert_not_called()
                self.assertEqual(
                    (
                        record
                        if family == "record" and case == "whole"
                        else splits
                        if case == "splits"
                        else script
                    ).call_args.args[:4],
                    (
                        pathlib.Path("/binary"),
                        pathlib.Path("/module"),
                        pathlib.Path("/case"),
                        18968,
                    ),
                )

    def test_record_splits_are_not_script_credit(self):
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "protocol",
                    "--nginx-binary",
                    "/binary",
                    "--module",
                    "/module",
                    "--root",
                    "/case",
                    "--family",
                    "script",
                    "--case",
                    "splits",
                ],
            ),
            mock.patch("sys.stderr", new_callable=io.StringIO),
            self.assertRaises(SystemExit) as stopped,
        ):
            protocol_main()
        self.assertEqual(stopped.exception.code, 2)


class RecordFixture(unittest.TestCase):
    def setUp(self):
        self.scripts = scripts(
            pathlib.Path(__file__).resolve().parents[2]
            / "src/ngx_http_error_abuse_module.c"
        )
        self.peer = RecordPeer(*self.scripts, threshold=2, ack_timeout=0.01)
        self.reply = RecordReply(
            "record-vector", integer_reply(0, 1, 0, 0), 0, 0, 4, armed=0
        )
        event_key, blocked_key = record_keys(self.reply.identity)
        self.vector = [
            b"EVALSHA",
            digest(self.scripts[1]),
            b"2",
            event_key,
            blocked_key,
            b"60000",
            b"2",
            b"60000",
            b"120000",
            b"123:1",
        ]

    def test_bounded_ten_element_decoder(self):
        wire = command(*self.vector)
        self.assertEqual(read_record_command(io.BytesIO(wire)), self.vector)
        for malformed in (
            command(*self.vector[:-1]),
            b"*10\r\n$1\r\na\r\n",
            b"*10\r\n$+1\r\na\r\n",
            b"*10\r\n$5000\r\n" + b"a" * 5000 + b"\r\n",
            wire[:-1],
        ):
            with self.subTest(malformed=malformed[:80]), self.assertRaises(ValueError):
                read_record_command(io.BytesIO(malformed))

    def test_exact_record_vector_and_nonce_controls(self):
        self.peer.record_vector(self.vector, self.reply)
        for index in range(9):
            mutated = list(self.vector)
            mutated[index] = b"wrong"
            with self.subTest(index=index), self.assertRaises(AssertionError):
                self.peer.record_vector(mutated, self.reply)
        for nonce in (b"bad", b"124:1", b"123:2", b"123:0"):
            mutated = [*self.vector[:9], nonce]
            with self.subTest(nonce=nonce), self.assertRaises(AssertionError):
                self.peer.record_vector(mutated, self.reply)

    def test_record_peer_requires_callback_release(self):
        self.peer.current = self.reply
        with (
            mock.patch(
                "test_runtime_protocol.read_command",
                side_effect=[[b"SCRIPT", b"LOAD", script] for script in self.scripts],
            ),
            mock.patch(
                "test_runtime_protocol.read_record_command", return_value=self.vector
            ),
            self.assertRaisesRegex(AssertionError, "missing RECORD callback release"),
        ):
            self.peer.serve(io.BytesIO())

    def test_record_peer_requires_consumption_before_suffix(self):
        self.reply.split = 1
        self.reply.release.set()
        self.peer.current = self.reply
        with (
            mock.patch(
                "test_runtime_protocol.read_command",
                side_effect=[[b"SCRIPT", b"LOAD", script] for script in self.scripts],
            ),
            mock.patch(
                "test_runtime_protocol.read_record_command", return_value=self.vector
            ),
            self.assertRaisesRegex(AssertionError, "prefix-consumed acknowledgement"),
        ):
            self.peer.serve(io.BytesIO())
        self.assertTrue(self.reply.sent.is_set())
        self.assertFalse(self.reply.finished.is_set())


class CoalescedControls(unittest.TestCase):
    def test_exact_baseline_descriptor_identity(self):
        baseline = {"1": "pipe:[1]", "10": "socket:[42]"}
        self.assertTrue(coalesced_fds(baseline, baseline, 0))
        self.assertTrue(coalesced_fds({**baseline, "11": "socket:[43]"}, baseline, 1))
        for actual, pending in (
            (None, 0),
            ({"1": "pipe:[1]", "10": "socket:[43]"}, 0),
            ({**baseline, "11": "pipe:[2]"}, 1),
            ({**baseline, "11": "socket:[43]"}, 0),
            (baseline, 1),
        ):
            self.assertFalse(coalesced_fds(actual, baseline, pending))

    def test_callback_fifo_types_failures_and_single_drain(self):
        body = (
            "EA_COALESCE get id=3 kind=4 failures=0\n"
            "EA_COALESCE record id=1 kind=6 failures=1\n"
            + reader_row("read", pending=0, tokens=0, parked=0)
        )
        begin = "EA_DRAIN begin id=7 fd=11 command=AA timer=1 due=100 reconnect=BB retry=0\n"
        end = (
            "EA_DRAIN end id=7 fd=-1 command=AA timer=1 due=100 reconnect=BB retry=0\n"
        )
        expected = [("get", "3", 4, 0), ("record", "1", 6, 1)]
        valid = begin + body + end
        self.assertEqual(coalesced_callbacks(valid), expected)
        drain = coalesced_drain(valid, expected)
        self.assertEqual(drain["id"], 7)
        self.assertEqual(
            (drain["begin_timer"], drain["begin_due"], drain["timer"], drain["due"]),
            (1, 100, 1, 100),
        )
        for bad in (
            valid.replace("get id=3", "get id=4"),
            valid.replace("kind=6", "kind=4"),
            valid.replace("failures=1", "failures=0"),
            valid.replace(end, ""),
            begin + body + body + end,
            begin
            + body.splitlines()[0]
            + "\n"
            + end
            + begin
            + "\n".join(body.splitlines()[1:])
            + end,
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(coalesced_drain(bad, expected))
        for bad in (
            valid.replace(
                "command=AA timer=1 due=100 reconnect=BB retry=0\n",
                "command=CC timer=1 due=100 reconnect=BB retry=0\n",
                1,
            ),
            valid.replace("timer=1", "timer=0", 1),
            valid.replace("due=100", "due=999", 1),
            valid.replace("retry=0", "retry=1"),
        ):
            with self.assertRaisesRegex(
                AssertionError, "drain timer/due transition drift"
            ):
                coalesced_drain(bad, expected)

    def test_frame_relative_prefix_and_exact_pending_owner(self):
        first = b"$-1\r\n"
        last = integer_reply(1, 10, 1234567890, 1)
        split = len(last) - 1
        pos, task = coalesced_position(last, split)
        base = {"length": 94, "pos": 94, "bytes": (b"b" * 32).hex()}
        prefix = first + last[:split]
        callback = "EA_COALESCE get id=3 kind=4 failures=0\n"
        expected = [("get", "3", 4, 0)]
        reader = reader_row(
            "read",
            length=94 + len(prefix),
            pos=94 + len(first) + pos,
            task=task,
            pending=1,
            tokens=0,
            parked=0,
            timer=1,
            bytes=(b"b" * 32 + prefix)[-32:].hex(),
        )
        self.assertIsNotNone(
            coalesced_prefix(callback + reader, base, first, last, split, expected, 0)
        )
        for bad in (
            reader.replace("pending=1", "pending=0"),
            reader.replace("timer=1", "timer=0"),
            reader.replace("tokens=0", "tokens=1"),
            reader.replace("pos=" + str(94 + len(first) + pos), "pos=" + str(94 + pos)),
            reader.replace("task=1", "task=0"),
            reader.replace("len=" + str(94 + len(prefix)), "len=" + str(len(prefix))),
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(
                    coalesced_prefix(
                        callback + bad, base, first, last, split, expected, 0
                    )
                )
        for bad in (
            callback + callback + reader,
            reader,
            callback.replace("id=3", "id=4") + reader,
        ):
            with self.assertRaisesRegex(AssertionError, "ownership/count"):
                coalesced_prefix(bad, base, first, last, split, expected, 0)
        for split in (0, len(last)):
            with self.assertRaisesRegex(AssertionError, "internal prefix"):
                coalesced_position(last, split)
        self.assertEqual(
            coalesced_position(b"$40\r\n" + b"x" * 40 + b"\r\n", 46), (1, 0)
        )

    def test_final_idle_must_follow_final_drain(self):
        get = reader_row("timeout", pending=0, tokens=0, parked=0, timer=0)
        script = (
            "EA_SCRIPT state=timeout gen=1 slot=0 queued=2 called=2 "
            "outstanding=0 ready=1 connected=1 timer=0 disconnecting=0 "
            "reconnect=0 cleanup=0 kind=0 length=0 bytes=\n"
        )
        end = (
            "EA_DRAIN end id=9 fd=-1 command=AA timer=1 due=100 reconnect=BB retry=0\n"
        )
        self.assertIsNone(coalesced_final_idle(get + script + end, 9))
        final = coalesced_final_idle(end + get + script, 9)
        self.assertEqual(final["get"]["where"], "timeout")
        self.assertEqual(final["script"]["where"], "timeout")

    def test_peer_requires_each_ack_and_exact_vectors(self):
        scripts_ = (b"check", b"record")
        for missing in ("release", "suffix", "ack", None):
            batch = CoalescedBatch(
                [
                    CoalescedFrame("script", "0", b"$1\r\nx\r\n"),
                    CoalescedFrame("script", "1", b"$1\r\ny\r\n"),
                ],
                1,
            )
            peer = CoalescedPeer(*scripts_, [batch], ack_timeout=0.001)
            for name in ("release", "suffix", "ack"):
                if name != missing:
                    getattr(batch, name).set()
            with mock.patch(
                "test_runtime_protocol.read_command",
                side_effect=[[b"SCRIPT", b"LOAD", s] for s in scripts_],
            ):
                if missing:
                    label = {"ack": "settlement", "suffix": "prefix-consumed"}.get(
                        missing, missing
                    )
                    with self.assertRaisesRegex(
                        AssertionError, f"missing COALESCE {label} acknowledgement"
                    ):
                        peer.serve(io.BytesIO())
                else:
                    peer.serve(io.BytesIO())
                    self.assertTrue(batch.queued.is_set())
                    self.assertTrue(batch.sent.is_set())
        for malformed, error, message in (
            (b"*10\r\n", ValueError, "malformed RESP command array"),
            (
                b"*3\r\n$6\r\nSCRIPT\r\n$4\r\nLOAD\r\n$5\r\ncut",
                ValueError,
                "truncated RESP command",
            ),
            (
                command(b"SCRIPT", b"LOAD", b"wrong"),
                AssertionError,
                "wrong COALESCE exact vector/FIFO",
            ),
        ):
            batch = CoalescedBatch([CoalescedFrame("script", "0", b"+OK\r\n")])
            peer = CoalescedPeer(*scripts_, [batch], ack_timeout=0.001)
            with (
                self.subTest(malformed=malformed),
                self.assertRaisesRegex(error, message),
            ):
                peer.serve(io.BytesIO(malformed))
        batch = CoalescedBatch([CoalescedFrame("record", "x", b"+OK\r\n")])
        with self.assertRaisesRegex(ValueError, "truncated record"):
            CoalescedPeer(*scripts_, [batch]).serve(io.BytesIO(b"*10\r\n$5\r\ncut"))


if __name__ == "__main__":
    unittest.main()
