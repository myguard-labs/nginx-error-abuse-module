#!/usr/bin/env python3
"""Controls for the Redis lifecycle test's completion and ordering oracles."""

import pathlib
import tempfile
import unittest
from unittest import mock

from test_runtime import LifecycleRedisServer, assert_redis_cleanup_completion


class ReplyCompletion(unittest.TestCase):
    def test_get_finishes_after_write_and_flush(self) -> None:
        peer = LifecycleRedisServer("nil")
        stream = mock.Mock()

        def pending(*_args: object) -> None:
            self.assertFalse(peer.finished.is_set())
            self.assertFalse(peer.completed.is_set())

        stream.write.side_effect = pending
        stream.flush.side_effect = pending
        self.assertTrue(peer._write_reply(stream, b"$-1\r\n", True))
        stream.write.assert_called_once_with(b"$-1\r\n")
        stream.flush.assert_called_once_with()
        peer.wait_finished(timeout=0)

    def test_handshake_does_not_finish_get(self) -> None:
        peer = LifecycleRedisServer("nil")
        self.assertTrue(peer._write_reply(mock.Mock(), b"+OK\r\n", False))
        self.assertFalse(peer.finished.is_set())
        with self.assertRaisesRegex(AssertionError, "did not finish"):
            peer.wait_finished(timeout=0)

    def test_write_and_flush_errors_surface_without_success(self) -> None:
        for operation in ("write", "flush"):
            with self.subTest(operation=operation):
                peer = LifecycleRedisServer("nil")
                stream = mock.Mock()
                error = BrokenPipeError("injected reply failure")
                getattr(stream, operation).side_effect = error
                self.assertFalse(peer._write_reply(stream, b"$-1\r\n", True))
                self.assertFalse(peer.finished.is_set())
                with self.assertRaisesRegex(
                    AssertionError, "Redis peer failed"
                ) as caught:
                    peer.wait_finished(timeout=0)
                self.assertIs(caught.exception.__cause__, error)


class CleanupOrdering(unittest.TestCase):
    INVALIDATED = "error_abuse: Redis check request invalidated\n"
    COMPLETED = "error_abuse: Redis check completed after cleanup (null=1)\n"

    def test_ordered_unique_cleanup_and_callback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "error.log"
            log.write_text(self.INVALIDATED + self.COMPLETED, encoding="ascii")
            assert_redis_cleanup_completion(log)

    def test_missing_duplicate_or_reversed_events_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "error.log"
            for text in (
                "",
                self.INVALIDATED,
                self.COMPLETED,
                self.INVALIDATED * 2 + self.COMPLETED,
                self.INVALIDATED + self.COMPLETED * 2,
                self.COMPLETED + self.INVALIDATED,
                self.INVALIDATED + self.COMPLETED.replace("null=1", "null=0"),
            ):
                with self.subTest(text=text):
                    log.write_text(text, encoding="ascii")
                    with self.assertRaises(AssertionError):
                        assert_redis_cleanup_completion(log)


if __name__ == "__main__":
    unittest.main()
