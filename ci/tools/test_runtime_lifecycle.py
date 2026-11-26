#!/usr/bin/env python3
"""Controls for runtime shutdown and Redis completion/ordering oracles."""

import pathlib
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

from test_runtime import LifecycleRedisServer, Nginx, assert_redis_cleanup_completion


class NginxShutdown(unittest.TestCase):
    def fixture(self, root: pathlib.Path, single: bool = True) -> Nginx:
        nginx = Nginx(pathlib.Path("nginx"), None, root, 18962, "", single)
        nginx.process = mock.Mock()
        nginx.process.poll.return_value = None
        nginx.process.returncode = 0
        return nginx

    @mock.patch("test_runtime.socket.create_connection")
    def test_single_process_wakes_after_term_before_wait(
        self, connect: mock.Mock
    ) -> None:
        nginx = self.fixture(pathlib.Path("unused"))
        process = nginx.process
        order = mock.Mock()
        order.attach_mock(process.terminate, "terminate")
        order.attach_mock(connect, "connect")
        order.attach_mock(process.wait, "wait")
        nginx.stop()
        self.assertEqual(order.mock_calls[0], mock.call.terminate())
        self.assertEqual(
            order.mock_calls[1], mock.call.connect(("127.0.0.1", 18962), 0.25)
        )
        self.assertEqual(order.mock_calls[-1], mock.call.wait(timeout=15))
        connect.return_value.__exit__.assert_called_once_with(None, None, None)
        process.kill.assert_not_called()
        self.assertIsNone(nginx.process)

    @mock.patch("test_runtime.socket.create_connection")
    def test_closed_listener_still_waits(self, connect: mock.Mock) -> None:
        connect.side_effect = ConnectionRefusedError("listener already closed")
        nginx = self.fixture(pathlib.Path("unused"))
        process = nginx.process
        nginx.stop()
        process.wait.assert_called_once_with(timeout=15)
        process.kill.assert_not_called()

    @mock.patch("test_runtime.socket.create_connection")
    def test_master_or_exited_process_does_not_wake(self, connect: mock.Mock) -> None:
        nginx = self.fixture(pathlib.Path("unused"), single=False)
        process = nginx.process
        nginx.stop()
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=15)
        nginx = self.fixture(pathlib.Path("unused"))
        process = nginx.process
        process.poll.return_value = 0
        nginx.stop()
        process.terminate.assert_not_called()
        process.wait.assert_not_called()
        nginx.stop()  # Already stopped is also a no-op.
        connect.assert_not_called()

    @mock.patch("test_runtime.socket.create_connection")
    def test_crash_and_timeout_remain_failures(self, _connect: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for rc in (1, -signal.SIGSEGV, -signal.SIGKILL):
                with self.subTest(rc=rc):
                    nginx = self.fixture(root)
                    process = nginx.process
                    process.returncode = rc
                    nginx.output_path.write_text("crash diagnostic", encoding="ascii")
                    if rc == -signal.SIGKILL:
                        process.wait.side_effect = [
                            subprocess.TimeoutExpired("nginx", 15),
                            rc,
                        ]
                    with self.assertRaisesRegex(RuntimeError, "crash diagnostic"):
                        nginx.stop()
                    if rc == -signal.SIGKILL:
                        process.kill.assert_called_once()
                        self.assertEqual(
                            process.wait.call_args_list,
                            [mock.call(timeout=15), mock.call(timeout=5)],
                        )
                    self.assertIsNone(nginx.process)

    @mock.patch("test_runtime.socket.create_connection")
    def test_clean_exit_does_not_hide_sanitizer_output(
        self, _connect: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            nginx = self.fixture(pathlib.Path(directory))
            nginx.output_path.write_text("AddressSanitizer: injected", encoding="ascii")
            nginx.stop()
            with self.assertRaisesRegex(AssertionError, "AddressSanitizer"):
                nginx.assert_clean_logs()


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
