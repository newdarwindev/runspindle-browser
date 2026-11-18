"""Actual local framing with synthetic authority; native Core driver is separate."""

import io
import json
import struct
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from browser_runtime.effect_pipe import MAX_REQUEST, MAX_RESPONSE, serve_once
from browser_runtime.effect_wire import Receiver
from browser_runtime.guarded_peer import GuardedPeer
from tests.test_effect_wire import encoded, request
from tests.test_guarded_effects import Fixture


def frame(raw):
    return struct.pack(">I", len(raw)) + raw


class PipeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)
        self.receiver = Receiver(
            GuardedPeer(authority=self.f, site=self.f, clock=lambda: self.f.now)
        )

    def exchange(self, raw, ticket="admitted"):
        output = io.BytesIO()
        okay = serve_once(io.BytesIO(raw), output, self.receiver, ticket)
        return okay, output.getvalue()

    def test_real_receiver_roundtrip_dispatch_then_readback_without_database(self):
        with patch("sqlite3.connect", side_effect=AssertionError("no Browser DB")):
            okay, output = self.exchange(frame(encoded(request())))
            self.assertTrue(okay)
            self.assertEqual(struct.unpack(">I", output[:4])[0], len(output) - 4)
            self.assertEqual(json.loads(output[4:])["outcome"], "unknown")
            self.f.grant = replace(self.f.grant, action="reconcile")
            okay, output = self.exchange(frame(encoded(request("reconcile"))))
            self.assertTrue(okay)
            self.assertEqual(json.loads(output[4:])["outcome"], "confirmed")
        self.assertEqual(self.f.effects(), 1)

    def test_incomplete_oversize_empty_and_trailing_frames_deny_before_effect(self):
        good = frame(encoded(request()))
        for raw in (
            b"",
            good[:3],
            good[:-1],
            struct.pack(">I", 0),
            struct.pack(">I", MAX_REQUEST + 1),
            good + b"x",
            good + good,
        ):
            self.assertEqual(self.exchange(raw), (False, b""))
        self.assertEqual(self.f.effects(), 0)

    def test_ticket_not_minted_from_valid_wire(self):
        self.assertEqual(
            self.exchange(frame(encoded(request())), object()), (False, b"")
        )
        self.assertEqual(self.f.effects(), 0)

    def test_partial_pipe_reads_and_writes_supported(self):
        class ShortReader(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 2))

        class ShortWriter(io.BytesIO):
            def write(self, data):
                return super().write(data[:3])

        output = ShortWriter()
        self.assertTrue(
            serve_once(
                ShortReader(frame(encoded(request()))),
                output,
                self.receiver,
                "admitted",
            )
        )
        self.assertEqual(json.loads(output.getvalue()[4:])["outcome"], "unknown")

    def test_cancellation_does_not_escape_or_publish_raw_error(self):
        self.f.cancel = True
        self.assertEqual(self.exchange(frame(encoded(request()))), (False, b""))
        self.assertEqual(self.f.effects(), 1)  # Core must retain reserved unknown.

    def test_unbounded_receiver_response_never_written(self):
        class ReceiverFixture:
            def exchange(self, *_):
                return b"x" * (MAX_RESPONSE + 1)

        output = io.BytesIO()
        self.assertFalse(
            serve_once(
                io.BytesIO(frame(b"synthetic")), output, ReceiverFixture(), object()
            )
        )
        self.assertEqual(output.getvalue(), b"")

    def test_partial_response_failure_is_not_reported_as_success(self):
        class BrokenWriter(io.BytesIO):
            def flush(self):
                raise KeyboardInterrupt("SYNTHETIC_PRIVATE")

        output = BrokenWriter()
        self.assertFalse(
            serve_once(
                io.BytesIO(frame(encoded(request()))), output, self.receiver, "admitted"
            )
        )
        self.assertNotIn(b"PRIVATE", output.getvalue())
        self.assertEqual(self.f.effects(), 1)


if __name__ == "__main__":
    unittest.main()
