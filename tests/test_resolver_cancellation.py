"""Cancellation classification with synthetic adapters and independent effects."""

import contextlib
import traceback
import unittest
from collections.abc import Iterator
from typing import NoReturn
from unittest.mock import patch

from browser_runtime.credentials import Denied
from browser_runtime.effects import Cancelled
from tests.test_trusted_credentials import CANARY, Adapters


class ResolverCancellationTests(unittest.TestCase):
    def exercise(
        self, stage: str, exit_mode: str = "normal", cleanup_error: bool = False
    ) -> None:
        adapter = Adapters()
        resolver = adapter.resolver()
        original = getattr(adapter, stage)

        def cancel(*args: object) -> NoReturn:
            if stage in ("read", "inject", "release"):
                original(*args)
            raise KeyboardInterrupt(CANARY)

        @contextlib.contextmanager
        def guard() -> Iterator[Adapters]:
            adapter.active = True
            try:
                yield adapter
            except BaseException:
                if exit_mode == "replace":
                    raise RuntimeError(CANARY) from None
                if exit_mode != "suppress":
                    raise
            finally:
                adapter.active = False
                adapter.calls.append("fence_closed")

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(adapter, "acquire", guard))
            stack.enter_context(patch.object(adapter, stage, cancel))
            if cleanup_error:

                def release(_handle: object) -> NoReturn:
                    adapter.calls.append("release")
                    raise RuntimeError(CANARY)

                stack.enter_context(patch.object(adapter, "release", release))
            try:
                resolver.resolve_and_inject(adapter.ticket)
            except Cancelled as error:
                envelope = (
                    str(error)
                    + repr(error)
                    + "".join(traceback.format_exception(error))
                )
                self.assertNotIn(CANARY, envelope)
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
            else:
                self.fail("cancellation must remain distinct from denial/success")
        self.assertFalse(adapter.active)
        self.assertEqual(
            adapter.spies["reads"], int(stage in ("read", "inject", "release"))
        )
        self.assertEqual(
            adapter.spies["injections"], int(stage in ("inject", "release"))
        )
        self.assertEqual(
            adapter.calls.count("release"), int(stage in ("inject", "release"))
        )
        before = list(adapter.calls)
        with self.assertRaises(Denied):
            resolver.resolve_and_inject(adapter.ticket)
        self.assertEqual(adapter.calls, before)

    def test_each_callback_cancellation_is_sanitized(self) -> None:
        for stage in ("admit", "observe", "current", "read", "inject", "release"):
            with self.subTest(stage=stage):
                self.exercise(stage)

    def test_guard_suppression_preserves_cancellation(self) -> None:
        for stage in ("admit", "read", "inject", "release"):
            with self.subTest(stage=stage):
                self.exercise(stage, "suppress")

    def test_guard_replacement_preserves_cancellation(self) -> None:
        for stage in ("admit", "read", "inject", "release"):
            with self.subTest(stage=stage):
                self.exercise(stage, "replace")

    def test_release_failure_cannot_replace_injection_cancellation(self) -> None:
        for mode in ("normal", "suppress", "replace"):
            with self.subTest(mode=mode):
                self.exercise("inject", mode, cleanup_error=True)

    def test_acquisition_and_exit_cancellation(self) -> None:
        for stage in ("enter", "exit"):
            adapter = Adapters()
            resolver = adapter.resolver()

            @contextlib.contextmanager
            def guard() -> Iterator[Adapters]:
                if stage == "enter":
                    raise SystemExit(CANARY)
                adapter.active = True
                try:
                    yield adapter
                finally:
                    adapter.active = False
                    raise SystemExit(CANARY)

            with patch.object(adapter, "acquire", guard):
                with self.assertRaises(Cancelled) as caught:
                    resolver.resolve_and_inject(adapter.ticket)
            self.assertNotIn(
                CANARY, "".join(traceback.format_exception(caught.exception))
            )
            self.assertIsNone(caught.exception.__context__)
            self.assertFalse(adapter.active)
            self.assertEqual(adapter.spies["injections"], int(stage == "exit"))

    def test_active_caller_exception_never_enters_public_error(self) -> None:
        for mode in ("cancel", "deny", "repeat"):
            adapter = Adapters()
            resolver = adapter.resolver()
            if mode == "repeat":
                resolver.resolve_and_inject(adapter.ticket)
            with patch.object(adapter, "inject", side_effect=KeyboardInterrupt(CANARY)):
                try:
                    raise RuntimeError(CANARY)
                except RuntimeError:
                    try:
                        resolver.resolve_and_inject(
                            object() if mode == "deny" else adapter.ticket
                        )
                    except (Cancelled, Denied) as error:
                        self.assertNotIn(
                            CANARY, "".join(traceback.format_exception(error))
                        )
                        self.assertIsNone(error.__context__)
                        self.assertIsNone(error.__cause__)
                    else:
                        self.fail("expected public error")

    def test_deliberate_latch_mutation_loses_cancellation(self) -> None:
        # Run a private source copy, not an installed/runtime monkeypatch. Removing
        # both inner latches lets a suppressing guard turn cancellation into denial.
        import types
        from pathlib import Path

        source = Path("browser_runtime/credentials.py").read_text()
        source = source.replace(
            "cancelled = not isinstance(error, Exception)", "cancelled = False"
        )
        source = source.replace(
            "cancelled = cancelled or not isinstance(error, Exception)",
            "cancelled = False",
        )
        namespace = types.ModuleType("browser_runtime.credentials_mutation")
        import sys

        with patch.dict(sys.modules, {namespace.__name__: namespace}):
            exec(compile(source, "credentials_mutation.py", "exec"), namespace.__dict__)
            adapter = Adapters()
            # Mutant owns exact dataclass types, so build its matching grant.
            adapter.grant = namespace.Grant(
                namespace.Target(
                    adapter.target.binding, "native", "frame", "https://example.test"
                ),
                "credential:one",
                12.0,
            )

            @contextlib.contextmanager
            def guard() -> Iterator[Adapters]:
                try:
                    yield adapter
                except BaseException:
                    pass

            resolver = namespace.Resolver(
                namespace.AdapterSet("a" * 64, adapter, adapter, adapter),
                expected_digest="a" * 64,
            )
            with (
                patch.object(adapter, "acquire", guard),
                patch.object(adapter, "admit", side_effect=KeyboardInterrupt),
            ):
                with self.assertRaises(namespace.Denied):
                    resolver.resolve_and_inject(adapter.ticket)
            self.assertEqual(adapter.spies, {"reads": 0, "injections": 0})


if __name__ == "__main__":
    unittest.main()
