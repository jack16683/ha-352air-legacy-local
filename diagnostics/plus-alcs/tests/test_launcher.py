import contextlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import launcher
from plus_testkit.model import ProbeError
from support import ACCOUNT, PASSWORD


def completed(stdout="", code=0):
    return subprocess.CompletedProcess(
        [], code, stdout, b"" if isinstance(stdout, bytes) else ""
    )


class LauncherTests(unittest.TestCase):
    def test_remote_docker_environment_is_rejected_before_inspection_or_copy(self):
        with (
            patch.dict(os.environ, {"DOCKER_HOST": "ssh://SYNTH_REMOTE_HOST"}),
            patch("launcher.command") as call,
        ):
            with self.assertRaisesRegex(ProbeError, "REMOTE_DOCKER_NOT_ALLOWED"):
                launcher.local_docker()
        call.assert_not_called()

    def test_remote_context_is_rejected(self):
        with (
            patch.dict(os.environ, {"DOCKER_HOST": ""}),
            patch(
                "launcher.command",
                return_value=completed("tcp://SYNTH_REMOTE_HOST:2375"),
            ),
        ):
            with self.assertRaisesRegex(ProbeError, "REMOTE_DOCKER_NOT_ALLOWED"):
                launcher.local_docker()

    def test_ha_container_must_have_host_network_and_crypto(self):
        with patch(
            "launcher.command",
            return_value=completed(
                "ghcr.io/home-assistant/home-assistant:stable|bridge"
            ),
        ) as call:
            self.assertFalse(launcher.container_ready("synthetic-ha"))
            self.assertEqual(call.call_count, 1)
        with patch(
            "launcher.command",
            side_effect=[
                completed("ghcr.io/home-assistant/home-assistant:stable|host"),
                completed(code=1),
            ],
        ):
            self.assertFalse(launcher.container_ready("synthetic-ha"))
        with patch(
            "launcher.command",
            side_effect=[
                completed("ghcr.io/home-assistant/home-assistant:stable|host"),
                completed(),
            ],
        ):
            self.assertTrue(launcher.container_ready("synthetic-ha"))

    def test_multiple_eligible_containers_are_not_chosen_arbitrarily(self):
        with (
            patch("launcher.local_docker"),
            patch(
                "launcher.command",
                return_value=completed("abcdef123456\nfedcba654321\n"),
            ),
            patch("launcher.container_ready", return_value=True),
        ):
            with self.assertRaisesRegex(ProbeError, "HA_CONTAINER_AMBIGUOUS"):
                launcher.select_container()

    def test_no_tty_prevents_copying_any_profile_or_recovery_file(self):
        args = launcher.parse(
            ["install", "192.168.3.172", "--recovery-file", "synthetic-plan.json"]
        )
        with (
            patch("launcher.select_container", return_value="synthetic-ha"),
            patch("launcher.sys.stdin.isatty", return_value=False),
            patch("launcher.payload") as payload,
        ):
            with self.assertRaisesRegex(ProbeError, "INTERACTIVE_TERMINAL_REQUIRED"):
                launcher.docker_launch(args, [])
        payload.assert_not_called()

    def test_runtime_payload_has_no_tests_vault_or_research_and_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile"
            profile.write_text(
                json.dumps(
                    {
                        "mx_app_id": "synthetic-id",
                        "app_key": "synthetic-key",
                        "app_secret": "synthetic-secret",
                    }
                )
            )
            profile.chmod(0o600)
            body = launcher.payload(profile_path=profile)
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
                names = archive.getnames()
                self.assertIn("app-profile.private.json", names)
                self.assertFalse(
                    any(
                        "research" in n
                        or "tests/" in n
                        or "recovery.enc" in n
                        or "__pycache__" in n
                        for n in names
                    )
                )
                self.assertTrue(
                    all(m.isfile() and m.mode == 0o600 for m in archive.getmembers())
                )
            body = launcher.payload(include_profile=False)
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
                self.assertNotIn("app-profile.private.json", archive.getnames())

    def test_runtime_extractor_works_with_bundle_independently_of_apk_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "runtime"
            target.mkdir(mode=0o700)
            run = subprocess.run(
                [os.sys.executable, "-c", launcher.EXTRACT, str(target)],
                input=launcher.payload(include_profile=False),
                capture_output=True,
            )
            self.assertEqual(run.returncode, 0)
            self.assertTrue((target / "plus_testkit/cli.py").exists())
            self.assertEqual((target / "probe.py").stat().st_mode & 0o777, 0o600)
            help_run = subprocess.run(
                [os.sys.executable, str(target / "probe.py"), "--help"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(help_run.returncode, 0)

    def test_docker_handoff_and_report_copy_are_local_and_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            argv = ["baseline", "192.168.3.172", "--report", str(report)]
            args = launcher.parse(argv)
            commands = []
            raw = json.dumps(
                {
                    "mode": "baseline",
                    "status": "baseline_completed",
                    "stages": {
                        "cloud_before": {"status": "ok", "power": 0, "body": PASSWORD}
                    },
                    "account": ACCOUNT,
                }
            ).encode()

            def command(cmd, **kwargs):
                commands.append(cmd)
                if "tempfile.mkdtemp" in " ".join(cmd):
                    return completed("/tmp/plus-alcs-probe-SYNTHETIC\n")
                if "1048577" in " ".join(cmd):
                    return completed(raw)
                return completed(b"")

            with (
                patch("launcher.select_container", return_value="synthetic-ha"),
                patch("launcher.sys.stdin.isatty", return_value=True),
                patch("launcher.command", side_effect=command),
                patch("launcher.payload", return_value=b"synthetic archive"),
                patch("launcher.subprocess.run", return_value=completed()) as execution,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(launcher.docker_launch(args, argv), 0)
            text = report.read_text()
            self.assertNotIn(PASSWORD, text)
            self.assertNotIn(ACCOUNT, text)
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)
            executed = execution.call_args.args[0]
            self.assertIn("-it", executed)
            self.assertIn("/config/plus-private-state", executed)
            self.assertTrue(any("shutil.rmtree" in " ".join(c) for c in commands))
            self.assertFalse(any(PASSWORD in " ".join(c) for c in commands))

    def test_launcher_never_echoes_accidentally_pasted_password_argument(self):
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = launcher.main(["baseline", "--password", PASSWORD])
        self.assertEqual(code, 2)
        self.assertNotIn(PASSWORD, output.getvalue())
