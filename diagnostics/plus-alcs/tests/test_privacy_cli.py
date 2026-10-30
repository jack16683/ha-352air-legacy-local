import ast
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from plus_testkit.cli import main, secret_input
from plus_testkit.lan import LanClient
from plus_testkit.model import Deadline, ProbeError
from plus_testkit.report import public_report
from support import ACCOUNT, PASSPHRASE, PASSWORD, RECOVERY, Cloud, Device


class CliPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile = self.root / "profile.json"
        self.profile.write_text(
            json.dumps(
                {
                    "mx_app_id": "SYNTH_MX_ID_392714",
                    "app_key": "SYNTH_APP_KEY_20492",
                    "app_secret": "SYNTH_APP_SECRET_402851",
                }
            )
        )
        self.profile.chmod(0o600)
        self.device = Device()
        self.addCleanup(self.device.close)
        self.cloud = Cloud(self.device)
        self.factory = lambda host: LanClient(
            host,
            port=self.device.port,
            allow_loopback=True,
            timeout=0.03,
            deadline=Deadline(10),
        )

    def run_cli(self, mode, extra=(), *, inputs=None):
        if inputs is None:
            inputs = [PASSPHRASE, PASSPHRASE, ACCOUNT, PASSWORD]
        values = iter(inputs)
        out, err = io.StringIO(), io.StringIO()
        args = [
            mode,
            "127.0.0.1",
            "--state-dir",
            str(self.root / "state"),
            "--profile",
            str(self.profile),
            *extra,
        ]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                args,
                prompt=lambda prompt: next(values),
                lan_factory=self.factory,
                cloud_factory=lambda *a, **k: self.cloud,
            )
        return code, json.loads(out.getvalue()), out.getvalue() + err.getvalue()

    def test_cli_baseline_is_redacted_in_stdout_stderr_and_vault(self):
        code, report, text = self.run_cli("baseline")
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "baseline_completed")
        for secret in [
            ACCOUNT,
            PASSWORD,
            PASSPHRASE,
            "SYNTHETIC_DEVICE",
            "127.0.0.1",
            "SYNTH_APP_SECRET_402851",
        ]:
            self.assertNotIn(secret, text)
            self.assertNotIn(
                secret.encode(), (self.root / "state/recovery.enc.json").read_bytes()
            )
        self.assertTrue(self.cloud.closed)

    def test_cli_install_and_verify_without_cloud_login(self):
        plan = self.root / "plan.json"
        plan.write_text(json.dumps(RECOVERY))
        plan.chmod(0o600)
        code, report, text = self.run_cli("install", ["--recovery-file", str(plan)])
        self.assertEqual(code, 0)
        self.assertEqual(report["write_datagrams"], 1)
        calls = list(self.cloud.calls)
        code, report, _ = self.run_cli("verify", inputs=[PASSPHRASE])
        self.assertEqual(code, 0)
        self.assertEqual(report["write_datagrams"], 0)
        self.assertEqual(self.cloud.calls, calls)

    def test_verify_cloud_recheck_is_separate_explicit_option(self):
        plan = self.root / "plan.json"
        plan.write_text(json.dumps(RECOVERY))
        plan.chmod(0o600)
        self.run_cli("install", ["--recovery-file", str(plan)])
        before = self.cloud.calls.count("login")
        code, report, text = self.run_cli(
            "verify", ["--cloud-check"], inputs=[PASSPHRASE, ACCOUNT, PASSWORD]
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.cloud.calls.count("login"), before + 1)
        self.assertTrue(report["stages"]["cloud_after"]["online"])
        self.assertEqual(report["write_datagrams"], 0)
        self.assertNotIn(PASSWORD, text)

    def test_unknown_argument_that_contains_password_is_not_echoed(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["baseline", "--password", PASSWORD])
        self.assertEqual(code, 1)
        self.assertNotIn(PASSWORD, out.getvalue() + err.getvalue())
        self.assertEqual(
            json.loads(out.getvalue())["error"]["reason"], "ARGUMENTS_INVALID"
        )

    def test_recovery_plan_required_before_password_input(self):
        code, report, text = self.run_cli("install", inputs=[])
        self.assertEqual(code, 1)
        self.assertEqual(report["error"]["reason"], "RECOVERY_PLAN_REQUIRED")
        self.assertEqual(self.device.writes, 0)

    def test_transport_or_library_error_text_never_becomes_diagnostic_text(self):
        def fail(*a):
            raise RuntimeError(PASSWORD + ACCOUNT)

        self.cloud.login = fail
        code, report, text = self.run_cli("baseline")
        self.assertEqual(code, 1)
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn(ACCOUNT, text)
        self.assertNotIn("Traceback", text)

    def test_even_unexpected_uppercase_probe_error_is_not_a_secret_channel(self):
        error = ProbeError(PASSWORD)
        self.assertEqual(error.code, "INTERNAL_ERROR")
        self.assertNotIn(PASSWORD, str(error))
        report = public_report(
            {
                "mode": "baseline",
                "status": "failed",
                "error": {"reason": PASSWORD, "password": PASSWORD},
            }
        )
        self.assertNotIn(PASSWORD, json.dumps(report))

    def test_no_tty_is_rejected_without_echo_fallback(self):
        with patch("plus_testkit.cli.os.open", side_effect=OSError("no tty")):
            with self.assertRaisesRegex(ProbeError, "INTERACTIVE_TERMINAL_REQUIRED"):
                secret_input("safe prompt")

    def test_report_field_whitelist_discards_raw_server_content_and_identifiers(self):
        internal = {
            "mode": "baseline",
            "status": "ok",
            "target": PASSWORD,
            "account": ACCOUNT,
            "stages": {
                "cloud_before": {
                    "status": "ok",
                    "power": 0,
                    "body": PASSWORD,
                    "token": PASSWORD,
                    "identityId": ACCOUNT,
                },
                ACCOUNT: {"status": "ok"},
            },
            "identity": {"plus_identity_verified": True, "name": PASSWORD},
        }
        text = json.dumps(public_report(internal))
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn(ACCOUNT, text)

    def test_report_output_never_overwrites_existing_file_or_symlink(self):
        existing = self.root / "report.json"
        existing.write_text("SYNTH_KEEP_THIS_FILE")
        code, report, text = self.run_cli("baseline", ["--report", str(existing)])
        self.assertEqual(code, 0)
        self.assertEqual(existing.read_text(), "SYNTH_KEEP_THIS_FILE")
        self.assertEqual(report["status"], "baseline_completed")

    def test_all_runtime_sources_parse_with_python38_grammar(self):
        root = Path(__file__).resolve().parents[1]
        for path in [
            root / "probe.py",
            root / "launcher.py",
            *sorted((root / "plus_testkit").glob("*.py")),
        ]:
            with self.subTest(file=path.name):
                ast.parse(path.read_text(), feature_version=(3, 8))

    def test_missing_dependency_has_sanitized_entrypoint_response(self):
        root = Path(__file__).resolve().parents[1]
        run = subprocess.run(
            [sys.executable, "-S", str(root / "probe.py"), "baseline", "192.168.3.172"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 2)
        self.assertEqual(
            json.loads(run.stdout)["error"]["reason"], "RUNTIME_DEPENDENCY_MISSING"
        )
        self.assertNotIn("Traceback", run.stderr)
