import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from plus_testkit.engine import Engine, observe_power
from plus_testkit.lan import LanClient
from plus_testkit.model import Deadline, ProbeError
from plus_testkit.vault import Vault
from support import (
    ACCOUNT,
    IDENTITY,
    MANUAL,
    PASSPHRASE,
    PASSWORD,
    RECOVERY,
    Cloud,
    Device,
)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.device = Device()
        self.addCleanup(self.device.close)
        self.vault = Vault(Path(self.temp.name) / "state", PASSPHRASE)
        self.addCleanup(self.vault.close)
        self.cloud = Cloud(self.device)
        self.factory = lambda host: LanClient(
            host,
            port=self.device.port,
            allow_loopback=True,
            timeout=0.03,
            deadline=Deadline(10),
        )
        self.engine = Engine("127.0.0.1", self.vault, self.factory, self.cloud)
        self.addCleanup(self.engine.close)

    def install(self, recovery=RECOVERY):
        return self.engine.baseline(ACCOUNT, PASSWORD, install=True, recovery=recovery)

    def test_baseline_has_no_write_or_new_server_key(self):
        result = self.engine.baseline(ACCOUNT, PASSWORD)
        self.assertEqual(result["status"], "baseline_completed")
        self.assertEqual(self.device.writes, 0)
        self.assertNotIn("new_server_key", self.vault.data)
        self.assertEqual(self.cloud.calls[:3], ["login", "access", "snapshot"])

    def test_requested_baseline_observation_without_restore_blocks_install(self):
        self.engine.observe = lambda *_: {
            "status": "not_confirmed",
            "observed_change": True,
            "observed_restore": False,
        }
        with self.assertRaisesRegex(ProbeError, "PHYSICAL_STATE_RESTORE_NOT_CONFIRMED"):
            self.install()
        self.assertEqual(self.device.writes, 0)
        self.assertTrue(self.engine.report["observation_attention"])

    def test_requested_new_key_observation_without_restore_requires_attention(self):
        results = iter(
            [
                {"status": "state_tracking_confirmed", "observed_restore": True},
                {"status": "read_failed", "observed_restore": False},
            ]
        )
        self.engine.observe = lambda *_: next(results)
        result = self.install()
        self.assertEqual(result["stages"]["new_read"]["status"], "ok")
        self.assertTrue(result["observation_attention"])
        self.assertEqual(self.device.writes, 1)

    def test_optional_cloud_recheck_requires_fresh_power_matching_local_read(self):
        self.install()
        self.engine.verify()
        self.cloud.stale = True
        self.engine.check_cloud(ACCOUNT, PASSWORD)
        self.assertTrue(self.engine.report["cloud_recheck_attention"])

    def test_cloud_precedes_single_install_then_fresh_auth_and_cloud_check(self):
        result = self.install()
        self.assertEqual(result["status"], "new_key_read_verified_cloud_online")
        self.assertEqual(self.device.writes, 1)
        self.assertTrue(self.vault.attempted("install"))
        self.assertEqual(result["durability"], "not_tested")
        setup_index = next(i for i, r in enumerate(self.device.requests) if r[0] == 3)
        self.assertTrue(
            any(
                r[1].endswith("property/get")
                for r in self.device.requests[:setup_index]
            )
        )
        self.assertTrue(
            any(
                r[1].endswith("service/auth")
                for r in self.device.requests[setup_index + 1 :]
            )
        )
        self.assertEqual(self.cloud.calls[-1], "snapshot")
        self.assertTrue(result["recovery"]["access_verified_before_write"])

    def test_ack_lost_but_applied_is_read_verified_without_retrying_write(self):
        self.device.setup = "drop_reply"
        result = self.install()
        self.assertEqual(self.device.writes, 1)
        self.assertEqual(
            result["stages"]["install_response"]["reason"], "WRITE_OUTCOME_UNKNOWN"
        )
        self.assertEqual(result["stages"]["new_read"]["status"], "ok")
        self.assertEqual(result["status"], "new_key_read_verified_cloud_online")

    def test_ack_200_without_install_is_not_success(self):
        self.device.setup = "ack_no_apply"
        result = self.install()
        self.assertEqual(result["stages"]["install_response"]["status"], "acknowledged")
        self.assertEqual(result["status"], "setup_outcome_unconfirmed")
        self.assertEqual(self.device.writes, 1)

    def test_ram_only_install_does_not_pass_reboot_verification(self):
        self.device.setup = "ram_only"
        self.install()
        self.device.reboot()
        check = Engine("127.0.0.1", self.vault, self.factory)
        self.addCleanup(check.close)
        result = check.verify(after_reboot=True)
        self.assertEqual(result["status"], "new_key_not_confirmed")
        self.assertEqual(result["durability"], "not_tested")
        self.assertEqual(self.device.writes, 1)

    def test_saved_install_passes_fresh_verify_after_reported_reboot(self):
        self.install()
        self.device.reboot()
        check = Engine("127.0.0.1", self.vault, self.factory)
        self.addCleanup(check.close)
        result = check.verify(after_reboot=True)
        self.assertEqual(result["status"], "new_key_read_verified")
        self.assertEqual(
            result["durability"], "read_verified_after_operator_reported_reboot"
        )
        self.assertEqual(self.device.writes, 1)

    def test_install_cannot_repeat_after_interruption_or_unknown_outcome(self):
        self.device.setup = "drop_reply"
        self.install()
        reopened = Vault(Path(self.temp.name) / "state", PASSPHRASE)
        self.addCleanup(reopened.close)
        reopened.load()
        next_engine = Engine("127.0.0.1", reopened, self.factory, self.cloud)
        self.addCleanup(next_engine.close)
        with self.assertRaisesRegex(ProbeError, "EXISTING_WRITE_USE_VERIFY_OR_RECOVER"):
            next_engine.baseline(ACCOUNT, PASSWORD, install=True, recovery=RECOVERY)
        self.assertEqual(self.device.writes, 1)

    def test_known_key_restore_uses_a_new_session_and_is_not_exact_rollback_claim(self):
        self.device.setup = "remove_old"
        self.install()
        self.assertEqual(
            self.engine.report["stages"]["old_read_after"]["status"], "not_confirmed"
        )
        self.assertEqual(
            self.engine.report["stages"]["old_existing_session_only"]["status"], "ok"
        )
        check = Engine("127.0.0.1", self.vault, self.factory)
        self.addCleanup(check.close)
        result = check.verify(restore=True)
        self.assertEqual(result["status"], "restored_key_read_verified")
        self.assertFalse(result["exact_configuration_restored"])
        self.assertEqual(result["cloud_after"], "not_checked_no_cloud_login")
        self.assertEqual(self.device.writes, 2)
        with self.assertRaisesRegex(ProbeError, "RESTORE_ALREADY_ATTEMPTED"):
            check.verify(restore=True)
        self.assertEqual(self.device.writes, 2)

    def test_manual_recovery_is_explicitly_unverified_and_never_resets_device(self):
        result = self.install(MANUAL)
        self.assertFalse(result["recovery"]["toolkit_verified"])
        check = Engine("127.0.0.1", self.vault, self.factory)
        self.addCleanup(check.close)
        with self.assertRaisesRegex(ProbeError, "MANUAL_RECOVERY_REQUIRED"):
            check.verify(restore=True)
        self.assertEqual(self.device.writes, 1)

    def test_cloud_check_failure_does_not_erase_local_success_or_pass_overall(self):
        self.cloud.fail_after = True
        result = self.install()
        self.assertEqual(result["stages"]["new_read"]["status"], "ok")
        self.assertFalse(result["stages"]["cloud_after"]["online"])
        self.assertEqual(result["status"], "new_key_read_verified_cloud_attention")

    def test_stale_cloud_baseline_blocks_setup(self):
        self.cloud.stale = True
        with self.assertRaisesRegex(ProbeError, "CLOUD_BASELINE_STALE"):
            self.install()
        self.assertEqual(self.device.writes, 0)

    def test_unsupported_firmware_blocks_setup(self):
        self.device.firmware = "2.0.0_OTHER"
        with self.assertRaisesRegex(ProbeError, "FIRMWARE_REVIEW_REQUIRED"):
            self.install()
        self.assertEqual(self.device.writes, 0)

    def test_bad_known_recovery_material_blocks_setup(self):
        plan = {
            "kind": "known_local_key",
            "prefix": "UNKNOWNX",
            "secret": "synthetic-wrong-secret",
        }
        with self.assertRaises(ProbeError):
            self.install(plan)
        self.assertEqual(self.device.writes, 0)

    def test_failed_durable_attempt_write_prevents_datagram(self):
        with patch.object(
            self.vault, "mark_attempt", side_effect=ProbeError("VAULT_SAVE_FAILED")
        ):
            with self.assertRaisesRegex(ProbeError, "WRITE_NOT_JOURNALED"):
                self.install()
        self.assertEqual(self.device.writes, 0)

    def test_old_record_target_mismatch_prevents_any_auth_or_write(self):
        self.vault.data.update(
            {
                "identity": {"product": IDENTITY.product, "name": "SYNTHETIC_OTHER"},
                "target": "127.0.0.1",
            }
        )
        with self.assertRaisesRegex(ProbeError, "VAULT_IDENTITY_MISMATCH"):
            self.install()
        self.assertEqual(self.device.writes, 0)
        self.assertEqual(self.cloud.calls, [])

    def test_same_identity_can_be_verified_after_dhcp_address_change(self):
        self.install()
        self.vault.data["target"] = "192.168.3.172"
        self.vault.save()
        check = Engine("127.0.0.1", self.vault, self.factory)
        self.addCleanup(check.close)
        result = check.verify()
        self.assertEqual(result["status"], "new_key_read_verified")
        self.assertTrue(result["identity"]["target_address_changed"])
        self.assertEqual(self.device.writes, 1)

    def test_outbound_allowlist_has_no_power_write_binding_reset_or_wifi_changes(self):
        self.install()
        for code, path, request, source in self.device.requests:
            self.assertIn(code, (1, 3))
            self.assertIn(
                request["method"],
                {
                    "device.info.get",
                    "core/service/auth",
                    "thing.service.property.get",
                    "core.service.setup",
                },
            )
            if code == 3:
                self.assertTrue(path.endswith("/core/service/setup"))
                self.assertEqual(request["params"]["configType"], "ServerAuthInfo")
                self.assertEqual(len(request["params"]["configValue"]), 1)
        self.assertEqual(self.device.writes, 1)


class ObservationTests(unittest.TestCase):
    def observe(self, values):
        now = [0]
        messages = []
        iterator = iter(values)

        class Reader:
            def read_power(self):
                return next(iterator, values[-1])

        result = observe_power(
            Reader(),
            0,
            messages.append,
            seconds=12,
            clock=lambda: now[0],
            sleep=lambda n: now.__setitem__(0, now[0] + n),
        )
        return result, messages

    def test_changed_then_restored(self):
        result, _ = self.observe([0, 1, 0])
        self.assertEqual(result["status"], "state_tracking_confirmed")
        self.assertTrue(result["observed_restore"])

    def test_unchanged_is_not_restore_confirmation(self):
        result, messages = self.observe([0, 0, 0])
        self.assertFalse(result["observed_change"])
        self.assertFalse(result["observed_restore"])
        self.assertIn("亲自确认", messages[-1])

    def test_changed_without_restore_is_not_success(self):
        result, _ = self.observe([1, 1, 1])
        self.assertTrue(result["observed_change"])
        self.assertFalse(result["observed_restore"])

    def test_read_failure_still_prompts_owner_to_restore_physically(self):
        now = [0]
        messages = []

        class Reader:
            def read_power(self):
                raise ProbeError("TIMEOUT")

        result = observe_power(
            Reader(),
            0,
            messages.append,
            seconds=12,
            clock=lambda: now[0],
            sleep=lambda n: now.__setitem__(0, now[0] + n),
        )
        self.assertEqual(result["status"], "read_failed")
        self.assertIn("亲自确认", messages[-1])
