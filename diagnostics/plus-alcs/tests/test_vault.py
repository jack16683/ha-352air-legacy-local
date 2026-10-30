import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from plus_testkit.model import ProbeError
from plus_testkit.vault import Vault, recovery_plan
from support import OLD, PASSPHRASE, PASSWORD


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / "private"
        self.vault = Vault(self.folder, PASSPHRASE)
        self.addCleanup(self.vault.close)

    def save(self):
        self.vault.data["new_server_key"] = OLD.private()
        self.vault.save()

    def test_roundtrip_is_encrypted_with_restricted_file_and_directory_modes(self):
        self.save()
        path = self.folder / "recovery.enc.json"
        raw = path.read_bytes()
        self.assertNotIn(OLD.secret.encode(), raw)
        self.assertNotIn(OLD.prefix.encode(), raw)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.folder.stat().st_mode), 0o700)
        self.assertEqual(self.vault.load()["new_server_key"], OLD.private())

    def test_wrong_passphrase_fails_authentication(self):
        self.save()
        other = Vault(self.folder, "SYNTH_WRONG_PASSPHRASE")
        self.addCleanup(other.close)
        with self.assertRaisesRegex(ProbeError, "VAULT_DECRYPT_FAILED"):
            other.load()

    def test_tampered_ciphertext_is_rejected(self):
        self.save()
        path = self.folder / "recovery.enc.json"
        obj = json.loads(path.read_text())
        obj["ciphertext"] = "A" + obj["ciphertext"][1:]
        path.write_text(json.dumps(obj))
        with self.assertRaises(ProbeError):
            self.vault.load()

    def test_untrusted_kdf_parameters_are_not_executed(self):
        self.save()
        path = self.folder / "recovery.enc.json"
        obj = json.loads(path.read_text())
        obj["kdf"] = "scrypt-999999999-8-1"
        path.write_text(json.dumps(obj))
        with self.assertRaisesRegex(ProbeError, "VAULT_INVALID"):
            self.vault.load()

    def test_password_and_cloud_token_fields_are_forbidden_even_inside_nested_objects(
        self,
    ):
        for key in ["password", "account", "username", "iot_token", "refresh_token"]:
            self.vault.data["nested"] = {key: PASSWORD}
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ProbeError, "VAULT_FORBIDDEN_FIELD"),
            ):
                self.vault.save()
        self.assertFalse(self.vault.exists())

    def test_symlink_vault_target_is_not_followed(self):
        outside = Path(self.temp.name) / "outside"
        outside.write_text("unchanged")
        (self.folder / "recovery.enc.json").symlink_to(outside)
        with self.assertRaises(ProbeError):
            self.save()
        self.assertEqual(outside.read_text(), "unchanged")

    def test_public_permissions_and_hardlinks_are_rejected(self):
        self.save()
        path = self.folder / "recovery.enc.json"
        path.chmod(0o644)
        with self.assertRaisesRegex(ProbeError, "PRIVATE_FILE_UNSAFE"):
            self.vault.load()
        path.chmod(0o600)
        os.link(path, self.folder / "second-link")
        with self.assertRaisesRegex(ProbeError, "PRIVATE_FILE_UNSAFE"):
            self.vault.load()

    def test_atomic_update_has_no_plaintext_or_leftover_temporary_files(self):
        self.save()
        self.vault.data["phase"] = "prepared"
        self.vault.save()
        self.assertEqual(self.vault.load()["phase"], "prepared")
        self.assertEqual(
            sorted(p.name for p in self.folder.iterdir()), ["recovery.enc.json"]
        )

    def test_one_shot_journal_survives_reopen(self):
        self.vault.mark_attempt("install")
        check = Vault(self.folder, PASSPHRASE)
        self.addCleanup(check.close)
        check.load()
        self.assertTrue(check.attempted("install"))
        with self.assertRaisesRegex(ProbeError, "WRITE_ALREADY_JOURNALED"):
            check.mark_attempt("install")

    def test_lock_prevents_concurrent_process_and_active_lock_cannot_be_unlocked(self):
        with self.vault.lock():
            with self.assertRaisesRegex(ProbeError, "STATE_LOCKED"):
                with self.vault.lock():
                    pass
            with self.assertRaisesRegex(ProbeError, "LOCK_PROCESS_ALIVE"):
                self.vault.unlock_stale()
        self.assertFalse((self.folder / "run.lock").exists())

    def test_stale_lock_can_be_removed_without_decrypting_or_retrying_write(self):
        path = self.folder / "run.lock"
        path.write_text("99999999")
        path.chmod(0o600)
        self.vault.unlock_stale()
        self.assertFalse(path.exists())

    def test_recovery_plan_rejects_unexpected_fields_and_weak_permissions(self):
        path = self.folder / "plan.json"
        path.write_text(
            json.dumps(
                {
                    "kind": "owner_manual",
                    "procedure": "official_app_repair",
                    "owner_can_execute": True,
                    "password": PASSWORD,
                }
            )
        )
        path.chmod(0o600)
        with self.assertRaisesRegex(ProbeError, "RECOVERY_PLAN_INVALID"):
            recovery_plan(path)
        path.write_text(
            json.dumps(
                {
                    "kind": "owner_manual",
                    "procedure": "official_app_repair",
                    "owner_can_execute": True,
                }
            )
        )
        path.chmod(0o644)
        with self.assertRaisesRegex(ProbeError, "PRIVATE_FILE_UNSAFE"):
            recovery_plan(path)
        path.chmod(0o600)
        self.assertEqual(recovery_plan(path)["kind"], "owner_manual")
