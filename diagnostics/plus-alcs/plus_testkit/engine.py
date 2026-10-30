"""Cloud-first orchestration, durable one-shot installation and explicit restore."""

from __future__ import annotations

import time

from . import __version__
from .model import Access, Identity, ProbeError, ServerKey, outcome


class Engine:
    def __init__(self, target, vault, lan_factory, cloud=None, *, observe=None):
        self.target, self.vault, self.lan_factory, self.cloud = (
            target,
            vault,
            lan_factory,
            cloud,
        )
        self.observe = observe
        self.clients = []
        self.report = {
            "tool_version": __version__,
            "mode": "",
            "status": "not_started",
            "identity": {},
            "stages": {},
            "write_datagrams": 0,
            "durability": "not_tested",
        }

    def client(self):
        client = self.lan_factory(self.target)
        self.clients.append(client)
        return client

    def identify(self, client):
        identity = client.identify()
        saved = self.vault.data.get("identity")
        if saved and (
            saved.get("product") != identity.product
            or saved.get("name") != identity.name
        ):
            raise ProbeError("VAULT_IDENTITY_MISMATCH")
        self.report["identity"] = identity.public()
        if saved:
            self.report["identity"]["target_address_changed"] = (
                self.vault.data.get("target") != self.target
            )
        return identity

    def connect(self, access, stage):
        client = self.client()
        self.identify(client)
        try:
            result = client.authenticate(access)
            self.report["stages"][stage + "_auth"] = result
        except ProbeError as error:
            self.report["stages"][stage + "_auth"] = error.public()
            raise
        return client

    def read(self, client, stage):
        result = outcome(client.read_power)
        self.report["stages"][stage] = result
        return result

    def baseline(self, account, password, *, install=False, recovery=None):
        self.report["mode"] = "install" if install else "baseline"
        if self.vault.attempted("install") or self.vault.attempted("restore"):
            raise ProbeError("EXISTING_WRITE_USE_VERIFY_OR_RECOVER")
        if self.cloud is None:
            raise ProbeError("CLOUD_CLIENT_REQUIRED")
        first = self.client()
        identity = self.identify(first)
        # No persistent write or key generation before a cloud baseline exists.
        self.report["stages"]["cloud_login"] = self.cloud.login(account, password)
        access = self.cloud.access_for(identity)
        cloud_before = self.cloud.snapshot()
        self.report["stages"]["cloud_before"] = cloud_before
        self.vault.data.update(
            {
                "identity": {
                    "product": identity.product,
                    "name": identity.name,
                    "firmware": identity.firmware,
                },
                "target": self.target,
                "original_access": access.private(),
                "cloud_baseline": cloud_before,
            }
        )
        self.vault.save()
        try:
            self.report["stages"]["old_auth_before"] = first.authenticate(access)
        except ProbeError as error:
            self.report["stages"]["old_auth_before"] = error.public()
            raise
        before = self.read(first, "old_read_before")
        if before["status"] != "ok":
            raise ProbeError("LOCAL_BASELINE_INCOMPLETE")
        self.vault.data["original_power"] = before["power"]
        self.vault.save()
        self.report["status"] = "baseline_completed"
        if self.observe:
            self.report["baseline_observation"] = self.observe(first, before["power"])
            if self.report["baseline_observation"].get("observed_restore") is not True:
                self.report["observation_attention"] = True
                self.report["status"] = "baseline_incomplete"
                if install:
                    raise ProbeError("PHYSICAL_STATE_RESTORE_NOT_CONFIRMED")
                return self.report
            cloud_before = self.cloud.snapshot()
            self.report["stages"]["cloud_before"] = cloud_before
            self.vault.data["cloud_baseline"] = cloud_before
            self.vault.save()
        if not install:
            return self.report
        if not identity.public()["expected_firmware_matches"]:
            raise ProbeError("FIRMWARE_REVIEW_REQUIRED")
        if cloud_before.get("online") is not True:
            raise ProbeError("CLOUD_BASELINE_OFFLINE")
        if cloud_before.get("fresh_sample") is not True:
            raise ProbeError("CLOUD_BASELINE_STALE")
        if cloud_before.get("power") != before["power"]:
            raise ProbeError("CLOUD_LAN_BASELINE_MISMATCH")
        if recovery is None:
            raise ProbeError("RECOVERY_PLAN_REQUIRED")
        if recovery["kind"] == "known_local_key":
            backup = ServerKey(recovery["prefix"], recovery["secret"])
            restored_access = backup.access(identity)
            check = self.connect(restored_access, "recovery_key_check")
            result = self.read(check, "recovery_key_read")
            if result["status"] != "ok":
                raise ProbeError("RECOVERY_KEY_NOT_VERIFIED")
            self.report["recovery"] = {
                "kind": "known_local_key",
                "access_verified_before_write": True,
                "exact_configuration_restore_guaranteed": False,
            }
        else:
            self.report["recovery"] = {
                "kind": "owner_manual_declared",
                "toolkit_verified": False,
                "exact_configuration_restore_available": False,
            }
        excluded = [access.key[:8]]
        if recovery["kind"] == "known_local_key":
            excluded.append(recovery["prefix"])
        new_key = ServerKey.generate(excluded)
        self.vault.data.update(
            {
                "new_server_key": new_key.private(),
                "recovery": recovery,
                "phase": "prepared",
            }
        )
        self.vault.save()
        self._write(first, new_key, "install")
        # An ACK/old live session never counts as proof of the new key.
        new_access = new_key.access(identity)
        try:
            new_client = self.connect(new_access, "new")
            result = self.read(new_client, "new_read")
            if self.observe and result["status"] == "ok":
                self.report["observation"] = self.observe(new_client, result["power"])
                if self.report["observation"].get("observed_restore") is not True:
                    self.report["observation_attention"] = True
        except ProbeError:
            self.report["stages"]["new_read"] = {"status": "not_confirmed"}
        try:
            old_client = self.connect(access, "old_after")
            self.read(old_client, "old_read_after")
        except ProbeError:
            self.report["stages"]["old_read_after"] = {"status": "not_confirmed"}
            self.read(first, "old_existing_session_only")
        self.report["stages"]["cloud_after"] = outcome(self.cloud.snapshot)
        new_ok = self.report["stages"]["new_read"]["status"] == "ok"
        cloud_after = self.report["stages"]["cloud_after"]
        cloud_ok = (
            cloud_after.get("online") is True
            and cloud_after.get("fresh_sample") is True
            and cloud_after.get("power")
            == self.report["stages"]["new_read"].get("power")
        )
        self.report["status"] = (
            (
                "new_key_read_verified_cloud_online"
                if cloud_ok
                else "new_key_read_verified_cloud_attention"
            )
            if new_ok
            else "setup_outcome_unconfirmed"
        )
        self.vault.data["last_public_result"] = self.report
        self.vault.save()
        return self.report

    def _write(self, client, key, operation):
        try:
            result = client.install(key, lambda: self.vault.mark_attempt(operation))
        except ProbeError as error:
            result = error.public()
        self.report["stages"][operation + "_response"] = result
        if not self.vault.attempted(operation):
            raise ProbeError("WRITE_NOT_JOURNALED")
        self.vault.data["operations"][operation]["response"] = result
        self.vault.save()

    def verify(self, *, after_reboot=False, restore=False):
        self.report["mode"] = "restore" if restore else "verify"
        state = self.vault.data
        if not state.get("new_server_key") or not state.get("identity"):
            raise ProbeError("NO_INSTALLATION_RECORD")
        identity = Identity(**state["identity"])
        original = Access.load(state["original_access"], identity)
        new_key = ServerKey(**state["new_server_key"])
        current = None
        for label, access in [("new", new_key.access(identity)), ("old", original)]:
            try:
                candidate = self.connect(access, label)
                self.read(candidate, label + "_read")
                if current is None:
                    current = candidate
            except ProbeError:
                self.report["stages"][label + "_read"] = {"status": "not_confirmed"}
        if not restore:
            self.report["status"] = (
                "new_key_read_verified"
                if self.report["stages"]["new_read"]["status"] == "ok"
                else "new_key_not_confirmed"
            )
            self.report["durability"] = (
                "read_verified_after_operator_reported_reboot"
                if after_reboot and self.report["status"] == "new_key_read_verified"
                else "not_tested"
            )
            return self.report
        recovery = state.get("recovery", {})
        if recovery.get("kind") != "known_local_key":
            raise ProbeError("MANUAL_RECOVERY_REQUIRED")
        if self.vault.attempted("restore"):
            raise ProbeError("RESTORE_ALREADY_ATTEMPTED")
        if current is None:
            raise ProbeError("NO_AUTHORIZED_RESTORE_SESSION")
        backup = ServerKey(recovery["prefix"], recovery["secret"])
        self._write(current, backup, "restore")
        try:
            restored = self.connect(backup.access(identity), "restored")
            result = self.read(restored, "restored_read")
        except ProbeError:
            result = {"status": "not_confirmed"}
            self.report["stages"]["restored_read"] = result
        self.report["status"] = (
            "restored_key_read_verified"
            if result["status"] == "ok"
            else "restore_outcome_unconfirmed"
        )
        self.report["exact_configuration_restored"] = False
        self.report["cloud_after"] = "not_checked_no_cloud_login"
        try:
            retained = self.connect(new_key.access(identity), "new_after_restore")
            self.read(retained, "new_key_read_after_restore")
        except ProbeError:
            self.report["stages"]["new_key_read_after_restore"] = {
                "status": "not_confirmed"
            }
        self.vault.data["last_public_result"] = self.report
        self.vault.save()
        return self.report

    def check_cloud(self, account, password):
        if self.cloud is None:
            raise ProbeError("CLOUD_CLIENT_REQUIRED")
        identity = Identity(**self.vault.data["identity"])
        self.report["stages"]["cloud_login"] = self.cloud.login(account, password)
        self.cloud.select_target(identity)
        self.report["stages"]["cloud_after"] = outcome(self.cloud.snapshot)
        self.report.pop("cloud_after", None)
        snapshot = self.report["stages"]["cloud_after"]
        local = self.report["stages"].get(
            "restored_read", self.report["stages"].get("new_read", {})
        )
        if (
            snapshot.get("online") is not True
            or snapshot.get("fresh_sample") is not True
            or local.get("status") != "ok"
            or snapshot.get("power") != local.get("power")
        ):
            self.report["cloud_recheck_attention"] = True

    def close(self):
        self.report["write_datagrams"] = sum(
            client.stats.get("write_datagrams", 0) for client in self.clients
        )
        self.report["lan_datagrams_sent"] = sum(
            client.stats.get("datagrams_sent", 0) for client in self.clients
        )
        for client in self.clients:
            try:
                client.close()
            except Exception:
                pass
        if self.cloud is not None:
            try:
                self.cloud.close()
            except Exception:
                pass


def observe_power(
    client, initial, prompt, *, seconds=45, clock=time.monotonic, sleep=time.sleep
):
    prompt(
        "设备初始电源为 %s；请在45秒内按机身电源切换一次、保持约5秒，再恢复原状态。工具只读取状态。"
        % ("ON" if initial else "OFF")
    )
    deadline = clock() + seconds
    changed = False
    restored = False
    samples = []
    while clock() < deadline and len(samples) < 16:
        sleep(min(3, max(0, deadline - clock())))
        if clock() >= deadline:
            break
        try:
            value = client.read_power()
        except ProbeError:
            prompt("读取失败，请亲自确认机器已恢复原电源状态；工具不会自动切换电源。")
            return {
                "status": "read_failed",
                "observed_change": changed,
                "observed_restore": False,
            }
        samples.append(value)
        if value != initial:
            changed = True
        elif changed:
            restored = True
            break
    if not restored:
        prompt(
            "未完整观察到状态改变和恢复，请亲自确认机器已恢复原电源状态；工具不会自动切换电源。"
        )
    return {
        "status": "state_tracking_confirmed"
        if changed and restored
        else "not_confirmed",
        "observed_change": changed,
        "observed_restore": restored,
        "power_samples": samples,
    }
