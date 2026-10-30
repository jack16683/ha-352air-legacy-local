"""Reports are reconstructed from a whitelist, never dumped from internal state."""

from __future__ import annotations

import re

from . import __version__
from .error_codes import ALLOWED_ERROR_CODES
from .model import CLOUD_STAGES

STATUSES = {
    "not_started",
    "failed",
    "ok",
    "acknowledged",
    "not_confirmed",
    "not_yet_verified",
    "baseline_completed",
    "baseline_incomplete",
    "setup_outcome_unconfirmed",
    "new_key_read_verified_cloud_online",
    "new_key_read_verified_cloud_attention",
    "new_key_read_verified",
    "new_key_not_confirmed",
    "restored_key_read_verified",
    "restore_outcome_unconfirmed",
    "read_failed",
    "state_tracking_confirmed",
}
BOOLS = {
    "plus_identity_verified",
    "expected_firmware_matches",
    "server_proof_verified",
    "online",
    "fresh_sample",
    "observed_change",
    "observed_restore",
    "access_verified_before_write",
    "exact_configuration_restore_guaranteed",
    "toolkit_verified",
    "exact_configuration_restore_available",
    "exact_configuration_restored",
    "target_address_changed",
    "cloud_recheck_attention",
}
NUMBERS = {
    "http_status": (100, 599),
    "power": (0, 1),
    "application_code": (0, 65535),
    "opt": (0, 255),
    "sample_age_seconds": (0, 10**9),
}
STAGES = {
    "cloud_login",
    "cloud_before",
    "old_auth_before",
    "old_read_before",
    "recovery_key_check_auth",
    "recovery_key_read",
    "install_response",
    "new_auth",
    "new_read",
    "old_after_auth",
    "old_read_after",
    "old_existing_session_only",
    "cloud_after",
    "old_auth",
    "old_read",
    "restore_response",
    "restored_auth",
    "restored_read",
    "new_after_restore_auth",
    "new_key_read_after_restore",
}


def safe_result(data):
    if not isinstance(data, dict):
        return {"status": "failed", "reason": "RESULT_INVALID"}
    out = {}
    for key, value in data.items():
        if key == "status" and isinstance(value, str) and value in STATUSES:
            out[key] = value
        elif key == "stage" and isinstance(value, str) and value in CLOUD_STAGES:
            out[key] = value
        elif (
            key == "reason" and isinstance(value, str) and value in ALLOWED_ERROR_CODES
        ):
            out[key] = value
        elif (
            key == "coap_code"
            and isinstance(value, str)
            and re.fullmatch(r"[245]\.[0-9]{2}", value)
        ):
            out[key] = value
        elif key in BOOLS and type(value) is bool:
            out[key] = value
        elif key in NUMBERS:
            lo, hi = NUMBERS[key]
            if value is None:
                out[key] = None
            elif type(value) is int and lo <= value <= hi:
                out[key] = value
        elif (
            key == "power_samples"
            and isinstance(value, list)
            and len(value) <= 16
            and all(type(x) is int and x in (0, 1) for x in value)
        ):
            out[key] = value
    return out


def public_report(report):
    out = {
        "tool_version": __version__,
        "mode": report.get("mode")
        if report.get("mode") in {"baseline", "install", "restore", "verify", "unlock"}
        else "unknown",
        "status": report.get("status")
        if report.get("status") in STATUSES
        else "failed",
    }
    for field in ("identity", "error", "observation", "baseline_observation"):
        if field in report:
            out[field] = safe_result(report[field])
    runtime = report.get("runtime")
    if (
        isinstance(runtime, dict)
        and runtime.get("kind") in {"host", "ha_container", "direct"}
        and isinstance(runtime.get("python"), str)
        and re.fullmatch(r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}", runtime["python"])
    ):
        out["runtime"] = {"kind": runtime["kind"], "python": runtime["python"]}
    out["stages"] = {
        key: safe_result(value)
        for key, value in report.get("stages", {}).items()
        if key in STAGES
    }
    for key in ("write_datagrams", "lan_datagrams_sent"):
        value = report.get(key)
        if type(value) is int and 0 <= value <= 10000:
            out[key] = value
    if report.get("durability") in {
        "not_tested",
        "read_verified_after_operator_reported_reboot",
    }:
        out["durability"] = report["durability"]
    if isinstance(report.get("recovery"), dict):
        value = report["recovery"]
        out["recovery"] = safe_result(value)
        if value.get("kind") in {"known_local_key", "owner_manual_declared"}:
            out["recovery"]["kind"] = value["kind"]
    if report.get("cloud_after") == "not_checked_no_cloud_login":
        out["cloud_after"] = "not_checked_no_cloud_login"
    if type(report.get("exact_configuration_restored")) is bool:
        out["exact_configuration_restored"] = report["exact_configuration_restored"]
    if report.get("cloud_recheck_attention") is True:
        out["cloud_recheck_attention"] = True
    if report.get("observation_attention") is True:
        out["observation_attention"] = True
    return out
