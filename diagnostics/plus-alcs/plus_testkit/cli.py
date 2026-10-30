"""Explicit operator modes; credentials are entered on the local controlling TTY."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import warnings

from .app_config import default_profile, prepare_default_profile
from .cloud import CloudClient, base
from .engine import Engine, observe_power
from .lan import LanClient
from .model import Deadline, ProbeError
from .report import public_report
from .vault import Vault, read_private, recovery_plan


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # Never echo unknown arguments: they might contain a pasted password.
        raise ProbeError("ARGUMENTS_INVALID")


def secret_input(prompt):
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
        os.close(fd)
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except Exception:
        raise ProbeError("INTERACTIVE_TERMINAL_REQUIRED") from None


def profile(path):
    try:
        obj = base.object_json(read_private(path, 16384))
        if set(obj) != {"mx_app_id", "app_key", "app_secret"}:
            raise ValueError
        for value in obj.values():
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 128
                or any(ord(c) < 33 or ord(c) > 126 for c in value)
            ):
                raise ValueError
        return base.AppProfile(**obj)
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("APP_PROFILE_INVALID") from None


def parser():
    p = Parser(
        prog="plus-probe",
        description="352 Plus 测试：先云端基线，再显式安装本地授权；不会发送电源写入。",
    )
    p.add_argument(
        "mode", choices=["baseline", "install", "verify", "restore", "unlock"]
    )
    p.add_argument("target", nargs="?", help="Plus 当前局域网 IPv4；unlock 模式不需要")
    p.add_argument("--state-dir", default="plus-private-state")
    p.add_argument("--report", help="新建脱敏报告文件；默认仅输出 JSON 到 stdout")
    p.add_argument(
        "--profile",
        default=str(default_profile()),
    )
    p.add_argument("--recovery-file", help="权限为600的恢复计划 JSON；install 必须指定")
    p.add_argument(
        "--cloud-check",
        action="store_true",
        help="verify/restore 后额外交互登录官方云端复查；默认只在局域网验证",
    )
    p.add_argument(
        "--observe",
        action="store_true",
        help="读取成功后提示按机身按钮，观察改变和恢复",
    )
    p.add_argument(
        "--after-reboot",
        action="store_true",
        help="verify 时记录运行者已自行重启设备；工具不会重启",
    )
    return p


def emit(report, path=None):
    text = json.dumps(public_report(report), ensure_ascii=False, indent=2) + "\n"
    if path:
        try:
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            print("报告文件不能新建；脱敏结果仍输出在下方。", file=sys.stderr)
    sys.stdout.write(text)


def main(argv=None, *, prompt=secret_input, lan_factory=None, cloud_factory=None):
    report = {
        "mode": "unknown",
        "status": "failed",
        "stages": {},
        "write_datagrams": 0,
        "durability": "not_tested",
    }
    engine = vault = None
    destination = None
    try:
        args = parser().parse_args(argv)
        destination = args.report
        report["mode"] = args.mode
        if args.mode == "unlock":
            vault = Vault(args.state_dir, "unlock-does-not-decrypt")
            vault.unlock_stale()
            report["status"] = "ok"
        else:
            if not args.target:
                raise ProbeError("TARGET_REQUIRED")
            if args.mode == "install" and not args.recovery_file:
                raise ProbeError("RECOVERY_PLAN_REQUIRED")
            if args.after_reboot and args.mode != "verify":
                raise ProbeError("ARGUMENTS_INVALID")
            if args.observe and args.mode not in {"baseline", "install"}:
                raise ProbeError("ARGUMENTS_INVALID")
            if args.cloud_check and args.mode not in {"verify", "restore"}:
                raise ProbeError("ARGUMENTS_INVALID")
            passphrase = prompt("本地恢复文件密码（至少12字符，请勿使用352密码）：")
            vault = Vault(args.state_dir, passphrase)
            exists = vault.exists()
            if not exists:
                if args.mode not in {"baseline", "install"}:
                    raise ProbeError("VAULT_NOT_FOUND")
                if prompt("再次输入本地恢复文件密码：") != passphrase:
                    raise ProbeError("VAULT_PASSWORD_MISMATCH")
            with vault.lock():
                if exists:
                    vault.load()
                if args.mode in {"baseline", "install"} and (
                    vault.attempted("install") or vault.attempted("restore")
                ):
                    raise ProbeError("EXISTING_WRITE_USE_VERIFY_OR_RECOVER")
                deadline = Deadline(240)
                factory = lan_factory or (
                    lambda host: LanClient(host, deadline=deadline)
                )
                cloud = None
                if args.mode in {"baseline", "install"} or args.cloud_check:
                    prepare_default_profile(
                        args.profile, notify=lambda s: print(s, file=sys.stderr)
                    )
                    configuration = profile(args.profile)
                    deadline = Deadline(240)
                    cloud = (cloud_factory or CloudClient)(
                        configuration, deadline=deadline
                    )
                observer = (
                    (
                        lambda client, initial: observe_power(
                            client, initial, lambda s: print(s, file=sys.stderr)
                        )
                    )
                    if args.observe
                    else None
                )
                engine = Engine(args.target, vault, factory, cloud, observe=observer)
                report = engine.report
                report["mode"] = args.mode
                if args.mode in {"baseline", "install"}:
                    plan = (
                        recovery_plan(args.recovery_file)
                        if args.mode == "install"
                        else None
                    )
                    account = prompt("352账号（隐藏输入，仅发往官方认证服务）：")
                    password = prompt("352密码（隐藏输入，不保存或写入报告）：")
                    if password == passphrase:
                        raise ProbeError("DO_NOT_REUSE_ACCOUNT_PASSWORD")
                    engine.baseline(
                        account, password, install=args.mode == "install", recovery=plan
                    )
                    del account, password
                else:
                    engine.verify(
                        after_reboot=args.after_reboot, restore=args.mode == "restore"
                    )
                    if args.cloud_check:
                        account = prompt("352账号（隐藏输入，仅发往官方认证服务）：")
                        password = prompt("352密码（隐藏输入，不保存或写入报告）：")
                        if password == passphrase:
                            raise ProbeError("DO_NOT_REUSE_ACCOUNT_PASSWORD")
                        engine.check_cloud(account, password)
                        del account, password
    except ProbeError as error:
        report["error"] = error.public()
        report["status"] = "failed"
    except KeyboardInterrupt:
        report["error"] = {
            "status": "failed",
            "reason": "INTERRUPTED_CHECK_RECOVERY_JOURNAL",
        }
        report["status"] = "failed"
    except Exception:
        report["error"] = {"status": "failed", "reason": "INTERNAL_ERROR"}
        report["status"] = "failed"
    finally:
        if engine is not None:
            engine.close()
        if vault is not None:
            vault.close()
    runtime_kind = os.environ.get("PLUS_PROBE_RUNTIME_KIND", "direct")
    report["runtime"] = {
        "kind": runtime_kind if runtime_kind in {"host", "ha_container"} else "direct",
        "python": "%d.%d.%d" % sys.version_info[:3],
    }
    emit(report, destination)
    return (
        0
        if not report.get("cloud_recheck_attention")
        and not report.get("observation_attention")
        and report.get("status")
        in {
            "ok",
            "baseline_completed",
            "new_key_read_verified_cloud_online",
            "new_key_read_verified",
            "restored_key_read_verified",
        }
        else 1
    )
