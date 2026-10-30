#!/usr/bin/env python3
"""Standard-library launcher; use host Python or an existing local HA container."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

from plus_testkit.app_config import default_profile
from plus_testkit.model import ProbeError
from plus_testkit.report import public_report

ROOT = Path(__file__).resolve().parent
RUNTIME_FILES = ["probe.py", "LICENSE", "app-profile.private.json"] + [
    "plus_testkit/" + name + ".py"
    for name in [
        "__init__",
        "model",
        "primitives",
        "protocol",
        "lan",
        "cloud_base",
        "cloud",
        "vault",
        "engine",
        "report",
        "error_codes",
        "cli",
        "app_config",
    ]
]
CHECK = "import sys,os; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; from cryptography.hazmat.primitives.kdf.scrypt import Scrypt; from cryptography.hazmat.primitives.ciphers import Cipher; assert sys.version_info >= (3,8)"
EXTRACT = r"""
import os,sys,tarfile
root=sys.argv[1];total=0
with tarfile.open(fileobj=sys.stdin.buffer,mode="r|gz") as archive:
 for member in archive:
  parts=member.name.split("/")
  if not member.isfile() or any(p in ("",".","..") for p in parts) or len(parts)>2 or member.size>1024*1024:raise ValueError("archive")
  if len(parts)==2 and parts[0]!="plus_testkit":raise ValueError("archive")
  total+=member.size
  if total>3*1024*1024:raise ValueError("archive")
  path=os.path.join(root,*parts);os.makedirs(os.path.dirname(path),mode=0o700,exist_ok=True)
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
  with os.fdopen(fd,"wb") as out:out.write(archive.extractfile(member).read())
"""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ProbeError("ARGUMENTS_INVALID")


def parse(argv):
    p = Parser(
        prog="run.sh",
        description="优先使用本机 Python；缺少依赖时只使用已有的本机 HA host 网络容器。账号密码在本机终端交互输入。",
    )
    p.add_argument(
        "mode", choices=["baseline", "install", "verify", "restore", "unlock"]
    )
    p.add_argument("target", nargs="?")
    p.add_argument("--state-dir")
    p.add_argument("--report")
    p.add_argument("--profile")
    p.add_argument("--recovery-file")
    p.add_argument("--ha-container", help="依赖不足且有多个 HA 容器时，选择已有容器")
    p.add_argument("--observe", action="store_true")
    p.add_argument("--cloud-check", action="store_true")
    p.add_argument("--after-reboot", action="store_true")
    return p.parse_args(argv)


def command(args, **kwargs):
    try:
        return subprocess.run(
            args, capture_output=True, timeout=kwargs.pop("timeout", 10), **kwargs
        )
    except Exception:
        raise ProbeError("RUNTIME_COMMAND_FAILED") from None


def local_docker():
    configured = os.environ.get("DOCKER_HOST", "")
    if configured and not configured.startswith("unix://"):
        raise ProbeError("REMOTE_DOCKER_NOT_ALLOWED")
    result = command(
        ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        text=True,
    )
    if result.returncode or not result.stdout.strip().startswith("unix://"):
        raise ProbeError("REMOTE_DOCKER_NOT_ALLOWED")


def container_ready(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
        return False
    result = command(
        [
            "docker",
            "inspect",
            "--format",
            "{{.Config.Image}}|{{.HostConfig.NetworkMode}}",
            name,
        ],
        text=True,
    )
    if result.returncode:
        return False
    image, sep, mode = result.stdout.strip().rpartition("|")
    if (
        not sep
        or mode != "host"
        or not any(s in image.lower() for s in ("homeassistant", "home-assistant"))
    ):
        return False
    result = command(
        [
            "docker",
            "exec",
            name,
            "python3",
            "-c",
            CHECK + "; sys.exit(0 if os.path.isdir('/config') else 1)",
        ]
    )
    return result.returncode == 0


def select_container(explicit=None):
    local_docker()
    if explicit:
        if not container_ready(explicit):
            raise ProbeError("HA_CONTAINER_UNSUITABLE")
        return explicit
    result = command(["docker", "ps", "--format", "{{.ID}}"], text=True)
    if result.returncode:
        raise ProbeError("DOCKER_UNAVAILABLE")
    matches = [
        line
        for line in result.stdout.splitlines()
        if re.fullmatch(r"[0-9a-f]{12,64}", line) and container_ready(line)
    ]
    if not matches:
        raise ProbeError("HA_RUNTIME_NOT_AVAILABLE")
    if len(matches) != 1:
        raise ProbeError("HA_CONTAINER_AMBIGUOUS")
    return matches[0]


def private_bytes(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            s = os.fstat(fd)
            if (
                not stat.S_ISREG(s.st_mode)
                or s.st_uid != os.geteuid()
                or s.st_mode & 0o077
                or s.st_nlink != 1
                or s.st_size > 16384
            ):
                raise ProbeError("PRIVATE_FILE_UNSAFE")
            return os.read(fd, 16385)
        finally:
            os.close(fd)
    except ProbeError:
        raise
    except OSError:
        raise ProbeError("PRIVATE_FILE_UNREADABLE") from None


def payload(profile_path=None, recovery_path=None, include_profile=True):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name in RUNTIME_FILES:
            if name == "app-profile.private.json" and not include_profile:
                continue
            if name == "app-profile.private.json":
                source = Path(profile_path) if profile_path else default_profile()
                if not source.exists() and not source.is_symlink() and not profile_path:
                    continue
                body = private_bytes(source)
            else:
                body = (ROOT / name).read_bytes()
            item = tarfile.TarInfo(name)
            item.size = len(body)
            item.mode = 0o600
            archive.addfile(item, io.BytesIO(body))
        if recovery_path:
            body = private_bytes(recovery_path)
            item = tarfile.TarInfo("recovery-plan.private.json")
            item.size = len(body)
            item.mode = 0o600
            archive.addfile(item, io.BytesIO(body))
    return data.getvalue()


def set_option(argv, option, value):
    out = []
    i = 0
    while i < len(argv):
        if argv[i] == option:
            i += 2
            continue
        if argv[i].startswith(option + "="):
            i += 1
            continue
        out.append(argv[i])
        i += 1
    if value is not None:
        out += [option, value]
    return out


def docker_launch(args, argv):
    name = select_container(args.ha_container)
    if args.mode != "unlock" and not sys.stdin.isatty():
        raise ProbeError("INTERACTIVE_TERMINAL_REQUIRED")
    destination = Path(args.report or ("plus-" + args.mode + "-report.json"))
    if destination.exists() or destination.is_symlink():
        raise ProbeError("REPORT_FILE_EXISTS")
    result = command(
        [
            "docker",
            "exec",
            name,
            "python3",
            "-c",
            "import tempfile;print(tempfile.mkdtemp(prefix='plus-alcs-probe-'))",
        ],
        text=True,
    )
    remote = result.stdout.strip()
    if result.returncode or not re.fullmatch(
        r"/tmp/plus-alcs-probe-[A-Za-z0-9_-]+", remote
    ):
        raise ProbeError("CONTAINER_TEMP_FAILED")
    try:
        uploaded = command(
            ["docker", "exec", "-i", name, "python3", "-c", EXTRACT, remote],
            input=payload(
                args.profile,
                args.recovery_file,
                include_profile=args.mode in {"baseline", "install"}
                or args.cloud_check,
            ),
        )
        if uploaded.returncode:
            raise ProbeError("CONTAINER_COPY_FAILED")
        forwarded = set_option(argv, "--ha-container", None)
        state = args.state_dir or "/config/plus-private-state"
        if not state.startswith("/config/") or "/../" in state or state.endswith("/.."):
            raise ProbeError("CONTAINER_STATE_PATH_INVALID")
        forwarded = set_option(forwarded, "--state-dir", state)
        source_profile = Path(args.profile) if args.profile else default_profile()
        forwarded = set_option(
            forwarded,
            "--profile",
            remote + "/app-profile.private.json"
            if source_profile.exists() or source_profile.is_symlink()
            else None,
        )
        forwarded = set_option(forwarded, "--report", remote + "/sanitized-report.json")
        if args.recovery_file:
            forwarded = set_option(
                forwarded, "--recovery-file", remote + "/recovery-plan.private.json"
            )
        print(
            "使用已有的本机 HA host 网络容器；恢复资料保存在其 /config 下，账号密码只在交互终端输入。",
            file=sys.stderr,
        )
        run = subprocess.run(
            [
                "docker",
                "exec",
                "-i" if args.mode == "unlock" else "-it",
                "-e",
                "PLUS_PROBE_RUNTIME_KIND=ha_container",
                name,
                "python3",
                remote + "/probe.py",
                *forwarded,
            ]
        )
        received = command(
            [
                "docker",
                "exec",
                name,
                "python3",
                "-c",
                "import sys;sys.stdout.buffer.write(open(sys.argv[1],'rb').read(1048577))",
                remote + "/sanitized-report.json",
            ]
        )
        if received.returncode or len(received.stdout) > 1024 * 1024:
            raise ProbeError("CONTAINER_REPORT_UNAVAILABLE")
        try:
            report = public_report(json.loads(received.stdout))
        except Exception:
            raise ProbeError("CONTAINER_REPORT_INVALID") from None
        fd = os.open(
            str(destination),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        print("已保存指定的脱敏报告；恢复目录不要上传。", file=sys.stderr)
        return run.returncode
    finally:
        try:
            cleanup = command(
                [
                    "docker",
                    "exec",
                    name,
                    "python3",
                    "-c",
                    "import shutil,sys;shutil.rmtree(sys.argv[1])",
                    remote,
                ]
            )
            if cleanup.returncode:
                raise ProbeError("CONTAINER_COPY_FAILED")
        except ProbeError:
            print("容器临时工具清理未确认；恢复资料仍保留在 /config。", file=sys.stderr)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parse(argv)
        ready = command([sys.executable, "-c", CHECK])
        if ready.returncode == 0 and not args.ha_container:
            os.environ["PLUS_PROBE_RUNTIME_KIND"] = "host"
            os.execv(sys.executable, [sys.executable, str(ROOT / "probe.py"), *argv])
        return docker_launch(args, argv)
    except ProbeError as error:
        print(
            json.dumps(
                {"status": "failed", "error": error.public()}, ensure_ascii=False
            )
        )
        return 2
    except KeyboardInterrupt:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error": {"reason": "INTERRUPTED_CHECK_RECOVERY_JOURNAL"},
                }
            )
        )
        return 130
    except Exception:
        print(
            json.dumps(
                {"status": "failed", "error": {"reason": "RUNTIME_LAUNCH_FAILED"}}
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
