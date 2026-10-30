"""Prepare application signing configuration locally; never runs an Android app.

Only the pinned public distribution is read, never uploaded or redistributed.
DEX layout: https://source.android.com/docs/core/runtime/dex-format
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import stat
import struct
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile
from pathlib import Path

from .model import ProbeError

APP_URL = "https://imtt.dd.qq.com/sjy.00009/sjy.00004/16891/apk/B150DC794F42DB430C0AAE7B80F3FB01.apk?fsname=com.mxchip.project352_1.8.1.apk"
APP_SIZE = 165115607
APP_SHA256 = "8748c78c74f0c8f2447b309fb6ba3744414689cfcf7424d5b101c1839e264c2c"


def default_profile():
    root = (
        Path("/config")
        if os.environ.get("PLUS_PROBE_RUNTIME_KIND") == "ha_container"
        else Path(__file__).resolve().parents[1]
    )
    return root / "plus-cloud-config/app-profile.private.json"


class DistributionRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.count = 0
        super().__init__()

    def redirect_request(self, request, response, code, message, headers, url):
        target = urlsplit(url)
        self.count += 1
        if (
            self.count > 3
            or target.scheme != "https"
            or target.username
            or target.password
            or not re.fullmatch(r"[0-9a-f]{32}\.rdt\.tfogc\.com", target.hostname or "")
        ):
            raise ProbeError("APP_DOWNLOAD_REDIRECT_BLOCKED")
        return super().redirect_request(request, response, code, message, headers, url)


class Dex:
    """Bounded parser for static fields in the pinned standard DEX format."""

    def __init__(self, raw):
        self.raw = raw
        if len(raw) < 112 or raw[:8] not in (
            b"dex\n035\x00",
            b"dex\n037\x00",
            b"dex\n038\x00",
            b"dex\n039\x00",
        ):
            raise ValueError
        if (
            self.u32(32) != len(raw)
            or self.u32(36) != 112
            or self.u32(40) != 0x12345678
        ):
            raise ValueError
        self.strings = self.table(56, 4)
        self.types = self.table(64, 4)
        self.fields = self.table(80, 8)
        self.classes = self.table(96, 32)

    def take(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.raw):
            raise ValueError
        return self.raw[offset : offset + size]

    def u32(self, offset):
        return struct.unpack("<I", self.take(offset, 4))[0]

    def table(self, offset, width):
        count, start = struct.unpack("<II", self.take(offset, 8))
        if count > 1000000:
            raise ValueError
        self.take(start, count * width)
        return count, start, width

    def entry(self, table, index):
        count, offset, width = table
        if index < 0 or index >= count:
            raise ValueError
        return offset + index * width

    def leb(self, offset):
        value = 0
        for shift in range(0, 35, 7):
            byte = self.take(offset, 1)[0]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128 and value <= 0xFFFFFFFF:
                return value, offset
        raise ValueError

    def string(self, index):
        offset = self.u32(self.entry(self.strings, index))
        length, offset = self.leb(offset)
        end = self.raw.find(b"\x00", offset, min(len(self.raw), offset + 2049))
        if end < 0 or length > 2048:
            raise ValueError
        raw = self.take(offset, end - offset)
        # Target class names, field names and application values are ASCII.
        return raw.decode("ascii")

    def descriptor(self, index):
        return self.string(self.u32(self.entry(self.types, index)))

    def static_strings(self, descriptor, names):
        for index in range(self.classes[0]):
            offset = self.entry(self.classes, index)
            try:
                found = self.descriptor(self.u32(offset))
            except UnicodeDecodeError:
                continue
            if found != descriptor:
                continue
            data_offset, values_offset = self.u32(offset + 24), self.u32(offset + 28)
            if not data_offset or not values_offset:
                raise ValueError
            count, position = self.leb(data_offset)
            for _ in range(3):
                _, position = self.leb(position)
            if count > 4096:
                raise ValueError
            fields = []
            field_index = 0
            for _ in range(count):
                delta, position = self.leb(position)
                flags, position = self.leb(position)
                field_index += delta
                field = self.entry(self.fields, field_index)
                owner, type_index, name_index = struct.unpack(
                    "<HHI", self.take(field, 8)
                )
                if self.descriptor(owner) != descriptor or not flags & 8:
                    raise ValueError
                fields.append((self.string(name_index), self.descriptor(type_index)))
            length, position = self.leb(values_offset)
            if length > count:
                raise ValueError
            result = {}
            for index in range(length):
                tag = self.take(position, 1)[0]
                position += 1
                kind, arg = tag & 31, tag >> 5
                if kind in (0x1E, 0x1F):
                    if (kind == 0x1E and arg != 0) or (kind == 0x1F and arg > 1):
                        raise ValueError
                    value = None
                elif kind in (0x00, 0x02, 0x03, 0x04, 0x06, 0x10, 0x11, 0x17):
                    value = int.from_bytes(self.take(position, arg + 1), "little")
                    position += arg + 1
                else:
                    raise ValueError
                name, field_type = fields[index]
                if name in names:
                    if (
                        kind != 0x17
                        or arg > 3
                        or field_type != "Ljava/lang/String;"
                        or name in result
                    ):
                        raise ValueError
                    result[name] = self.string(value)
            if set(result) != set(names):
                raise ValueError
            return result
        return None


def extract_profile(apk):
    apk.seek(0)
    digest = hashlib.sha256()
    size = 0
    while True:
        block = apk.read(1024 * 1024)
        if not block:
            break
        size += len(block)
        digest.update(block)
    if size != APP_SIZE or digest.hexdigest() != APP_SHA256:
        raise ProbeError("APP_DISTRIBUTION_MISMATCH")
    apk.seek(0)
    try:
        with zipfile.ZipFile(apk) as archive:
            dex_files = []
            for name in ("classes.dex", "classes2.dex"):
                members = [m for m in archive.infolist() if m.filename == name]
                if len(members) != 1 or members[0].file_size > 32 * 1024 * 1024:
                    raise ValueError
                dex_files.append(Dex(archive.read(members[0])))
        config = dex_files[0].static_strings(
            "Lcom/mxchip/project352/BuildConfig;", {"fyKey", "fySecret"}
        )
        constants = dex_files[1].static_strings(
            "Lcom/mxchip/project352/constants/MxConstant;", {"APPID"}
        )
        if config is None or constants is None:
            raise ValueError
        result = {
            "mx_app_id": constants["APPID"],
            "app_key": config["fyKey"],
            "app_secret": config["fySecret"],
        }
        if any(
            not value or len(value) > 128 or not all(33 <= ord(c) <= 126 for c in value)
            for value in result.values()
        ):
            raise ValueError
        return result
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("APP_CONFIG_EXTRACTION_FAILED") from None


def download_profile():
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        DistributionRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    end = time.monotonic() + 300
    try:
        with tempfile.TemporaryFile() as apk:
            request = urllib.request.Request(
                APP_URL, headers={"Accept-Encoding": "identity"}
            )
            with opener.open(request, timeout=20) as response:
                if (
                    response.status != 200
                    or response.headers.get("Content-Encoding", "identity")
                    != "identity"
                ):
                    raise ProbeError("APP_DOWNLOAD_FAILED")
                total = 0
                while True:
                    if time.monotonic() >= end:
                        raise ProbeError("APP_DOWNLOAD_TIMEOUT")
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > APP_SIZE:
                        raise ProbeError("APP_DISTRIBUTION_MISMATCH")
                    apk.write(block)
            return extract_profile(apk)
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("APP_DOWNLOAD_FAILED") from None
    finally:
        opener.close()


def prepare_default_profile(path, *, notify):
    path = Path(path)
    if path.exists() or path.is_symlink():
        return
    if path != default_profile():
        raise ProbeError("APP_PROFILE_REQUIRED")
    directory = path.parent
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ProbeError("APP_CONFIG_DIRECTORY_UNSAFE")
    notify(
        "首次准备云端登录配置：下载并校验固定版本公开安装包（约158 MiB），不安装或运行 App；不需要你提供 App 或 token。"
    )
    values = download_profile()
    raw = (json.dumps(values, separators=(",", ":")) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".config-", dir=str(directory))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Exclusive link publishes a complete private file without overwriting one.
        os.link(temporary, str(path), follow_symlinks=False)
        fd = os.open(str(directory), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        raise ProbeError("APP_CONFIG_SAVE_FAILED") from None
    finally:
        os.unlink(temporary)
