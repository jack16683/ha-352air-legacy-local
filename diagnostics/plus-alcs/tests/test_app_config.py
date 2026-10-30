"""Generated DEX fixtures and mocked distribution transport; no real account."""

import contextlib
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from plus_testkit import app_config as config
from plus_testkit.model import ProbeError


def leb(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def dex_fixture(descriptor, values):
    strings = sorted({descriptor, "Ljava/lang/String;", *values, *values.values()})
    types = [descriptor, "Ljava/lang/String;"]
    names = sorted(values)
    string_start = 112
    type_start = string_start + len(strings) * 4
    field_start = type_start + len(types) * 4
    class_start = field_start + len(names) * 8
    raw = bytearray(class_start + 32)
    for index, string in enumerate(strings):
        struct.pack_into("<I", raw, string_start + index * 4, len(raw))
        raw.extend(leb(len(string)) + string.encode() + b"\x00")
    for index, name in enumerate(types):
        struct.pack_into("<I", raw, type_start + index * 4, strings.index(name))
    for index, name in enumerate(names):
        struct.pack_into(
            "<HHI", raw, field_start + index * 8, 0, 1, strings.index(name)
        )
    data = len(raw)
    raw.extend(leb(len(names)) + b"\x00\x00\x00")
    for index in range(len(names)):
        raw.extend(leb(0 if index == 0 else 1) + leb(0x19))
    encoded = len(raw)
    raw.extend(leb(len(names)))
    for name in names:
        raw.extend(b"\x17" + bytes([strings.index(values[name])]))
    struct.pack_into("<I", raw, class_start, 0)
    struct.pack_into("<II", raw, class_start + 24, data, encoded)
    raw[:8] = b"dex\n035\x00"
    struct.pack_into("<III", raw, 32, len(raw), 112, 0x12345678)
    for offset, count, start in (
        (56, len(strings), string_start),
        (64, 2, type_start),
        (80, len(names), field_start),
        (96, 1, class_start),
    ):
        struct.pack_into("<II", raw, offset, count, start)
    return bytes(raw)


VALUES = {
    "mx_app_id": "synthetic-id",
    "app_key": "synthetic-key",
    "app_secret": "synthetic-app-secret",
}


def apk_fixture():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr(
            "classes.dex",
            dex_fixture(
                "Lcom/mxchip/project352/BuildConfig;",
                {"fyKey": VALUES["app_key"], "fySecret": VALUES["app_secret"]},
            ),
        )
        archive.writestr(
            "classes2.dex",
            dex_fixture(
                "Lcom/mxchip/project352/constants/MxConstant;",
                {"APPID": VALUES["mx_app_id"]},
            ),
        )
    return data.getvalue()


class Response:
    status = 200
    headers = {}

    def __init__(self, raw):
        self.stream = io.BytesIO(raw)

    def read(self, count):
        return self.stream.read(count)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class Opener:
    def __init__(self, raw):
        self.raw = raw
        self.requests = []

    def open(self, request, **kwargs):
        self.requests.append(request)
        return Response(self.raw)

    def close(self):
        pass


class AppConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.raw = apk_fixture()
        self.stack = self.enterContext(contextlib.ExitStack())
        self.stack.enter_context(patch.object(config, "APP_SIZE", len(self.raw)))
        self.stack.enter_context(
            patch.object(config, "APP_SHA256", hashlib.sha256(self.raw).hexdigest())
        )

    def test_generated_two_dex_static_field_lookup(self):
        self.assertEqual(config.extract_profile(io.BytesIO(self.raw)), VALUES)

    def test_modified_distribution_fails_before_any_extraction(self):
        with self.assertRaisesRegex(ProbeError, "APP_DISTRIBUTION_MISMATCH"):
            config.extract_profile(io.BytesIO(self.raw[:-1] + b"!"))

    def test_malformed_dex_offsets_and_leb_fail_closed(self):
        raw = dex_fixture("Lexample/Config;", {"key": "value"})
        for sample in (b"short", raw[:-1], raw[:40] + b"\x00" * 4 + raw[44:]):
            with self.assertRaises(ValueError):
                config.Dex(sample)
        reader = config.Dex(raw)
        with self.assertRaises(ValueError):
            reader.leb(len(raw))
        with self.assertRaises(ValueError):
            reader.entry(reader.strings, 1000001)

    def test_only_fixed_https_distribution_is_requested(self):
        opener = Opener(self.raw)
        with patch(
            "plus_testkit.app_config.urllib.request.build_opener", return_value=opener
        ):
            self.assertEqual(config.download_profile(), VALUES)
        self.assertEqual(opener.requests[0].full_url, config.APP_URL)
        self.assertEqual(opener.requests[0].get_method(), "GET")

    def test_redirects_and_proxy_environment_are_not_used(self):
        for url in (
            "http://" + "a" * 32 + ".rdt.tfogc.com/file",
            "https://attacker.invalid/file",
        ):
            with self.assertRaisesRegex(ProbeError, "APP_DOWNLOAD_REDIRECT_BLOCKED"):
                config.DistributionRedirect().redirect_request(
                    None, None, 302, "", {}, url
                )
        with patch.dict(os.environ, {"https_proxy": "http://synthetic.invalid:8080"}):
            with patch(
                "plus_testkit.app_config.urllib.request.build_opener",
                wraps=config.urllib.request.build_opener,
            ) as factory:
                with patch(
                    "plus_testkit.app_config.extract_profile", return_value=VALUES
                ):
                    with patch(
                        "urllib.request.OpenerDirector.open",
                        return_value=Response(self.raw),
                    ):
                        config.download_profile()
        handlers = factory.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertTrue(handlers[2]._context.check_hostname)

    def test_only_distribution_cdn_https_redirects_are_allowed_and_bounded(self):
        handler = config.DistributionRedirect()
        request = config.urllib.request.Request(config.APP_URL)
        url = "https://" + "a" * 32 + ".rdt.tfogc.com/distribution"
        for _ in range(3):
            redirected = handler.redirect_request(request, None, 302, "", {}, url)
            self.assertEqual(redirected.full_url, url)
        with self.assertRaisesRegex(ProbeError, "APP_DOWNLOAD_REDIRECT_BLOCKED"):
            handler.redirect_request(request, None, 302, "", {}, url)

    def test_downloader_rejects_oversize_body_and_sanitizes_exception(self):
        opener = Opener(self.raw + b"extra")
        with patch(
            "plus_testkit.app_config.urllib.request.build_opener", return_value=opener
        ):
            with self.assertRaisesRegex(ProbeError, "APP_DISTRIBUTION_MISMATCH"):
                config.download_profile()
        with patch(
            "plus_testkit.app_config.urllib.request.OpenerDirector.open",
            side_effect=RuntimeError(VALUES["app_secret"]),
        ):
            with self.assertRaises(ProbeError) as error:
                config.download_profile()
        self.assertNotIn(VALUES["app_secret"], str(error.exception))

    def test_preparation_is_private_atomic_cached_and_does_not_echo_values(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config/app-profile.private.json"
            messages = []
            with patch.object(config, "default_profile", return_value=target):
                with patch.object(
                    config, "download_profile", return_value=VALUES
                ) as fetch:
                    config.prepare_default_profile(target, notify=messages.append)
                    config.prepare_default_profile(target, notify=messages.append)
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(json.loads(target.read_text()), VALUES)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(target.stat().st_nlink, 1)
            self.assertEqual(len(list(target.parent.iterdir())), 1)
            self.assertNotIn(VALUES["app_secret"], "".join(messages))

    def test_arbitrary_override_is_not_created_and_unsafe_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config/app-profile.private.json"
            with self.assertRaisesRegex(ProbeError, "APP_PROFILE_REQUIRED"):
                config.prepare_default_profile(target, notify=lambda _: None)
            target.parent.mkdir(mode=0o755)
            with patch.object(config, "default_profile", return_value=target):
                with self.assertRaisesRegex(ProbeError, "APP_CONFIG_DIRECTORY_UNSAFE"):
                    config.prepare_default_profile(target, notify=lambda _: None)

    def test_container_configuration_cache_is_persistent_under_config(self):
        with patch.dict(os.environ, {"PLUS_PROBE_RUNTIME_KIND": "ha_container"}):
            self.assertEqual(
                str(config.default_profile()),
                "/config/plus-cloud-config/app-profile.private.json",
            )
