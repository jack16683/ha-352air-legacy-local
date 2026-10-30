import gzip
import json
import os
import ssl
import time
import unittest
import urllib.error
from unittest.mock import patch

from plus_testkit.cloud import (
    PROPERTIES,
    STATUS,
    CloudClient,
    HTTPTransport,
    NoRedirect,
    base,
)
from plus_testkit.model import ProbeError
from support import ACCOUNT, IDENTITY, OLD, PASSWORD

PROFILE = base.AppProfile("synthetic-appid", "synthetic-key", "synthetic-app-secret")


class Response:
    status = 200

    def __init__(self, body):
        self.body = body

    def read(self, size):
        return self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class Opener:
    def __init__(self, body=b"{}", error=None):
        self.body = body
        self.error = error
        self.messages = []

    def open(self, message, timeout):
        self.messages.append(message)
        if self.error:
            raise self.error
        return Response(self.body)

    def close(self):
        pass


class OfficialServer:
    def __init__(self):
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        if request.path == "/api/v1/enduser/login":
            data = json.loads(request.body)
            assert data["account"] == ACCOUNT and data["password"] == PASSWORD
            return 200, json.dumps(
                {"code": 0, "data": {"access_token": "synthetic-352-token"}}
            ).encode()
        if request.path == base.OA_PATH:
            return 200, json.dumps(
                {
                    "data": {
                        "code": 100,
                        "data": {"loginSuccessResult": {"sid": "synthetic-oa-sid"}},
                    }
                }
            ).encode()
        body = json.loads(request.body)
        if request.path == base.REGION_PATH:
            data = {
                "oaApiGatewayEndpoint": "living-account.cn-shanghai.aliyuncs.com",
                "apiGatewayEndpoint": "api.link.aliyun.com",
            }
        elif request.path == base.SESSION_PATH:
            data = {
                "identityId": "synthetic-owner",
                "iotToken": "synthetic-iot-token",
                "refreshToken": "synthetic-refresh-token",
                "iotTokenExpire": 3600,
                "refreshTokenExpire": 7200,
            }
        elif request.path == base.LIST_PATH:
            data = {
                "total": 1,
                "pageNo": 1,
                "pageSize": 50,
                "data": [
                    {
                        "iotId": "synthetic-iot-id",
                        "productKey": IDENTITY.product,
                        "deviceName": IDENTITY.name,
                    }
                ],
            }
        elif request.path == base.ACCESS_PATH:
            data = [
                {
                    "iotId": "synthetic-iot-id",
                    "productKey": IDENTITY.product,
                    "deviceName": IDENTITY.name,
                    "accessKey": OLD.access(IDENTITY).key,
                    "accessToken": OLD.access(IDENTITY).token,
                }
            ]
        elif request.path == STATUS:
            data = {"status": 1, "time": int(time.time() * 1000)}
        elif request.path == PROPERTIES:
            data = {"PowerSwitch": {"value": 0, "time": int(time.time() * 1000)}}
        else:
            raise AssertionError("Unknown official endpoint")
        return 200, json.dumps({"id": body["id"], "code": 200, "data": data}).encode()


class CloudTests(unittest.TestCase):
    def request(self, host="api.link.aliyun.com", path=STATUS):
        return base.gateway_request(
            PROFILE,
            "status",
            host,
            path,
            b"{}",
            int(time.time() * 1000),
            "synthetic-nonce",
        )

    def test_only_official_https_endpoint_is_built(self):
        transport = HTTPTransport()
        self.addCleanup(transport.close)
        opener = Opener()
        transport.opener = opener
        status, body = transport(self.request())
        self.assertEqual((status, body), (200, b"{}"))
        self.assertTrue(
            opener.messages[0].full_url.startswith("https://api.link.aliyun.com/")
        )
        self.assertEqual(opener.messages[0].method, "POST")
        self.assertEqual(opener.messages[0].get_header("Accept-encoding"), "identity")

    def test_http_redirects_are_explicitly_blocked(self):
        with self.assertRaisesRegex(ProbeError, "HTTPS_REDIRECT_BLOCKED"):
            NoRedirect().redirect_request(None, None, None, None, None, None, None)

    def test_environment_proxy_is_not_used_and_tls_is_verified(self):
        with patch.dict(os.environ, {"https_proxy": "http://SYNTH_PROXY.invalid:8080"}):
            transport = HTTPTransport()
        self.addCleanup(transport.close)
        self.assertFalse(
            any(
                getattr(handler, "proxies", {}) for handler in transport.opener.handlers
            )
        )
        https = [h for h in transport.opener.handlers if hasattr(h, "_context")]
        self.assertTrue(
            any(
                h._context.verify_mode == ssl.CERT_REQUIRED
                and h._context.check_hostname
                for h in https
            )
        )

    def test_arbitrary_host_and_path_are_blocked_before_open(self):
        transport = HTTPTransport()
        self.addCleanup(transport.close)
        opener = Opener()
        transport.opener = opener
        for request in [
            base.Request("status", "attacker.invalid", STATUS, {}, b"{}"),
            base.Request("status", base.MX_HOST, "/reset", {}, b"{}"),
        ]:
            with self.assertRaises(ProbeError):
                transport(request)
        self.assertEqual(opener.messages, [])

    def test_gzip_body_is_bounded(self):
        transport = HTTPTransport()
        self.addCleanup(transport.close)
        transport.opener = Opener(gzip.compress(b'{"code":200}'))
        self.assertEqual(transport(self.request())[1], b'{"code":200}')
        transport.opener = Opener(gzip.compress(b"A" * (1024 * 1024 + 100)))
        with self.assertRaisesRegex(ProbeError, "HTTPS_BODY_LIMIT"):
            transport(self.request())

    def test_http_error_does_not_return_error_body_or_reason(self):
        transport = HTTPTransport()
        self.addCleanup(transport.close)
        transport.opener = Opener(
            error=urllib.error.HTTPError(
                "https://api.link.aliyun.com/", 403, PASSWORD, {}, None
            )
        )
        self.assertEqual(transport(self.request()), (403, b""))

    def test_connection_exception_is_not_exposed(self):
        transport = HTTPTransport()
        self.addCleanup(transport.close)
        transport.opener = Opener(error=RuntimeError(PASSWORD))
        with self.assertRaises(ProbeError) as raised:
            transport(self.request())
        self.assertNotIn(PASSWORD, str(raised.exception))
        self.assertEqual(raised.exception.code, "HTTPS_CONNECTION_FAILED")

    def test_entire_cloud_flow_uses_synthetic_responses_and_separate_tokens(self):
        server = OfficialServer()
        client = CloudClient(PROFILE, transport=server)
        self.addCleanup(client.close)
        client.login(ACCOUNT, PASSWORD)
        access = client.access_for(IDENTITY)
        snapshot = client.snapshot()
        self.assertEqual(access.key, OLD.access(IDENTITY).key)
        self.assertTrue(snapshot["online"] and snapshot["fresh_sample"])
        self.assertEqual(snapshot["power"], 0)
        self.assertEqual(
            [r.path for r in server.requests],
            [
                "/api/v1/enduser/login",
                base.REGION_PATH,
                base.OA_PATH,
                base.SESSION_PATH,
                base.LIST_PATH,
                base.ACCESS_PATH,
                STATUS,
                PROPERTIES,
            ],
        )
        self.assertTrue(
            all("password" not in r.body.decode() for r in server.requests[1:])
        )

    def test_business_failure_reports_stage_without_echoing_server_message(self):
        server = OfficialServer()

        def transport(request):
            if request.path == base.OA_PATH:
                return 200, json.dumps(
                    {"data": {"code": 26251, "message": PASSWORD}}
                ).encode()
            return server(request)

        client = CloudClient(PROFILE, transport=transport)
        with self.assertRaises(ProbeError) as raised:
            client.login(ACCOUNT, PASSWORD)
        self.assertEqual(raised.exception.public()["stage"], "oa_login")
        self.assertEqual(raised.exception.public()["application_code"], 26251)
        self.assertNotIn(PASSWORD, str(raised.exception))

    def test_host_header_cannot_redirect_virtual_host_routing(self):
        transport = HTTPTransport()
        self.addCleanup(transport.close)
        opener = Opener()
        transport.opener = opener
        req = self.request()
        req.headers["host"] = "attacker.invalid"
        with self.assertRaisesRegex(ProbeError, "HTTPS_HOST_HEADER_BLOCKED"):
            transport(req)
        self.assertEqual(opener.messages, [])
