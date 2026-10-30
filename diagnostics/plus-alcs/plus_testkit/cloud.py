"""Official HTTPS endpoints only; no proxies, redirects, telemetry or body logs."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
import uuid
import zlib

from . import cloud_base as base
from .model import Access, Deadline, ProbeError, power_value

PROPERTIES = "/thing/properties/get"
STATUS = "/thing/status/get"
base.ALLOWED_PATHS.update({PROPERTIES, STATUS})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ProbeError("HTTPS_REDIRECT_BLOCKED")


class HTTPTransport:
    def __init__(self, deadline=None):
        self.deadline = deadline or Deadline()
        self.count = 0
        self.last_error = None
        self.last_http_status = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def __call__(self, request):
        self.last_error = None
        self.last_http_status = None
        try:
            if request.host == base.MX_HOST:
                if (
                    request.path != "/api/v1/enduser/login"
                    or request.stage != "mx_login"
                ):
                    raise ProbeError("HTTPS_PATH_BLOCKED")
            else:
                base.approved_host(request.host)
                if request.path not in base.ALLOWED_PATHS:
                    raise ProbeError("HTTPS_PATH_BLOCKED")
            self.count += 1
            if self.count > 40:
                raise ProbeError("CLOUD_REQUEST_LIMIT")
            query = base.urlencode(request.query)
            url = (
                "https://"
                + request.host
                + request.path
                + ("?" + query if query else "")
            )
            headers = dict(request.headers)
            if any(
                k.lower() == "host" and v != request.host for k, v in headers.items()
            ):
                raise ProbeError("HTTPS_HOST_HEADER_BLOCKED")
            headers["Accept-Encoding"] = "identity"
            message = urllib.request.Request(
                url, data=request.body, headers=headers, method="POST"
            )
            try:
                with self.opener.open(
                    message, timeout=self.deadline.remaining(12)
                ) as response:
                    code = response.status
                    raw = response.read(1024 * 1024 + 1)
            except urllib.error.HTTPError as error:
                code = error.code
                self.last_http_status = code
                error.close()
                return code, b""
            self.last_http_status = code
            if len(raw) > 1024 * 1024:
                raise ProbeError("HTTPS_BODY_LIMIT")
            if raw.startswith(b"\x1f\x8b"):
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                raw = decoder.decompress(raw, 1024 * 1024 + 1)
                if len(raw) > 1024 * 1024 or not decoder.eof or decoder.unused_data:
                    raise ProbeError("HTTPS_BODY_LIMIT")
            return code, raw
        except ProbeError as error:
            self.last_error = error.code
            raise
        except Exception:
            self.last_error = "HTTPS_CONNECTION_FAILED"
            raise ProbeError("HTTPS_CONNECTION_FAILED") from None

    def close(self):
        self.opener.close()


class CloudClient:
    def __init__(self, profile, *, transport=None, deadline=None):
        self.transport = transport or HTTPTransport(deadline)
        self.flow = base.CloudFlow(profile, self.transport)
        self.target = None
        self._identity = None

    def _call(self, function):
        try:
            return function()
        except base.FlowError as error:
            code = getattr(self.transport, "last_error", None)
            if code:
                raise ProbeError(code, stage=error.stage) from None
            known = {
                "INTERACTIVE_CHALLENGE",
                "CLIENT_CONTEXT_REQUIRED",
                "REQUEST_ID_MISMATCH",
                "DEVICE_IDENTITY_MISMATCH",
                "IDENTITY_CHANGED",
                "LOGIN_REQUIRED",
                "DEVICE_NOT_UNIQUELY_AUTHORIZED",
                "INVALID_PAGINATION",
                "DUPLICATE_DEVICE",
                "PAGE_LIMIT",
            }
            reason = error.code if error.code in known else "CLOUD_REQUEST_FAILED"
            http = getattr(self.transport, "last_http_status", None)
            raise ProbeError(
                reason,
                application_code=error.code if http in (None, 200) else None,
                stage=error.stage,
                http_status=http,
            ) from None
        except ProbeError:
            raise
        except Exception:
            raise ProbeError("CLOUD_RESPONSE_INVALID") from None

    def login(self, account, password):
        context = base.client_risk_context(
            str(uuid.uuid4()), "ffffffffffffffffffffffff", "36"
        )
        self._call(lambda: self.flow.login(account, password, context))
        return {"status": "ok"}

    def access_for(self, identity):
        self.select_target(identity)
        cred = self._call(
            lambda: self.flow.credentials_for(identity.product, identity.name)
        )
        return Access(identity, cred.access_key, cred.access_token)

    def select_target(self, identity):
        self._call(lambda: self.flow.list_devices(max_pages=5))
        matches = [
            r
            for r in self.flow.devices.values()
            if r["productKey"] == identity.product and r["deviceName"] == identity.name
        ]
        if len(matches) != 1:
            raise ProbeError("DEVICE_NOT_UNIQUELY_AUTHORIZED", stage="device_list")
        self.target = matches[0]["iotId"]
        self._identity = identity

    def snapshot(self):
        if self.target is None:
            raise ProbeError("CLOUD_TARGET_REQUIRED")
        state = self._call(
            lambda: self.flow._iot("status", STATUS, {"iotId": self.target}, "1.0.5")
        )
        data = self._call(
            lambda: self.flow._iot(
                "properties", PROPERTIES, {"iotId": self.target}, "1.0.2"
            )
        )
        if not isinstance(state, dict):
            raise ProbeError("CLOUD_STATUS_INVALID")
        status = state.get("status")
        if isinstance(status, dict):
            status = status.get("value")
        if type(status) is not int or status not in (0, 1, 3, 8):
            raise ProbeError("CLOUD_STATUS_INVALID")
        power = power_value(data)
        item = data.get("PowerSwitch")
        stamp = item.get("time") if isinstance(item, dict) else None
        age = None
        if type(stamp) is int and stamp > 0:
            seconds = stamp / 1000 if stamp > 10**11 else stamp
            if seconds <= time.time() + 60:
                age = max(0, int(time.time() - seconds))
        return {
            "status": "ok",
            "online": status == 1,
            "power": power,
            "sample_age_seconds": age,
            "fresh_sample": age is not None and age <= 120,
        }

    def close(self):
        self.flow._clear()
        if hasattr(self.transport, "close"):
            self.transport.close()
