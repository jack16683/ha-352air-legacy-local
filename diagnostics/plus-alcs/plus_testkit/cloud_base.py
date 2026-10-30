"""Account-to-ALCS research candidate; no built-in network transport.

The transport is injected for offline tests. No pairing, binding, password reset,
push registration, telemetry, device writes, or persistent credential storage.
Actual cloud acceptance, login risk controls and firmware support are unverified.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from email.utils import formatdate
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
MX_HOST = "app.352air.com"
REGION_PATH = "/living/account/region/get"
OA_PATH = "/api/prd/loginbyoauth.json"
SESSION_PATH = "/account/createSessionByAuthCode"
REFRESH_PATH = "/account/checkOrRefreshSession"
LIST_PATH = "/uc/listBindingByAccount"
ACCESS_PATH = "/alcs/device/accessInfo/get"
ALLOWED_PATHS = {
    REGION_PATH,
    OA_PATH,
    SESSION_PATH,
    REFRESH_PATH,
    LIST_PATH,
    ACCESS_PATH,
}


class FlowError(Exception):
    def __init__(self, stage: str, code: int | str):
        self.stage, self.code = stage, code
        super().__init__(f"{stage}: {code}")


def object_json(raw: bytes) -> dict:
    if len(raw) > 1024 * 1024:
        raise ValueError("Response too large")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object")
    return value


def compact(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def nonempty(value, stage):
    if not isinstance(value, str) or not value or value != value.strip():
        raise FlowError(stage, "MISSING_FIELD")
    return value


def approved_host(host: str) -> str:
    if not isinstance(host, str) or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise FlowError("region", "INVALID_HOST")
    if host in {"api.link.aliyun.com", "sdk.openaccount.aliyun.com"}:
        return host
    if re.fullmatch(r"[a-z0-9-]+\.api-iot\.aliyuncs\.com", host):
        return host
    if re.fullmatch(r"api-iot\.[a-z0-9-]+\.aliyuncs\.com", host):
        return host
    if re.fullmatch(r"[a-z0-9-]+-sdk\.openaccount\.aliyun\.com", host):
        return host
    if re.fullmatch(r"living-account\.[a-z0-9-]+\.aliyuncs\.com", host):
        return host
    raise FlowError("region", "UNAPPROVED_HOST")


@dataclass(frozen=True)
class AppProfile:
    mx_app_id: str = field(repr=False)
    app_key: str = field(repr=False)
    app_secret: str = field(repr=False)


@dataclass(frozen=True, repr=False)
class Request:
    stage: str
    host: str
    path: str
    headers: dict = field(repr=False)
    body: bytes = field(repr=False)
    query: dict = field(default_factory=dict, repr=False)
    canonical: str = field(default="", repr=False)

    def __repr__(self):
        return f"Request(stage={self.stage!r}, host={self.host!r}, path={self.path!r})"


@dataclass(frozen=True, repr=False)
class DeviceCredentials:
    iot_id: str
    product_key: str
    device_name: str
    access_key: str
    access_token: str


def client_risk_context(
    device_id,
    utdid,
    platform_version,
    *,
    brand="LocalResearch",
    model="ResearchClient",
    net_type="unknown",
    router_mac="",
):
    """APK field schema using caller-supplied client metadata, not attestation.

    Empty UMID/app-auth values follow this APK's getSecurityToken() implementation.
    No location, IMEI or generated WUA/captcha tokens are supplied.
    """
    for value in (device_id, utdid, platform_version):
        nonempty(value, "client_context")
    return {
        "platformName": "android",
        "platformVersion": platform_version,
        "appVersion": "1080001",
        "appVersionName": "1.8.1",
        "sdkVersion": "3.4.2",
        "utdid": utdid,
        "umidToken": "",
        "deviceId": device_id,
        "brand": brand,
        "model": model,
        "appAuthToken": "",
        "yunOSId": "",
        "locale": "zh_CN",
        "netType": net_type,
        "routerMac": router_mac,
        "USE_OA_PWD_ENCRYPT": "true",
        "appID": "com.mxchip.project352",
        "signType": "RSA",
        "USE_H5_NC": "true",
    }


def mx_login_request(profile, account, password, timestamp, area="86"):
    for value in (account, area):
        nonempty(value, "mx_login")
    if not isinstance(password, str) or not password:
        raise FlowError("mx_login", "MISSING_PASSWORD")
    path = "/api/v1/enduser/login"
    signature = hashlib.md5(
        (profile.mx_app_id + path + str(timestamp)).encode()
    ).hexdigest()
    headers = {
        "Content-Type": "application/json;charset=utf-8",
        "Authorization": "Token",
        "ts": str(timestamp),
        "sign": signature,
    }
    # Default Gson omits null code/reason; password is not transformed here.
    return Request(
        "mx_login",
        MX_HOST,
        path,
        headers,
        compact({"account": account, "password": password, "area": area}),
    )


def canonical_string(path, headers, query=None, form=None):
    signed = {key: value for key, value in headers.items() if key.startswith("x-ca-")}
    # SignUtil's caller supplies headers before adding the signature/header list.
    if "x-ca-signature" in signed or "x-ca-signature-headers" in signed:
        raise ValueError("Request has already been signed")
    prefix = (
        "POST\n"
        + "\n".join(
            headers.get(key, "")
            for key in ("accept", "content-md5", "content-type", "date")
        )
        + "\n"
    )
    header_text = "".join(f"{key}:{signed[key]}\n" for key in sorted(signed))
    params = dict(query or {})
    params.update(form or {})
    resource = path
    if params:
        resource += "?" + "&".join(
            key + ("=" + value if value not in (None, "") else "")
            for key, value in sorted(params.items())
        )
    return prefix + header_text + resource, sorted(signed)


def gateway_request(
    profile, stage, host, path, body, timestamp_ms, nonce, *, query=None, form=None
):
    host = approved_host(host)
    if path not in ALLOWED_PATHS:
        raise FlowError(stage, "UNAPPROVED_PATH")
    content_type = (
        "application/x-www-form-urlencoded; charset=utf-8"
        if form is not None
        else "application/octet-stream; charset=utf-8"
    )
    headers = {
        "accept": "application/json; charset=utf-8",
        "content-type": content_type,
        "date": formatdate(timestamp_ms / 1000, usegmt=True),
        "x-ca-timestamp": str(timestamp_ms),
        "x-ca-nonce": nonce,
        "x-ca-key": profile.app_key,
        "x-ca-signature-method": "HmacSHA1",
        "ca_version": "1",
        "host": host,
        "user-agent": "ALIYUN-ANDROID-DEMO",
    }
    if form is None and body:
        headers["content-md5"] = base64.b64encode(hashlib.md5(body).digest()).decode()
    canonical, names = canonical_string(path, headers, query, form)
    headers["x-ca-signature"] = base64.b64encode(
        hmac.digest(profile.app_secret.encode(), canonical.encode(), "sha1")
    ).decode()
    headers["x-ca-signature-headers"] = ",".join(names)
    wire_body = urlencode(sorted(form.items())).encode() if form is not None else body
    return Request(stage, host, path, headers, wire_body, query or {}, canonical)


class CloudFlow:
    def __init__(
        self,
        profile: AppProfile,
        transport: Callable | None = None,
        clock=time.time,
        nonce=lambda: str(uuid.uuid4()),
    ):
        self.profile, self.transport, self.clock, self.nonce = (
            profile,
            transport,
            clock,
            nonce,
        )
        self.events = []
        self._clear()

    def _clear(self):
        self.mx_token = self.oa_sid = self.iot_token = self.refresh_token = (
            self.identity
        ) = ""
        self.token_expiry = self.refresh_expiry = 0
        self.oa_host, self.api_host = (
            "sdk.openaccount.aliyun.com",
            "api.link.aliyun.com",
        )
        self.devices = {}

    def _send(self, request):
        if self.transport is None:
            raise FlowError(request.stage, "NO_TRANSPORT")
        try:
            status, raw = self.transport(request)
            if type(status) is not int or status != 200:
                raise FlowError(
                    request.stage, status if type(status) is int else "HTTP_ERROR"
                )
            obj = object_json(raw)
        except FlowError:
            raise
        except Exception:
            raise FlowError(request.stage, "TRANSPORT_OR_PARSE_ERROR") from None
        self.events.append({"stage": request.stage, "http": status})
        return obj

    def _gateway(self, stage, host, path, params, version, token=""):
        request_id = self.nonce()
        meta = {"apiVer": version}
        if token:
            meta["iotToken"] = token
        body = compact(
            {"id": request_id, "version": "1.0", "request": meta, "params": params}
        )
        request = gateway_request(
            self.profile,
            stage,
            host,
            path,
            body,
            int(self.clock() * 1000),
            self.nonce(),
            query={"x-ca-request-id": request_id},
        )
        result = self._send(request)
        if str(result.get("id")) != request_id:
            raise FlowError(stage, "REQUEST_ID_MISMATCH")
        code = result.get("code")
        if type(code) is not int or code != 200:
            raise FlowError(stage, code if type(code) is int else "BUSINESS_ERROR")
        return result.get("data")

    def login(self, account, password, risk_context=None):
        self._clear()
        self.events.clear()
        if not isinstance(risk_context, dict) or not all(
            risk_context.get(key)
            for key in ("appID", "signType", "platformName", "deviceId")
        ):
            raise FlowError("client_context", "CLIENT_CONTEXT_REQUIRED")
        try:
            result = self._send(
                mx_login_request(self.profile, account, password, int(self.clock()))
            )
            if type(result.get("code")) is not int or result["code"] not in (0, 200):
                raise FlowError(
                    "mx_login",
                    result.get("code")
                    if type(result.get("code")) is int
                    else "BUSINESS_ERROR",
                )
            self.mx_token = nonempty(
                (result.get("data") or {}).get("access_token"), "mx_login"
            )
            region = self._gateway(
                "region",
                self.api_host,
                REGION_PATH,
                {
                    "type": "THIRD_AUTHCODE",
                    "authCode": self.mx_token,
                    "countryCode": "CN",
                },
                "1.0.2",
            )
            if not isinstance(region, dict):
                raise FlowError("region", "INVALID_DATA")
            self.oa_host = approved_host(region.get("oaApiGatewayEndpoint"))
            self.api_host = approved_host(region.get("apiGatewayEndpoint"))
            payload = {
                "oauthPlateform": 23,
                "oauthAppKey": self.profile.app_key,
                "authCode": self.mx_token,
                "country": "CN",
                "riskControlInfo": risk_context or {},
            }
            form = {"loginByOauthRequest": compact(payload).decode()}
            request = gateway_request(
                self.profile,
                "oa_login",
                self.oa_host,
                OA_PATH,
                b"",
                int(self.clock() * 1000),
                self.nonce(),
                form=form,
            )
            result = self._send(request)
            business = result.get("data")
            if (
                not isinstance(business, dict)
                or type(business.get("code")) is not int
                or business["code"] not in (1, 100)
            ):
                raise FlowError(
                    "oa_login",
                    business.get("code")
                    if isinstance(business, dict) and type(business.get("code")) is int
                    else "BUSINESS_ERROR",
                )
            login_data = business.get("data") or {}
            # Challenges must remain explicit; there is no fallback to password APIs.
            if any(
                login_data.get(key)
                for key in ("checkCodeResult", "doubleCheckUrl", "mobileBindRequired")
            ):
                raise FlowError("oa_login", "INTERACTIVE_CHALLENGE")
            self.oa_sid = nonempty(
                (login_data.get("loginSuccessResult") or {}).get("sid"), "oa_login"
            )
            data = self._gateway(
                "iot_session",
                self.api_host,
                SESSION_PATH,
                {
                    "request": {
                        "authCode": self.oa_sid,
                        "appKey": self.profile.app_key,
                        "accountType": "OA_SESSION",
                    }
                },
                "1.0.4",
            )
            self._install_iot(data)
        except Exception:
            self._clear()
            raise

    def _install_iot(self, data):
        if not isinstance(data, dict):
            raise FlowError("iot_session", "INVALID_DATA")
        identity = nonempty(data.get("identityId"), "iot_session")
        if self.identity and identity != self.identity:
            self._clear()
            raise FlowError("iot_session", "IDENTITY_CHANGED")
        values = [
            nonempty(data.get(name), "iot_session")
            for name in ("iotToken", "refreshToken")
        ]
        try:
            for name in ("iotTokenExpire", "refreshTokenExpire"):
                value = data[name]
                if type(value) is not int and not (
                    isinstance(value, str) and value.isdecimal()
                ):
                    raise ValueError
            durations = [
                int(data[name]) for name in ("iotTokenExpire", "refreshTokenExpire")
            ]
            if (
                any(
                    type(data[name]) is bool
                    for name in ("iotTokenExpire", "refreshTokenExpire")
                )
                or min(durations) <= 0
            ):
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise FlowError("iot_session", "INVALID_EXPIRY") from None
        self.identity, self.iot_token, self.refresh_token = identity, *values
        self.token_expiry, self.refresh_expiry = [
            self.clock() + duration for duration in durations
        ]

    def _refresh(self):
        if not self.refresh_token or self.clock() >= self.refresh_expiry:
            self._clear()
            raise FlowError("refresh", "LOGIN_REQUIRED")
        data = self._gateway(
            "refresh",
            self.api_host,
            REFRESH_PATH,
            {
                "request": {
                    "identityId": self.identity,
                    "refreshToken": self.refresh_token,
                }
            },
            "1.0.4",
        )
        self._install_iot(data)

    def _iot(self, stage, path, params, version):
        if not self.iot_token:
            raise FlowError(stage, "LOGIN_REQUIRED")
        if self.clock() >= self.token_expiry:
            self._refresh()
        try:
            return self._gateway(
                stage, self.api_host, path, params, version, self.iot_token
            )
        except FlowError as error:
            if error.code != 401:
                raise
            self._refresh()
            # One retry only; any second failure is propagated.
            return self._gateway(
                stage, self.api_host, path, params, version, self.iot_token
            )

    def list_devices(self, page_size=50, max_pages=20):
        self.devices = {}
        if (
            type(page_size) is not int
            or not 1 <= page_size <= 100
            or type(max_pages) is not int
            or not 1 <= max_pages <= 20
        ):
            raise FlowError("device_list", "INVALID_LIMIT")
        rows = {}
        expected_total = None
        for page in range(1, max_pages + 1):
            data = self._iot(
                "device_list",
                LIST_PATH,
                {"pageNo": page, "pageSize": page_size},
                "1.0.2",
            )
            if not isinstance(data, dict) or not isinstance(data.get("data"), list):
                raise FlowError("device_list", "INVALID_PAGE")
            total = data.get("total")
            if type(total) is not int or total < 0 or data.get("pageNo") != page:
                raise FlowError("device_list", "INVALID_PAGINATION")
            if expected_total is None:
                expected_total = total
            elif expected_total != total:
                raise FlowError("device_list", "TOTAL_CHANGED")
            for row in data["data"]:
                if not isinstance(row, dict):
                    raise FlowError("device_list", "INVALID_DEVICE")
                item = {
                    key: nonempty(row.get(key), "device_list")
                    for key in ("iotId", "productKey", "deviceName")
                }
                if item["iotId"] in rows:
                    raise FlowError("device_list", "DUPLICATE_DEVICE")
                rows[item["iotId"]] = item
            if len(rows) > total:
                raise FlowError("device_list", "INVALID_TOTAL")
            if len(rows) == total:
                self.devices = rows
                return list(rows.values())
            if not data["data"]:
                raise FlowError("device_list", "INCOMPLETE_PAGE")
        raise FlowError("device_list", "PAGE_LIMIT")

    def credentials_for(self, product_key, device_name):
        matches = [
            row
            for row in self.devices.values()
            if row["productKey"] == product_key and row["deviceName"] == device_name
        ]
        if len(matches) != 1:
            raise FlowError("access_info", "DEVICE_NOT_UNIQUELY_AUTHORIZED")
        expected = matches[0]
        data = self._iot(
            "access_info", ACCESS_PATH, {"iotIdList": [expected["iotId"]]}, "1.0.0"
        )
        if (
            not isinstance(data, list)
            or len(data) != 1
            or not isinstance(data[0], dict)
        ):
            raise FlowError("access_info", "INVALID_RESULT")
        row = data[0]
        if any(row.get(key) != expected[key] for key in expected):
            raise FlowError("access_info", "DEVICE_IDENTITY_MISMATCH")
        return DeviceCredentials(
            expected["iotId"],
            product_key,
            device_name,
            nonempty(row.get("accessKey"), "access_info"),
            nonempty(row.get("accessToken"), "access_info"),
        )
