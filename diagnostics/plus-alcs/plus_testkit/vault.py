"""Authenticated encrypted recovery journal. Never stores account passwords."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .model import ProbeError

AAD = b"352-plus-local-recovery-v1"
MAX_FILE = 1024 * 1024


def _object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProbeError("VAULT_INVALID")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("VAULT_INVALID") from None


def _owned_regular(fd, maximum=MAX_FILE):
    s = os.fstat(fd)
    if (
        not stat.S_ISREG(s.st_mode)
        or s.st_uid != os.geteuid()
        or s.st_mode & 0o077
        or s.st_nlink != 1
        or s.st_size > maximum
    ):
        raise ProbeError("PRIVATE_FILE_UNSAFE")
    return s


def read_private(path, maximum=MAX_FILE):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _owned_regular(fd, maximum)
            body = os.read(fd, maximum + 1)
            if len(body) > maximum:
                raise ProbeError("PRIVATE_FILE_LIMIT")
            return body
        finally:
            os.close(fd)
    except ProbeError:
        raise
    except OSError:
        raise ProbeError("PRIVATE_FILE_UNREADABLE") from None


class Vault:
    def __init__(self, directory, passphrase):
        if not isinstance(passphrase, str) or len(passphrase) < 12:
            raise ProbeError("VAULT_PASSPHRASE_TOO_SHORT")
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.fd = os.open(
                str(self.directory),
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError:
            raise ProbeError("STATE_DIRECTORY_UNSAFE") from None
        s = os.fstat(self.fd)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077:
            self.close()
            raise ProbeError("STATE_DIRECTORY_UNSAFE")
        self._passphrase = passphrase
        self.data = {"schema": 1, "operations": {}}

    def close(self):
        if getattr(self, "fd", None) is not None:
            os.close(self.fd)
            self.fd = None

    def _key(self, salt):
        return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(
            self._passphrase.encode()
        )

    def exists(self):
        try:
            s = os.stat("recovery.enc.json", dir_fd=self.fd, follow_symlinks=False)
            if not stat.S_ISREG(s.st_mode):
                raise ProbeError("PRIVATE_FILE_UNSAFE")
            return True
        except FileNotFoundError:
            return False

    def load(self):
        try:
            fd = os.open(
                "recovery.enc.json",
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self.fd,
            )
            try:
                _owned_regular(fd)
                raw = os.read(fd, MAX_FILE + 1)
            finally:
                os.close(fd)
            obj = _object(raw)
            if (
                set(obj) != {"version", "kdf", "salt", "nonce", "ciphertext"}
                or obj["version"] != 1
                or obj["kdf"] != "scrypt-16384-8-1"
            ):
                raise ProbeError("VAULT_INVALID")
            salt, nonce, ciphertext = [
                base64.b64decode(obj[k], validate=True)
                for k in ("salt", "nonce", "ciphertext")
            ]
            if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) > MAX_FILE:
                raise ProbeError("VAULT_INVALID")
            data = _object(AESGCM(self._key(salt)).decrypt(nonce, ciphertext, AAD))
            if (
                not isinstance(data, dict)
                or data.get("schema") != 1
                or not isinstance(data.get("operations"), dict)
            ):
                raise ProbeError("VAULT_INVALID")
            self.data = data
            return self.data
        except ProbeError:
            raise
        except Exception:
            raise ProbeError("VAULT_DECRYPT_FAILED") from None

    def save(self):
        # No account/password/session token fields are allowed anywhere in the journal.
        forbidden = {
            "password",
            "account",
            "username",
            "mx_token",
            "iot_token",
            "refresh_token",
            "oa_sid",
            "access_token",
            "air_token",
            "iotToken",
            "refreshToken",
            "identityId",
            "sessionId",
            "sessionKey",
        }

        def check(value):
            if isinstance(value, dict):
                if forbidden.intersection(value):
                    raise ProbeError("VAULT_FORBIDDEN_FIELD")
                for item in value.values():
                    check(item)
            elif isinstance(value, list):
                for item in value:
                    check(item)

        check(self.data)
        payload = json.dumps(
            self.data, separators=(",", ":"), ensure_ascii=False
        ).encode()
        if len(payload) > MAX_FILE // 2:
            raise ProbeError("VAULT_LIMIT")
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        cipher = AESGCM(self._key(salt)).encrypt(nonce, payload, AAD)
        obj = {
            "version": 1,
            "kdf": "scrypt-16384-8-1",
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(cipher).decode(),
        }
        raw = json.dumps(obj, separators=(",", ":")).encode()
        temp = ".recovery-" + secrets.token_hex(12)
        try:
            if self.exists():
                fd = os.open(
                    "recovery.enc.json",
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self.fd,
                )
                try:
                    _owned_regular(fd)
                finally:
                    os.close(fd)
            fd = os.open(
                temp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self.fd,
            )
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                raise
            os.replace(
                temp, "recovery.enc.json", src_dir_fd=self.fd, dst_dir_fd=self.fd
            )
            os.fsync(self.fd)
        except ProbeError:
            raise
        except OSError:
            raise ProbeError("VAULT_SAVE_FAILED") from None
        finally:
            try:
                os.unlink(temp, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def attempted(self, operation):
        return bool(self.data["operations"].get(operation, {}).get("attempted"))

    def mark_attempt(self, operation):
        if operation not in ("install", "restore"):
            raise ProbeError("OPERATION_INVALID")
        if self.attempted(operation):
            raise ProbeError("WRITE_ALREADY_JOURNALED")
        self.data["operations"][operation] = {"attempted": True, "outcome": "unknown"}
        self.save()

    @contextlib.contextmanager
    def lock(self):
        try:
            fd = os.open(
                "run.lock",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self.fd,
            )
        except FileExistsError:
            raise ProbeError("STATE_LOCKED") from None
        try:
            os.write(fd, str(os.getpid()).encode())
            os.fsync(fd)
            yield
        finally:
            os.close(fd)
            os.unlink("run.lock", dir_fd=self.fd)
            os.fsync(self.fd)

    def unlock_stale(self):
        try:
            fd = os.open(
                "run.lock", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=self.fd
            )
            try:
                _owned_regular(fd, 32)
                pid = int(os.read(fd, 32))
            finally:
                os.close(fd)
            if pid <= 0:
                raise ProbeError("LOCK_INVALID")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise ProbeError("LOCK_PROCESS_ALIVE")
            os.unlink("run.lock", dir_fd=self.fd)
            os.fsync(self.fd)
        except ProbeError:
            raise
        except FileNotFoundError:
            raise ProbeError("LOCK_NOT_PRESENT") from None
        except Exception:
            raise ProbeError("LOCK_CANNOT_BE_CLEARED") from None


def recovery_plan(path):
    obj = _object(read_private(path, 16384))
    if not isinstance(obj, dict):
        raise ProbeError("RECOVERY_PLAN_INVALID")
    if obj.get("kind") == "known_local_key" and set(obj) == {
        "kind",
        "prefix",
        "secret",
    }:
        from .model import ServerKey

        key = ServerKey(obj["prefix"], obj["secret"])
        return {"kind": "known_local_key", **key.private()}
    if (
        obj.get("kind") == "owner_manual"
        and set(obj) == {"kind", "procedure", "owner_can_execute"}
        and obj["owner_can_execute"] is True
        and obj["procedure"] in {"official_app_repair", "factory_reset_and_rebind"}
    ):
        return obj
    raise ProbeError("RECOVERY_PLAN_INVALID")
