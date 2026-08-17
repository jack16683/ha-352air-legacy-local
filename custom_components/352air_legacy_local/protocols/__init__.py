# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure codecs and discovery helpers for 352 local UDP devices."""

from __future__ import annotations

from ..models import DeviceModel, ProtocolFamily, family_for_model
from .a5a0 import A5A0Codec
from .base import (
    DISCOVERY_OUTER_OPERATION,
    NORMAL_OUTER_OPERATION,
    DeviceCodec,
    build_outer_frame,
    crc16_genibus,
    f072_crc_is_valid,
    f072_request_crc_is_valid,
    f072_response_crc_is_valid,
    parse_outer_frame,
)
from .discovery import decode_discovery_reply, encode_discovery_probe
from .f072 import F072Codec, F072G30Codec, F072X50Codec
from .m25 import M25Codec


def codec_for_model(model: DeviceModel) -> DeviceCodec:
    """Create the family codec selected by a user-confirmed retail model."""

    family = family_for_model(model)
    if family is ProtocolFamily.M25:
        return M25Codec()
    if family is ProtocolFamily.A5A0:
        return A5A0Codec()
    if family is ProtocolFamily.F072_X50:
        return F072X50Codec(model)
    return F072G30Codec(model)


__all__ = [
    "DISCOVERY_OUTER_OPERATION",
    "NORMAL_OUTER_OPERATION",
    "A5A0Codec",
    "DeviceCodec",
    "F072Codec",
    "F072G30Codec",
    "F072X50Codec",
    "M25Codec",
    "build_outer_frame",
    "codec_for_model",
    "crc16_genibus",
    "decode_discovery_reply",
    "encode_discovery_probe",
    "f072_crc_is_valid",
    "f072_request_crc_is_valid",
    "f072_response_crc_is_valid",
    "parse_outer_frame",
]
