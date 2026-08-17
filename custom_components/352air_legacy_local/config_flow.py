# SPDX-License-Identifier: GPL-3.0-or-later
"""Configuration and safe, read-only discovery flow."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo

from .const import (
    CONF_HOST,
    CONF_MAC,
    CONF_MODEL,
    DOMAIN,
    MODEL_OPTIONS,
    MODEL_WIRE_TYPES,
    MODEL_X83C,
    compatible_models,
    normalize_mac,
)
from .discovery import (
    DiscoveryError,
    DiscoveryResult,
    DiscoveryTimeoutError,
    async_discover_device,
)


def _model_schema(
    default: str | None = None, models: tuple[str, ...] | None = None
) -> vol.Schema:
    """Build the required explicit model confirmation control."""
    selected_models = models or tuple(MODEL_OPTIONS)
    selector = vol.In({model: MODEL_OPTIONS[model] for model in selected_models})
    if default is None:
        return vol.Schema({vol.Required(CONF_MODEL): selector})
    return vol.Schema({vol.Required(CONF_MODEL, default=default): selector})


def _full_schema(defaults: Mapping[str, Any] | None = None) -> vol.Schema:
    """Build the manual configuration form."""
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, "")): str,
            vol.Required(CONF_MAC, default=defaults.get(CONF_MAC, "")): str,
            vol.Required(
                CONF_MODEL,
                default=defaults.get(CONF_MODEL, MODEL_X83C),
            ): vol.In(MODEL_OPTIONS),
        }
    )


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure a 352 device only after an identity-confirming probe."""

    VERSION = 1
    MINOR_VERSION = 1

    _pending_discovery: DiscoveryResult | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a manually supplied IPv4 address, MAC address, and model."""
        errors: dict[str, str] = {}
        if user_input is not None:
            result = await self._async_validate_input(user_input, errors)
            if result is not None:
                model = str(user_input[CONF_MODEL])
                await self.async_set_unique_id(result.mac)
                self._abort_if_unique_id_configured(
                    updates=self._entry_data(result, model),
                    reload_on_update=True,
                )
                return self.async_create_entry(
                    title=f"352 {MODEL_OPTIONS[model]}",
                    data=self._entry_data(result, model),
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_full_schema(user_input),
            errors=errors,
        )

    async def async_step_dhcp(
        self, discovery_info: DhcpServiceInfo
    ) -> ConfigFlowResult:
        """Handle a DHCP candidate and defer exact model choice to the user."""
        host = discovery_info.ip
        mac = discovery_info.macaddress
        if host is None or mac is None:
            return self.async_abort(reason="invalid_discovery")

        try:
            normalized_mac = normalize_mac(mac)
            result = await async_discover_device(str(host), normalized_mac)
        except (DiscoveryError, ValueError):
            return self.async_abort(reason="cannot_connect")

        await self.async_set_unique_id(result.mac)
        self._abort_if_unique_id_configured(
            updates=self._entry_data(result, None),
            reload_on_update=True,
        )
        self._pending_discovery = result
        return await self.async_step_confirm_model()

    async def async_step_confirm_model(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Require an explicit retail-model confirmation for an ambiguous wire type."""
        result = self._pending_discovery
        if result is None:
            return self.async_abort(reason="invalid_discovery")

        models = compatible_models(result.wire_type)
        if not models:
            return self.async_abort(reason="unsupported_device")

        if user_input is not None:
            model = str(user_input[CONF_MODEL])
            if model not in models:
                return self.async_show_form(
                    step_id="confirm_model",
                    data_schema=_model_schema(models=models),
                    errors={CONF_MODEL: "model_mismatch"},
                )
            return self.async_create_entry(
                title=f"352 {MODEL_OPTIONS[model]}",
                data=self._entry_data(result, model),
            )

        return self.async_show_form(
            step_id="confirm_model",
            data_schema=_model_schema(models=models),
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Re-probe changed local addressing and safely reload the same entry."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            result = await self._async_validate_input(user_input, errors)
            if result is not None:
                await self.async_set_unique_id(result.mac)
                self._abort_if_unique_id_mismatch()
                model = str(user_input[CONF_MODEL])
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates=self._entry_data(result, model),
                )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_full_schema(entry.data),
            errors=errors,
        )

    async def _async_validate_input(
        self, user_input: Mapping[str, Any], errors: dict[str, str]
    ) -> DiscoveryResult | None:
        """Validate a form with a read-only targeted discovery query."""
        try:
            host = str(ipaddress.IPv4Address(str(user_input[CONF_HOST]).strip()))
        except (ipaddress.AddressValueError, KeyError):
            errors[CONF_HOST] = "invalid_host"
            return None

        try:
            mac = normalize_mac(str(user_input[CONF_MAC]))
        except (TypeError, ValueError, KeyError):
            errors[CONF_MAC] = "invalid_mac"
            return None

        model = str(user_input.get(CONF_MODEL, ""))
        if model not in MODEL_WIRE_TYPES:
            errors[CONF_MODEL] = "invalid_model"
            return None

        try:
            result = await async_discover_device(host, mac, MODEL_WIRE_TYPES[model])
        except DiscoveryTimeoutError:
            errors["base"] = "cannot_connect"
            return None
        except DiscoveryError:
            errors["base"] = "cannot_connect"
            return None

        if model not in compatible_models(result.wire_type, (model,)):
            errors[CONF_MODEL] = "model_mismatch"
            return None
        return result

    @staticmethod
    def _entry_data(result: DiscoveryResult, model: str | None) -> dict[str, str | int]:
        """Build config-entry data without retaining discovery packet bytes."""
        data = result.as_entry_data()
        if model is not None:
            data[CONF_MODEL] = model
        return data
