# SPDX-License-Identifier: GPL-3.0-or-later
"""Configuration and safe, read-only discovery flow."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.helpers import selector
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo

from .const import (
    CONF_AUTH,
    CONF_CLEAR_LOCAL_SCHEDULES,
    CONF_COMPANY,
    CONF_HOST,
    CONF_MAC,
    CONF_MODEL,
    DOMAIN,
    MODEL_OPTIONS,
    MODEL_WIRE_TYPES,
    NETWORK_DISCOVERY_TIMEOUT_SECONDS,
    compatible_models,
    normalize_mac,
)
from .discovery import (
    DiscoveryError,
    DiscoveryResult,
    DiscoveryTimeoutError,
)
from .life_models import LIFE_MODEL_OPTIONS
from .local_discovery import (
    LocalIdentity,
    LocalResult,
    async_discover_device,
    async_discover_devices,
    async_scan_interfaces,
    result_id,
)
from .protocols.discovery import DISCOVERY_COMPANY
from .schedule import (
    ScheduleCleanupError,
    async_clear_local_schedules,
    schedule_cleanup_supported,
)

_LOGGER = logging.getLogger(__name__)
_CONF_DEVICE = "device"
_AUTO_MODEL = "AUTO"
_MANUAL_MODELS = {
    _AUTO_MODEL: "Auto",
    **MODEL_OPTIONS,
    **LIFE_MODEL_OPTIONS,
}
_SHARED_MODEL_NAMES = {
    "X83C_PLUS": "LIFE_X83C_PLUS",
    "G30": "LIFE_G30_G45",
    "G45": "LIFE_G30_G45",
}


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
            vol.Optional(CONF_MAC, default=defaults.get(CONF_MAC, "")): str,
            vol.Required(
                CONF_MODEL,
                default=defaults.get(CONF_MODEL, _AUTO_MODEL),
            ): vol.In(_MANUAL_MODELS),
            vol.Optional(
                CONF_AUTH, default=_header_default(defaults, CONF_AUTH, 4)
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Optional(
                CONF_COMPANY, default=_header_default(defaults, CONF_COMPANY, 2)
            ): str,
        }
    )


def _header_default(defaults: Mapping[str, Any], key: str, width: int) -> str:
    """Render stored integer credentials as hex when reconfiguring."""
    value = defaults.get(key, "")
    return f"{value:0{width}X}" if isinstance(value, int) else str(value)


def _parse_header_hex(value: Any, width: int) -> int | None:
    """Accept an optional hex byte/word without ambiguous decimal conversion."""
    if isinstance(value, int) and not isinstance(value, bool):
        if 0 <= value < 16**width:
            return value
        raise ValueError("Header field is out of range")
    if not isinstance(value, str):
        raise ValueError("Header field must be hexadecimal")
    compact = value.strip().lower().removeprefix("0x").replace(" ", "").replace(":", "")
    if not compact:
        if value.strip():
            raise ValueError("Header field must contain hexadecimal digits")
        return None
    if len(compact) > width or any(char not in "0123456789abcdef" for char in compact):
        raise ValueError("Header field is out of range or not hexadecimal")
    return int(compact, 16)


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure a 352 device only after an identity-confirming probe."""

    VERSION = 1
    MINOR_VERSION = 1

    _pending_discovery: LocalResult | None = None
    _pending_model: str | None = None
    _pending_reconfigure_entry: config_entries.ConfigEntry[Any] | None = None
    _discovered_devices: dict[str, LocalResult] | None = None
    _discovery_task: asyncio.Task[tuple[LocalResult, ...]] | None = None

    def _configured_identities(self) -> frozenset[str]:
        """Filter both stable protocol IDs and known MACs from every mechanism."""
        identifiers: set[str] = set()
        for entry in self._async_current_entries():
            if entry.unique_id is not None:
                identifiers.add(entry.unique_id)
            if mac := entry.data.get(CONF_MAC):
                identifiers.add(str(mac))
        return frozenset(identifiers)

    async def _async_scan(self) -> tuple[LocalResult, ...]:
        return await async_discover_devices(
            interfaces=await async_scan_interfaces(self.hass),
            excluded_macs=self._configured_identities(),
        )

    def _mac_already_configured(self, result: LocalResult) -> bool:
        """Do not create a second protocol entry for an already configured MAC."""
        if result.mac is None:
            return False
        return any(
            entry.unique_id != result_id(result)
            and (
                entry.unique_id == result.mac or entry.data.get(CONF_MAC) == result.mac
            )
            for entry in self._async_current_entries()
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Offer explicit automatic discovery and full manual setup paths."""
        if user_input is not None:
            # Accept a submitted manual form from an already-open older flow.
            return await self.async_step_manual(user_input)
        return self.async_show_menu(step_id="user", menu_options=["auto", "manual"])

    async def async_step_auto(
        self, _user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Use a verified DHCP candidate or search the local network read-only."""
        if self._pending_discovery is not None:
            if isinstance(self._pending_discovery, LocalIdentity):
                return await self.async_step_confirm_local()
            return await self.async_step_confirm_model()

        if self._discovery_task is None:
            self._discovery_task = self.hass.async_create_task(
                self._async_scan(),
                name="352air network setup discovery",
            )
        if not self._discovery_task.done():
            return self.async_show_progress(
                step_id="auto",
                progress_action="searching",
                progress_task=self._discovery_task,
                description_placeholders={
                    "seconds": str(int(NETWORK_DISCOVERY_TIMEOUT_SECONDS))
                },
            )
        task = self._discovery_task
        self._discovery_task = None
        try:
            discovered = task.result()
        except DiscoveryError:
            _LOGGER.debug("Automatic discovery failed; see discovery diagnostics")
            discovered = ()
        configured = self._configured_identities()
        self._discovered_devices = {
            result_id(result): result
            for result in discovered
            if result_id(result) not in configured and result.mac not in configured
        }
        if not self._discovered_devices:
            return self.async_show_progress_done(next_step_id="no_devices")
        return self.async_show_progress_done(next_step_id="select_device")

    async def async_step_no_devices(
        self, _user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let users retry discovery or switch to the complete manual form."""
        return self.async_show_menu(
            step_id="no_devices", menu_options=["auto", "manual"]
        )

    async def async_step_select_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Select one of the independently validated local device identities."""
        discovered = self._discovered_devices or {}
        if user_input is not None:
            selected = str(user_input.get(_CONF_DEVICE, ""))
            if (result := discovered.get(selected)) is not None:
                if self._mac_already_configured(result):
                    return self.async_abort(reason="already_configured")
                await self.async_set_unique_id(result_id(result))
                self._abort_if_unique_id_configured(
                    updates=self._entry_data(result, None), reload_on_update=True
                )
                self._pending_discovery = result
                if isinstance(result, LocalIdentity):
                    return await self.async_step_confirm_local()
                return await self.async_step_confirm_model()
        options = {
            result_id(result): (
                f"352 {result.name} ({result.host}, 352Life)"
                if isinstance(result, LocalIdentity)
                else f"352 ({result.host}, {result.mac}, Legacy)"
            )
            for result in discovered.values()
        }
        return self.async_show_form(
            step_id="select_device",
            data_schema=vol.Schema({vol.Required(_CONF_DEVICE): vol.In(options)}),
            errors={_CONF_DEVICE: "invalid_device"} if user_input else {},
        )

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a manually supplied IPv4 address, MAC address, and model."""
        errors: dict[str, str] = {}
        if user_input is not None:
            result = await self._async_validate_input(user_input, errors)
            if result is not None:
                if self._mac_already_configured(result):
                    return self.async_abort(reason="already_configured")
                model = str(user_input[CONF_MODEL])
                await self.async_set_unique_id(result_id(result))
                self._abort_if_unique_id_configured(
                    updates=self._entry_data(result, model),
                    reload_on_update=True,
                )
                if model == _AUTO_MODEL and isinstance(result, DiscoveryResult):
                    self._pending_discovery = result
                    return await self.async_step_confirm_model()
                return await self._async_continue_after_identity(result, model)

        return self.async_show_form(
            step_id="manual",
            data_schema=_full_schema(
                user_input
                or (
                    {
                        CONF_HOST: self._pending_discovery.host,
                        CONF_MAC: self._pending_discovery.mac or "",
                    }
                    if self._pending_discovery
                    else None
                )
            ),
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
            result = await async_discover_device(
                str(host),
                normalized_mac,
                interfaces=await async_scan_interfaces(self.hass),
            )
        except (DiscoveryError, ValueError):
            _LOGGER.debug("DHCP discovery failed; see discovery diagnostics")
            return self.async_abort(reason="cannot_connect")

        await self.async_set_unique_id(result_id(result))
        if self._mac_already_configured(result):
            return self.async_abort(reason="already_configured")
        self._abort_if_unique_id_configured(
            updates=self._entry_data(result, None),
            reload_on_update=True,
        )
        self._pending_discovery = result
        return await self.async_step_user()

    async def async_step_confirm_model(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Require an explicit retail-model confirmation for an ambiguous wire type."""
        result = self._pending_discovery
        if result is None:
            return self.async_abort(reason="invalid_discovery")
        if isinstance(result, LocalIdentity):
            return await self.async_step_confirm_local()

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
            return await self._async_continue_after_identity(result, model)

        return self.async_show_form(
            step_id="confirm_model",
            data_schema=_model_schema(models=models),
        )

    async def async_step_confirm_local(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Clearly confirm discovery-only setup, without inventing control state."""
        result = self._pending_discovery
        if not isinstance(result, LocalIdentity):
            return self.async_abort(reason="invalid_discovery")
        self._pending_model = result.model
        if user_input is not None:
            return self._finish_pending_entry()
        return self.async_show_form(
            step_id="confirm_local",
            data_schema=vol.Schema({}),
            description_placeholders={
                "model": result.name,
                "host": result.host,
                "mechanism": result.mechanism,
            },
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
                await self.async_set_unique_id(result_id(result))
                self._abort_if_unique_id_mismatch()
                model = str(user_input[CONF_MODEL])
                if model == _AUTO_MODEL and isinstance(result, DiscoveryResult):
                    self._pending_discovery = result
                    self._pending_reconfigure_entry = entry
                    return await self.async_step_confirm_model()
                return await self._async_continue_after_identity(
                    result,
                    model,
                    reconfigure_entry=entry,
                )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_full_schema(entry.data),
            errors=errors,
        )

    async def async_step_schedule_cleanup(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Optionally remove the device's four persistent recurring schedules."""
        result = self._pending_discovery
        model = self._pending_model
        if not isinstance(result, DiscoveryResult) or model is None:
            return self.async_abort(reason="invalid_discovery")

        errors: dict[str, str] = {}
        if user_input is not None:
            if bool(user_input.get(CONF_CLEAR_LOCAL_SCHEDULES, False)):
                try:
                    await async_clear_local_schedules(result)
                except ScheduleCleanupError:
                    errors["base"] = "schedule_cleanup_failed"
                else:
                    return self._finish_pending_entry()
            else:
                return self._finish_pending_entry()

        return self.async_show_form(
            step_id="schedule_cleanup",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_CLEAR_LOCAL_SCHEDULES,
                        default=bool(
                            user_input
                            and user_input.get(CONF_CLEAR_LOCAL_SCHEDULES, False)
                        ),
                    ): selector.BooleanSelector()
                }
            ),
            errors=errors,
        )

    async def _async_continue_after_identity(
        self,
        result: LocalResult,
        model: str,
        *,
        reconfigure_entry: config_entries.ConfigEntry[Any] | None = None,
    ) -> ConfigFlowResult:
        """Store verified identity data before the optional write step."""
        self._pending_discovery = result
        self._pending_model = model
        if reconfigure_entry is not None:
            self._pending_reconfigure_entry = reconfigure_entry
        if isinstance(result, LocalIdentity):
            self._pending_model = result.model
            return await self.async_step_confirm_local()
        if schedule_cleanup_supported(result.wire_type):
            return await self.async_step_schedule_cleanup()
        return self._finish_pending_entry()

    def _finish_pending_entry(self) -> ConfigFlowResult:
        """Create or update only after the optional cleanup step is resolved."""
        result = self._pending_discovery
        model = self._pending_model
        if result is None or model is None:
            return self.async_abort(reason="invalid_discovery")
        data = self._entry_data(result, model)
        if self._pending_reconfigure_entry is not None:
            return self.async_update_reload_and_abort(
                self._pending_reconfigure_entry,
                data_updates=data,
            )
        name = (
            result.name if isinstance(result, LocalIdentity) else MODEL_OPTIONS[model]
        )
        return self.async_create_entry(title=f"352 {name}", data=data)

    async def _async_validate_input(
        self, user_input: Mapping[str, Any], errors: dict[str, str]
    ) -> LocalResult | None:
        """Validate a form with a read-only targeted discovery query."""
        try:
            address = ipaddress.IPv4Address(str(user_input[CONF_HOST]).strip())
            if (
                address.is_unspecified
                or address.is_multicast
                or int(address) == 2**32 - 1
            ):
                raise ipaddress.AddressValueError
            host = str(address)
        except (ipaddress.AddressValueError, KeyError):
            errors[CONF_HOST] = "invalid_host"
            return None

        try:
            entered_mac = str(user_input.get(CONF_MAC, "")).strip()
            mac = normalize_mac(entered_mac) if entered_mac else None
        except (TypeError, ValueError):
            errors[CONF_MAC] = "invalid_mac"
            return None

        model = str(user_input.get(CONF_MODEL, ""))
        if model not in _MANUAL_MODELS:
            errors[CONF_MODEL] = "invalid_model"
            return None

        header_values: dict[str, int | None] = {}
        for key, width in ((CONF_AUTH, 4), (CONF_COMPANY, 2)):
            try:
                header_values[key] = _parse_header_hex(user_input.get(key, ""), width)
            except ValueError:
                errors[key] = f"invalid_{key}"
        if errors:
            return None
        if mac is None and any(value is not None for value in header_values.values()):
            errors[CONF_MAC] = "mac_required_for_header"
            return None
        company = header_values[CONF_COMPANY]
        try:
            result = await async_discover_device(
                host,
                mac,
                MODEL_WIRE_TYPES.get(model, (1, 2, 3, 4)),
                interfaces=await async_scan_interfaces(self.hass),
                company=DISCOVERY_COMPANY if company is None else company,
                auth=header_values[CONF_AUTH],
                compatibility_probes=True,
            )
        except DiscoveryTimeoutError:
            _LOGGER.debug("Manual discovery timed out; see discovery diagnostics")
            errors["base"] = "cannot_connect"
            return None
        except DiscoveryError:
            _LOGGER.debug("Manual discovery failed; see discovery diagnostics")
            errors["base"] = "cannot_connect"
            return None

        if isinstance(result, LocalIdentity):
            if model not in {_AUTO_MODEL, result.model} and (
                _SHARED_MODEL_NAMES.get(model) != result.model
            ):
                errors[CONF_MODEL] = "model_mismatch"
                return None
        elif model != _AUTO_MODEL and model not in compatible_models(
            result.wire_type, (model,)
        ):
            errors[CONF_MODEL] = "model_mismatch"
            return None
        return result

    @staticmethod
    def _entry_data(result: LocalResult, model: str | None) -> dict[str, str | int]:
        """Build config-entry data without retaining discovery packet bytes."""
        data = result.as_entry_data()
        if model not in {None, _AUTO_MODEL} and not isinstance(result, LocalIdentity):
            data[CONF_MODEL] = model
        return data
