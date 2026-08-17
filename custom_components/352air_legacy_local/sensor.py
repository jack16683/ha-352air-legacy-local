# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only sensors for fields proven by each legacy protocol family."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    EntityCategory,
    UnitOfDensity,
    UnitOfRatio,
    UnitOfTemperature,
    UnitOfTime,
    UnitOfVolume,
    UnitOfVolumeFlowRate,
)
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import ConfigEntry
from .airflow import airflow_curve, current_airflow_m3h
from .const import (
    CONTINUOUS_AIRFLOW_MODELS,
    FIVE_SPEED_MODELS,
    MODEL_M25,
    PURIFIER_MODELS,
    SIX_SPEED_MODELS,
)
from .entity import LegacyEntity, state_attribute
from .runtime import RuntimeData


@dataclass(frozen=True, kw_only=True)
class LegacySensorDescription(SensorEntityDescription):
    """A translated HA description plus its optional protocol state attribute."""

    state_attribute: str
    supported_models: frozenset[str]
    value_map: Mapping[int, str] | None = None


_AIR_QUALITY_OPTIONS = ["excellent", "good", "poor"]
_AIR_QUALITY_MAP = {1: "excellent", 2: "good", 3: "poor"}
_LINKAGE_OPTIONS = ["not_linked", "linked"]
_LINKAGE_MAP = {0: "not_linked", 1: "linked"}
_FILTER_PROFILE_OPTIONS = ["profile_0", "profile_1", "profile_2"]
_FILTER_PROFILE_MAP = {0: "profile_0", 1: "profile_1", 2: "profile_2"}
_G30_FILTER_PROFILE_OPTIONS = ["standard", "super_carbon"]
_G30_FILTER_PROFILE_MAP = {0: "standard", 1: "super_carbon"}

_SENSORS: tuple[LegacySensorDescription, ...] = (
    LegacySensorDescription(
        key="pm25",
        translation_key="pm25",
        state_attribute="pm25",
        supported_models=PURIFIER_MODELS | {MODEL_M25},
        icon="mdi:weather-hazy",
        device_class=SensorDeviceClass.PM25,
        native_unit_of_measurement=UnitOfDensity.MICROGRAMS_PER_CUBIC_METER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="air_quality",
        translation_key="air_quality",
        state_attribute="air_quality",
        supported_models=PURIFIER_MODELS,
        icon="mdi:air-filter",
        device_class=SensorDeviceClass.ENUM,
        options=_AIR_QUALITY_OPTIONS,
        value_map=_AIR_QUALITY_MAP,
    ),
    LegacySensorDescription(
        key="timer_remaining",
        translation_key="timer_remaining",
        state_attribute="timer_remaining",
        supported_models=PURIFIER_MODELS,
        icon="mdi:timer-outline",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.MINUTES,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="current_run_processed_air",
        translation_key="current_run_processed_air",
        state_attribute="processed_air",
        supported_models=PURIFIER_MODELS,
        icon="mdi:air-purifier",
        device_class=SensorDeviceClass.VOLUME,
        native_unit_of_measurement=UnitOfVolume.CUBIC_METERS,
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    LegacySensorDescription(
        key="purified_air_total",
        translation_key="purified_air_total",
        state_attribute="purified_air",
        supported_models=PURIFIER_MODELS,
        icon="mdi:counter",
        device_class=SensorDeviceClass.VOLUME,
        native_unit_of_measurement=UnitOfVolume.CUBIC_METERS,
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    LegacySensorDescription(
        key="filter_airflow_profile",
        translation_key="filter_airflow_profile",
        state_attribute="filter_type_raw",
        supported_models=SIX_SPEED_MODELS | FIVE_SPEED_MODELS,
        icon="mdi:air-filter",
        device_class=SensorDeviceClass.ENUM,
        options=_FILTER_PROFILE_OPTIONS,
        value_map=_FILTER_PROFILE_MAP,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    LegacySensorDescription(
        key="filter_airflow_profile",
        translation_key="filter_airflow_profile",
        state_attribute="filter_type_raw",
        supported_models=CONTINUOUS_AIRFLOW_MODELS,
        icon="mdi:air-filter",
        device_class=SensorDeviceClass.ENUM,
        options=_G30_FILTER_PROFILE_OPTIONS,
        value_map=_G30_FILTER_PROFILE_MAP,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    LegacySensorDescription(
        key="linkage_state",
        translation_key="linkage_state",
        state_attribute="linkage_raw",
        supported_models=SIX_SPEED_MODELS | FIVE_SPEED_MODELS | {MODEL_M25},
        icon="mdi:link-variant",
        device_class=SensorDeviceClass.ENUM,
        options=_LINKAGE_OPTIONS,
        value_map=_LINKAGE_MAP,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    LegacySensorDescription(
        key="temperature",
        translation_key="temperature",
        state_attribute="temperature",
        supported_models=CONTINUOUS_AIRFLOW_MODELS,
        icon="mdi:thermometer",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="humidity",
        translation_key="humidity",
        state_attribute="humidity",
        supported_models=CONTINUOUS_AIRFLOW_MODELS,
        icon="mdi:water-percent",
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement=UnitOfRatio.PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="co2",
        translation_key="co2",
        state_attribute="co2",
        supported_models=CONTINUOUS_AIRFLOW_MODELS,
        icon="mdi:molecule-co2",
        device_class=SensorDeviceClass.CO2,
        native_unit_of_measurement=UnitOfRatio.PARTS_PER_MILLION,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="airflow",
        translation_key="airflow",
        state_attribute="airflow",
        supported_models=PURIFIER_MODELS,
        icon="mdi:weather-windy",
        device_class=SensorDeviceClass.VOLUME_FLOW_RATE,
        native_unit_of_measurement=UnitOfVolumeFlowRate.CUBIC_METERS_PER_HOUR,
        state_class=SensorStateClass.MEASUREMENT,
    ),
)


async def async_setup_entry(
    _hass: Any,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add only sensors whose value offsets are documented for this model family."""
    runtime = entry.runtime_data
    async_add_entities(
        LegacySensor(runtime, description)
        for description in _SENSORS
        if runtime.model in description.supported_models
    )


class LegacySensor(SensorEntity, LegacyEntity):
    """A translated sensor reading from current in-memory device state."""

    entity_description: LegacySensorDescription

    def __init__(
        self, runtime: RuntimeData, description: LegacySensorDescription
    ) -> None:
        LegacyEntity.__init__(self, runtime, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> int | float | str | None:
        """Return no value if the optional field was absent from a valid packet."""
        if self.entity_description.key == "airflow":
            return current_airflow_m3h(
                self._runtime.model,
                speed=state_attribute(self._runtime, "speed"),
                filter_profile=state_attribute(self._runtime, "filter_type_raw"),
                reported_airflow=state_attribute(self._runtime, "airflow"),
            )
        value = state_attribute(self._runtime, self.entity_description.state_attribute)
        if self.entity_description.value_map is not None:
            return (
                self.entity_description.value_map.get(value)
                if isinstance(value, int)
                else None
            )
        return value if isinstance(value, str | int | float) else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Keep the original code beside a translated categorical value."""
        if self.entity_description.value_map is None:
            return None
        value = state_attribute(self._runtime, self.entity_description.state_attribute)
        if not isinstance(value, int):
            return None
        attributes: dict[str, Any] = {"raw_code": value}
        if self.entity_description.key == "filter_airflow_profile" and (
            curve := airflow_curve(self._runtime.model, value)
        ):
            attributes["airflow_by_speed_m3h"] = {
                str(speed): airflow for speed, airflow in enumerate(curve, 1)
            }
        return attributes
