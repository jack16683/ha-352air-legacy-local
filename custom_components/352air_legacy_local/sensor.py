# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only sensors for fields proven by each legacy protocol family."""

from __future__ import annotations

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
from .const import (
    CONTINUOUS_AIRFLOW_MODELS,
    MODEL_M25,
    PURIFIER_MODELS,
)
from .entity import LegacyEntity, state_attribute
from .runtime import RuntimeData


@dataclass(frozen=True, kw_only=True)
class LegacySensorDescription(SensorEntityDescription):
    """A translated HA description plus its optional protocol state attribute."""

    state_attribute: str
    supported_models: frozenset[str]


_SENSORS: tuple[LegacySensorDescription, ...] = (
    LegacySensorDescription(
        key="pm25",
        translation_key="pm25",
        state_attribute="pm25",
        supported_models=PURIFIER_MODELS | {MODEL_M25},
        device_class=SensorDeviceClass.PM25,
        native_unit_of_measurement=UnitOfDensity.MICROGRAMS_PER_CUBIC_METER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="raw_air_quality",
        translation_key="raw_air_quality",
        state_attribute="air_quality",
        supported_models=PURIFIER_MODELS,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    LegacySensorDescription(
        key="timer_remaining",
        translation_key="timer_remaining",
        state_attribute="timer_remaining",
        supported_models=PURIFIER_MODELS,
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.MINUTES,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="processed_air_total",
        translation_key="processed_air_total",
        state_attribute="processed_air",
        supported_models=PURIFIER_MODELS,
        device_class=SensorDeviceClass.VOLUME,
        native_unit_of_measurement=UnitOfVolume.CUBIC_METERS,
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    LegacySensorDescription(
        key="purified_air_total",
        translation_key="purified_air_total",
        state_attribute="purified_air",
        supported_models=PURIFIER_MODELS,
        device_class=SensorDeviceClass.VOLUME,
        native_unit_of_measurement=UnitOfVolume.CUBIC_METERS,
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    LegacySensorDescription(
        key="filter_type_raw",
        translation_key="filter_type_raw",
        state_attribute="filter_type_raw",
        supported_models=PURIFIER_MODELS,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    LegacySensorDescription(
        key="temperature",
        translation_key="temperature",
        state_attribute="temperature",
        supported_models=CONTINUOUS_AIRFLOW_MODELS,
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="humidity",
        translation_key="humidity",
        state_attribute="humidity",
        supported_models=CONTINUOUS_AIRFLOW_MODELS,
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement=UnitOfRatio.PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="co2",
        translation_key="co2",
        state_attribute="co2",
        supported_models=CONTINUOUS_AIRFLOW_MODELS,
        device_class=SensorDeviceClass.CO2,
        native_unit_of_measurement=UnitOfRatio.PARTS_PER_MILLION,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    LegacySensorDescription(
        key="airflow",
        translation_key="airflow",
        state_attribute="airflow",
        supported_models=CONTINUOUS_AIRFLOW_MODELS,
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
        value = state_attribute(self._runtime, self.entity_description.state_attribute)
        return value if isinstance(value, str | int | float) else None
