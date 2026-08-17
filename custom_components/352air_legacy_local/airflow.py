# SPDX-License-Identifier: GPL-3.0-or-later
"""APK-derived nominal airflow curves for discrete-speed purifiers."""

from __future__ import annotations

from .const import CONTINUOUS_AIRFLOW_MODELS, FIVE_SPEED_MODELS, SIX_SPEED_MODELS

# filterType is an airflow-profile selector, not filter presence or lifetime.
_A5_AIRFLOW_CURVES: dict[int, tuple[int, ...]] = {
    0: (140, 240, 360, 500, 610, 760),
    1: (60, 140, 220, 330, 390, 500),
    2: (130, 220, 330, 430, 500, 640),
}
_X50_AIRFLOW_CURVES: dict[int, tuple[int, ...]] = {
    0: (150, 220, 300, 400, 510, 600),
    1: (120, 170, 240, 330, 430, 540),
}


def airflow_curve(model: str, filter_profile: int) -> tuple[int, ...] | None:
    """Return a documented speed-to-airflow curve, if the APK contains one."""
    if model in SIX_SPEED_MODELS:
        return _A5_AIRFLOW_CURVES.get(filter_profile)
    if model in FIVE_SPEED_MODELS:
        return _X50_AIRFLOW_CURVES.get(filter_profile)
    return None


def current_airflow_m3h(
    model: str,
    *,
    speed: object,
    filter_profile: object,
    reported_airflow: object,
) -> int | None:
    """Return direct G30/G45 airflow or an APK-derived discrete nominal value."""
    if model in CONTINUOUS_AIRFLOW_MODELS:
        return reported_airflow if isinstance(reported_airflow, int) else None
    if not isinstance(speed, int) or not isinstance(filter_profile, int):
        return None
    curve = airflow_curve(model, filter_profile)
    if curve is None or not 1 <= speed <= len(curve):
        return None
    return curve[speed - 1]
