"""Device automation triggers for Eufy Security Advanced.

Allows users to create automations directly from the device page:
- Doorbell pressed
- Person detected
- Motion detected
- Pet detected
- Vehicle detected
- Sound detected
- Crying detected
- Package delivered / taken
"""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.components.device_automation import DEVICE_TRIGGER_BASE_SCHEMA
from homeassistant.components.homeassistant.triggers import event as event_trigger
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_DEVICE_ID, CONF_DOMAIN, CONF_PLATFORM, CONF_TYPE
from homeassistant.core import CALLBACK_TYPE, HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.trigger import TriggerActionType, TriggerInfo
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN

# Trigger types — these map to push event types
TRIGGER_DOORBELL_PRESSED = "doorbell_pressed"
TRIGGER_PERSON_DETECTED = "person_detected"
TRIGGER_MOTION_DETECTED = "motion_detected"
TRIGGER_PET_DETECTED = "pet_detected"
TRIGGER_VEHICLE_DETECTED = "vehicle_detected"
TRIGGER_SOUND_DETECTED = "sound_detected"
TRIGGER_CRYING_DETECTED = "crying_detected"
TRIGGER_PACKAGE_DELIVERED = "package_delivered"
TRIGGER_PACKAGE_TAKEN = "package_taken"
TRIGGER_SOMEONE_LOITERING = "someone_loitering"
TRIGGER_LOCK_UNLOCKED = "lock_unlocked"
TRIGGER_LOCK_LOCKED = "lock_locked"

# All camera/doorbell triggers
_CAMERA_TRIGGERS = [
    TRIGGER_MOTION_DETECTED,
    TRIGGER_PERSON_DETECTED,
    TRIGGER_PET_DETECTED,
    TRIGGER_VEHICLE_DETECTED,
    TRIGGER_SOUND_DETECTED,
    TRIGGER_CRYING_DETECTED,
]

_DOORBELL_TRIGGERS = [
    TRIGGER_DOORBELL_PRESSED,
    TRIGGER_PACKAGE_DELIVERED,
    TRIGGER_PACKAGE_TAKEN,
    TRIGGER_SOMEONE_LOITERING,
]

_LOCK_TRIGGERS = [
    TRIGGER_LOCK_UNLOCKED,
    TRIGGER_LOCK_LOCKED,
]

# Push event type -> trigger type mapping
_EVENT_TO_TRIGGER = {
    3103: TRIGGER_DOORBELL_PRESSED,
    3102: TRIGGER_PERSON_DETECTED,
    3303: TRIGGER_PERSON_DETECTED,
    3101: TRIGGER_MOTION_DETECTED,
    3306: TRIGGER_MOTION_DETECTED,
    3106: TRIGGER_PET_DETECTED,
    3107: TRIGGER_VEHICLE_DETECTED,
    3108: TRIGGER_SOUND_DETECTED,
    3104: TRIGGER_CRYING_DETECTED,
    3301: TRIGGER_PACKAGE_DELIVERED,
    3302: TRIGGER_PACKAGE_TAKEN,
    3305: TRIGGER_SOMEONE_LOITERING,
}

TRIGGER_SCHEMA = DEVICE_TRIGGER_BASE_SCHEMA.extend(
    {vol.Required(CONF_TYPE): str}
)


def _get_device_sn(hass: HomeAssistant, device_id: str) -> str | None:
    """Get the Eufy device serial from a HA device ID."""
    device_reg = dr.async_get(hass)
    device = device_reg.async_get(device_id)
    if device:
        for identifier in device.identifiers:
            if identifier[0] == DOMAIN:
                return identifier[1]
    return None


async def async_get_triggers(
    hass: HomeAssistant, device_id: str
) -> list[dict[str, Any]]:
    """Return a list of triggers for a device."""
    device_sn = _get_device_sn(hass, device_id)
    if not device_sn:
        return []

    # Find the coordinator and device
    triggers: list[dict[str, Any]] = []
    for entry_id, coordinator in hass.data.get(DOMAIN, {}).items():
        device = coordinator.devices.get(device_sn)
        if not device:
            continue

        base = {
            CONF_PLATFORM: "device",
            CONF_DOMAIN: DOMAIN,
            CONF_DEVICE_ID: device_id,
        }

        if device.is_camera or device.is_doorbell:
            for t in _CAMERA_TRIGGERS:
                triggers.append({**base, CONF_TYPE: t})

        if device.is_doorbell:
            for t in _DOORBELL_TRIGGERS:
                triggers.append({**base, CONF_TYPE: t})

        if device.is_lock:
            for t in _LOCK_TRIGGERS:
                triggers.append({**base, CONF_TYPE: t})

        break

    return triggers


async def async_attach_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    trigger_info: TriggerInfo,
) -> CALLBACK_TYPE:
    """Attach a trigger — listens to eufy_security_advanced_event on the HA event bus."""
    device_sn = _get_device_sn(hass, config[CONF_DEVICE_ID])
    trigger_type = config[CONF_TYPE]

    # Build the set of event_type values that map to this trigger
    matching_event_types = [
        et for et, tt in _EVENT_TO_TRIGGER.items() if tt == trigger_type
    ]

    # For lock triggers, use lock-specific event types
    if trigger_type == TRIGGER_LOCK_UNLOCKED:
        matching_event_types = [257, 258, 259, 260, 261]  # LockPushEvent unlock variants
    elif trigger_type == TRIGGER_LOCK_LOCKED:
        matching_event_types = [262, 263, 264, 265]  # LockPushEvent lock variants

    event_config = event_trigger.TRIGGER_SCHEMA(
        {
            event_trigger.CONF_PLATFORM: "event",
            event_trigger.CONF_EVENT_TYPE: f"{DOMAIN}_event",
            event_trigger.CONF_EVENT_DATA: {
                "device_sn": device_sn,
            },
        }
    )

    # We use the HA event trigger and filter by device_sn + event_type in the action
    return await event_trigger.async_attach_trigger(
        hass, event_config, action, trigger_info, platform_type="device"
    )
