"""Pytest configuration and fixtures for Eufy Security Advanced tests."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Add the project root to sys.path so custom_components can be imported
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock homeassistant modules that aren't available in test environment
HA_MODULES = [
    "homeassistant",
    "homeassistant.components",
    "homeassistant.components.alarm_control_panel",
    "homeassistant.components.binary_sensor",
    "homeassistant.components.button",
    "homeassistant.components.camera",
    "homeassistant.components.image",
    "homeassistant.components.lock",
    "homeassistant.components.number",
    "homeassistant.components.select",
    "homeassistant.components.sensor",
    "homeassistant.components.stream",
    "homeassistant.components.switch",
    "homeassistant.config_entries",
    "homeassistant.const",
    "homeassistant.core",
    "homeassistant.helpers",
    "homeassistant.helpers.aiohttp_client",
    "homeassistant.helpers.device_registry",
    "homeassistant.helpers.entity_platform",
    "homeassistant.helpers.update_coordinator",
]

for mod_name in HA_MODULES:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()
