"""Config flow for Eufy Security Advanced integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_AUTO_START_ON_DOORBELL,
    CONF_AUTO_START_ON_MOTION,
    CONF_AUTO_START_ON_PERSON,
    CONF_AUTO_START_STREAM,
    CONF_COUNTRY,
    CONF_STREAM_KEEPALIVE,
    CONF_STREAM_TIMEOUT,
    DEFAULT_AUTO_START_ON_DOORBELL,
    DEFAULT_AUTO_START_ON_MOTION,
    DEFAULT_AUTO_START_ON_PERSON,
    DEFAULT_AUTO_START_STREAM,
    DEFAULT_STREAM_KEEPALIVE,
    DEFAULT_STREAM_TIMEOUT,
    DOMAIN,
)
from .lib.cloud_api import (
    AuthenticationError,
    CaptchaRequired,
    EufyCloudApi,
    EufyCloudApiError,
    TwoFactorRequired,
)

_LOGGER = logging.getLogger(__name__)


class EufySecurityConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Eufy Security Advanced."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._email: str = ""
        self._password: str = ""
        self._country: str = "US"
        self._api: EufyCloudApi | None = None
        self._captcha_id: str = ""
        self._captcha_img: str = ""

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow handler."""
        return EufySecurityOptionsFlow(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step — collect credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._email = user_input[CONF_EMAIL]
            self._password = user_input[CONF_PASSWORD]
            self._country = user_input.get(CONF_COUNTRY, "US").upper()

            await self.async_set_unique_id(self._email.lower())
            self._abort_if_unique_id_configured()

            session = async_get_clientsession(self.hass)
            self._api = EufyCloudApi(
                self._email, self._password, self._country, session=session
            )

            try:
                await self._api.login()
                return await self._async_create_entry()

            except TwoFactorRequired:
                try:
                    await self._api.send_verify_code(message_type=2)
                except Exception:
                    _LOGGER.debug("Failed to send verify code", exc_info=True)
                return await self.async_step_verify_code()

            except CaptchaRequired as err:
                self._captcha_id = err.captcha_id
                self._captcha_img = err.captcha_img
                return await self.async_step_captcha()

            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except EufyCloudApiError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during setup")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Optional(CONF_COUNTRY, default="US"): str,
                }
            ),
            errors=errors,
        )

    async def async_step_verify_code(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle 2FA verification code entry."""
        errors: dict[str, str] = {}

        if user_input is not None:
            code = user_input.get("verify_code", "")
            try:
                await self._api.login(verify_code=code)
                await self._api.trust_device(code)
                return await self._async_create_entry()
            except TwoFactorRequired:
                errors["base"] = "verify_code_failed"
            except CaptchaRequired as err:
                self._captcha_id = err.captcha_id
                self._captcha_img = err.captcha_img
                return await self.async_step_captcha()
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Verification error")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="verify_code",
            data_schema=vol.Schema({vol.Required("verify_code"): str}),
            errors=errors,
        )

    async def async_step_captcha(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle CAPTCHA challenge."""
        errors: dict[str, str] = {}

        if user_input is not None:
            answer = user_input.get("captcha_answer", "")
            try:
                await self._api.login(
                    captcha_id=self._captcha_id, captcha_answer=answer,
                )
                return await self._async_create_entry()
            except CaptchaRequired as err:
                self._captcha_id = err.captcha_id
                self._captcha_img = err.captcha_img
                errors["base"] = "captcha_failed"
            except TwoFactorRequired:
                try:
                    await self._api.send_verify_code(message_type=2)
                except Exception:
                    pass
                return await self.async_step_verify_code()
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("CAPTCHA error")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="captcha",
            data_schema=vol.Schema({vol.Required("captcha_answer"): str}),
            description_placeholders={"captcha_img": self._captcha_img},
            errors=errors,
        )

    async def _async_create_entry(self) -> ConfigFlowResult:
        """Create the config entry after successful login.

        Validates we can actually fetch devices before saving.
        """
        # Test that we can fetch data before committing
        try:
            await self._api.get_station_list()
            await self._api.get_device_list()
            station_count = len(self._api.stations)
            device_count = len(self._api.devices)
            _LOGGER.info(
                "Connection validated: %d stations, %d devices",
                station_count, device_count,
            )
        except Exception:
            _LOGGER.warning("Login succeeded but device fetch failed", exc_info=True)

        persistent = self._api.persistent_data

        return self.async_create_entry(
            title=f"Eufy Security ({self._email})",
            data={
                CONF_EMAIL: self._email,
                CONF_PASSWORD: self._password,
                CONF_COUNTRY: self._country,
                "user_id": persistent.user_id,
                "auth_token": persistent.auth_token,
                "token_expires_at": persistent.token_expires_at,
                "api_base": persistent.api_base,
                "client_private_key": persistent.client_private_key,
                "server_public_key": persistent.server_public_key,
            },
        )


class EufySecurityOptionsFlow(OptionsFlow):
    """Handle options for Eufy Security Advanced."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Main options page — stream behavior settings."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = self._config_entry.options

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_AUTO_START_STREAM,
                        default=current.get(CONF_AUTO_START_STREAM, DEFAULT_AUTO_START_STREAM),
                    ): bool,
                    vol.Optional(
                        CONF_AUTO_START_ON_DOORBELL,
                        default=current.get(CONF_AUTO_START_ON_DOORBELL, DEFAULT_AUTO_START_ON_DOORBELL),
                    ): bool,
                    vol.Optional(
                        CONF_AUTO_START_ON_PERSON,
                        default=current.get(CONF_AUTO_START_ON_PERSON, DEFAULT_AUTO_START_ON_PERSON),
                    ): bool,
                    vol.Optional(
                        CONF_AUTO_START_ON_MOTION,
                        default=current.get(CONF_AUTO_START_ON_MOTION, DEFAULT_AUTO_START_ON_MOTION),
                    ): bool,
                    vol.Optional(
                        CONF_STREAM_TIMEOUT,
                        default=current.get(CONF_STREAM_TIMEOUT, DEFAULT_STREAM_TIMEOUT),
                    ): vol.All(vol.Coerce(int), vol.Range(min=10, max=300)),
                    vol.Optional(
                        CONF_STREAM_KEEPALIVE,
                        default=current.get(CONF_STREAM_KEEPALIVE, DEFAULT_STREAM_KEEPALIVE),
                    ): vol.All(vol.Coerce(int), vol.Range(min=30, max=600)),
                }
            ),
        )
