"""Constants for Eufy Security Advanced integration."""

from __future__ import annotations

DOMAIN = "eufy_security_advanced"
MANUFACTURER = "Eufy"

# Configuration keys
CONF_COUNTRY = "country"

# Stream auto-start/stop options
CONF_AUTO_START_STREAM = "auto_start_stream"
CONF_AUTO_START_ON_PERSON = "auto_start_on_person"
CONF_AUTO_START_ON_MOTION = "auto_start_on_motion"
CONF_AUTO_START_ON_DOORBELL = "auto_start_on_doorbell"
CONF_STREAM_TIMEOUT = "stream_timeout"
CONF_STREAM_KEEPALIVE = "stream_keepalive"

# Default values
DEFAULT_PORT = 32100
DEFAULT_TIMEOUT = 30
DEFAULT_STREAM_TIMEOUT = 30  # seconds — auto-stop stream after this
DEFAULT_STREAM_KEEPALIVE = 120  # seconds — extend stream if new events arrive
DEFAULT_AUTO_START_STREAM = True
DEFAULT_AUTO_START_ON_PERSON = True
DEFAULT_AUTO_START_ON_MOTION = False  # motion can be noisy, off by default
DEFAULT_AUTO_START_ON_DOORBELL = True

# Cloud API
API_BASE_URL = "https://extend.eufylife.com"
API_LOGIN_PATH = "v2/passport/login_sec"
API_STATION_LIST_PATH = "v2/house/station_list"
API_DEVICE_LIST_PATH = "v2/house/device_list"
API_HISTORY_PATH = "v2/event/app/get_all_history_record"
API_CIPHER_PATH = "v2/app/cipher/get_ciphers"
API_SET_PARAMS_PATH = "v1/app/upload_devs_params"
API_DSK_KEYS_PATH = "v1/app/equipment/get_dsk_keys"
API_SEND_VERIFY_CODE_PATH = "v1/sms/send/verify_code"
API_TRUST_DEVICE_PATH = "v1/app/trust_device/add"
API_HOUSE_LIST_PATH = "v1/house/list"
API_REGISTER_PUSH_TOKEN_PATH = "v1/apppush/register_push_token"
API_CHECK_PUSH_TOKEN_PATH = "v1/app/review/app_push_check"

# ECDH
ECDH_CURVE = "prime256v1"
SERVER_PUBLIC_KEY_DEFAULT = (
    "04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a"
    "3868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076"
)

# Cloud API headers (impersonate Android app)
API_APP_VERSION = "v4.6.0_1630"
API_OS_TYPE = "android"
API_OS_VERSION = "31"
API_PHONE_MODEL = "ONEPLUS A3003"
API_NET_TYPE = "wifi"
API_SN = "75814221ee75"
API_OPENUDID = "5e4621b0152c0d00"
API_MNC = "02"
API_MCC = "262"

# FCM / Push notification constants
FCM_APP_PACKAGE = "com.oceanwing.battery.cam"
FCM_APP_ID = "1:348804314802:android:440a6773b3620da7"
FCM_SENDER_ID = "348804314802"
FCM_APP_CERT_SHA1 = "F051262F9F99B638F3C76DE349830638555B4A0A"
FCM_PROJECT_ID = "batterycam-3250a"
FCM_GOOGLE_API_KEY = "AIzaSyCSz1uxGrHXsEktm7O3_wv-uLGpC9BvXR8"
FCM_MCS_HOST = "mtalk.google.com"
FCM_MCS_PORT = 5228
FCM_MCS_VERSION = 41

# P2P constants
P2P_UDP_PORT = 32100
P2P_LOCAL_PORT = 32108
P2P_HEARTBEAT_INTERVAL = 5.0
P2P_HEARTBEAT_TIMEOUT_COUNT = 10
P2P_KEEPALIVE_INTERVAL = 2.0
P2P_COMMAND_TIMEOUT = 5.0
P2P_COMMAND_MAX_RETRIES = 10
P2P_CONNECT_TIMEOUT = 25.0
P2P_LOOKUP_TIMEOUT = 20.0
P2P_RECV_BUFFER_SIZE = 1_048_576
P2P_MAX_ACK_PER_PACKET = 17
P2P_SEQUENCE_BOUNDARY = 20_000

# P2P cloud lookup servers (hardcoded fallbacks)
P2P_CLOUD_SERVERS = [
    ("34.235.4.153", 32100),
    ("18.223.127.200", 32100),
    ("54.153.101.7", 32100),
]

# P2P IP obfuscation lookup table
P2P_LOOKUP_TABLE = bytes.fromhex(
    "4959433db5bf6da347534f6165e371e9677f02030badb3892b2f35c16b8b9597"
    "11e5a70deff1050783fb9d3bc5c713171d1f2529d3df"
)

# MQTT broker mapping
MQTT_BROKERS = {
    "https://security-app.eufylife.com": "security-mqtt.eufylife.com",
    "https://security-app-eu.eufylife.com": "security-mqtt-eu.eufylife.com",
    "https://security-app-ci.eufylife.com": "security-mqtt-ci.eufylife.com",
}
MQTT_PORT = 8789
MQTT_KEEPALIVE = 60

# Data update intervals
UPDATE_INTERVAL_SECONDS = 600  # 10 min cloud polling
STREAM_TIMEOUT_SECONDS = 30
