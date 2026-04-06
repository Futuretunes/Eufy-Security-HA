"""Eufy Security type definitions and enumerations."""

from __future__ import annotations

from enum import IntEnum


# ---------------------------------------------------------------------------
# Device types
# ---------------------------------------------------------------------------
class DeviceType(IntEnum):
    """Eufy device type identifiers from the cloud API."""

    STATION = 0
    CAMERA = 1
    SENSOR = 2
    FLOODLIGHT = 3
    CAMERA_E = 4
    DOORBELL = 5
    BATTERY_DOORBELL = 7
    CAMERA2C = 8
    CAMERA2 = 9
    MOTION_SENSOR = 10
    KEYPAD = 11
    CAMERA2_PRO = 14
    CAMERA2C_PRO = 15
    BATTERY_DOORBELL_2 = 16
    HB3 = 18
    CAMERA3 = 19
    CAMERA3C = 23
    PROFESSIONAL_247 = 24
    MINIBASE_CHIME = 25
    CAMERA3_PRO = 26
    HOMEBASE_MINI = 28
    INDOOR_CAMERA = 30
    INDOOR_PT_CAMERA = 31
    SOLO_CAMERA = 32
    SOLO_CAMERA_PRO = 33
    INDOOR_CAMERA_1080 = 34
    INDOOR_PT_CAMERA_1080 = 35
    FLOODLIGHT_CAMERA_8422 = 37
    FLOODLIGHT_CAMERA_8423 = 38
    FLOODLIGHT_CAMERA_8424 = 39
    INDOOR_OUTDOOR_CAMERA_1080P = 44
    INDOOR_OUTDOOR_CAMERA_1080P_NO_LIGHT = 45
    INDOOR_OUTDOOR_CAMERA_2K = 46
    FLOODLIGHT_CAMERA_8425 = 47
    OUTDOOR_PT_CAMERA = 48  # S340
    CAMERA_E40 = 49
    LOCK_BLE = 50
    LOCK_WIFI = 51
    LOCK_BLE_NO_FINGER = 52
    LOCK_WIFI_NO_FINGER = 53
    LOCK_8503 = 54
    LOCK_8530 = 55
    LOCK_85A3 = 56
    LOCK_8592 = 57
    LOCK_8504 = 58
    SOLO_CAMERA_SPOTLIGHT_1080 = 60
    SOLO_CAMERA_SPOTLIGHT_2K = 61
    SOLO_CAMERA_SPOTLIGHT_SOLAR = 62
    SOLO_CAMERA_SOLAR = 63
    SOLO_CAMERA_C210 = 64
    FLOODLIGHT_CAMERA_8426 = 87
    SOLO_CAMERA_E30 = 88
    CAMERA_S4 = 89
    SMART_DROP = 90
    BATTERY_DOORBELL_PLUS = 91
    DOORBELL_SOLO = 93
    BATTERY_DOORBELL_PLUS_E340 = 94
    BATTERY_DOORBELL_C30 = 95
    BATTERY_DOORBELL_C31 = 96
    SOLOCAM_E42 = 98
    INDOOR_COST_DOWN_CAMERA = 100
    INDOOR_PT_CAMERA_S350 = 104
    INDOOR_PT_CAMERA_E30 = 105
    CAMERA_FG = 110
    CAMERA_4G_S330 = 111
    SIREN_SENSOR_E20 = 123
    ENTRY_SENSOR_E20 = 126
    PIR_SENSOR_E20 = 127
    GARAGE_CAMERA = 131
    GARAGE_CAMERA_2 = 132
    GARAGE_CAMERA_3 = 133
    SMART_SAFE_S10 = 140
    SMART_SAFE_S12 = 141
    WALL_LIGHT_CAM = 151
    SMART_TRACK_LINK = 157
    SMART_TRACK_CARD = 159
    LOCK_8502 = 180
    LOCK_8506 = 184
    LOCK_8531 = 189
    LOCK_85L0 = 201
    LOCK_85D0 = 202
    LOCK_85V0 = 203
    INDOOR_C220 = 10008
    INDOOR_C210 = 10009
    INDOOR_C220_2 = 10010
    INDOOR_C210_2 = 10011
    CAMERA_C35 = 10035


# ---------------------------------------------------------------------------
# Device categories (helpers)
# ---------------------------------------------------------------------------
STATION_TYPES = {
    DeviceType.STATION,
    DeviceType.HB3,
    DeviceType.MINIBASE_CHIME,
    DeviceType.HOMEBASE_MINI,
}

CAMERA_TYPES = {
    DeviceType.CAMERA, DeviceType.CAMERA_E, DeviceType.CAMERA2,
    DeviceType.CAMERA2C, DeviceType.CAMERA2_PRO, DeviceType.CAMERA2C_PRO,
    DeviceType.CAMERA3, DeviceType.CAMERA3C, DeviceType.CAMERA3_PRO,
    DeviceType.CAMERA_E40, DeviceType.CAMERA_S4, DeviceType.CAMERA_FG,
    DeviceType.CAMERA_4G_S330, DeviceType.CAMERA_C35,
    DeviceType.PROFESSIONAL_247,
    DeviceType.INDOOR_CAMERA, DeviceType.INDOOR_PT_CAMERA,
    DeviceType.INDOOR_CAMERA_1080, DeviceType.INDOOR_PT_CAMERA_1080,
    DeviceType.INDOOR_OUTDOOR_CAMERA_1080P,
    DeviceType.INDOOR_OUTDOOR_CAMERA_1080P_NO_LIGHT,
    DeviceType.INDOOR_OUTDOOR_CAMERA_2K,
    DeviceType.INDOOR_PT_CAMERA_S350, DeviceType.INDOOR_PT_CAMERA_E30,
    DeviceType.INDOOR_COST_DOWN_CAMERA,
    DeviceType.INDOOR_C220, DeviceType.INDOOR_C210,
    DeviceType.INDOOR_C220_2, DeviceType.INDOOR_C210_2,
    DeviceType.SOLO_CAMERA, DeviceType.SOLO_CAMERA_PRO,
    DeviceType.SOLO_CAMERA_SPOTLIGHT_1080,
    DeviceType.SOLO_CAMERA_SPOTLIGHT_2K,
    DeviceType.SOLO_CAMERA_SPOTLIGHT_SOLAR,
    DeviceType.SOLO_CAMERA_SOLAR, DeviceType.SOLO_CAMERA_C210,
    DeviceType.SOLO_CAMERA_E30, DeviceType.SOLOCAM_E42,
    DeviceType.FLOODLIGHT, DeviceType.FLOODLIGHT_CAMERA_8422,
    DeviceType.FLOODLIGHT_CAMERA_8423, DeviceType.FLOODLIGHT_CAMERA_8424,
    DeviceType.FLOODLIGHT_CAMERA_8425, DeviceType.FLOODLIGHT_CAMERA_8426,
    DeviceType.OUTDOOR_PT_CAMERA,
    DeviceType.WALL_LIGHT_CAM,
    DeviceType.GARAGE_CAMERA, DeviceType.GARAGE_CAMERA_2,
    DeviceType.GARAGE_CAMERA_3,
}

DOORBELL_TYPES = {
    DeviceType.DOORBELL, DeviceType.BATTERY_DOORBELL,
    DeviceType.BATTERY_DOORBELL_2, DeviceType.BATTERY_DOORBELL_PLUS,
    DeviceType.DOORBELL_SOLO, DeviceType.BATTERY_DOORBELL_PLUS_E340,
    DeviceType.BATTERY_DOORBELL_C30, DeviceType.BATTERY_DOORBELL_C31,
}

LOCK_TYPES = {
    DeviceType.LOCK_BLE, DeviceType.LOCK_WIFI,
    DeviceType.LOCK_BLE_NO_FINGER, DeviceType.LOCK_WIFI_NO_FINGER,
    DeviceType.LOCK_8503, DeviceType.LOCK_8530, DeviceType.LOCK_85A3,
    DeviceType.LOCK_8592, DeviceType.LOCK_8504, DeviceType.LOCK_8502,
    DeviceType.LOCK_8506, DeviceType.LOCK_8531, DeviceType.LOCK_85L0,
    DeviceType.LOCK_85D0, DeviceType.LOCK_85V0,
}

SENSOR_TYPES = {
    DeviceType.SENSOR, DeviceType.MOTION_SENSOR,
    DeviceType.ENTRY_SENSOR_E20, DeviceType.PIR_SENSOR_E20,
    DeviceType.SIREN_SENSOR_E20,
}

BATTERY_TYPES = (
    {DeviceType.BATTERY_DOORBELL, DeviceType.BATTERY_DOORBELL_2,
     DeviceType.BATTERY_DOORBELL_PLUS, DeviceType.BATTERY_DOORBELL_PLUS_E340,
     DeviceType.BATTERY_DOORBELL_C30, DeviceType.BATTERY_DOORBELL_C31,
     DeviceType.CAMERA2C, DeviceType.CAMERA2C_PRO, DeviceType.CAMERA2,
     DeviceType.CAMERA2_PRO, DeviceType.CAMERA3, DeviceType.CAMERA3C,
     DeviceType.CAMERA3_PRO, DeviceType.CAMERA_E40, DeviceType.CAMERA,
     DeviceType.CAMERA_E, DeviceType.SOLO_CAMERA, DeviceType.SOLO_CAMERA_PRO,
     DeviceType.SOLO_CAMERA_SPOTLIGHT_1080,
     DeviceType.SOLO_CAMERA_SPOTLIGHT_2K,
     DeviceType.SOLO_CAMERA_SPOTLIGHT_SOLAR,
     DeviceType.SOLO_CAMERA_SOLAR, DeviceType.SOLO_CAMERA_C210,
     DeviceType.SOLO_CAMERA_E30, DeviceType.SOLOCAM_E42,
     DeviceType.SENSOR, DeviceType.MOTION_SENSOR,
     DeviceType.ENTRY_SENSOR_E20, DeviceType.PIR_SENSOR_E20}
    | LOCK_TYPES
)


# ---------------------------------------------------------------------------
# Guard mode
# ---------------------------------------------------------------------------
class GuardMode(IntEnum):
    UNKNOWN = -1
    AWAY = 0
    HOME = 1
    SCHEDULE = 2
    CUSTOM1 = 3
    CUSTOM2 = 4
    CUSTOM3 = 5
    OFF = 6
    GEO = 47
    DISARMED = 63


# ---------------------------------------------------------------------------
# P2P message types
# ---------------------------------------------------------------------------
class P2PMessageType(IntEnum):
    """UDP envelope message type IDs."""

    # Requests
    STUN = 0xF100
    LOOKUP = 0xF120
    LOOKUP_WITH_KEY = 0xF126
    LOOKUP_WITH_KEY2 = 0xF16A
    LOCAL_LOOKUP = 0xF130
    CHECK_CAM = 0xF141
    CHECK_CAM2 = 0xF183
    TURN_LOOKUP_WITH_KEY = 0xF180
    TURN_SERVER_INIT = 0xF170
    TURN_CLIENT_OK = 0xF172
    PING = 0xF1E0
    PONG = 0xF1E1
    DATA = 0xF1D0
    ACK = 0xF1D1
    END = 0xF1F0

    # Responses (same numeric values, distinguished by context)
    STUN_RESP = 0xF101
    LOOKUP_RESP = 0xF121
    LOOKUP_ADDR = 0xF140
    LOCAL_LOOKUP_RESP = 0xF141
    TURN_SERVER_LIST = 0xF169
    TURN_SERVER_OK = 0xF171
    TURN_SERVER_TOKEN = 0xF173
    TURN_SERVER_LOOKUP_OK = 0xF181
    LOOKUP_ADDR2 = 0xF182
    TURN_SERVER_CAM_ID = 0xF184
    CAM_ID = 0xF142


class P2PDataType(IntEnum):
    """Data channel type within DATA/ACK messages."""

    DATA = 0xD100
    VIDEO = 0xD101
    CONTROL = 0xD102
    BINARY = 0xD103


# ---------------------------------------------------------------------------
# P2P command types
# ---------------------------------------------------------------------------
class CommandType(IntEnum):
    CMD_START_REALTIME_MEDIA = 1003
    CMD_STOP_REALTIME_MEDIA = 1004
    CMD_START_TALKBACK = 1005
    CMD_STOP_TALKBACK = 1006
    CMD_DOWNLOAD_VIDEO = 1024
    CMD_DOWNLOAD_CANCEL = 1051
    CMD_GATEWAYINFO = 1100
    CMD_CAMERA_INFO = 1103
    CMD_PING = 1139
    CMD_NAS_SWITCH = 1145
    CMD_NAS_TEST = 1146
    CMD_SDINFO_EX = 1144
    CMD_GET_ALARM_MODE = 1151
    CMD_GET_DEVICE_PING = 1152
    CMD_SET_TONE_FILE = 1201
    CMD_SET_DEVS_TONE_FILE = 1202
    CMD_SET_ARMING = 1224
    CMD_VIDEO_FRAME = 1300
    CMD_AUDIO_FRAME = 1301
    CMD_STREAM_MSG = 1302
    CMD_DOWNLOAD_FINISH = 1304
    CMD_SET_PAYLOAD = 1350
    CMD_NOTIFY_PAYLOAD = 1351
    CMD_DOORBELL_SET_PAYLOAD = 1700
    CMD_DOORLOCK_DATA_PASS_THROUGH = 1911
    CMD_SET_PAYLOAD_LOCKV12 = 1930
    CMD_TRANSFER_PAYLOAD = 1940
    CMD_P2P_ON_OFF_LOCK = 1961


# ---------------------------------------------------------------------------
# Lock sub-command types
# ---------------------------------------------------------------------------
class ESLBleCommand(IntEnum):
    ON_OFF_LOCK = 8


class SmartLockCommand(IntEnum):
    ON_OFF_LOCK = 6018


class IndoorCommandType(IntEnum):
    CMD_START_SPEAK = 1001
    CMD_END_SPEAK = 1002


# ---------------------------------------------------------------------------
# RTSP-capable device types
# ---------------------------------------------------------------------------
RTSP_CAPABLE_TYPES = {
    DeviceType.CAMERA2, DeviceType.CAMERA2_PRO,
    DeviceType.CAMERA2C, DeviceType.CAMERA2C_PRO,
    DeviceType.CAMERA3, DeviceType.CAMERA3C, DeviceType.CAMERA3_PRO,
    DeviceType.INDOOR_CAMERA, DeviceType.INDOOR_PT_CAMERA,
    DeviceType.INDOOR_CAMERA_1080, DeviceType.INDOOR_PT_CAMERA_1080,
    DeviceType.INDOOR_PT_CAMERA_S350, DeviceType.INDOOR_PT_CAMERA_E30,
    DeviceType.SOLO_CAMERA, DeviceType.SOLO_CAMERA_PRO,
    DeviceType.SOLO_CAMERA_SPOTLIGHT_1080,
    DeviceType.SOLO_CAMERA_SPOTLIGHT_2K,
    DeviceType.FLOODLIGHT, DeviceType.FLOODLIGHT_CAMERA_8422,
    DeviceType.FLOODLIGHT_CAMERA_8423, DeviceType.FLOODLIGHT_CAMERA_8424,
    DeviceType.FLOODLIGHT_CAMERA_8425, DeviceType.FLOODLIGHT_CAMERA_8426,
    DeviceType.DOORBELL,
}


# ---------------------------------------------------------------------------
# P2P encryption level
# ---------------------------------------------------------------------------
class P2PEncryptionLevel(IntEnum):
    NONE = 0
    LEVEL_1 = 1
    LEVEL_2 = 2


# ---------------------------------------------------------------------------
# Connection mode
# ---------------------------------------------------------------------------
class P2PConnectionMode(IntEnum):
    ONLY_LOCAL = 0
    QUICKEST = 1
    PREFER_LOCAL = 2


# ---------------------------------------------------------------------------
# Param types (for REST API upload_devs_params)
# ---------------------------------------------------------------------------
class ParamType(IntEnum):
    GUARD_MODE = 1224
    DEFAULT_SCHEDULE_MODE = 1257
    SNOOZE_MODE = 1271
    WATERMARK_MODE = 1214
    CAMERA_SPEAKER_VOLUME = 1230
    CAMERA_RECORD_CLIP_LENGTH = 1249
    CAMERA_RECORD_RETRIGGER_INTERVAL = 1250
    PUSH_MSG_MODE = 1252
    CAMERA_RECORD_ENABLE_AUDIO = 1366
    FLOODLIGHT_MANUAL_SWITCH = 1400
    FLOODLIGHT_MANUAL_BRIGHTNESS = 1401
    OPEN_DEVICE = 2001
    NIGHT_VISUAL = 2002
    VOLUME = 2003
    DETECT_MODE = 2004
    DETECT_MOTION_SENSITIVE = 2005
    DETECT_SWITCH = 2027
    PRIVATE_MODE = 99904


# ---------------------------------------------------------------------------
# Cloud API response codes
# ---------------------------------------------------------------------------
class ResponseCode(IntEnum):
    OK = 0
    SESSION_TIMEOUT = 401
    SERVER_MAINTENANCE = 424
    CONNECT_ERROR = 997
    NETWORK_ERROR = 998
    SERVER_ERROR = 999
    INVALID_PARAM = 10000
    EMAIL_NOT_REGISTERED = 22008
    WRONG_CREDENTIALS = 26006
    ACCOUNT_INACTIVE = 26015
    VERIFY_CODE_ERROR = 26050
    VERIFY_CODE_EXPIRED = 26051
    NEED_VERIFY_CODE = 26052
    VERIFY_CODE_MAX = 26053
    MAX_LOGIN_LIMIT = 100028
    ENCRYPTION_FAIL = 100029
    DECRYPTION_FAIL = 100030
    LOGIN_NEED_CAPTCHA = 100032
    LOGIN_CAPTCHA_ERROR = 100033
    REQUEST_TOO_FAST = 250999


# ---------------------------------------------------------------------------
# Push notification event types
# ---------------------------------------------------------------------------
class DoorbellPushEvent(IntEnum):
    BACKGROUND_ACTIVE = 3100
    MOTION_DETECTION = 3101
    FACE_DETECTION = 3102
    PRESS_DOORBELL = 3103
    PET_DETECTION = 3106
    VEHICLE_DETECTION = 3107
    PACKAGE_DELIVERED = 3301
    PACKAGE_TAKEN = 3302
    FAMILY_DETECTION = 3303
    PACKAGE_STRANDED = 3304
    SOMEONE_LOITERING = 3305
    RADAR_MOTION_DETECTION = 3306


class CusPushEvent(IntEnum):
    SECURITY = 1
    TFCARD = 2
    DOOR_SENSOR = 3
    CAM_STATE = 4
    MODE_SWITCH = 9
    ALARM = 10
    MOTION_SENSOR_PIR = 14


class IndoorPushEvent(IntEnum):
    MOTION = 3100
    FACE = 3102
    CRYING = 3104
    PET = 3106
    SOUND = 3108


class LockPushEvent(IntEnum):
    MANUAL_UNLOCK = 257
    AUTO_UNLOCK = 258
    PW_UNLOCK = 259
    FINGERPRINT_UNLOCK = 260
    APP_UNLOCK = 261
    MANUAL_LOCK = 262
    KEYPAD_LOCK = 263
    APP_LOCK = 264
    AUTO_LOCK = 265
    LOW_POWER = 513
    MECHANICAL_ANOMALY = 517
    VIOLENT_DESTRUCTION = 518


class SmartSafeEvent(IntEnum):
    WRONG_PIN = 1
    OPENED = 2
    LOW_BATTERY = 3
    SHAKING = 4
    LONG_OPEN = 5


# ---------------------------------------------------------------------------
# Audio / Video codecs
# ---------------------------------------------------------------------------
class VideoCodec(IntEnum):
    UNKNOWN = 0
    H264 = 1
    H265 = 2


class AudioCodec(IntEnum):
    NONE = -1
    UNKNOWN = 0
    AAC = 1
    AAC_LC = 2
    AAC_ELD = 3
