from copy import deepcopy

import pytest

from th1.http2.frames import HTTP2FrameSignature, HTTP2SettingsFrame
from th1.http2.parser import parse_nghttpd_log


@pytest.mark.parametrize("key", [8, 9, 0x10, 0x4D44])
@pytest.mark.parametrize("value", [0, 1])
def test_extension_settings_round_trip(key, value):
    expected = {
        "frame_type": "SETTINGS",
        "stream_id": 0,
        "settings": [{"key": key, "value": value}],
    }
    frame = HTTP2FrameSignature.from_dict(deepcopy(expected))
    assert frame.to_dict() == expected
    restored = HTTP2FrameSignature.from_dict(deepcopy(frame.to_dict()))
    assert restored.to_dict() == expected
    assert frame.equals(restored) == (True, "")


@pytest.mark.parametrize("key", [8, 9, 0x10, 0x4D44])
def test_extension_settings_values_affect_equality(key):
    disabled = HTTP2SettingsFrame(0, [{"key": key, "value": 0}])
    enabled = HTTP2SettingsFrame(0, [{"key": key, "value": 1}])
    equal, reason = disabled.equals(enabled)
    assert not equal
    assert f"{key}:0 != {key}:1" in reason


def test_connect_and_priority_settings_are_distinct():
    connect = HTTP2SettingsFrame(0, [{"key": 8, "value": 1}])
    priorities = HTTP2SettingsFrame(0, [{"key": 9, "value": 1}])
    assert not connect.equals(priorities)[0]


@pytest.mark.parametrize("key", [0xAAAA, "GREASE"])
def test_unknown_settings_keep_grease_normalization(key):
    frame = HTTP2SettingsFrame(0, [{"key": key, "value": 123}])
    assert frame.to_dict()["settings"] == [{"key": "GREASE", "value": "GREASE"}]


@pytest.mark.parametrize("metadata_id", ["4d44", "4D44"])
def test_parse_nghttpd_extension_settings(metadata_id):
    log = f"""[id=1] [  0.001] recv SETTINGS frame <length=24, flags=0x00, stream_id=0>
          (niv=4)
          [SETTINGS_ENABLE_CONNECT_PROTOCOL(0x08):1]
          [SETTINGS_NO_RFC7540_PRIORITIES(0x09):0]
          [UNKNOWN(0x10):1]
          [UNKNOWN(0x{metadata_id}):1]
""".encode()
    signature = parse_nghttpd_log(log)
    assert signature.to_dict()["frames"][0]["settings"] == [
        {"key": 8, "value": 1},
        {"key": 9, "value": 0},
        {"key": 0x10, "value": 1},
        {"key": 0x4D44, "value": 1},
    ]
