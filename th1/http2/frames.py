from typing import List, Optional

from ..base import Signature


class HTTP2FrameSignature(Signature):
    # A registry of subclasses
    registry = {}
    frame_type: str

    def __init__(self, stream_id: Optional[int] = 0):
        self.stream_id = stream_id

    def __init_subclass__(cls, frame_type: str, **kwargs):
        """Register subclasses to the registry"""
        super().__init_subclass__(**kwargs)
        cls.registry[frame_type] = cls
        cls.frame_type = frame_type

    def to_dict(self) -> dict:
        d = {"frame_type": self.frame_type}
        if self.stream_id is not None:
            d["stream_id"] = self.stream_id
        return d

    @classmethod
    def from_dict(cls, d):
        """Unserialize an HTTP2FrameSignature from a dict.

        Initializes the suitable subclass if exists, otherwise initializes
        an HTTP2FrameSignature proper instance.
        """
        d = d.copy()
        frame_type = d.pop("frame_type")
        if frame_type not in cls.registry:
            raise Exception("Unknow frame type: {}".format(frame_type))
        return cls.registry[frame_type].from_dict(d)

    def equals(self, other: "HTTP2FrameSignature"):
        raise NotImplementedError()


class HTTP2SettingsFrame(HTTP2FrameSignature, frame_type="SETTINGS"):
    # Some browsers (e.g. Chrome 98) added a non-existent, randomly-generated
    # settings key to the SETTINGS frame. This is denoted as HTTP2_GREASE due
    # to similarity with TLS GREASE
    HTTP2_GREASE = "GREASE"

    # See RFC7540, section "Defined SETTINGS parameters"
    VALID_SETTINGS = [1, 2, 3, 4, 5, 6]

    def __init__(self, stream_id: Optional[int], settings: list[tuple[int, int]]):
        super().__init__(stream_id)
        self.settings = []
        for setting in settings:
            if setting["key"] not in self.VALID_SETTINGS:
                setting["key"] = self.HTTP2_GREASE
            if setting["key"] == self.HTTP2_GREASE:
                setting["value"] = self.HTTP2_GREASE
            self.settings.append(setting)

    def to_dict(self):
        d = super().to_dict()
        d["settings"] = self.settings
        return d

    @classmethod
    def from_dict(cls, d: dict):
        return cls(stream_id=d.get("stream_id"), settings=d["settings"])

    def equals(self, other: "HTTP2SettingsFrame") -> tuple[bool, str]:
        for our_setting, their_setting in zip(self.settings, other.settings):
            if (
                our_setting["key"] != their_setting["key"]
                or our_setting["value"] != their_setting["value"]
            ):
                return (
                    False,
                    f"http2 settings frame: {our_setting['key']}:{our_setting['value']} != {their_setting['key']}:{their_setting['value']}",
                )
        return True, ""


class HTTP2WindowUpdateFrame(HTTP2FrameSignature, frame_type="WINDOW_UPDATE"):
    def __init__(self, stream_id: Optional[int], window_size_increment: int):
        super().__init__(stream_id)
        self.window_size_increment = window_size_increment

    def to_dict(self):
        d = super().to_dict()
        d["window_size_increment"] = self.window_size_increment
        return d

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            stream_id=d.get("stream_id"),
            window_size_increment=d["window_size_increment"],
        )

    def equals(self, other: "HTTP2WindowUpdateFrame") -> tuple[bool, str]:
        if self.window_size_increment != other.window_size_increment:
            return (
                False,
                f"http2 window_size_increment not equal, {self.window_size_increment} != {other.window_size_increment}",
            )
        return True, ""


class HTTP2HeadersFrame(HTTP2FrameSignature, frame_type="HEADERS"):
    def __init__(
        self, stream_id: Optional[int], pseudo_headers: List[str], headers: list[str]
    ):
        super().__init__(stream_id)
        self.pseudo_headers = pseudo_headers
        self.headers = headers

    def equals(self, other: "HTTP2HeadersFrame") -> tuple[bool, str]:
        if set(self.pseudo_headers) != set(other.pseudo_headers):
            symdiff = list(
                set(self.pseudo_headers).symmetric_difference(other.pseudo_headers)
            )
            msg = f"HTTP/2 pseudo-headers differ: " f"Symmetric difference {symdiff}"
            return False, msg

        if self.pseudo_headers != other.pseudo_headers:
            msg = (
                f"HTTP/2 pseudo-headers differ in order: "
                f"{self.pseudo_headers} != {other.pseudo_headers}"
            )
            return False, msg

        if set(self.headers) != set(other.headers):
            symdiff = list(set(self.headers).symmetric_difference(other.headers))
            msg = f"HTTP/2 headers differ: " f"Symmetric difference {symdiff}"
            return False, msg

        if self.headers != other.headers:
            msg = (
                f"HTTP/2 headers differ in order: " f"{self.headers} != {other.headers}"
            )
            return False, msg

        return True, ""

    def to_dict(self):
        d = super().to_dict()
        d["pseudo_headers"] = self.pseudo_headers
        d["headers"] = self.headers
        return d

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            stream_id=d.get("stream_id"),
            pseudo_headers=d["pseudo_headers"],
            headers=d["headers"],
        )


class HTTP2PriorityFrame(HTTP2FrameSignature, frame_type="PRIORITY"):
    def __init__(
        self, stream_id: Optional[int], dep_stream_id: int, weight: int, exclusive: bool
    ):
        super().__init__(stream_id)
        self.priority = {
            "dep_stream_id": dep_stream_id,
            "weight": weight,
            "exclusive": exclusive,
        }

    def to_dict(self):
        d = super().to_dict()
        d["priority"] = self.priority
        return d

    @classmethod
    def from_dict(cls, d: dict):
        return cls(stream_id=d.get("stream_id"), **d["priority"])

    def equals(self, other: "HTTP2PriorityFrame"):
        if self.priority != other.priority:
            return (
                False,
                f"http2 priority frame diff: {self.priority} != {other.priority}",
            )
        return True, ""
