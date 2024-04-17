from ..base import Signature
from .frames import *


class HTTP2Signature(Signature):
    """
    Signature of an HTTP/2 client.

    Combines the first frames sent by the client during the initial phase of
    the HTTP/2 connection to form a signature, which can then be compared with
    other client's signature to identify whether it originated from a similar
    client.

    The signature includes all the frames up to, and including, the first
    HEADERS frame sent by the client. The HEADERS frame is recorded partially,
    excluding the actual HTTP headers, as the focus of this class is on HTTP/2
    only parameters.
    The HTTP/2 signature of a browser.

    In HTTP/2 multiple parameters can be used to fingerprint the browser.
    Currently this class contains the following parameters:
    * The order of the HTTP/2 pseudo-headers.
    * The "regular" HTTP headers sent by the browser upon first connection to a website.
    """

    def __init__(self, frames: list[HTTP2FrameSignature]):
        """
        Initialize a new HTTP2Signature.

        Signatures can be compared with one another to check if they are equal.

        Paramaeters
        -----------
        frames: list[HTTP2FrameSignature]
            List of frames sent by the client during the initial phase of the
            HTTP/2 connections. The frames recorded are all the frames up to,
            and including, the HEADERS frame.
        """
        self.frames = frames

    @property
    def relevant_frames(self):
        frames = []
        for frame in self.frames:
            # ignore empty settings frame
            if frame.frame_type == "SETTINGS" and len(frame.settings) == 0:
                continue
            frames.append(frame)
        return frames

    def equals(self, other) -> tuple[bool, str]:
        # old type of data, only headers
        if len(self.frames) == 1 or len(other.frames) == 1:
            our_header_frame = None
            other_header_frame = None
            for frame in self.frames:
                if frame.frame_type == "HEADERS":
                    our_header_frame = frame
            for frame in other.frames:
                if frame.frame_type == "HEADERS":
                    other_header_frame = frame
            if not our_header_frame or not other_header_frame:
                return False, "http2 header frame not matched"

            equal, reason = our_header_frame.equals(other_header_frame)
            if not equal:
                return False, reason

            return True, ""

        if len(self.relevant_frames) != len(other.relevant_frames):
            return False, "http2 frame count not match"

        for our_frame, other_frame in zip(self.relevant_frames, other.relevant_frames):
            equal, reason = our_frame.equals(other_frame)
            if not equal:
                return False, reason

        return True, ""

    def to_dict(self):
        """Serialize to a dict object."""
        return {"frames": [frame.to_dict() for frame in self.frames]}

    @classmethod
    def from_dict(cls, d: dict):
        """Unserialize HTTP2Signature from a dict.

        Parameters
        ----------
        d : dict
            HTTP/2 signature encoded to a Python dict, possibly by using
            HTTP2Signature.to_dict()

        Returns
        -------
        sig : HTTP2Signature
            Signature constructed from the dict representation.
        """
        return cls(
            frames=[HTTP2FrameSignature.from_dict(frame) for frame in d["frames"]]
        )
