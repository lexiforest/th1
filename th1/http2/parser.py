"""
Utility module to parse nghttpd logs and extract HTTP/2 client signatures from them.
"""
import re
from typing import Dict, List, Tuple
from .signature import HTTP2FrameSignature, HTTP2Signature


def _process_settings_frame(lines) -> List[Tuple[int, int]]:
    match = None
    while match is None:
        # Consume the next lines until the number of settings is found
        match = re.match(r"\s*\(niv=(\d+)\)", next(lines))
    niv = int(match.group(1))

    settings = []
    for _ in range(niv):
        line = next(lines)
        match = re.match(r"\s*\[[A-Z_]+\(0x(\d+)\):(\d+)\]", line)
        if not match:
            raise Exception(f"Malformed log: unexpected line '{line}'")

        key = int(match.group(1), 16)
        value = int(match.group(2))
        settings.append({"key": key, "value": value})
        # settings.append((key, value))

    return settings


def _process_window_update_frame(lines) -> int:
    line = next(lines)
    match = re.match(r"\s*\(window_size_increment=(\d+)\)", line)
    if not match:
        raise Exception(f"Malformed log: unexpected line '{line}'")

    return int(match.group(1))


def _process_headers_frame(previous_lines: List[str], stream_id: int):
    pseudo_headers = []
    headers = []
    for line in previous_lines:
        match = re.match(rf".*recv \(stream_id={stream_id}\) (.*)", line)
        # print(match)
        if match:
            header = match.group(1)
            # If the headers starts with ":" it is a pseudo-header,
            # i.e. ":authority". In this case keep only the header name and
            # discard the value
            if header.startswith(":"):
                m = re.match(r"(:\w+):", header)
                if m:
                    pseudo_headers.append(m.group(1))
            else:
                headers.append(header)
    return pseudo_headers, headers


def _process_priority_frame(lines) -> Dict:
    line = next(lines)
    match = re.match(r"\s*\(dep_stream_id=(\d+), weight=(\d+), exclusive=(\d+)\)", line)
    if not match:
        raise Exception(f"Malformed log: unexpected line '{line}'")
    return {
        "dep_stream_id": int(match.group(1)),
        "weight": int(match.group(2)),
        "exclusive": bool(int(match.group(3))),
    }


def parse_nghttpd_log(log: bytes):
    """Parse the nghttpd log.

    Returns a dictionary containing the HTTP/2 frames found in the log.
    The keys are client IDs as reported by nghttpd. Each value is a list
    of frames each parsed into a dictionary format.
    """
    frames = []
    lines = iter(log.decode().splitlines())
    previous_lines = []
    try:
        for line in lines:
            # A frame received from the client would appear in the log as:
            # "[id=1] [  7.801] recv WINDOW_UPDATE frame <length=4, flags=0x00, stream_id=0>"
            match = re.match(
                r"\[id=(\d+)\].*recv ([A-Z_]+) frame.*stream_id=(\d+)", line
            )
            if not match:
                # The log lines of the HEADERS frame come before the
                # "recv HEADERS" log line. Therefore we have to keep
                # track of previously received lines.
                previous_lines.append(line)
                continue

            client_id = int(match.group(1))
            frame_type = match.group(2)
            stream_id = int(match.group(3))

            frame = {
                "frame_type": frame_type,
                "stream_id": stream_id,
                "client_id": client_id,
            }
            if frame_type == "SETTINGS":
                frame["settings"] = _process_settings_frame(lines)
            elif frame_type == "WINDOW_UPDATE":
                frame["window_size_increment"] = _process_window_update_frame(lines)
            elif frame_type == "HEADERS":
                frame["pseudo_headers"], frame["headers"] = _process_headers_frame(
                    previous_lines, stream_id
                )
            elif frame_type == "PRIORITY":
                frame["priority"] = _process_priority_frame(lines)
            else:
                raise Exception(f"Unknown frame type: {frame_type}")

            frames.append(frame)

            previous_lines = []

            # Stop after the first HEADERS frame
            if frame_type == "HEADERS":
                break
    except StopIteration:
        raise Exception("Malformed log: log ended unexpectedly")

    print(frames)

    return HTTP2Signature.from_dict({"frames": frames})

    # return [
    #     {
    #         "client_id": client_id,
    #         "signature": HTTP2Signature.from_dict({"frames": frames}),
    #     }
    #     for client_id, frames in NghttpdLogParser(log).parse().items()
    # ]
