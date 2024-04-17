import json
import argparse

import yaml

from th1.http2.parser import parse_nghttpd_log
from th1.tls.parser import parse_pcap


parser = argparse.ArgumentParser()
parser.add_argument("--browser", type=str, required=True, help="incoming browser string")
parser.add_argument("--port", type=int, default=8443, help="which PORT was used to listen to parse")
parser.add_argument("--raw-ip", action="store_true", default=False, help="This is raw IP pcap file")
args = parser.parse_args()

filename = f"logs/{args.browser}.pcap"
with open(filename, "rb") as f:
    content = f.read()
    tls = parse_pcap(content, port=args.port, raw_ip=args.raw_ip)
    print(tls)
    print(tls[0]["signature"].to_dict())


filename = f"logs/{args.browser}.log"
with open(filename, "rb") as f:
    http2 = parse_nghttpd_log(f.read())
    print(http2.to_dict())


filename = f"logs/{args.browser}.json"
with open(filename, "rb") as f:
    third_party = json.loads(f.read())


result_yaml = {
    "browser": {
        "name": "NEW",
        "version": "NEW",
        "os": "macOS",
    },
    "third_party": third_party,
    "signature": {
        "tls_client_hello": tls[0]["signature"].to_dict(),
        "http2": http2.to_dict(),
    },
}


filename = "signatures/NEW.yaml"

with open(filename, "w") as f:
    f.write(yaml.dump(result_yaml))
