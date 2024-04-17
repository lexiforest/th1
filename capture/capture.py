import argparse
import json
import subprocess
import time
from contextlib import contextmanager
import lxml.html

import yaml
from loguru import logger
from selenium import webdriver
from playwright.sync_api import sync_playwright

from th1.http2.parser import parse_nghttpd_log
from th1.tls.parser import parse_pcap

# You can not control what port chrome will use.
LOCAL_PORTS = [0, 65535]
TIMEOUT = 20
LISTEN_PORT = "8443"


@contextmanager
def start_tcpdump(interface: str):
    """Initialize a sniffer to capture curl's traffic."""

    logger.info(f"Running tcpdump on interface {interface}")

    try:
        p = subprocess.Popen(
            [
                "sudo",
                "tcpdump",
                "-n",
                "-i",
                interface,
                "-s",
                "0",
                "-w",
                "-",
                "-U",  # Important, makes tcpdump unbuffered
                (
                    f"(tcp src portrange {LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}"
                    f" and tcp dst port {LISTEN_PORT}) or "
                    f"(tcp dst portrange {LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}"
                    f" and tcp src port {LISTEN_PORT})"
                ),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        yield p
    finally:
        p.terminate()
        p.wait(timeout=TIMEOUT)


@contextmanager
def start_nghttpd():
    """Initiailize an HTTP/2 server.
    The returned object is an asyncio.subprocess.Process object,
    so async methods must be used with it.
    """
    logger.info("Running nghttpd on :8443")

    try:
        proc = subprocess.Popen(
            [
                "nghttpd",
                "-v",
                LISTEN_PORT,
                "capture/ssl/server.key",
                "capture/ssl/server.crt",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=TIMEOUT)


def capture(browser, interface):
    # driver = connect_to_selenium(browser)
    with start_tcpdump(interface) as tcpdump, start_nghttpd() as nghttpd:

        try:
            time.sleep(1000000)
        except KeyboardInterrupt:
            pass

        try:
            stdout, stderr = tcpdump.communicate(timeout=8)
            assert tcpdump.returncode == 0, f"tcp dump failed: {stderr}"
        except subprocess.TimeoutExpired:
            tcpdump.kill()
            stdout, stderr = tcpdump.communicate(timeout=5)

        tls_results = parse_pcap(stdout, port=8443)

        # print(stdout, stderr)
        for result in tls_results:
            print(result["signature"].to_dict())

        try:
            stdout, stderr = nghttpd.communicate(timeout=5)
            assert nghttpd.returncode == 0, f"nghttpd failed: {nghttpd.returncode} {stderr}"
        except subprocess.TimeoutExpired:
            nghttpd.kill()
            stdout, stderr = nghttpd.communicate(timeout=5)
        http2_result = parse_nghttpd_log(stdout)

        # print(http2_result)
        for line in stdout.decode().split("\n"):
            print(line)
        # print(stdout, stderr)

    result_yaml = {
        "browser": {
            "name": name,
            "version": version,
            "os": os,
        },
        "third_party": json.loads(ja3_content),
        "signature": {
            "tls_client_hello": tls_results[0]["signature"].to_dict(),
            "http2": http2_result.to_dict(),
        },
    }

    filename = f"signatures/{name}_{version}_{os}.yaml"

    with open(filename, "w") as f:
        f.write(yaml.dump(result_yaml))


def capture_all(interface):
    # for browser in ["chrome", "firefox", "edge"]:
    for browser in ["edge"]:
        for version in ["118.0", "119.0", "120.0"]:
            logger.info("running {} {}", browser, version)
            capture(browser, interface)


if __name__ == "__main__":
    import chromedriver_autoinstaller
    chromedriver_autoinstaller.install()
    parser = argparse.ArgumentParser()
    parser.add_argument( "-i", "--interface", default="eth0", help="interface to capture")
    parser.add_argument( "-b", "--browser", default="chrome", help="browser to capture")
    args = parser.parse_args()
    capture(args.browser, args.interface)
    # capture_all(args.interface)
