#!/usr/bin/env python
"""
Bitmask startup and wait for vpn/firewall initialization
"""
import argparse
import json
import logging
import os
import subprocess
import sys
import time

import requests

logging.basicConfig(level=logging.INFO, format="[%(levelname)-8s] %(message)s")
log = logging.getLogger(__name__)

EXTERNAL_IP_URL = "https://ifconfig.me/ip"


def check_external_ip():
    """verify with an external service"""
    res = requests.get(EXTERNAL_IP_URL)
    res.raise_for_status()
    return res.text.strip()


def call_bitmask(*args):
    """wraps calls to bitmaskctl, detects errors"""
    cmd = ("bitmaskctl", "--json") + args
    result = subprocess.check_output(cmd, universal_newlines=True)
    log.debug("%s -> %s", cmd, result)
    jresult = json.loads(result)
    if jresult["error"]:
        raise RuntimeError("cmd={0!r} output={1!r}".format(cmd, jresult))
    return jresult


def check_ready(status):
    """parses bitmask vpn status"""
    log.debug("vpn_status: %s", status)
    if status["error"] is not None:
        log.error("vpn status error: %r", status["error"])
        return False
    vpn_status = status["result"]["childrenStatus"]["vpn"]["status"] == "on"
    fw_status = status["result"]["childrenStatus"]["firewall"]["status"] == "on"
    overall_status = status["result"]["status"] == "on"
    log.debug(
        "vpn_status=%s fw_status=%s status=%s", vpn_status, fw_status, overall_status
    )
    return vpn_status and fw_status and overall_status


def start_vpn(max_retries=10):
    """starts vpn, waits for it to be ready"""
    call_bitmask("vpn", "start")
    ready = False
    retries = 0
    for i in range(1, max_retries + 1):
        stat = call_bitmask("vpn", "status")
        ready = check_ready(stat)
        log.debug("check_ready: %s", ready)
        if ready:
            log.info("vpn ready")
            break
        else:
            log.warning("vpn not ready yet (%d of %d)", i, max_retries)
            time.sleep(2)
            retries += 1
    if not ready:
        log.error("vpn not ready after %d attempts", retries)
        sys.exit(2)


def bitmask_init(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    args = parser.parse_args(argv)
    if args.debug:
        log.setLevel(logging.DEBUG)

    user = args.username or os.environ["BITMASK_USER"]
    _pass = args.password or os.environ["BITMASK_PASS"]

    log.info("logging in as %s", user)
    call_bitmask("user", "auth", user, "--pass", _pass)
    log.info("grabbing cert")
    call_bitmask("vpn", "get_cert")
    log.info("starting vpn")
    # call_bitmask("vpn", "check")
    start_vpn()

    # new_ip = check_external_ip()
    # log.info("vpn ip: %s", new_ip)


if __name__ == "__main__":
    bitmask_init()
