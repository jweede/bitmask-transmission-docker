#!/usr/bin/env python3
"""
Bitmask startup and wait for vpn/firewall initialization
"""
import argparse
import logging
import os
import subprocess
import json
import time
import sys

logging.basicConfig(level=logging.INFO, format="[%(levelname)-8s] %(message)s")
log = logging.getLogger(__name__)


def call_bitmask(*args):
    return subprocess.check_output(("bitmaskctl", "--json") + args, universal_newlines=True)


def check_ready(vpn_status_raw_json):
    """parses bitmask vpn status"""
    log.debug("vpn_status: %s", vpn_status_raw_json)
    status = json.loads(vpn_status_raw_json)
    error_status = status["error"]
    if error_status is not None:
        log.error("vpn status error: %r", error_status)
        return False
    vpn_status = status["result"]["childrenStatus"]["vpn"]["status"] == "on"
    fw_status = status["result"]["childrenStatus"]["firewall"]["status"] == "on"
    overall_status = status["result"]["status"] == "on"
    log.debug("vpn_status=%s fw_status=%s status=%s", vpn_status, fw_status, overall_status)
    return vpn_status and fw_status and overall_status


def start_vpn(max_retries=5):
    """starts vpn, waits for it to be ready"""
    call_bitmask("vpn", "start")
    ready = False
    retries = 0
    for i in range(1, max_retries+1):
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


if __name__ == "__main__":
    bitmask_init()
