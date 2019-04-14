#!/usr/bin/env python3
""""""
import logging
import os
import subprocess

logging.basicConfig(level=logging.INFO, format="[%(levelname)-8s] %(message)s")
log = logging.getLogger(__name__)


def call_bitmask(*args):
    return subprocess.check_output(("bitmaskctl", "--json") + args)


def start_vpn():
    call_bitmask("vpn", "start")
    ready = False
    while not ready:
        stat = call_bitmask("vpn", "status")
        log.debug("vpn_status: %s", stat)


def bitmask_init():
    user, _pass = os.environ["BITMASK_USER"], os.environ["BITMASK_PASS"]
    log.info("logging in as %s", user)
    call_bitmask("user", "auth", user, "--pass", _pass)

    call_bitmask("vpn", "get_cert")

    # call_bitmask("vpn", "check")
    start_vpn()


if __name__ == "__main__":
    bitmask_init()
