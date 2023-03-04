#!/usr/bin/env python
"""
Retries name resolution and adds result to hostsfile.
"""
import argparse
import socket
import logging
import time

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

HOSTS_FILE = "/etc/hosts"


def resolve_hostname(hostname, retries=10):
    for _ in range(retries):
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            log.debug("DNS resolution error, retrying.")
            time.sleep(1)
    raise RuntimeError(
        "Unable to resolve {0} after {1} attempts.".format(hostname, retries)
    )


def add_hosts_entry(hostname, ip):
    with open(HOSTS_FILE, "a+") as fp:
        fp.write("{0}    {1}\n".format(ip, hostname))


def resolve_spotty_dns(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--debug", action="store_true", help="debug logging")
    parser.add_argument("hostname", nargs="+", help="hostname to resolve")
    args = parser.parse_args(argv)

    if args.debug:
        log.setLevel(logging.DEBUG)

    for hostname in args.hostname:
        ip = resolve_hostname(hostname)
        log.info("Resolved: %s -> %s", hostname, ip)
        add_hosts_entry(hostname, ip)


if __name__ == "__main__":
    resolve_spotty_dns()
