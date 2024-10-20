#!/usr/bin/env python3
"""
Enforces transmission configuration.
If transmission is running and the config changes,
it will send a HUP to the process to reload config.
"""
import argparse
import copy
import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path

script_name = Path(__file__).name

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(script_name)

DEFAULT_SETTINGS_PATH = Path("/config/settings.json")


class TransmissionSettingsManager:
    __slots__ = ("s", "settings", "initial_settings")

    daemon_name = "transmission-daemon"

    def __init__(self, settings_path):
        self.s = Path(settings_path).resolve()
        if not self.s.parent.exists():
            self.s.parent.mkdir()
        try:
            self.settings = json.loads(self.s.read_text())
            log.info("Loaded settings from %s", self.s)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            self.settings = {}
            log.warning("No settings found, initializing %s", self.s)
        self.initial_settings = copy.deepcopy(self.settings)

    def set_defaults(self):
        self.settings.update(
            {
                "incomplete-dir-enabled": False,
                "download-dir": "/downloads",
                "watch-dir-enabled": False,
            }
        )

    def set_if_exist(self, env_name, setting_name):
        val = os.environ.get(env_name)
        if val:
            self.settings[setting_name] = val

    def bind_to_interface_addresses(self, dev_name):
        """finds the interface addresses using `ip` and adds them as settings to transmission."""
        self.wait_for_interface(dev_name)

        ip_output = subprocess.check_output(
            ["ip", "addr", "show", "dev", dev_name], text=True
        )
        m4 = re.search(r"inet ([0-9.]+)/[0-9]+", ip_output)
        if m4:
            self.settings["bind-address-ipv4"] = m4.group(1)
        m6 = re.search(r"inet6 ([a-f0-9:]+)/[0-9]+", ip_output)
        if m6:
            self.settings["bind-address-ipv6"] = m6.group(1)

    @staticmethod
    def wait_for_interface(dev_name, retries=10, interval=5):
        """wait for dev to exist"""
        for i in range(1, retries + 1):
            if Path(f"/sys/class/net/{dev_name}").exists():
                return True
            else:
                log.warning(f"{dev_name} not ready yet, retrying %d", i)
                time.sleep(interval)
        else:
            log.error("Maximum retries reached")
            raise RuntimeError(
                f"Device {dev_name!r} still missing after {retries} attempts"
            )

    def write_settings(self):
        if self.settings != self.initial_settings:
            self.s.write_text(json.dumps(self.settings, indent=4, sort_keys=True))
            log.info("Wrote transmission settings to %s", self.s)
            self.send_reload_to_transmission()
        else:
            log.info("No change to transmission settings in %s", self.s)

    def send_reload_to_transmission(self):
        """
        Send reload signal to transmission
        https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md#reload-settings
        """
        log.info("Sending HUP to %s", self.daemon_name)
        subprocess.run(["killall", "-HUP", self.daemon_name], check=False)

    @classmethod
    def main(cls, argv=None):
        parser = argparse.ArgumentParser()
        parser.add_argument("settings_path", type=Path, default=DEFAULT_SETTINGS_PATH)

        args = parser.parse_args(argv)

        tsm = cls(args.settings_path)

        tsm.set_defaults()
        tsm.set_if_exist("TRANSMISSION_RPC_URL", "rpc-url")
        tsm.bind_to_interface_addresses("tun0")

        tsm.write_settings()


if __name__ == "__main__":
    TransmissionSettingsManager.main()
