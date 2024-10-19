"""
Enforces transmission configuration
"""
import argparse
import json
import os
import pathlib
import re
import subprocess


class TransmissionSettingsManager:

    def __init__(self, settings_path):
        self.s = pathlib.Path(settings_path)
        try:
            self.settings = json.loads(self.s.read_text())
        except:
            self.settings = {}

    def set_defaults(self):
        self.settings.update({
            "incomplete-dir-enabled": False,
            "download-dir": "/downloads",
            "watch-dir-enabled": False,
        })

    def set_if_exist(self, env_name, setting_name):
        val = os.environ.get(env_name)
        if val:
            self.settings[setting_name] = val

    def bind_to_interface_addresses(self, dev_name):
        """finds the interface addresses using `ip` and adds them as settings to transmission."""
        ip_output = subprocess.check_output(["ip", "addr", "show", "dev", dev_name], text=True)
        m4 = re.search(r"inet ([0-9.]+)/[0-9]+", ip_output)
        if m4:
            self.settings["bind-address-ipv4"] = m4.group(1)
        m6 = re.search(r"inet6 ([a-f0-9:]+)/[0-9]+", ip_output)
        if m6:
            self.settings["bind-address-ipv6"] = m6.group(1)

    def write_settings(self):
        self.s.write_text(json.dumps(self.settings, indent=4, sort_keys=True))

    @classmethod
    def main(cls, argv=None):
        parser = argparse.ArgumentParser()
        parser.add_argument("settings_path", type=pathlib.Path)

        args = parser.parse_args(argv)

        tsm = cls(args.settings_path)

        tsm.set_defaults()
        tsm.set_if_exist("TRANSMISSION_RPC_URL", "rpc-url")
        tsm.bind_to_interface_addresses("tun0")

        tsm.write_settings()


if __name__ == "__main__":
    TransmissionSettingsManager.main()
