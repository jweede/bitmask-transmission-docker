#!/usr/bin/env python3
"""
Configures transmission from a yaml file
"""
import argparse
import json
import yaml
import os
import subprocess


def transmission_config(src, dest):
    subprocess.check_output(
        ["mkdir", "-p", os.path.dirname(src), os.path.dirname(dest)]
    )
    with open(src) as fp:
        data = yaml.safe_load(fp)
    with open(dest, "w") as fp:
        json.dump(data, fp)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("src")
    parser.add_argument("dest")
    args = parser.parse_args(argv)

    transmission_config(args.src, args.dest)


if __name__ == "__main__":
    main()
