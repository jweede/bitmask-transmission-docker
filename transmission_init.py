#!/usr/bin/env python3
""""""
import argparse
import json
import yaml
import os


def transmission_config(src, dest):
    os.makedirs(os.path.dirname(src), exist_ok=True)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(src) as fp:
        data = yaml.load(fp)
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
