#!/usr/bin/env python3
"""
Adapted from https://gitlab.com/nitrohorse/bitmask-openvpn-generator
"""
import json
import os
import pathlib
from datetime import datetime
import logging
from typing import List, Dict, Any
import re

import requests
import jinja2
from OpenSSL import crypto

here = pathlib.Path(__file__).resolve().parent
cache_dir = here / "_ovpn_cache"

ca_cert = pathlib.Path("ca_cert.pem")
client_cert = pathlib.Path("client_cert.pem")
client_key = pathlib.Path("client_key.pem")

providers = [
    {
        "name": "riseup",
        "domain_url": "https://riseup.net",
        "provider_path": "/provider.json",
        "configs_path": "/1/configs.json",
    },
    {
        "name": "calyx",
        "domain_url": "https://calyx.net",
        "provider_path": "/provider.json",
        "configs_path": "/1/configs.json",
    },
]

# gateways = [
# 	{
# 		"provider": "riseup",
# 		"ip_address": "37.218.241.7",
# 		"host": "cisne.riseup.net",
# 		"location": {
# 			"name": "Miami",
# 			"country_code": "US"
# 		},
# 		"protocols": [
# 			"tcp"
# 		],
# 		"ports": [
# 			"1194"
# 		]
# 	}
# ]
gateways = []

# openvpn_configurations = {
# 	"riseup": {
# 		"auth": "SHA1",
# 		"cipher": "AES-128-CBC",
# 		"keepalive": "10 30",
# 		"tls-cipher": "DHE-RSA-AES128-SHA",
# 		"tun-ipv6": True
# 	}
# }
openvpn_configurations = {}

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

jenv = jinja2.Environment(
    loader=jinja2.FileSystemLoader([here]), undefined=jinja2.StrictUndefined
)
jenv.globals.update(
    {
        "providers": providers,
        "gateways": gateways,
        "openvpn_configurations": openvpn_configurations,
        "script_name": pathlib.Path(__file__).name,
        "ca_cert": ca_cert,
        "client_cert": client_cert,
        "client_key": client_key,
    }
)

ssl_verify = os.environ.get("SSL_VERIFICATION_DISABLE") is None


def format_subject_issuer(x509_issuer):
    """
    https://web.archive.org/web/20191001225633/http://www.zedwood.com/article/python-openssl-x509-parse-certificate
    """
    items = (str(v, "utf-8") for k, v in x509_issuer.get_components())
    return ", ".join(items)


def format_asn1_date(d: bytes):
    return datetime.strptime(d.decode("ascii"), "%Y%m%d%H%M%SZ").strftime("%Y-%m-%d")


def is_ca_cert_fingerprint_valid(x509_sha256, expected_ca_cert_fingerprint):
    sha256_prefix = "SHA256: "
    expected_ca_cert_fingerprint = expected_ca_cert_fingerprint.replace(
        sha256_prefix, ""
    )
    x509_sha256_formatted = (
        x509_sha256.replace(sha256_prefix, "").replace(":", "").lower()
    )
    return x509_sha256_formatted == expected_ca_cert_fingerprint


def is_provider_info_valid(provider_timestamp: str) -> bool:
    datetime_format = "%Y-%m-%d %H:%M:%S.%f"
    datetime_now = str(datetime.now())
    diff_in_days = (
        datetime.strptime(datetime_now, datetime_format)
        - datetime.strptime(provider_timestamp, datetime_format)
    ).days
    if diff_in_days <= 1:
        return True
    else:
        return False


def days_until_from_now(date: str) -> int:
    return (datetime.strptime(date, "%Y-%m-%d") - datetime.now()).days


def update_provider_info(provider: Dict[str, str], data: Dict[str, str]) -> None:
    provider["api_uri"] = data["api_uri"]
    provider["api_version"] = data["api_version"]
    provider["ca_cert_fingerprint"] = data["ca_cert_fingerprint"]
    provider["ca_cert_uri"] = data["ca_cert_uri"]


def fetch_and_save_ca_cert(ca_cert_uri: str, ca_cert_path: pathlib.Path) -> None:
    resp = requests.get(ca_cert_uri, verify=ssl_verify)
    ca_cert_path.write_bytes(resp.content)


def validate_cert_fingerprint(
    expected_ca_cert_fingerprint, ca_cert_path: pathlib.Path
) -> bool:
    x509 = crypto.load_certificate(
        crypto.FILETYPE_PEM, pathlib.Path(ca_cert_path).read_bytes()
    )
    x509_sha256_fingerprint = str(x509.digest("sha256"), "utf-8")
    log.info("CA certificate issuer: %s", format_subject_issuer(x509.get_issuer()))
    log.info(
        "CA certificate is valid from %s to %s",
        format_asn1_date(x509.get_notBefore()),
        format_asn1_date(x509.get_notAfter()),
    )
    return is_ca_cert_fingerprint_valid(
        x509_sha256_fingerprint, expected_ca_cert_fingerprint
    )


def fetch_and_save_provider_info(
    providers: List[Dict[str, str]], providers_info: pathlib.Path
) -> None:
    for provider in providers:
        resp = requests.get(
            f'{provider["domain_url"]}{provider["provider_path"]}',
            verify=ssl_verify,
        )
        data = resp.json()
        update_provider_info(provider, data)

        providers_dict = {
            "provider_info_last_checked": str(datetime.now()),
            "providers": providers,
        }
        providers_info.write_text(json.dumps(providers_dict, indent=2))


def update_gateways(
    gateways: List[Dict[str, Any]], data: Dict[str, Any], provider_name: str
):
    for i, data_gateway in enumerate(data["gateways"]):
        protocols = []
        ports = []

        for transport in data_gateway["capabilities"]["transport"]:
            if transport == "openvpn":
                protocols = data_gateway["capabilities"]["protocols"]
                ports = data_gateway["capabilities"]["ports"]
            elif transport["type"] == "openvpn":
                protocols = transport["protocols"]
                ports = transport["ports"]

        location_name = ""
        location_country_code = ""

        # Riseup specific due to inconsistent API (location key/name for NYC is opposite casing)
        if bool(data["locations"]):
            if (
                provider_name == "riseup"
                and data_gateway["location"] == "new york city"
            ):
                location_name = "New York City"
                location_country_code = "US"
            else:
                location_name = data["locations"][data_gateway["location"]]["name"]
                location_country_code = data["locations"][data_gateway["location"]][
                    "country_code"
                ]

        # Calyx specific due to empty location info
        if provider_name == "calyx" and data_gateway["host"] == "vpn2.calyx.net":
            location_name = "New York City"
            location_country_code = "US"

        gateways.append(
            {
                "provider": provider_name,
                "ip_address": data_gateway["ip_address"],
                "host": data_gateway["host"],
                "location": {
                    "name": location_name,
                    "country_code": location_country_code,
                },
                "protocols": protocols,
                "ports": ports,
            }
        )

    return gateways


def update_openvpn_configurations(
    openvpn_configurations: Dict, data: Dict, provider_name: str
) -> Dict:
    openvpn_configurations[provider_name] = data
    return openvpn_configurations


def main():
    global providers, gateways, openvpn_configurations

    cache_dir.mkdir(exist_ok=True)
    providers_info_path = cache_dir / "providers.json"

    if not providers_info_path.exists():
        log.info("Fetching provider info...")
        fetch_and_save_provider_info(providers, providers_info_path)

    data = json.loads(providers_info_path.read_text())
    if is_provider_info_valid(data["provider_info_last_checked"]):
        log.info("Re-using provider info...")
        providers = data["providers"]
    else:
        log.info("Updating provider info...")
        fetch_and_save_provider_info(providers, providers_info_path)

    for provider in providers:
        provider_name = provider["name"]
        ca_cert_path = cache_dir.joinpath(provider_name, ca_cert)
        cache_dir.joinpath(provider_name).mkdir(exist_ok=True)
        if ca_cert_path.exists():
            log.info("Re-using CA certificate for %s...", provider_name)
        else:
            log.info("Fetching CA certificate for %s...", provider_name)
            fetch_and_save_ca_cert(provider["ca_cert_uri"], ca_cert_path)

        log.info(
            "Validating SHA256 fingerprints between CA certificate and provider info for %s...",
            provider_name,
        )
        if not validate_cert_fingerprint(provider["ca_cert_fingerprint"], ca_cert_path):
            log.error(
                "CA certificate's SHA256 fingerprint does not match expected SHA256 fingerprint for %s, quitting...",
                provider_name,
            )
            raise SystemExit(0)
        log.info("Fingerprints match!")

        log.info("Fetching client certificate and private key for %s...", provider_name)
        client_cert_url = f"{provider['api_uri']}/{provider['api_version']}/cert"
        resp = requests.post(client_cert_url, verify=ca_cert_path)
        openvpn_pair: bytes = resp.content

        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, openvpn_pair)
        log.info(
            "Client certificate issuer: %s", format_subject_issuer(x509.get_issuer())
        )
        log.info(
            "Client certificate is valid from %s to %s and expires in %s days",
            format_asn1_date(x509.get_notBefore()),
            format_asn1_date(x509.get_notAfter()),
            days_until_from_now(format_asn1_date(x509.get_notAfter())),
        )

        log.info(
            "Fetching encrypted internet proxy capabilities and gateways for %s...",
            provider_name,
        )

        resp = requests.get(
            f'{provider["api_uri"]}{provider["configs_path"]}',
            verify=ca_cert_path,
        )
        data = resp.json()

        resp = requests.get(
            f'{provider["api_uri"]}{data["services"]["eip"]}',
            verify=ca_cert_path,
        )
        data = resp.json()

        gateways = update_gateways(gateways, data, provider_name)
        gateways.sort(key=lambda k: k["location"]["name"])

        openvpn_configurations = update_openvpn_configurations(
            openvpn_configurations, data["openvpn_configuration"], provider_name
        )

        log.info("Splitting client certificate key pair file for %s...", provider_name)
        client_cert_path = cache_dir.joinpath(provider_name, client_cert)
        client_key_path = cache_dir.joinpath(provider_name, client_key)

        m = re.match(
            rb"^(.*-----END RSA PRIVATE KEY-----)\n(.*)\s*$",
            openvpn_pair,
            flags=re.DOTALL,
        )
        client_key_path.write_bytes(m.group(1))
        client_cert_path.write_bytes(m.group(2))

        log.info("Ready!")

    ### Get user input

    print("\nServer:\n")
    for i, gateway in enumerate(gateways, start=1):
        print(
            "{}. [{}] {}, {} ({} / {})".format(
                i,
                gateway["provider"],
                gateway["location"]["name"],
                gateway["location"]["country_code"],
                gateway["host"],
                gateway["ip_address"],
            )
        )

    server_number_choice = int(input("\nEnter selection (#): "))
    chosen_gateway = gateways[server_number_choice - 1]

    print("\nProtocol:\n")
    for i, protocol in enumerate(chosen_gateway["protocols"], start=1):
        print("{}. {}".format(i, protocol.upper()))

    protocol_number_choice = int(input("\nEnter selection (#): "))
    chosen_protocol = chosen_gateway["protocols"][protocol_number_choice - 1]

    print("\nPort:\n")
    for i, port in enumerate(chosen_gateway["ports"], start=1):
        print("{}. {}".format(i, port))

    port_number_choice = int(input("\nEnter selection (#): "))
    chosen_port = chosen_gateway["ports"][port_number_choice - 1]

    ovpn = "bitmask-{}-{}-ip-{}-{}-{}.ovpn".format(
        chosen_gateway["provider"],
        chosen_gateway["protocols"][protocol_number_choice - 1],
        chosen_gateway["location"]["name"].lower(),
        chosen_gateway["location"]["country_code"].lower(),
        chosen_gateway["ports"][port_number_choice - 1],
    )

    bitmask_ovpns = pathlib.Path("bitmask_ovpns")
    ovpn_file_path = bitmask_ovpns / ovpn
    bitmask_ovpns.mkdir(exist_ok=True)
    print("\n")

    log.info("Generating OpenVPN configuration and writing to %s", ovpn_file_path)
    provider_cert_dir = cache_dir / chosen_gateway["provider"]

    with ovpn_file_path.open("w") as fp:
        jenv.get_template("ovpn_template.j2").stream(
            chosen_gateway=chosen_gateway,
            chosen_protocol=chosen_protocol,
            chosen_port=chosen_port,
            cache_dir=cache_dir,
            ca_txt=(provider_cert_dir / ca_cert).read_text(),
            cert_txt=(provider_cert_dir / client_cert).read_text(),
            key_txt=(provider_cert_dir / client_key).read_text(),
        ).dump(fp=fp)

    log.info("Done!")

    log.info("Cleaning client certificate and private keys...")
    for provider in providers:
        cache_dir.joinpath(provider["name"], client_cert).unlink()
        cache_dir.joinpath(provider["name"], client_key).unlink()
        # cache_dir.joinpath(provider["name"], openvpn_pair).unlink()


if __name__ == "__main__":
    main()
