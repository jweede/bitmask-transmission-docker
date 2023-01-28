#!/usr/bin/env python3
"""
Adapted from https://gitlab.com/nitrohorse/bitmask-openvpn-generator
"""
import json
import os
import pathlib
from datetime import datetime
import logging

import requests
import jinja2
from OpenSSL import crypto

ca_cert = pathlib.Path("ca_cert.pem")
openvpn_pair = pathlib.Path("openvpn_pair.pem")
client_cert = pathlib.Path("client_cert.pem")
client_key = pathlib.Path("client_key.pem")

providers_info = pathlib.Path("providers.json")

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

here = pathlib.Path(__file__).resolve().parent
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
        "Path": pathlib.Path,
        "ca_cert": ca_cert,
        "openvpn_pair": openvpn_pair,
        "client_cert": client_cert,
        "client_key": client_key,
    }
)


# https://web.archive.org/web/20191001225633/http://www.zedwood.com/article/python-openssl-x509-parse-certificate
def format_subject_issuer(x509_issuer):
    items = (str(v, "utf-8") for k, v in x509_issuer.get_components())
    return ", ".join(items)


def format_asn1_date(d):
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


def is_provider_info_valid(provider_timestamp):
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


def days_until_from_now(date):
    return (
        datetime.strptime(date, "%Y-%m-%d")
        - datetime.strptime(str(datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
    ).days


def update_provider_info(provider, data):
    provider["api_uri"] = data["api_uri"]
    provider["api_version"] = data["api_version"]
    provider["ca_cert_fingerprint"] = data["ca_cert_fingerprint"]
    provider["ca_cert_uri"] = data["ca_cert_uri"]


def fetch_and_save_ca_cert(ca_cert_uri, ca_cert_path):
    resp = requests.get(ca_cert_uri)
    pathlib.Path(ca_cert_path).write_bytes(resp.content)


def validate_cert_fingerprint(expected_ca_cert_fingerprint, ca_cert_path):
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


def fetch_and_save_provider_info(providers, providers_info):
    for provider in providers:
        receive = requests.get(
            "{}{}".format(provider["domain_url"], provider["provider_path"]),
        )
        data = receive.json()
        update_provider_info(provider, data)

        providers_dict = {
            "provider_info_last_checked": str(datetime.now()),
            "providers": providers,
        }
        pathlib.Path(providers_info).write_text(json.dumps(providers_dict, indent=2))


def update_gateways(gateways, data, provider_name):
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


def update_openvpn_configurations(openvpn_configurations, data, provider_name):
    openvpn_configurations[provider_name] = data
    return openvpn_configurations


def main():
    global providers, gateways, openvpn_configurations

    if not providers_info.exists():
        log.info("Fetching provider info...")
        fetch_and_save_provider_info(providers, providers_info)

    data = json.loads(providers_info.read_text())
    if is_provider_info_valid(data["provider_info_last_checked"]):
        log.info("Re-using provider info...")
        providers = data["providers"]
    else:
        log.info("Updating provider info...")
        fetch_and_save_provider_info(providers, providers_info)

    for provider in providers:
        ca_cert_path = os.path.join(provider["name"], ca_cert)
        if os.path.exists(ca_cert_path):
            log.info("Re-using CA certificate for %s...", provider["name"])
        else:
            log.info("Fetching CA certificate for %s...", provider["name"])
            os.makedirs(provider["name"])
            ca_cert_path = os.path.join(provider["name"], ca_cert)
            fetch_and_save_ca_cert(provider["ca_cert_uri"], ca_cert_path)

        log.info(
            "Validating SHA256 fingerprints between CA certificate and provider info for %s...",
            provider["name"],
        )
        ca_cert_path = os.path.join(provider["name"], ca_cert)
        is_valid = validate_cert_fingerprint(
            provider["ca_cert_fingerprint"], ca_cert_path
        )

        if not is_valid:
            log.error(
                "CA certificate's SHA256 fingerprint does not match expected SHA256 fingerprint for %s, quitting...",
                provider["name"],
            )
            raise SystemExit(0)

        log.info("Fingerprints match!")

        log.info(
            "Fetching client certificate and private key for %s...", provider["name"]
        )
        client_cert_url = f"{provider['api_uri']}/{provider['api_version']}/cert"

        receive = requests.post(client_cert_url, verify=ca_cert_path)
        openvpn_pair_path = pathlib.Path(provider["name"], openvpn_pair)
        openvpn_pair_path.write_bytes(receive.content)

        x509 = crypto.load_certificate(
            crypto.FILETYPE_PEM, pathlib.Path(openvpn_pair_path).read_bytes()
        )
        log.info(
            "Client certificate issuer: %s",
            format_subject_issuer(x509.get_issuer()),
        )

        log.info(
            "Client certificate is valid from %s to %s and expires in %s days",
            format_asn1_date(x509.get_notBefore()),
            format_asn1_date(x509.get_notAfter()),
            days_until_from_now(format_asn1_date(x509.get_notAfter())),
        )

        log.info(
            "Fetching encrypted internet proxy capabilities and gateways for %s...",
            provider["name"],
        )

        receive = requests.get(
            f'{provider["api_uri"]}{provider["configs_path"]}',
            verify=ca_cert_path,
        )
        data = receive.json()

        receive = requests.get(
            f'{provider["api_uri"]}{data["services"]["eip"]}',
            verify=ca_cert_path,
        )
        data = receive.json()

        gateways = update_gateways(gateways, data, provider["name"])
        gateways.sort(key=lambda k: k["location"]["name"])

        openvpn_configurations = update_openvpn_configurations(
            openvpn_configurations, data["openvpn_configuration"], provider["name"]
        )

        log.info(
            "Splitting client certificate key pair file for %s...", provider["name"]
        )
        client_cert_path = os.path.join(provider["name"], client_cert)
        client_key_path = os.path.join(provider["name"], client_key)

        client_cert_file = open(client_cert_path, "w")
        client_key_file = open(client_key_path, "w")
        openvpn_pair_file = open(openvpn_pair_path, "r")
        line = openvpn_pair_file.readline()

        while line != "-----END RSA PRIVATE KEY-----\n":
            client_key_file.write(line)
            line = openvpn_pair_file.readline()

        client_key_file.write(line)
        line = openvpn_pair_file.readline()

        while line:
            client_cert_file.write(line)
            line = openvpn_pair_file.readline()

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

    with ovpn_file_path.open("w") as fp:
        jenv.get_template("ovpn_template.j2").stream(
            chosen_gateway=chosen_gateway,
            chosen_protocol=chosen_protocol,
            chosen_port=chosen_port,
        ).dump(fp=fp)
    #
    # ovpn_file = open(ovpn_file_path, "w")
    # ovpn_file.write("client")
    # ovpn_file.write("\n")
    # ovpn_file.write("tls-client")
    # ovpn_file.write("\n")
    # ovpn_file.write("dev tun")
    # ovpn_file.write("\n")
    # ovpn_file.write(
    #     "proto {}".format(
    #         chosen_gateway["protocols"][protocol_number_choice - 1]
    #     )
    # )
    # ovpn_file.write("\n")
    # ovpn_file.write(
    #     "remote {} {} # {} / {}, {}".format(
    #         chosen_gateway["ip_address"],
    #         chosen_gateway["ports"][port_number_choice - 1],
    #         chosen_gateway["host"],
    #         chosen_gateway["location"]["name"],
    #         chosen_gateway["location"]["country_code"],
    #     )
    # )
    # ovpn_file.write("\n")
    # for k, v in openvpn_configurations[
    #     chosen_gateway["provider"]
    # ].items():
    #     if type(v) is bool:
    #         ovpn_file.write("{}".format(k))
    #     elif k == "tls-cipher" and v == "DHE-RSA-AES128-SHA":
    #         ovpn_file.write("{} {}".format(k, "TLS-DHE-RSA-WITH-AES-128-CBC-SHA"))
    #     else:
    #         ovpn_file.write("{} {}".format(k, v))
    #     ovpn_file.write("\n")
    # ovpn_file.write("resolv-retry infinite")
    # ovpn_file.write("\n")
    # ovpn_file.write("nobind")
    # ovpn_file.write("\n")
    # ovpn_file.write("verb 3")
    # ovpn_file.write("\n")
    # ovpn_file.write("persist-key")
    # ovpn_file.write("\n")
    # ovpn_file.write("persist-tun")
    # ovpn_file.write("\n")
    # ovpn_file.write("reneg-sec 0")
    # ovpn_file.write("\n")
    # ovpn_file.write("pull")
    # ovpn_file.write("\n")
    # ovpn_file.write("auth-nocache")
    # ovpn_file.write("\n")
    # ovpn_file.write("script-security 2")
    # ovpn_file.write("\n")
    # ovpn_file.write("tls-version-min 1.2")
    # ovpn_file.write("\n")
    # ovpn_file.write("redirect-gateway ipv6")
    # ovpn_file.write("\n")
    # ovpn_file.write("remote-cert-tls server")
    # ovpn_file.write("\n")
    # ovpn_file.write('remote-cert-eku "TLS Web Server Authentication"')
    # ovpn_file.write("\n")
    # ovpn_file.write(
    #     "verify-x509-name {} name".format(chosen_gateway["host"])
    # )
    # ovpn_file.write("\n")
    # ovpn_file.write("<ca>")
    # ovpn_file.write("\n")
    # ca_cert_path = os.path.join(chosen_gateway["provider"], ca_cert)
    # ca_cert_file = open(ca_cert_path, "r")
    # line = ca_cert_file.readline()
    # while line:
    #     ovpn_file.write(line)
    #     line = ca_cert_file.readline()
    # ovpn_file.write("</ca>")
    # ovpn_file.write("\n")
    # ovpn_file.write("<cert>")
    # ovpn_file.write("\n")
    # client_cert_path = os.path.join(
    #     chosen_gateway["provider"], client_cert
    # )
    # client_cert_file = open(client_cert_path, "r")
    # line = client_cert_file.readline()
    # while line:
    #     ovpn_file.write(line)
    #     line = client_cert_file.readline()
    # ovpn_file.write("</cert>")
    # ovpn_file.write("\n")
    # ovpn_file.write("<key>")
    # ovpn_file.write("\n")
    # client_key_path = os.path.join(
    #     chosen_gateway["provider"], client_key
    # )
    # client_key_file = open(client_key_path, "r")
    # line = client_key_file.readline()
    # while line:
    #     ovpn_file.write(line)
    #     line = client_key_file.readline()
    # ovpn_file.write("</key>")
    log.info("Done!")

    log.info("Cleaning client certificate and private keys...")
    for provider in providers:
        pathlib.Path(provider["name"], client_cert).unlink()
        pathlib.Path(provider["name"], client_key).unlink()
        pathlib.Path(provider["name"], openvpn_pair).unlink()


if __name__ == "__main__":
    main()
