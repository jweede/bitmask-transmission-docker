#!/usr/bin/env python3
"""
Adapted from https://gitlab.com/nitrohorse/bitmask-openvpn-generator
"""
import json
import os
import pathlib
from datetime import datetime

import jinja2
import requests
from OpenSSL import crypto

ca_cert = 'ca_cert.pem'
openvpn_pair = 'openvpn_pair.pem'
client_cert = 'client_cert.pem'
client_key = 'client_key.pem'

providers_info = 'providers.json'

providers = [
    {
        'name': 'riseup',
        'domain_url': 'https://riseup.net',
        'provider_path': '/provider.json',
        'configs_path': '/1/configs.json'
    },
    {
        'name': 'calyx',
        'domain_url': 'https://calyx.net',
        'provider_path': '/provider.json',
        'configs_path': '/1/configs.json'
    }
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
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader([here]), undefined=jinja2.StrictUndefined)
jinja_env.globals.update(
    script_name=pathlib.Path(__file__).name,
    Path=pathlib.Path,
    providers=providers,
    gateways=gateways,
    openvpn_configurations=openvpn_configurations,
)

# https://web.archive.org/web/20191001225633/http://www.zedwood.com/article/python-openssl-x509-parse-certificate
def format_subject_issuer(x509Issuer):
    items = []
    for item in x509Issuer.get_components():
        items.append(str(item[1], 'utf-8'))
    return ', '.join(items)


def format_asn1_date(d):
    return datetime.strptime(d.decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d')


def is_ca_cert_fingerprint_valid(x509_sha256, expected_ca_cert_fingerprint):
    sha256_prefix = 'SHA256: '
    expected_ca_cert_fingerprint = expected_ca_cert_fingerprint.replace(sha256_prefix, '')
    x509_sha256_formatted = x509_sha256.replace(sha256_prefix, '').replace(':', '').lower()
    return x509_sha256_formatted == expected_ca_cert_fingerprint


def is_provider_info_valid(provider_timestamp):
    datetime_format = '%Y-%m-%d %H:%M:%S.%f'
    datetime_now = str(datetime.now())
    diff_in_days = (datetime.strptime(datetime_now, datetime_format) - datetime.strptime(
        provider_timestamp, datetime_format)).days
    if diff_in_days <= 1:
        return True
    else:
        return False


def days_until_from_now(date):
    return (datetime.strptime(date, '%Y-%m-%d') - datetime.strptime(str(datetime.now()),
                                                                    '%Y-%m-%d %H:%M:%S.%f')).days


def update_provider_info(provider, data):
    provider['api_uri'] = data['api_uri']
    provider['api_version'] = data['api_version']
    provider['ca_cert_fingerprint'] = data['ca_cert_fingerprint']
    provider['ca_cert_uri'] = data['ca_cert_uri']


def fetch_and_save_ca_cert(ca_cert_uri, ca_cert_path):
    resp = requests.get(ca_cert_uri)
    pathlib.Path(ca_cert_path).write_bytes(resp.content)


def validate_cert_fingerprint(expected_ca_cert_fingerprint, ca_cert_path):
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pathlib.Path(ca_cert_path).read_bytes())
    x509_sha256_fingerprint = str(x509.digest('sha256'), 'utf-8')
    print('CA certificate issuer: {}'.format(format_subject_issuer(x509.get_issuer())))
    print('CA certificate is valid from {} to {}'.format(
        format_asn1_date(x509.get_notBefore()),
        format_asn1_date(x509.get_notAfter())
    ))
    return is_ca_cert_fingerprint_valid(x509_sha256_fingerprint, expected_ca_cert_fingerprint)


def fetch_and_save_provider_info(providers, providers_info):
    for provider in providers:
        if provider['name'] == 'calyx':
            # Fetching for Calyx throws
            # [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate
            # verify=False for now
            shouldVerify = False
        else:
            shouldVerify = True
        receive = requests.get('{}{}'.format(
            provider['domain_url'],
            provider['provider_path']
        ), verify=shouldVerify)
        data = receive.json()
        update_provider_info(provider, data)

        providers_dict = {}
        providers_dict['provider_info_last_checked'] = str(datetime.now())
        providers_dict['providers'] = providers

        pathlib.Path(providers_info).write_text(json.dumps(providers_dict))


def update_gateways(gateways, data, provider_name):
    for i, data_gateway in enumerate(data['gateways']):
        protocols = []
        ports = []

        for transport in data_gateway['capabilities']['transport']:
            if transport == 'openvpn':
                protocols = data_gateway['capabilities']['protocols']
                ports = data_gateway['capabilities']['ports']
            elif transport['type'] == 'openvpn':
                protocols = transport['protocols']
                ports = transport['ports']

        location_name = ''
        location_country_code = ''

        # Riseup specific due to inconsistent API (location key/name for NYC is opposite casing)
        if (bool(data['locations'])):
            if (provider_name == 'riseup' and data_gateway['location'] == 'new york city'):
                location_name = 'New York City'
                location_country_code = 'US'
            else:
                location_name = data['locations'][data_gateway['location']]['name']
                location_country_code = data['locations'][data_gateway['location']]['country_code']

        # Calyx specific due to empty location info
        if (provider_name == 'calyx' and data_gateway['host'] == 'vpn2.calyx.net'):
            location_name = 'New York City'
            location_country_code = 'US'

        gateways.append({
            'provider': provider_name,
            'ip_address': data_gateway['ip_address'],
            'host': data_gateway['host'],
            'location': {
                'name': location_name,
                'country_code': location_country_code
            },
            'protocols': protocols,
            'ports': ports
        })

    return gateways


def update_openvpn_configurations(openvpn_configurations, data, provider_name):
    openvpn_configurations[provider_name] = data
    return openvpn_configurations


class BitmaskOpenVPNGenerator:



def main():
    global providers, gateways, openvpn_configurations

    if os.path.exists(providers_info):
        with open(providers_info, 'r') as f:
            data = json.load(f)
        if is_provider_info_valid(data['provider_info_last_checked']):
            print('Re-using provider info...')
            providers = data['providers']
        else:
            print('Updating provider info...')
            fetch_and_save_provider_info(providers, providers_info)

    else:  # first run
        print('Fetching provider info...')
        fetch_and_save_provider_info(providers, providers_info)

    for provider in providers:
        ca_cert_path = pathlib.Path(provider['name'], ca_cert)
        if os.path.exists(ca_cert_path):
            print('Re-using CA certificate for {}...'.format(provider['name']))
        else:
            print('Fetching CA certificate for {}...'.format(provider['name']))
            os.makedirs(provider['name'])
            ca_cert_path = os.path.join(provider['name'], ca_cert)
            fetch_and_save_ca_cert(provider['ca_cert_uri'], ca_cert_path)

        print(
            'Validating SHA256 fingerprints between CA certificate and provider info for {}...'.format(
                provider['name']
            ))
        ca_cert_path = os.path.join(provider['name'], ca_cert)
        is_valid = validate_cert_fingerprint(provider['ca_cert_fingerprint'], ca_cert_path)

        if is_valid == False:
            print(
                "CA certificate's SHA256 fingerprint does not match expected SHA256 fingerprint for {}, quitting...".format(
                    provider['name']
                ))
            raise SystemExit(0)

        print('Fingerprints match!')

        print('Fetching client certificate and private key for {}...'.format(
            provider['name']
        ))
        client_cert_url = '{}/{}/cert'.format(
            provider['api_uri'],
            provider['api_version']
        )

        receive = requests.post(client_cert_url, verify=ca_cert_path)
        openvpn_pair_path = os.path.join(provider['name'], openvpn_pair)
        with open(openvpn_pair_path, 'wb') as f:
            f.write(receive.content)

        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pathlib.Path(openvpn_pair_path).read_bytes())
        print('Client certificate issuer: {}'.format(format_subject_issuer(x509.get_issuer())))

        print('Client certificate is valid from {} to {} and expires in {} days'.format(
            format_asn1_date(x509.get_notBefore()),
            format_asn1_date(x509.get_notAfter()),
            days_until_from_now(format_asn1_date(x509.get_notAfter()))
        ))

        print('Fetching encrypted internet proxy capabilities and gateways for {}...'.format(
            provider['name']
        ))

        receive = requests.get('{}{}'.format(
            provider['api_uri'],
            provider['configs_path']
        ),
            verify=ca_cert_path
        )
        data = receive.json()

        receive = requests.get('{}{}'.format(
            provider['api_uri'],
            data['services']['eip']
        ),
            verify=ca_cert_path
        )
        data = receive.json()

        gateways = update_gateways(
            gateways,
            data,
            provider['name']
        )

        gateways = sorted(gateways, key=lambda k: k['location']['name'])

        openvpn_configurations = update_openvpn_configurations(
            openvpn_configurations,
            data['openvpn_configuration'],
            provider['name']
        )

        print('Splitting client certificate key pair file for {}...'.format(
            provider['name']
        ))
        client_cert_path = os.path.join(provider['name'], client_cert)
        client_key_path = os.path.join(provider['name'], client_key)

        client_cert_file = open(client_cert_path, 'w')
        client_key_file = open(client_key_path, 'w')
        openvpn_pair_file = open(openvpn_pair_path, 'r')
        line = openvpn_pair_file.readline()

        while line != '-----END RSA PRIVATE KEY-----\n':
            client_key_file.write(line)
            line = openvpn_pair_file.readline()

        client_key_file.write(line)
        line = openvpn_pair_file.readline()

        while line:
            client_cert_file.write(line)
            line = openvpn_pair_file.readline()

        print('Ready!')

    ### Get user input

    print('\nServer:\n')
    for i, gateway in enumerate(gateways, start=1):
        print('{}. [{}] {}, {} ({} / {})'.format(
            i,
            gateway['provider'],
            gateway['location']['name'],
            gateway['location']['country_code'],
            gateway['host'],
            gateway['ip_address']
        ))

    server_number_choice = int(input('\nEnter selection (#): '))

    print('\nProtocol:\n')
    for i, protocol in enumerate(gateways[server_number_choice - 1]['protocols'], start=1):
        print('{}. {}'.format(i, protocol.upper()))

    protocol_number_choice = int(input('\nEnter selection (#): '))

    print('\nPort:\n')
    for i, port in enumerate(gateways[server_number_choice - 1]['ports'], start=1):
        print('{}. {}'.format(i, port))

    port_number_choice = int(input('\nEnter selection (#): '))

    ovpn = 'bitmask-{}-{}-ip-{}-{}-{}.ovpn'.format(
        gateways[server_number_choice - 1]['provider'],
        gateways[server_number_choice - 1]['protocols'][protocol_number_choice - 1],
        gateways[server_number_choice - 1]['location']['name'].lower(),
        gateways[server_number_choice - 1]['location']['country_code'].lower(),
        gateways[server_number_choice - 1]['ports'][port_number_choice - 1],
    )

    bitmask_ovpns = 'bitmask_ovpns'
    ovpn_file_path = os.path.join(bitmask_ovpns, ovpn)

    if os.path.exists(bitmask_ovpns) is False:
        os.makedirs(bitmask_ovpns)

    print('\nGenerating OpenVPN configuration and writing to {}'.format(ovpn_file_path))

    with open(ovpn_file_path, 'w') as fp:
        jinja_env.get_template("ovpn_template.j2").stream(
            protocol_number_choice=protocol_number_choice,
            server_number_choice=server_number_choice,
            port_number_choice=protocol_number_choice,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
        ).dump(fp=fp)
    print('Done!')

    print('Cleaning client certificate and private keys...')
    for provider in providers:
        client_cert_path = os.path.join(provider['name'], client_cert)
        client_key_path = os.path.join(provider['name'], client_key)
        openvpn_pair_path = os.path.join(provider['name'], openvpn_pair)
        os.remove(client_cert_path)
        os.remove(client_key_path)
        os.remove(openvpn_pair_path)


if __name__ == "__main__":
    main()