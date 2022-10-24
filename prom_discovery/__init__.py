#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of service_discovery_scanner module

__intname__ = "service_discovery_scanner"
__author__ = "Orsiris de Jong"
__copyright__ = "Copyright (C) 2022 Orsiris de Jong"
__licence__ = "BSD 3 Clause"
__build__ = "2022091801"
__version__ = "1.0"

import ipaddress
import socket
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from typing import Union, Callable
import progressbar  # progressbar2
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())
TOTAL_HOSTS_COUNT = 0
ALIVE_HTTP_HOSTS = []
ALIVE_HTTPS_HOSTS = []
ALIVE_SNMP_HOSTS = []
PROGRESSBAR = None

# Defaults (can be overriden with cmdline arguments)
HTTP_TIMEOUT = 4
HTTP_RETRIES = 0
SNMP_COMMUNITY = "public"
SNMP_VERSION = "2c"
SNMP_PORT = 161
HTTP_ENDPOINT = "/metrics"
HTTP_PORT = 9100


def check_host(
    check_function: Callable,
    ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    port,
    resolve: bool = False,
    **kwargs
):
    try:
        ip_addr = ip.__str__()
        endpoint = check_function(ip_addr, port, **kwargs)
        if endpoint:
            if resolve:
                # Result format is (hostname, alias-list, ip)
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip_addr)
                    if hostname:
                        ip_addr = hostname
                except socket.herror:
                    pass
            if endpoint.startswith("http://"):
                ALIVE_HTTP_HOSTS.append("{}:{}".format(ip_addr, port))
            if endpoint.startswith("https://"):
                ALIVE_HTTPS_HOSTS.append("{}:{}".format(ip_addr, port))
            if endpoint.startswith("snmp://"):
                ALIVE_SNMP_HOSTS.append("{}:{}".format(ip_addr, port))
        PROGRESSBAR.update(PROGRESSBAR.value + 1)
    except Exception:
        logger.debug("Trace", exc_info=True)


def check_subnet(
    subnet: Union[ipaddress.IPv4Network, ipaddress.IPv6Network, str],
    port,
    resolve: bool = False,
    **kwargs
):
    global TOTAL_HOSTS_COUNT
    global PROGRESSBAR

    check_function = kwargs.pop("check_function")

    network = ipaddress.IPv4Network(subnet, strict=True)
    usable_adresses = network.num_addresses - 2
    PROGRESSBAR = progressbar.ProgressBar(
        maxval=usable_adresses,
        widgets=[progressbar.Bar("=", "[", "]"), " ", progressbar.Percentage()],
    )
    PROGRESSBAR.start()

    with ThreadPoolExecutor(threads) as pool:
        for ip in network.hosts():
            pool.submit(check_host, check_function, ip, port, resolve=resolve, **kwargs)

    PROGRESSBAR.finish()


if __name__ == "__main__":
    parser = ArgumentParser(
        prog="prom_discover.py",
        description="Search for prometheus metrics in given network",
    )

    parser.add_argument(
        dest="network", default=None, help="CIDR notation network, eg 192.168.1.0/24"
    )

    parser.add_argument(
        "--snmp",
        action="store_true",
        help="Discover SNMP targets instead of metrics endpoints",
    )

    parser.add_argument(
        "-c",
        "--community",
        dest="snmp_community",
        type=str,
        default="public",
        required=False,
        help="List of comma separated snmp communities to test",
    )

    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        required=False,
        help="Default port where to search for metrics endpoint (defaults to 9100 for http and 161 for snmp)",
    )

    parser.add_argument(
        "-m",
        "--endpoint",
        dest="http_endpoint",
        required=False,
        help="Where to fetch the data, defaults for /metrics",
    )

    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        type=int,
        default=32,
        required=False,
        help="Number of concurrent network connections",
    )

    parser.add_argument(
        "--http-retries",
        dest="http_retries",
        type=int,
        required=False,
        help="Number of times we shall retry a HTTP / HTTPS metrics connection, defaults to 0",
    )

    parser.add_argument(
        "--http-timeout",
        dest="http_timeout",
        type=int,
        required=False,
        help="How many time in seconds before a HTTP / HTTPS metrics connection is considered failed, defaults to 1",
    )

    parser.add_argument(
        "--http-type",
        dest="http_type",
        type=str,
        required=False,
        help="Which http protocol shall we test, valid options are 'all', 'http' and 'https'",
    )

    parser.add_argument(
        "--no-verify-certificate",
        action="store_true",
        help="Do not check HTTPS certificate validity",
    )

    parser.add_argument(
        "--cacert",
        dest="ca_cert",
        type=str,
        required=False,
        help="Optional path to CA certificate package",
    )

    parser.add_argument(
        "--allow-ssl3", action="store_true", help="Allow non secure SSL / TLS protocols"
    )

    parser.add_argument("-r", "--resolve", action="store_true")

    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")

    args = parser.parse_args()

    if args.version:
        print("{} v{}".format(__file__, __version__))
        exit(2)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    network = args.network
    threads = args.threads
    resolve = args.resolve
    check_type = None

    if args.snmp:
        check_type = "snmp"
        print("Searching for SNMP targets in {}".format(network))
        from snmp_discover import is_snmp_host_alive

        if not args.port:
            port = SNMP_PORT  # Set default SNMP port
        else:
            port = args.port

        config = {
            "check_function": is_snmp_host_alive,
            "snmp_auth": None,
            "threads": threads,
        }
    else:
        check_type = "http"
        from http_discover import check_http_response, requests

        if args.http_timeout:
            http_timeout = args.http_timeout
        else:
            http_timeout = HTTP_TIMEOUT
        if args.http_retries:
            http_retries = args.http_retries
        else:
            http_retries = HTTP_RETRIES
        if not args.port:
            port = HTTP_PORT
        else:
            port = args.port
        if not args.http_endpoint:
            http_endpoint = HTTP_ENDPOINT
        else:
            http_endpoint = args.http_endpoint

        if args.http_type:
            http_type = args.http_type.lower()
            if http_type not in ["http", "https"]:
                http_type = "all"
        else:
            http_type = "all"
        if http_type == "all":
            print("Searching for http and https targets in {}".format(network))
        else:
            print("Searching for {} targets in {}".format(http_type, network))

        if args.no_verify_certificate:
            https_verify = not args.no_verify_certificate
            requests.packages.urllib3.disable_warnings()
        else:
            https_verify = True
        if args.ca_cert:
            https_verify = args.ca_cert
        if args.allow_ssl3:
            # https://stackoverflow.com/a/72518559
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "ALL:@SECLEVEL=1"

        config = {
            "check_function": check_http_response,
            "http_type": http_type,
            "https_verify": https_verify,
            "http_endpoint": http_endpoint,
            "http_retries": http_retries,
            "http_timeout": http_timeout,
            "threads": threads,
        }

    try:
        _ = ipaddress.IPv4Network(network)
    except Exception as exc1:
        pass
        try:
            _ = ipaddress.IPv6Network(network)
        except Exception as exc2:
            print("Cannot compute network: {} / {}".format(exc1, exc2))
            exit(127)

    logger.debug("Config: {}".format(config))

    try:
        check_subnet(network, port, resolve, **config)
    except Exception:
        logger.debug("Trace:", exc_info=True)
    else:
        print("HTTP HOSTS:")
        print(ALIVE_HTTP_HOSTS)
        print("HTTPS HOSTS:")
        print(ALIVE_HTTPS_HOSTS)
        print("SNMP HOSTS:")
        print(ALIVE_SNMP_HOSTS)
