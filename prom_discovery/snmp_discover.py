#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of service_discovery_scanner module

__intname__ = "service_discovery_scanner.snmp_discover"
__author__ = "Orsiris de Jong"
__copyright__ = "Copyright (C) 2022 Orsiris de Jong"
__licence__ = "BSD 3 Clause"
__build__ = "2022091101"

from typing import Union, Tuple
from pysnmp.hlapi import *
import ipaddress


def is_snmp_host_alive(
    host: str = "127.0.0.1",
    port: int = 161,
    snmp_auth: Union[Tuple[str, str, str], str] = "public",
    protocol_version: str = "2c",
):
    transport = None
    try:
        _ = ipaddress.IPv4Address(host)
    except Exception:
        pass
    else:
        transport = UdpTransportTarget((host, port), timeout=2.0, retries=0)
    try:
        _ = ipaddress.IPv6Address(host)
    except Exception:
        pass
    else:
        transport = Udp6TransportTarget((host, port), timeout=2.0, retries=0)

    if not transport:
        raise ValueError("Invalid host address provided: {}".format(host))

    if isinstance(snmp_auth, str):
        # Assume we have a SNMPv1 or SNMPv2c community string
        # mpModel=0 : SNMPv1, mpModel=1 : SNMPv2c
        authentication = CommunityData(
            snmp_auth, mpModel=1 if protocol_version == "2c" else 0
        )
    else:
        authentication = UsmUserData(snmp_auth[0], snmp_auth[1], snmp_auth[2])
    iterator = getCmd(
        SnmpEngine(),
        authentication,
        transport,
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication or errorStatus:
        return False
    else:
        return "snmp://{}:{}".format(host, port)
