#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of service_discovery_scanner module

__intname__ = "service_discovery_scanner.http_discover"
__author__ = "Orsiris de Jong"
__copyright__ = "Copyright (C) 2022 Orsiris de Jong"
__licence__ = "BSD 3 Clause"
__build__ = "2022091801"

from logging import getLogger
import requests
import ssl
from requests.adapters import HTTPAdapter

logger = getLogger()


def check_http_response(host: str, port: int, **kwargs):
    http_type = kwargs.get("http_type")
    http_endpoint = kwargs.get("http_endpoint")
    http_retries = kwargs.get("http_retries")
    http_timeout = kwargs.get("http_timeout")
    https_verify = kwargs.get("https_verify", False)

    session = requests.Session()

    if http_type in ["all", "https"]:
        session.mount("https://", HTTPAdapter(max_retries=http_retries))
        try:
            endpoint = "https://{}:{}{}".format(host, port, http_endpoint)
            result = session.get(endpoint, timeout=http_timeout, verify=https_verify)
            if str(result.status_code)[0] in [
                "2",
                "3",
            ]:  # Accepted status codes 2xx and 3xx
                return endpoint
        except requests.exceptions.ConnectTimeout:
            logger.debug("HTTPS timeout for {}".format(host))
        except ssl.SSLCertVerificationError:
            print("CERT VERIF ERROR")
            return False
        except requests.exceptions.SSLError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in exc.__str__():
                print("Host {}: CERTIFICATE VERIFY ERROR".format(host))
                return False
            logger.debug("HTTPS SSL Error for {}".format(host))
            logger.debug("Trace:", exc_info=True)
        except Exception:
            logger.debug("Trace:", exc_info=True)

    if http_type in ["all", "http"]:
        session.mount("http://", HTTPAdapter(max_retries=http_retries))
        try:
            endpoint = "http://{}:{}{}".format(host, port, http_endpoint)
            result = session.get(
                endpoint,
                timeout=http_timeout,
            )
            if str(result.status_code)[0] in [
                "2",
                "3",
            ]:  # Accepted status codes 2xx and 3xx
                return endpoint
        except requests.exceptions.ConnectTimeout:
            logger.debug("HTTP timeout for {}".format(host))
        except requests.exceptions.SSLError:
            logger.debug("HTTP SSL Error for {}".format(host))
        except Exception:
            logger.debug("Trace:", exc_info=True)
    return False
