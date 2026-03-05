"""
Aquatone Parser

Currently only parses `JSON` output of aquatone.

Tested with output from [aquatone-git](https://github.com/shelld3v/aquatone)
"""

import contextlib
from pathlib import Path
from urllib.parse import urlparse

from scans2any.helpers.utils import is_valid_ip, read_json
from scans2any.internal import Host, Infrastructure, Service, SortedSet
from scans2any.internal.service import get_port_by_service

CONFIG = {
    "extensions": [".json"],
}

# Custom columns produced by this parser that can be requested via -c
CUSTOM_COLUMNS: dict[str, str] = {
    "http_status": "http_status",
}


def add_arguments(parser):
    """
    Add arguments to the parser for input format.
    """
    parser.add_argument(
        "--aquatone",
        type=str,
        action="append",
        nargs="+",
        metavar="filename/directory",
        help="Aquatone session file (aquatone_session.json) or directory",
    )


def parse(filename: str | Path) -> Infrastructure:
    """
    Parses Aquatone report in potentially different output formats.

    Currently only `JSON` supported.

    Parameters
    ----------
    filename : str | Path
        Path to `JSON` output file of aquatone tool.

    Returns
    -------
    Infrastructure
        Aquatone scan as `Infrastructure` object.
    """
    try:
        aquatone_hosts = __parse_json(filename)
    except Exception:
        raise
    # Aquatone is trusted for protocol and service_names
    return Infrastructure(
        aquatone_hosts,
        "Aquatone",
        trusted_fields={"service": ["protocol", "service_names"]},
    )


def __parse_json(filename: str | Path) -> list[Host]:
    """
    Parser for `JSON` output format of aquatone.

    Parameters
    ----------
    filename : str
        Path to aquatone's `JSON` output file

    Returns
    -------
    list[Host]
        List of identified hosts
    """

    hosts: list[Host] = []
    aquatone_json: dict[str, dict] = read_json(filename, dict)

    for _, page in aquatone_json["pages"].items():
        try:
            new_host = __make_host(page)
            service = __make_service(page)
            new_host.add_service(service)
            # No OS information in aquatone `json` format
            hosts.append(new_host)
        except (KeyError, IndexError):
            continue  # Skip incomplete objects from partial parsing

    return hosts


def __make_host(page: dict) -> Host:
    """
    Make new `Host` from aquatone-json 'page' entry.
    """

    hostname = page["hostname"].lower()
    addrs = page.get("addrs") or []
    addresses: set[str] = set()

    # Return immediately if hostname is already a valid IP
    if is_valid_ip(hostname):
        return Host(address=set([hostname]), hostnames=set(), os=set())

    for ip in addrs:
        if is_valid_ip(ip):
            addresses.add(ip)

    return Host(address=addresses, hostnames=set([hostname]), os=set())


def __make_service(page: dict) -> Service:
    """
    Make new `Service` from aquatone-json 'page' entry.
    """

    url = urlparse(page["url"])
    page_title = page["pageTitle"]
    server_header = __get_server_header(page)
    banners: SortedSet[str] = SortedSet()

    if page_title:
        banners.add(page_title)
    if server_header:
        banners.add(server_header)

    # Ensure port is always an int - url.port is None for default ports
    port: int = url.port or get_port_by_service(url.scheme, "tcp")

    # Aquatone JSON includes the HTTP status code under key 'status'
    custom_fields: dict[str, set] = {}
    if "status" in page:
        with contextlib.suppress(IndexError):
            custom_fields["http_status"] = {page["status"][:3]}

    service = Service(
        port=port,
        protocol="tcp",  # TODO: technically could be udp (quic)
        service_names=SortedSet([url.scheme]),
        banners=banners,
        custom_fields=custom_fields,
        trusted_fields={"protocol", "service_names"},  # Aquatone is accurate on these
    )

    return service


def __get_server_header(aquatone_json: dict) -> str:
    """
    Return value of `Server` header, if it exists for the (aquatone json) host
    """

    for header in aquatone_json["headers"]:
        if header["name"] == "Server":
            return header["value"]

    return ""
