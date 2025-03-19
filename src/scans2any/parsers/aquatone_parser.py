"""
Aquatone Parser

Currently only parses `JSON` output of aquatone.

Tested with output from [aquatone-git](https://github.com/shelld3v/aquatone)
"""

from urllib.parse import urlparse

from scans2any.helpers.utils import is_ipv4, read_json
from scans2any.internal import Host, Infrastructure, Service, SortedSet
from scans2any.internal.service import get_port_by_service

CONFIG = {
    "extensions": [".json"],
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


def parse(filename: str) -> Infrastructure:
    """
    Parses Aquatone report in potentially different output formats.

    Currently only `JSON` supported.

    Parameters
    ----------
    filename : str
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
    return Infrastructure(aquatone_hosts, "Aquatone")


def __parse_json(filename: str) -> list[Host]:
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
    addrs = page["addrs"]

    if is_ipv4(hostname):
        new_host = Host(address=hostname, hostnames=SortedSet(), os=SortedSet())
    elif addrs is not None:
        new_host = Host(
            address=addrs[0], hostnames=SortedSet([hostname]), os=SortedSet()
        )
    else:
        new_host = Host(address=None, hostnames=SortedSet([hostname]), os=SortedSet())

    return new_host


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

    service = Service(
        port=url.port if url.port else get_port_by_service(url.scheme, "tcp"),
        protocol="tcp",
        service_names=SortedSet([url.scheme]),
        banners=banners,
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
