"""
Nessus Parser
"""

import ast
from pathlib import Path

from defusedxml.ElementTree import iterparse

from scans2any.helpers.utils import find_os, is_valid_ip
from scans2any.internal import Host, Infrastructure, Service, SortedSet

CONFIG = {
    "extensions": [".nessus"],
}

# Custom columns produced by this parser that can be requested via -c
CUSTOM_COLUMNS: dict[str, str] = {
    "vulnerability-type": "Vulnerability-Type",
}


def add_arguments(parser):
    """
    Add arguments to the parser for input format.
    """
    parser.add_argument(
        "--nessus",
        type=str,
        action="append",
        nargs="+",
        metavar="filename/directory",
        help="Nessus report (.nessus) file/directory",
    )


class NessusReport:
    """
    The NessusReportv2 generator will return vulnerability items from any
    Nessus version 2 formatted Nessus report file.  The returned data will be
    a python dictionary representation of the ReportItem with the relevant
    host properties attached.  The ReportItem's structure itself will determine
    the resulting dictionary, what attributes are returned, and what is not.

    Please note that in order to use this generator, you must install the python
    ``lxml`` package.

    Args:
        fobj (File object or string path):
            Either a File-like object or a string path pointing to the file to
            be parsed.

    Examples:
        For example, if we wanted to load a Nessus report from disk and iterate
        through the contents, it would simply be a matter of:


        ...     report = NessusReport(nessus_file)
        ...     for item in report:
        ...         print(item)
    """

    def __init__(self, fobj, tags_of_interest=None):
        self._iter = iterparse(fobj, events=("start", "end"))
        self.tags_of_interest = tags_of_interest

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        """
        Get the next Host from the nessus file and return it as a
        python list.

        Generally speaking this method is not called directly, but is instead
        called as part of a loop.
        """

        host = []
        for event, elem in self._iter:
            if event == "start" and elem.tag == "ReportHost":
                # If we detect a new ReportHost, then we will want to rebuild
                # the host information cache, starting with the ReportHost's
                # name for the host.
                self._cache = {"host-report-name": elem.get("name")}
            elif event == "end":
                match elem.tag:
                    case "HostProperties":
                        # Once we have finished parsing out all of the host
                        # properties, we need to update the host cache with
                        #  this new information.
                        for child in elem:
                            # if child.tag in valid_host_properties:
                            self._cache[child.get("name")] = child.text
                        host.append(self._cache)
                        elem.clear()
                    case "ReportHost":
                        elem.clear()
                        return host
                    case "NessusClientData_v2":
                        # If we reach the end of the Nessus file, then we
                        # need to raise a StopIteration exception to inform
                        # the code downstream that we have reached the end
                        # of the file.
                        raise StopIteration()
                    case "ReportItem":
                        vuln = elem.attrib.copy()
                        plugin_output = elem.findtext("plugin_output")
                        if plugin_output:
                            vuln["plugin_output"] = plugin_output
                        host.append(vuln)
                        elem.clear()


def parse(filename: str | Path) -> Infrastructure:
    """
    Parses `csv` export of nessus scan.

    Parameters
    ----------
    filename : str | Path
        Path to nessus `csv` export.

    Returns
    -------
    Infrastructure
        Nessus scan as infrastructure object.
    """

    infra = Infrastructure(identifier="Nessus")
    new_hosts = []

    nessus_report = NessusReport(filename)
    for item in nessus_report:
        new_host = __parse_report_item(item)
        if new_host:
            new_hosts.append(new_host)

    infra.add_hosts(new_hosts)
    return infra


def __parse_report_item(host: list) -> Host | None:
    """
    Parse report item of `NessusReportv2` and create a new host with the
    corresponding service.

    Parameters
    ----------
    item : dict
        Report item of `NessusReportv2` instance.

    Returns
    -------
    Host
        Host with service, identified by the report item.
    """

    # Host information, list item 0
    address = host[0].get("host-ip")
    hostname = host[0].get("host-fqdn")
    detected_os = __detect_os(host[0])

    # Create host
    if address and is_valid_ip(address):
        if hostname and not is_valid_ip(hostname):
            new_host = Host(
                address=set([address]), hostnames=set([hostname.lower()]), os=set()
            )
        else:
            new_host = Host(address=set([address]), hostnames=set(), os=set())
    elif hostname is not None:
        new_host = Host(address=set(), hostnames=set([hostname.lower()]), os=set())
    else:
        return None

    # Add OS detection results
    new_host.os = set((osvalue, "Nessus") for osvalue in detected_os)

    # Service information loop
    new_services = []
    for item in host[1:]:
        port = int(item["port"])
        protocol = item.get("protocol")
        service = item.get("svc_name")
        plugin_name = item.get("pluginName")
        severity = int(item.get("severity", 0))

        if port == 0:
            # Get additional DNS Names
            if plugin_name == "Additional DNS Hostnames":
                plugin_out = item.get("plugin_output").splitlines()[1:]
                for dns in plugin_out:
                    if dns.startswith("  - "):
                        item = dns[4:].lower().strip()
                        new_host.hostnames.add(item)
                    else:
                        raise ValueError(
                            "Unexpected format in Additional DNS Hostnames"
                        )
        else:
            vuln_types = (
                SortedSet([plugin_name[:50].strip()])
                if plugin_name and severity >= 2
                else SortedSet()
            )

            new_service = Service(
                port=port,
                protocol=protocol,
                service_names=SortedSet([service]),
                banners=SortedSet(),
                custom_fields={"Vulnerability-Type": vuln_types} if vuln_types else {},
            )

            # Get SSH and HTTP data
            if plugin_name == "HTTP Server Type and Version":
                plugin_out = item.get("plugin_output").split(":")[1]
                new_service.banners.add(plugin_out.strip())
            elif plugin_name == "SSH Server Type and Version Information":
                plugin_out = (
                    item.get("plugin_output")
                    .split(":")[1]
                    .splitlines()[0][9:]
                    .replace("_", "/")
                    .replace("-", " ")
                )
                new_service.banners.add(plugin_out.strip())

                # Possible interesting data, but seems mostily duplicate
                # pluginID="106375" pluginName="nginx HTTP Server Detection"
                # pluginID="24260" pluginName="HyperText Transfer Protocol (HTTP) Information"

            new_services.append(new_service)

    new_host.add_services(new_services)
    return new_host


def __detect_os(item: dict, min_confidence: float = 90.0) -> list[str]:
    """
    Detect OS from Nessus report items.

    Parameters
    ----------
    item : dict
        Nessus report item.
    min_confidence : float, optional
        Minimum confidence level to consider a prediction (default is 50.0).

    Returns
    -------
    list[str]
        List of detected operating systems.
    """
    detected_os = set()

    # List of keys to search for OS information
    os_keys = ["operating-system", "os", "ssh-fingerprint"]

    for key in os_keys:
        if key in item:
            os_result = find_os(item[key])
            if os_result:
                detected_os.add(os_result)

    if "sinfp-ml-prediction" in item:
        try:
            predictions = ast.literal_eval(item["sinfp-ml-prediction"])
            # Filter predictions based on minimum confidence level
            high_confidence_preds = [
                pred
                for pred in predictions
                if pred.get("confidence", 0) >= min_confidence
            ]
            if high_confidence_preds:
                # Select the prediction with the highest confidence
                best_prediction = max(
                    high_confidence_preds, key=lambda x: x["confidence"]
                )
                os_result = find_os(best_prediction.get("predicted-os", ""))
                if os_result:
                    detected_os.add(os_result)
        except (ValueError, SyntaxError):
            # Handle invalid 'sinfp-ml-prediction' format
            pass

    return list(detected_os)
