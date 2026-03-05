"""Filter hosts by IP address allow/blocklists and port allow/blocklists."""

from ipaddress import ip_address, summarize_address_range

from scans2any.internal import Infrastructure, printer

PRIORITY = 1


def add_arguments(parser):
    """
    Add arguments to the parser for the ip and port filter.
    """
    parser.add_argument(
        "--ip-allowlist",
        nargs="+",
        help="IP ranges to allow (format: --ip-allowlist start_ip-end_ip start_ip-end_ip ...)",
        default=[],
    )
    parser.add_argument(
        "--ip-blocklist",
        nargs="+",
        help="IP ranges to block (format: --ip-blocklist start_ip-end_ip start_ip-end_ip ...)",
        default=[],
    )
    parser.add_argument(
        "--port-allowlist",
        nargs="+",
        help="Port ranges to allow (format: --port-allowlist start_port-end_port start_port-end_port ...)",
        default=[],
    )
    parser.add_argument(
        "--port-blocklist",
        nargs="+",
        help="Port ranges to block (format: --port-blocklist start_port-end_port start_port-end_port ...)",
        default=[],
    )


def apply_filter(infra: Infrastructure, args):
    """Filter out ips and/or ports by blocklist or by allowlist."""

    # Process Allowlisted and Blocklisted IPs
    if args.ip_allowlist:
        allowed_ips = set()
        for address_range in args.ip_allowlist:
            try:
                start_ip, end_ip = address_range.split("-")
                networks = summarize_address_range(
                    ip_address(start_ip), ip_address(end_ip)
                )
                for network in networks:
                    for ip in network:
                        allowed_ips.add(str(ip))
            except ValueError:
                printer.error(
                    f"Invalid IP range: {address_range}. Please use the format start_ip-end_ip."
                )
                return

        infra.hosts = [
            h for h in infra.hosts if any(ip in allowed_ips for ip in h.address)
        ]

    if args.ip_blocklist:
        blocked_ips = set()
        for address_range in args.ip_blocklist:
            try:
                start_ip, end_ip = address_range.split("-")
                networks = summarize_address_range(
                    ip_address(start_ip), ip_address(end_ip)
                )
                for network in networks:
                    for ip in network:
                        blocked_ips.add(str(ip))
            except ValueError:
                printer.error(
                    f"Invalid IP range: {address_range}. Please use the format start_ip-end_ip."
                )
                return

        for host in infra.hosts:
            host.address = set(ip for ip in host.address if ip not in blocked_ips)
        infra.hosts = [h for h in infra.hosts if h.address]

    # Process Allowlisted and Blocklisted Ports for each host
    if args.port_allowlist or args.port_blocklist:
        allowed_ports = set()
        if args.port_allowlist:
            for port_range in args.port_allowlist:
                try:
                    start_port, end_port = map(int, port_range.split("-"))
                    allowed_ports.update(range(start_port, end_port + 1))
                except ValueError:
                    printer.error(
                        f"Invalid port range: {port_range}. Please use the format start_port-end_port."
                    )
                    return

        blocked_ports = set()
        if args.port_blocklist:
            for port_range in args.port_blocklist:
                try:
                    start_port, end_port = map(int, port_range.split("-"))
                    blocked_ports.update(range(start_port, end_port + 1))
                except ValueError:
                    printer.error(
                        f"Invalid port range: {port_range}. Please use the format start_port-end_port."
                    )
                    return

        for host in infra.hosts:
            if args.port_allowlist:
                host.services = [s for s in host.services if s.port in allowed_ports]
            if args.port_blocklist:
                host.services = [
                    s for s in host.services if s.port not in blocked_ports
                ]
