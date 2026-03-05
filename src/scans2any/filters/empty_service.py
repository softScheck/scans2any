"""Remove services with no identified service name or banner."""

from scans2any.internal import Host

PRIORITY = 3


def apply_filter(host: Host, args):
    """Filter services, that have no identified open banner or service name."""

    host.services = [
        service for service in host.services if service.service_names or service.banners
    ]
