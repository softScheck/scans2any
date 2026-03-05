"""Remove hosts with no identified open services from the infrastructure."""

from scans2any.internal import Infrastructure

PRIORITY = 4


def apply_filter(infra: Infrastructure, args):
    """Filter hosts, that have no identified open ports."""

    delete_service_names = ("", "ident")

    infra.hosts = [
        host
        for host in infra.hosts
        if host.services
        and not (  # remove hosts with one service that has one service name that is in the delete_service_names list
            len(host.services) == 1
            and len(host.services[0].service_names) == 1
            and host.services[0].service_names[0] in delete_service_names
        )
    ]
