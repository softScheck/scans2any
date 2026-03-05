"""Resolve collisions by keeping only the first entry in each sorted set."""

from scans2any.internal import Host, SortedSet

PRIORITY = 5


def apply_filter(host: Host, args):
    """Resolves multiple conflicting banners/service names by selecting the first."""

    for service in host.services:
        if len(service.banners) > 0:
            service.banners = SortedSet([service.banners[0]])
        if len(service.service_names) > 0:
            service.service_names = SortedSet([service.service_names[0]])

    if host.os:
        host.os = SortedSet([next(iter(host.os))])
