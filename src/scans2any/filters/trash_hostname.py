"""Remove uninformative or noisy hostnames from hosts."""

from scans2any.internal import Host, SortedSet

PRIORITY = 2


def apply_filter(host: Host, args):
    """Filters a service's hostnames for "trash"."""
    hostnames = list(host.hostnames)

    # Sort hostnames by length (shortest to longest)
    hostnames.sort(key=len)
    filtered_hostnames = []

    for i, hostname in enumerate(hostnames):
        # Check if the hostname is a prefix of any longer hostname with a dot following
        prefix = f"{hostname}."
        is_subdomain = False

        for longer_hostname in hostnames[i + 1 :]:
            if longer_hostname.startswith(prefix):
                is_subdomain = True
                break

        if not is_subdomain:
            filtered_hostnames.append(hostname)

    host.hostnames = SortedSet(filtered_hostnames)
