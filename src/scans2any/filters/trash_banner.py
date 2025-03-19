import re

from scans2any.internal import Service, SortedSet

PRIORITY = 2


def apply_filter(service: Service | None, args):
    """Filters a service's banners for "trash"."""

    if not service or not service.banners:
        return

    trash_banners = (
        "",
        "-",
        "unknown",
        "Not Found",
        "Loading...",
        "Bad Request",
        "200 \u2014 Document follows",
        "Error",
        "ERROR!",
        "Error response",
        "server",
        "Dienst",
        "Service",
        "Service Unavailable",
        "Document Error: Not Found",
        "Site Not Found",
    )

    trash = {banner.lower() for banner in trash_banners}

    # Precompile the regex pattern for performance
    pattern = re.compile(r"^'?4\d\d\b", re.IGNORECASE)

    filtered_banners = [
        banner
        for banner in service.banners
        if banner.lower() not in trash and not pattern.match(banner)
    ]

    # Remove duplicates and substrings in both directions
    filtered_banners = list(filtered_banners)
    to_remove = set()

    for banner in filtered_banners:
        for other in filtered_banners:
            if banner != other and banner.lower() in other.lower():
                to_remove.add(banner)  # Mark the smaller (contained) banner for removal

    # Remove only the elements marked for removal
    filtered_banners = SortedSet(
        [banner for banner in filtered_banners if banner not in to_remove]
    )

    service.banners = filtered_banners
