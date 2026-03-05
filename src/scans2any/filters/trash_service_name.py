"""Remove uninformative or placeholder service names from services."""

from scans2any.internal import Service, SortedSet

PRIORITY = 2


def apply_filter(service: Service | None, args):
    """Filters a service's service_names for "trash" and "bad" names."""
    if not service:
        return

    trash = {"", "unknown", "tcpwrapped"}
    bad = {"www"}
    merge = {"http", "https"}

    # First pass: Exclude trash service names
    filtered_service_names: SortedSet[str] = SortedSet(
        [name for name in service.service_names if name.lower() not in trash]
    )

    # Only perform the second filter if there are multiple service names
    if len(filtered_service_names) > 1:
        filtered_service_names = SortedSet(
            [
                name
                for name in filtered_service_names
                if name.lower() not in bad and not name.lower().endswith("?")
            ]
        )

    # Merge service names together if one of them is in list merge, if http is in list merge, http and service_name should be merged to http/service_name
    for service_name in filtered_service_names:
        if service_name.lower() in merge and len(filtered_service_names) == 2:
            filtered_service_names = SortedSet(
                [f"{filtered_service_names[0]}/{filtered_service_names[1]}"]
            )

    service.service_names = filtered_service_names
