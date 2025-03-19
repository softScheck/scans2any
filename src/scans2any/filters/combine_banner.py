from scans2any.internal import Service
from scans2any.internal.sorted_set import SortedSet

PRIORITY = 3


def apply_filter(service: Service, args):
    """Combine info from multiple service banners into one banner"""

    # Remove too long banners to combine
    service.banners = SortedSet(
        [
            banner
            for banner in service.banners
            if len(banner) <= 50 or len(service.banners) == 1
        ]
    )

    # Combine banners
    combined_banner = " | ".join(service.banners)
    service.banners = SortedSet([combined_banner])
