import copy
import textwrap

from scans2any import filters
from scans2any.internal import Host, Infrastructure, Service, SortedSet

#  Test Infrastructure

host = Host(
    address=SortedSet(["127.0.0.1"]),
    hostnames=SortedSet(["localhost"]),
    os=SortedSet(["linux"]),
)

service_1 = Service(
    port=22,
    protocol="tcp",
    service_names=SortedSet(["ssh"]),
    banners=SortedSet(["OpenSSH 1.0"]),
)
service_2 = Service(
    port=80,
    protocol="tcp",
    service_names=SortedSet(["http", "www"]),
    banners=SortedSet(["Apache Web Server"]),
)
service_3 = Service(
    port=443,
    protocol="tcp",
    service_names=SortedSet(["https"]),
    banners=SortedSet(["Apache Web Server"]),
)
service_4 = Service(
    port=1111,
    protocol="udp",
    service_names=SortedSet(["unknown"]),
    banners=SortedSet(["Ok Banner", "", "unknown"]),
)
host.add_services([service_1, service_2, service_3, service_4])

infra = Infrastructure([host], "Test Infrastructure")

assert str(infra) == textwrap.dedent("""
            127.0.0.1
            ~ Hostnames:
                ['localhost']
            ~ OS:
                ['linux']
            ~ Services:
                22/tcp - ['ssh']
                    ['OpenSSH 1.0']
                80/tcp - ['http', 'www']
                    ['Apache Web Server']
                443/tcp - ['https']
                    ['Apache Web Server']
                1111/udp - ['unknown']
                    ['', 'Ok Banner', 'unknown']
        """)


def test_trash_service_names_filter():
    infra_ = copy.deepcopy(infra)

    for host in infra_.hosts:
        for service in host.services:
            filters.trash_service_name.apply_filter(service, None)

    assert str(infra_) == textwrap.dedent("""
            127.0.0.1
            ~ Hostnames:
                ['localhost']
            ~ OS:
                ['linux']
            ~ Services:
                22/tcp - ['ssh']
                    ['OpenSSH 1.0']
                80/tcp - ['http']
                    ['Apache Web Server']
                443/tcp - ['https']
                    ['Apache Web Server']
                1111/udp - []
                    ['', 'Ok Banner', 'unknown']
        """)


def test_trash_banners_filter():
    infra_ = copy.deepcopy(infra)

    for host in infra_.hosts:
        for service in host.services:
            filters.trash_banner.apply_filter(service, None)

    assert str(infra_) == textwrap.dedent("""
            127.0.0.1
            ~ Hostnames:
                ['localhost']
            ~ OS:
                ['linux']
            ~ Services:
                22/tcp - ['ssh']
                    ['OpenSSH 1.0']
                80/tcp - ['http', 'www']
                    ['Apache Web Server']
                443/tcp - ['https']
                    ['Apache Web Server']
                1111/udp - ['unknown']
                    ['Ok Banner']
        """)
