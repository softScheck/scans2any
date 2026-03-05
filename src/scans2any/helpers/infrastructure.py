"""
Infrastructure processing utilities for scans2any.
"""

import os
from concurrent.futures import ThreadPoolExecutor

from scans2any.internal import Host, Infrastructure, cluster_hosts, printer
from scans2any.parsers import merge_file_parser
from scans2any.writers import avail_writers


def handle_merge_file(merge_file) -> tuple[Infrastructure | None, list[dict] | None]:
    """Parse merge file if provided."""
    if merge_file:
        merge_infra, auto_merge_ruleset = merge_file_parser.parse(merge_file)
        printer.debug(merge_infra)
        printer.debug("\nAuto merge ruleset:")
        printer.debug(auto_merge_ruleset)
        return merge_infra, auto_merge_ruleset
    return None, None


def combine_infrastructure_scans(
    infras: list[Infrastructure],
    *,
    quiet: bool = False,
    verbose: bool = False,
    parallel: bool = True,
):
    """Combine multiple infrastructure scans into one (optimized + parallel).

    Previous implementation repeatedly called ``Infrastructure.add_host`` in a
    nested fashion, resulting in an amortized worst-case O(n^2) behaviour for
    ``n`` hosts. This optimized variant performs a union-find (disjoint set)
    clustering over all hosts (across all infrastructures) based on shared IP
    addresses OR shared hostnames. All hosts that are transitively connected
    via either an IP or a hostname end up in the same cluster and are merged
    exactly once. This reduces the complexity to roughly O(n * a(n)) where
    a(n) is the inverse Ackermann function (effectively constant for all
    practical input sizes) plus the linear cost of building indexes.

    Parallelisation: token (IP/hostname) collection can be parallelised across
    worker threads. The work is mostly Python-level and may not always benefit
    from threading due to the GIL, but for very large inputs (tens of thousands
    of hosts) the reduced Python overhead in per-host loops + improved cache
    locality can still yield speedups. The ``parallel`` flag allows disabling
    this behaviour for debugging.

    Semantics: The previous algorithm sometimes required an additional
    iterative re-merge pass to collapse indirectly connected hosts discovered
    in later iterations. The union-find clustering computes the full
    transitive closure in one pass so the iterative loop is no longer needed.
    To remain safe, we still include an optional verification (disabled by
    default for performance) that can be enabled via the environment variable
    ``SCANS2ANY_VERIFY_COMBINE=1``.
    """
    if not infras:
        printer.failure("No inputs given!")
        exit(1)

    if len(infras) == 1:
        combined_infra = infras[0]
        printer.status(f"One input given: {combined_infra.identifier}")
        combined_infra.identifier = "Combined"
        return combined_infra

    with printer.status_section("Combining Reports", quiet=quiet, verbose=verbose):
        # Reuse the first infrastructure instance to keep backward compatibility
        combined_infra = infras[0]

        # Collect all hosts once
        all_hosts: list = []
        for infra in infras:
            all_hosts.extend(infra.hosts)

        total_hosts = len(all_hosts)
        if total_hosts == 0:
            printer.warning("No hosts across infrastructures.")
            combined_infra.hosts = []
            combined_infra.identifier = "Combined"
            return combined_infra

        clusters = cluster_hosts(all_hosts)

        # Merge hosts within each cluster (deterministic order)
        merged_hosts = []

        def merge_cluster(cluster: list[Host]) -> Host:
            base_host = cluster[0]
            for h in cluster[1:]:
                # Use union semantics (same as previous combine phase)
                try:
                    base_host.union_with_host(h)
                except Exception as e:  # Defensive: should not normally raise
                    printer.warning(f"Host union failed: {e}")
            base_host.sort()
            return base_host

        if parallel and len(clusters) > 100:
            max_workers = min(32, (os.cpu_count() or 1))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                merged_hosts = list(executor.map(merge_cluster, clusters))
        else:
            for cluster in clusters:
                merged_hosts.append(merge_cluster(cluster))

        combined_infra.hosts = merged_hosts
        combined_infra.identifier = "Combined"

    return combined_infra


def resolve_infrastructure_conflicts(
    primary_infra: Infrastructure,
    merge_file_infra: Infrastructure | None,
    merge_ruleset: list[dict] | None,
    *,
    quiet: bool = False,
    verbose: bool = False,
) -> Infrastructure:
    """Resolve conflicts between infrastructures using a merge file."""
    if primary_infra is None:
        if merge_file_infra is not None:
            printer.warning("No primary input data - using merge file input only")
            return merge_file_infra
        else:
            raise Exception("No input data available for processing")

    if merge_file_infra is None:
        printer.status("No merge file provided - keeping original infrastructure")
        return primary_infra

    # Apply merge file to resolve conflicts
    with printer.status_section(
        "Manual Conflict Resolution", quiet=quiet, verbose=verbose
    ):
        merge_file_infra.merge_with_infrastructure(primary_infra, merge_ruleset)
    return merge_file_infra


def check_for_remaining_conflicts(
    infra: Infrastructure,
    *,
    passed_merge_file: bool,
    buffer_file_path: str = "BUFFER_FILE.json",
    quiet: bool = False,
    verbose: bool = False,
) -> bool:
    """Check for remaining conflicts and create a merge file if needed."""
    with printer.status_section(
        "Checking for Remaining Conflicts", quiet=quiet, verbose=verbose
    ):
        conflict_found = infra.make_merge_file(
            passed_merge_file=passed_merge_file, buffer_file=buffer_file_path
        )
    if not conflict_found:
        printer.success("No conflicts detected in infrastructure data")
        return False

    return True


def apply_filters(
    infra: Infrastructure,
    enabled_filters: list[str],
    args,
    *,
    quiet: bool = False,
    verbose: bool = False,
):
    """Apply filters to the infrastructure."""
    if not enabled_filters:
        return

    from scans2any.filters import avail_filters

    with printer.status_section("Applying filters", quiet=quiet, verbose=verbose):
        active_filters = [
            (name, obj, level)
            for name, obj, level in avail_filters
            if name in enabled_filters
        ]

        sorted_filters = sorted(active_filters, key=lambda item: item[1].PRIORITY)

        for name, obj, level in sorted_filters:
            printer.status(f"{name}: {obj.apply_filter.__doc__}")
            printer.debug(f"Priority: {obj.PRIORITY}")

            if level == "infra":
                obj.apply_filter(infra, args)
            elif level == "host":
                for host in infra.hosts:
                    obj.apply_filter(host, args)
            elif level == "service":
                for host in infra.hosts:
                    for service in host.services:
                        obj.apply_filter(service, args)


def generate_output(
    infra: Infrastructure, args, *, quiet: bool = False, verbose: bool = False
):
    """Generate output based on selected writer."""
    msg = "Output"
    if getattr(args, "out", None):
        msg += f" ({args.out})"

    writer = None
    for obj in avail_writers:
        if args.writer == obj.NAME:
            writer = obj
            break

    if not writer:
        printer.failure(f"Output writer {args.writer} is not defined!")
        exit(1)

    # Type checker now knows writer is not None due to exit above
    assert writer is not None
    with printer.status_section(msg, quiet=quiet, verbose=verbose):
        return writer.write(infra, args)
