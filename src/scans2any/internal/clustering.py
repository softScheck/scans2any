"""
Clustering algorithms for scans2any.
"""

from itertools import chain

from scans2any.internal.host import Host


def cluster_hosts(hosts: list[Host]) -> list[list[Host]]:
    """
    Groups hosts into connected components based on shared IP addresses or hostnames.
    Returns a list of clusters, where each cluster is a list of Hosts.
    The hosts within each cluster are ordered by their original index in the input list.

    Uses union-find with path halving and union by rank.  Tokens (IPs and
    hostnames) are processed in a single pass: the first host that introduces a
    token becomes its representative, and every subsequent host sharing the same
    token is immediately unioned with it.  This avoids building an intermediate
    ``token -> [index, …]`` map and the extra iteration that followed.
    """
    total_hosts = len(hosts)
    if total_hosts == 0:
        return []

    parent = list(range(total_hosts))
    rank = [0] * total_hosts

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # Path halving
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if rank[ra] < rank[rb]:
            parent[ra] = rb
        elif rank[ra] > rank[rb]:
            parent[rb] = ra
        else:
            parent[rb] = ra
            rank[ra] += 1

    # Single-pass: union on the fly as duplicate tokens are encountered.
    # Only one representative index per token is stored (dict[str, int]).
    token_first: dict[str, int] = {}
    for idx, host in enumerate(hosts):
        for token in chain(host.address, host.hostnames):
            first = token_first.get(token)
            if first is not None:
                union(first, idx)
            else:
                token_first[token] = idx

    clusters: dict[int, list[int]] = {}
    for i in range(total_hosts):
        root = find(i)
        clusters.setdefault(root, []).append(i)

    return [[hosts[i] for i in indices] for indices in clusters.values()]
