import json
import random
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

import msgpack
from netaddr import EUI


class IPv4Addresses:
    """Dynamic container for named IPv4Address attributes, with no boilerplate.

    Usage:
        ips = IPv4Addresses()
        ips.ip1 = IPv4Address("192.168.1.1")
        ips.ip2 = IPv4Address("192.168.1.2")
    """

    def __setattr__(self, name, value):
        if not isinstance(value, IPv4Interface):
            raise TypeError(f"{name}: expected IPv4Interface, got {type(value).__name__}")
        super().__setattr__(name, value)

    # ---------------- dict ----------------

    def to_dict(self):
        return {k: str(v) for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        for k, v in d.items():
            super(IPv4Addresses, obj).__setattr__(k, IPv4Interface(v))
        return obj

    # ---------------- JSON ----------------

    def to_json(self):
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, s):
        return cls.from_dict(json.loads(s))

    # ---------------- msgpack ----------------

    def pack(self):
        return msgpack.packb(self.to_dict(), use_bin_type=True)

    @classmethod
    def unpack(cls, blob):
        return cls.from_dict(msgpack.unpackb(blob, raw=False))


class IPv4Networks:
    """Dynamic container for named IPv4Network attributes, with no boilerplate.

    Usage:
        nets = IPv4Networks()
        nets.lan = IPv4Network("192.168.1.0/24")
        nets.mgmt = IPv4Network("10.0.0.0/8")
    """

    def __setattr__(self, name, value):
        if not isinstance(value, IPv4Network):
            raise TypeError(f"{name}: expected IPv4Network, got {type(value).__name__}")
        super().__setattr__(name, value)

    # ---------------- dict ----------------

    def to_dict(self):
        return {k: str(v) for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        for k, v in d.items():
            super(IPv4Networks, obj).__setattr__(k, IPv4Network(v))
        return obj

    # ---------------- JSON ----------------

    def to_json(self):
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, s):
        return cls.from_dict(json.loads(s))

    # ---------------- msgpack ----------------

    def pack(self):
        return msgpack.packb(self.to_dict(), use_bin_type=True)

    @classmethod
    def unpack(cls, blob):
        return cls.from_dict(msgpack.unpackb(blob, raw=False))


_PRIVATE_NETWORKS = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
]


def _pick_one(mask, from_network, exclude, from_private_network):
    """Pick a single random /mask network. Internal helper for random_ipv4networks."""
    block_size = 2 ** (32 - mask)

    def make(abs_idx):
        return IPv4Network((abs_idx * block_size, mask))

    def available(net):
        return not any(net.overlaps(ex) for ex in exclude)

    def indices_in(a, b):
        first = (a + block_size - 1) // block_size
        last = (b + 1) // block_size - 1
        return range(first, last + 1) if first <= last else range(0, 0)

    flo = int(from_network.network_address)
    fhi = int(from_network.broadcast_address)
    if from_private_network:
        boxes = []
        for p in _PRIVATE_NETWORKS:
            lo = max(flo, int(p.network_address))
            hi = min(fhi, int(p.broadcast_address))
            if lo <= hi:
                boxes.append((lo, hi))
    else:
        boxes = [(flo, fhi)]

    spans = [(r.start, len(r)) for lo, hi in boxes for r in [indices_in(lo, hi)] if r]
    total = sum(count for _, count in spans)

    if total == 0:
        raise ValueError(f"No /{mask} network fits in the search space")

    def pick_abs_idx():
        if from_private_network and len(spans) > 1:
            # Pick uniformly across private ranges (not weighted by range size)
            start, count = random.choice(spans)
            return start + random.randrange(count)
        n = random.randrange(total)
        for start, count in spans:
            if n < count:
                return start + n
            n -= count
        return spans[-1][0]  # unreachable: n < total guarantees a match above

    if total <= 65536:
        candidates = [make(i) for start, count in spans
                      for i in range(start, start + count)
                      if available(make(i))]
        if not candidates:
            raise ValueError(f"No available /{mask} network with the given constraints")
        return random.choice(candidates)

    for _ in range(1000):
        candidate = make(pick_abs_idx())
        if available(candidate):
            return candidate

    raise ValueError(f"No available /{mask} network found after 1000 attempts")


def random_ipv4networks(
    masks,
    from_network=IPv4Network("0.0.0.0/0"),
    exclude=None,
    from_private_network=False,
):
    """Return a list of disjoint random IPv4Networks.

    `masks` is an int or a list of ints; one network is returned per mask,
    all mutually disjoint and not overlapping any network in `exclude`.
    Optionally restricted to RFC-1918 private ranges with `from_private_network=True`.

    `from` being a reserved keyword, the parameter is named `from_network`.

    Raises ValueError if any network cannot be allocated.
    """
    if isinstance(masks, int):
        masks = [masks]

    working_exclude = list(exclude) if exclude else []
    result = []
    for mask in masks:
        net = _pick_one(mask, from_network, working_exclude, from_private_network)
        result.append(net)
        working_exclude.append(net)
    return result


def random_ipv4s(network, n=1, exclude_ips=None, exclude_nets=None):
    """Return a list of n distinct random IPv4Interface within `network`,
    excluding any address in `exclude_ips` or covered by any network in `exclude_nets`.

    Raises ValueError if fewer than n addresses are available.
    """
    ex_ips = set(exclude_ips) if exclude_ips else set()
    ex_nets = list(exclude_nets) if exclude_nets else []

    base = int(network.network_address)
    total = network.num_addresses

    def make(i):
        return IPv4Interface(f"{IPv4Address(base + i)}/{network.prefixlen}")

    def available(ip):
        return ip not in ex_ips and not any(ip in net for net in ex_nets)

    # Exclude network address (offset 0) and broadcast (offset total-1) for prefix <= 30.
    # /31 (point-to-point, RFC 3021) and /32 (host route) have no reserved boundary addresses.
    if network.prefixlen <= 30:
        host_range = range(1, total - 1)
    else:
        host_range = range(total)

    # Small space: enumerate all candidates, then sample.
    if total <= 65536:
        candidates = [make(i) for i in host_range if available(make(i))]
        if len(candidates) < n:
            raise ValueError(
                f"Not enough available addresses: need {n}, found {len(candidates)}"
            )
        return random.sample(candidates, n)

    # Large space: pick one at a time, accumulating into a working exclude set.
    working_ex = set(ex_ips)
    result = []
    for _ in range(n):
        for _ in range(1000):
            candidate = make(random.randrange(host_range.start, host_range.stop))
            if candidate not in working_ex and not any(candidate in net for net in ex_nets):
                result.append(candidate)
                working_ex.add(candidate)
                break
        else:
            raise ValueError(
                f"Could not find enough available addresses (got {len(result)}/{n})"
            )
    return result


def random_ipv4s_with_range(network, gap, n=1, exclude_ips=None, exclude_nets=None):
    """Return a list of n + 2*k distinct random IPv4Interface within `network`.

    `gap` is either an int or a list of ints. ``k = 1`` when gap is an int,
    ``k = len(gap)`` otherwise.

    The returned list has the form:
        [ip_min1, ip_max1, ip_min2, ip_max2, ..., ip_mink, ip_maxk, ip1, ..., ipn]

    Guarantees:
    - int(ip_max_i.ip) - int(ip_min_i.ip) == gap[i]  (or gap when gap is an int)
    - ip_max_i < ip_min_{i+1}  (ranges are strictly ordered, non-overlapping)
    - ip1 .. ipn are outside every range [ip_min_i, ip_max_i]

    Raises ValueError if the constraints cannot be satisfied.
    """
    gaps = [gap] if isinstance(gap, int) else list(gap)
    k = len(gaps)

    ex_ips = set(exclude_ips) if exclude_ips else set()
    ex_nets = list(exclude_nets) if exclude_nets else []

    base = int(network.network_address)
    total = network.num_addresses
    prefixlen = network.prefixlen

    def make(i):
        return IPv4Interface(f"{IPv4Address(base + i)}/{prefixlen}")

    def is_excluded(ip):
        return ip in ex_ips or any(ip in net for net in ex_nets)

    # Minimum space: k ranges placed back-to-back with 1-address gaps between them.
    # Minimum last offset: sum(gaps) + k - 1; need total >= sum(gaps) + k.
    min_needed = sum(gaps) + k
    if total < min_needed:
        raise ValueError(
            f"Network {network} is too small to fit {k} range(s) with gaps {gaps}"
        )

    # suffix_sums[i] = sum(gaps[i:])
    suffix_sums = [0] * (k + 1)
    for i in range(k - 1, -1, -1):
        suffix_sums[i] = suffix_sums[i + 1] + gaps[i]

    def hi_for(i):
        """Max start offset for range i that still leaves room for ranges i+1..k-1."""
        return total - 1 - suffix_sums[i] - (k - 1 - i)

    SMALL = 65536

    def try_place_ranges():
        """Try one left-to-right placement. Returns [(start, end), ...] or None."""
        range_offsets = []
        lo = 0
        for i in range(k):
            h = hi_for(i)
            if h < lo:
                return None
            g = gaps[i]
            space = h - lo + 1
            if space <= SMALL:
                candidates = [
                    j
                    for j in range(lo, h + 1)
                    if not is_excluded(make(j)) and not is_excluded(make(j + g))
                ]
                if not candidates:
                    return None
                s = random.choice(candidates)
            else:
                s = None
                for _ in range(1000):
                    c = random.randint(lo, h)
                    if not is_excluded(make(c)) and not is_excluded(make(c + g)):
                        s = c
                        break
                if s is None:
                    return None
            range_offsets.append((s, s + g))
            lo = s + g + 1
        return range_offsets

    range_offsets = None
    for _ in range(1000):
        range_offsets = try_place_ranges()
        if range_offsets is not None:
            break
    if range_offsets is None:
        raise ValueError(
            f"Could not place {k} range(s) with gaps {gaps} with the given exclusions"
        )

    def in_any_range(offset):
        return any(s <= offset <= e for s, e in range_offsets)

    def extra_available(offset):
        ip = make(offset)
        return (
            ip not in ex_ips
            and not in_any_range(offset)
            and not any(ip in net for net in ex_nets)
        )

    if total <= SMALL:
        extra_candidates = [make(i) for i in range(total) if extra_available(i)]
        if len(extra_candidates) < n:
            raise ValueError(
                f"Not enough addresses outside the range(s) for {n} extra IPs: "
                f"found {len(extra_candidates)}"
            )
        extras = random.sample(extra_candidates, n)
    else:
        chosen = set()
        extras = []
        for _ in range(n):
            for _ in range(1000):
                offset = random.randrange(total)
                candidate = make(offset)
                if extra_available(offset) and candidate not in chosen:
                    extras.append(candidate)
                    chosen.add(candidate)
                    break
            else:
                raise ValueError(
                    f"Could not find enough extra addresses (got {len(extras)}/{n})"
                )

    result = []
    for s, e in range_offsets:
        result.append(make(s))
        result.append(make(e))
    result.extend(extras)
    return result


def random_ips_from_topology(data, topology):
    """Assign random IPs to data.ips from data.nets based on a NetScheme0 topology.

    topology: {net_name: [machine, ...] or {machine: iface_spec, ...}}
    (the _topology class attribute format of NetScheme0)

    For each machine m:
    - belongs to exactly one network netX → data.ips.m  (in data.nets.netX)
    - belongs to multiple networks       → data.ips.m_netX for each netX
    """
    # Build inverse map: machine -> [net_name, ...]  (preserve insertion order)
    machine_nets = {}
    for net_name, machines in topology.items():
        names = machines.keys() if isinstance(machines, dict) else machines
        for m in names:
            machine_nets.setdefault(m, []).append(net_name)

    # Assign IPs, tracking used addresses per network to avoid duplicates
    assigned = {}  # {net_name: list[IPv4Interface]}
    for machine, nets in machine_nets.items():
        for net_name in nets:
            network = getattr(data.nets, net_name)
            ip = random_ipv4s(network, 1, exclude_ips=assigned.get(net_name))[0]
            assigned.setdefault(net_name, []).append(ip)
            attr = machine if len(nets) == 1 else f"{machine}_{net_name}"
            setattr(data.ips, attr, ip)


def random_mac_address(prefix=None, n=1):
    """Return a list of n distinct random EUI MAC addresses.

    `prefix` is an optional colon- or dash-separated hex string specifying the
    leading bytes (e.g. ``"00:1A:2B"`` for a 3-byte OUI prefix).
    Remaining bytes are chosen at random.

    Raises ValueError if n distinct addresses cannot be generated.
    """
    if prefix is not None:
        sep = "-" if "-" in prefix else ":"
        prefix_bytes = bytes(int(x, 16) for x in prefix.split(sep))
    else:
        prefix_bytes = b""

    suffix_len = 6 - len(prefix_bytes)
    if suffix_len < 0:
        raise ValueError(
            f"Prefix too long: {prefix!r} ({len(prefix_bytes)} bytes, max 6)"
        )

    total = 256**suffix_len
    if n > total:
        raise ValueError(
            f"Cannot generate {n} distinct MACs with {suffix_len} random bytes (max {total})"
        )

    def make(suffix_bytes):
        all_bytes = prefix_bytes + suffix_bytes
        if prefix is None:
            all_bytes = bytes([all_bytes[0] & 0xFE]) + all_bytes[1:]
        return EUI(":".join(f"{b:02x}" for b in all_bytes))

    if total <= 65536:
        candidates = [make(i.to_bytes(suffix_len, "big")) for i in range(total)]
        return random.sample(candidates, n)

    seen = set()
    result = []
    for _ in range(n):
        for _ in range(1000):
            suffix = random.randbytes(suffix_len)
            if suffix not in seen:
                seen.add(suffix)
                result.append(make(suffix))
                break
        else:
            raise ValueError(
                f"Could not generate {n} distinct MACs after 1000 attempts"
            )
    return result
