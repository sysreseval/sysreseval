"""Build a hidden mirror of a lab topology, for grading from machines the student cannot see.

Evaluation strategy — the "hidden mirror"
-----------------------------------------
A machine configured by the student cannot be trusted to grade itself: the
student controls every machine around it and could fake a service, block a
probe, or reconfigure a server. So such labs never test the student's live
network. Instead every lab builds, in parallel, a **hidden clone** of the whole
topology (same subnets, same IP addresses, same interface numbering, but on
separate Kathara links, with every machine ``hidden=True``). The clones of the
clients/servers are fully controlled by the lab (it starts exactly the services
it wants to probe).

At grading time, for every graded machine ``m`` the grader:

1. downloads the *current* configuration of ``m`` (step 1), e.g. the nftables
   ruleset or the traffic-control tree;
2. transplants it verbatim onto the hidden clone ``m_h`` (step 2);
3. probes connectivity / behaviour **through / to the clone** from the hidden
   controlled machines (step 3), where the expected result is known.

Because the clone is byte-for-byte identical in addressing and interface names,
a configuration written with ``iifname``, ``ip saddr``, ``dev eth1`` … behaves
exactly as it does on the real machine — but now against probes the student
cannot see or tamper with.

This module holds the topology side of the technique, which is purely
structural: :func:`expand_topology` (clone of ``_topology`` / ``_machine_specs``,
computed once at module load) and :func:`copy_addressing` (clone of the subnets
and addresses, called from ``Data.generate()``). The transplant and the probes
depend on what is graded and live in the subject modules: ``firewall.py``
(``transplant_ruleset``, ``probe_tcp`` …, controlled HTTP / banner / UDP
servers) and ``tc.py`` (``transplant_tc``).

The module is deployed to ``/opt/sre/lib/`` and imported from lab ``srelab.py``
files with ``import hidden_mirror`` or ``from hidden_mirror import ...``.
"""


# ---------------------------------------------------------------------------
# topology utilities
# ---------------------------------------------------------------------------

def _normalize_topology(topology):
    """Return ``{net_name: {machine: eth_index}}`` with every interface index
    resolved to a concrete int, replicating ``NetScheme0.__init__``'s counter.
    Accepts the list form, the ``{m: iface}`` form and the ``{m: (iface, mac)}``
    form used in ``_topology``.
    """
    norm = {}
    counter = {}
    for net_name, machines in topology.items():
        items = machines.items() if isinstance(machines, dict) else ((m, None) for m in machines)
        norm[net_name] = {}
        for mname, iface_spec in items:
            iface = iface_spec[0] if isinstance(iface_spec, tuple) else iface_spec
            if iface is None:
                iface = counter.get(mname, 0)
            counter[mname] = max(counter.get(mname, 0), iface) + 1
            norm[net_name][mname] = iface
    return norm


def machines_by_net(topology):
    """Return ``{machine: [net_name, ...]}`` (insertion order) for *topology*."""
    result = {}
    for net_name, machines in topology.items():
        names = machines.keys() if isinstance(machines, dict) else machines
        for m in names:
            result.setdefault(m, []).append(net_name)
    return result


def router_machines(topology):
    """Return the set of machines connected to more than one network (the routers)."""
    return {m for m, nets in machines_by_net(topology).items() if len(nets) > 1}


# ---------------------------------------------------------------------------
# topology mirroring (build side)
# ---------------------------------------------------------------------------

def expand_topology(topology, machine_specs, suffix="_h", extra_specs=None):
    """Return ``(full_topology, full_machine_specs)`` = *topology* plus a hidden
    clone of every network and machine.

    This is **purely structural** (no ``data`` needed) so it is deterministic and
    can be computed once at module load and assigned to ``NetScheme._topology`` /
    ``NetScheme._machine_specs`` — which is what ``_resolve_spec`` actually reads
    (it inspects class dicts / ``data`` attributes, never instance attributes set
    in ``__init__``). Pair it with :func:`copy_addressing`, called from
    ``Data.generate()`` to populate the clone IPs (those persist in ``data.json``).

    * network ``net`` → clone ``net+suffix`` (same subnet, separate link);
    * machine ``m``  → clone ``m+suffix`` (``hidden=True``, ``allow_connection=False``,
      never ``bridged``) on the cloned networks with the SAME interface numbers.

    *extra_specs* (``{machine: {spec: value}}``) overrides the specs of the given
    clones, e.g. ``{'m1': {'x11_host': False}}`` for a clone that must not get
    the X11 setup of its visible twin.
    """
    norm = _normalize_topology(topology)
    m_nets = machines_by_net(topology)

    full_topology = {net: dict(m2i) for net, m2i in norm.items()}
    for net, m2i in norm.items():
        full_topology[f"{net}{suffix}"] = {f"{m}{suffix}": i for m, i in m2i.items()}

    full_specs = dict(machine_specs)
    for m in m_nets:
        clone = f"{m}{suffix}"
        if clone in full_specs:
            continue
        spec = dict(machine_specs.get(m, {}))
        spec.pop('bridged', None)
        spec.pop('color', None)
        spec['hidden'] = True
        spec['allow_connection'] = False
        if extra_specs and m in extra_specs:
            spec.update(extra_specs[m])
        full_specs[clone] = spec

    return full_topology, full_specs


def copy_addressing(data, topology, suffix="_h"):
    """Copy the subnets and IP addresses of *topology* onto the hidden clone.

    Must be called from ``Data.generate()`` AFTER the visible IPs are assigned
    (e.g. by ``random_ips_from_topology(data, topology)``). It writes the clone
    entries into ``data.nets`` / ``data.ips`` (so they are serialised and survive
    a reload). Naming follows ``random_ips_from_topology``:
    ``data.ips.m`` when *m* has one network, ``data.ips.m_net`` otherwise.
    """
    m_nets = machines_by_net(topology)
    for net_name in topology:
        setattr(data.nets, f"{net_name}{suffix}", getattr(data.nets, net_name))
    for m, nets in m_nets.items():
        if len(nets) == 1:
            setattr(data.ips, f"{m}{suffix}", getattr(data.ips, m))
        else:
            for net_name in nets:
                setattr(data.ips, f"{m}{suffix}_{net_name}{suffix}",
                        getattr(data.ips, f"{m}_{net_name}"))
