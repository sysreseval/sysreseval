"""What a project of each lab costs a host, in memory and in processors: the figure the placement
sets aside for one more project of that lab (``Pool.pick`` with ``[pool] capacity =
"resources"``), and the load of a host counted in the same units.

The cost of a lab comes, in this order, from:

* what its projects really used (**measured**): the agents measure their running projects
  (``agent/usage.py``) and the book keeps, per lab, what its last ``MAX_SAMPLES`` projects used;
  from ``MIN_SAMPLES`` projects on, the cost is the ``QUANTILE`` of them (most projects of the
  lab need no more);
* the weight the lab declares (**declared**): ``sre make-titles`` stores it and the lab list
  carries it; one unit of weight stands for ``CostBook.unit`` (``[pool] weight_memory_mb`` /
  ``weight_cpu``).  With one or two projects measured, the larger of this and of what they used;
* a **default**, for a lab without weight that was never seen.

Pure: no aiohttp, no clock of its own (the callers give the time), like the plans of
``manager.py``."""
import math
from dataclasses import dataclass, field
from typing import NamedTuple


class Cost(NamedTuple):
    """What one project sets aside on a host."""
    mem_mb: float       # memory, MiB
    cpu: float          # processors, cores used on average


class Usage(NamedTuple):
    """One entry of the ``usage`` of a host status (``agent/usage.py``), coerced by the pool."""
    name: str                   # the running lab name of the project
    lab: str                    # its lab, in the form of the lab list (``lab_key``)
    containers: int | None      # None: not measured
    mem_mb: float | None
    cpu: float | None           # the mean since the project settled (None: not yet)
    settled: bool


class Sample(NamedTuple):
    """What one project of a lab used, as last measured."""
    mem_mb: float       # the most it was seen using
    cpu: float          # its mean since it settled
    containers: int
    at: float           # wall-clock time of the measure


SOURCE_MEASURED = 'measured'
SOURCE_DECLARED = 'declared'
SOURCE_DEFAULT = 'default'

MIN_SAMPLES = 3         # the projects of a lab measured before their figures alone make its cost
MAX_SAMPLES = 40        # the projects kept per lab: the last ones measured
QUANTILE = 0.8          # the cost of a measured lab: this share of its projects need no more
MAX_LABS = 1000         # the labs kept: the ones seen last (a debug project started by path is a lab of its own)
DEFAULT_MEMORY_MB = 512.0   # a lab without weight, never measured (``[pool] project_memory_mb`` when it is set)
DEFAULT_CPU = 0.2
#: The least a project costs: a cost of nothing would let a host take any number of them.
MIN_COST = Cost(16.0, 0.01)
#: The most a figure may say (a weight, a memory in MiB, a number of cores): beyond, it is no figure.
MAX_FIGURE = 1e7

#: The costs file (beside the state file of the pool): a cache, nothing set by hand.
COSTS_VERSION = 1
KEY_VERSION = 'version'
KEY_SAVED_AT = 'saved_at'
KEY_LABS = 'labs'
LAB_WEIGHT = 'weight'
LAB_SEEN = 'seen'
LAB_SAMPLES = 'samples'
SAMPLE_PROJECT = 'project'
SAMPLE_MEM = 'mem_mb'
SAMPLE_CPU = 'cpu'
SAMPLE_CONTAINERS = 'containers'
SAMPLE_AT = 'at'
MAX_NAME = 300          # the longest lab or project name kept


def lab_key(name: str) -> str:
    """A lab name in the form of the lab list (``sre/dhcp.py``), from that form or from the one
    of a project (``sre@dhcp.py``): the key of a lab in the book."""
    return name.replace('@', '/')


def figure(value) -> float | None:
    """A finite number from 0 to ``MAX_FIGURE`` that is not a bool, else ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0 or value > MAX_FIGURE:
        return None
    return float(value)


def quantile(values, q: float) -> float:
    """The *q* quantile of *values* (not empty), interpolated between the two nearest ones."""
    ordered = sorted(values)
    position = q * (len(ordered) - 1)
    low = math.floor(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def at_least(cost: Cost, floor: Cost = MIN_COST) -> Cost:
    return Cost(max(cost.mem_mb, floor.mem_mb), max(cost.cpu, floor.cpu))


@dataclass
class LabRecord:
    """What the book knows of one lab."""
    weight: float | None = None                     # the weight it declares (None: none known)
    samples: dict = field(default_factory=dict)     # project name -> Sample, the one measured last at the end
    seen: float = 0.0                               # wall-clock time it was last declared or measured


class CostBook:
    """The costs of the labs of a pool.  *default*: the cost of a lab without weight and never
    measured; *unit*: what one unit of weight stands for."""

    def __init__(self, *, default: Cost = Cost(DEFAULT_MEMORY_MB, DEFAULT_CPU), unit: Cost = Cost(5.0, 0.001)):
        self.default = at_least(default)
        self.unit = unit
        self.labs: dict[str, LabRecord] = {}
        #: Something changed since the last ``to_json()``: the pool saves the file again.
        self.dirty = False
        self._resolved: dict[str, tuple] = {}       # lab -> (Cost, source), until the lab changes

    # -- what feeds the book --------------------------------------------------------------------

    def _record(self, lab: str, at: float) -> LabRecord:
        record = self.labs.get(lab)
        if record is None:
            if len(self.labs) >= MAX_LABS:
                oldest = min(self.labs, key=lambda name: self.labs[name].seen)
                del self.labs[oldest]
                self._resolved.pop(oldest, None)
            record = self.labs[lab] = LabRecord()
        record.seen = max(record.seen, at)
        return record

    def declare(self, entries, at: float = 0.0):
        """The weights of a lab list (the ``lab`` entries of ``Pool.labs`` that have a
        ``weight``).  A list without weights (an older host, a lab tree whose ``titles.json``
        was not made again) erases nothing."""
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or not entry['name']:
                continue
            weight = figure(entry.get(LAB_WEIGHT))
            if weight is None or len(entry['name']) > MAX_NAME:
                continue
            lab = lab_key(entry['name'])
            record = self._record(lab, at)
            if record.weight != weight:
                record.weight = weight
                self.dirty = True
                self._resolved.pop(lab, None)

    def observe(self, usage, at: float):
        """The ``usage`` of one host status (``Usage`` entries): every settled project with its
        figures is the newest sample of its lab — its memory the most it was seen using, its
        processors the mean it tells."""
        for row in usage:
            if not row.settled or row.mem_mb is None or row.cpu is None:
                continue
            record = self._record(row.lab, at)
            known = record.samples.pop(row.name, None)
            sample = Sample(mem_mb=max(row.mem_mb, known.mem_mb) if known else row.mem_mb, cpu=row.cpu,
                            containers=row.containers or 0, at=at)
            record.samples[row.name] = sample           # the one measured last at the end
            while len(record.samples) > MAX_SAMPLES:
                del record.samples[next(iter(record.samples))]
            if known is None or known[:3] != sample[:3]:
                self.dirty = True
                self._resolved.pop(row.lab, None)

    # -- what the book answers ------------------------------------------------------------------

    def resolve(self, lab: str | None) -> tuple:
        """``(Cost, source)`` of one more project of *lab* (``None``, or a lab the book never
        heard of: the default)."""
        if not lab:
            return self.default, SOURCE_DEFAULT
        lab = lab_key(lab)
        found = self._resolved.get(lab)
        if found is None:
            found = self._resolved[lab] = self._resolve(self.labs.get(lab))
        return found

    def _resolve(self, record: LabRecord | None) -> tuple:
        if record is None:
            return self.default, SOURCE_DEFAULT
        samples = list(record.samples.values())
        if len(samples) >= MIN_SAMPLES:
            return at_least(Cost(quantile([s.mem_mb for s in samples], QUANTILE),
                                 quantile([s.cpu for s in samples], QUANTILE))), SOURCE_MEASURED
        if record.weight is not None:
            cost, source = Cost(record.weight * self.unit.mem_mb, record.weight * self.unit.cpu), SOURCE_DECLARED
        else:
            cost, source = self.default, SOURCE_DEFAULT
        if samples:     # too few to trust alone: never below what they used
            cost = Cost(max(cost.mem_mb, max(s.mem_mb for s in samples)), max(cost.cpu, max(s.cpu for s in samples)))
        return at_least(cost), source

    def cost(self, lab: str | None) -> Cost:
        return self.resolve(lab)[0]

    def measured_unit(self) -> Cost | None:
        """What one unit of weight really stood for on this pool: over the labs that declare a
        weight and were measured, the sum of what a project of each used on average, by the sum
        of their weights.  A hint to set ``[pool] weight_memory_mb`` / ``weight_cpu`` with:
        nothing here feeds it back."""
        memory = processors = weights = 0.0
        for record in self.labs.values():
            if not record.weight or not record.samples:
                continue
            samples = record.samples.values()
            memory += sum(s.mem_mb for s in samples) / len(samples)
            processors += sum(s.cpu for s in samples) / len(samples)
            weights += record.weight
        return Cost(memory / weights, processors / weights) if weights else None

    def rows(self, titles: dict | None = None) -> list:
        """One row per lab of the book, by name: its declared weight, the containers its projects
        had (the most seen), its cost and where that comes from, the projects measured."""
        titles = titles or {}
        rows = []
        for lab in sorted(self.labs):
            record = self.labs[lab]
            cost, source = self.resolve(lab)
            rows.append({'lab': lab, 'title': titles.get(lab), 'weight': record.weight,
                         'containers': max((s.containers for s in record.samples.values()), default=None),
                         'mem_mb': round(cost.mem_mb, 1), 'cpu': round(cost.cpu, 3),
                         'samples': len(record.samples), 'source': source})
        return rows

    # -- the file -------------------------------------------------------------------------------

    def to_json(self, saved_at: float) -> dict:
        """The content of the costs file; the book is clean afterwards."""
        self.dirty = False
        return {KEY_VERSION: COSTS_VERSION, KEY_SAVED_AT: round(saved_at), KEY_LABS: {
            lab: {LAB_WEIGHT: record.weight, LAB_SEEN: round(record.seen), LAB_SAMPLES: [
                {SAMPLE_PROJECT: name, SAMPLE_MEM: round(s.mem_mb, 1), SAMPLE_CPU: round(s.cpu, 4),
                 SAMPLE_CONTAINERS: s.containers, SAMPLE_AT: round(s.at)} for name, s in record.samples.items()]}
            for lab, record in self.labs.items()}}

    def load(self, data) -> bool:
        """Fill the book from the content of a costs file, whatever is not what ``to_json()``
        writes being left out (a file edited by hand, another version); false when *data* is no
        costs file at all (nothing is taken)."""
        if not isinstance(data, dict) or data.get(KEY_VERSION) != COSTS_VERSION or not isinstance(data.get(KEY_LABS), dict):
            return False
        for lab, entry in data[KEY_LABS].items():
            if not isinstance(lab, str) or not lab or len(lab) > MAX_NAME or not isinstance(entry, dict) \
                    or len(self.labs) >= MAX_LABS:
                continue
            record = LabRecord(weight=figure(entry.get(LAB_WEIGHT)), seen=figure(entry.get(LAB_SEEN)) or 0.0)
            samples = entry.get(LAB_SAMPLES)
            for item in (samples if isinstance(samples, list) else [])[-MAX_SAMPLES:]:
                if not isinstance(item, dict):
                    continue
                name, memory, processors = item.get(SAMPLE_PROJECT), figure(item.get(SAMPLE_MEM)), figure(item.get(SAMPLE_CPU))
                if not isinstance(name, str) or not name or len(name) > MAX_NAME or memory is None or processors is None:
                    continue
                record.samples[name] = Sample(memory, processors, int(figure(item.get(SAMPLE_CONTAINERS)) or 0),
                                              figure(item.get(SAMPLE_AT)) or 0.0)
            if record.weight is not None or record.samples:
                self.labs[lab_key(lab)] = record
        self._resolved.clear()
        self.dirty = False
        return True


class HostLoad(NamedTuple):
    """The load of a host in the units of the costs."""
    mem_free_mb: float      # what new projects may take: MemAvailable less the reserve and the starts in flight
    mem_capacity_mb: float  # its memory less the reserve
    cpu_used: float         # the cores its projects and the starts in flight are counted for
    cpu_capacity: float     # its processors by the share projects may use (``cpu_target``)

    def fits(self, cost: Cost) -> bool:
        """Whether one more project of that cost holds."""
        return self.mem_free_mb >= cost.mem_mb and self.cpu_used + cost.cpu <= self.cpu_capacity

    @property
    def fill(self) -> float:
        """How full the host is: the larger of its memory in use and of its processors counted,
        each as a share of its capacity (above 1 when it is over it)."""
        memory = 1.0 - min(self.mem_free_mb, self.mem_capacity_mb) / self.mem_capacity_mb
        return max(memory, self.cpu_used / self.cpu_capacity)

    def rooms(self, reference: Cost) -> tuple:
        """``(by its memory, by its processors)``: how many more projects of the cost
        *reference* the host holds."""
        return (int(self.mem_free_mb // reference.mem_mb),
                max(0, int((self.cpu_capacity - self.cpu_used) // reference.cpu)))


def host_load(*, cpus, mem_total_mb, mem_available_mb, cpu_busy, committed_cpu: float, in_flight,
              reserve_mb: float, cpu_target: float) -> HostLoad | None:
    """The load of a host from its status: *cpus*, *mem_total_mb*, *mem_available_mb* and
    *cpu_busy* as its agent tells them, *committed_cpu* the sum of the costs of the labs of its
    projects, *in_flight* the costs of the projects being started there (their containers may
    not show in the readings yet).  The memory is the one the host really has left (it sees
    everything running there); the processors are what its projects are counted for, or what the
    host really burns when that is more (the Docker daemon, a runaway container).  ``None`` when
    the agent does not tell the size of its host (older than these figures, unreachable): the
    host is judged by its number of projects."""
    if not cpus or not mem_total_mb or mem_available_mb is None:
        return None
    capacity = max(1.0, mem_total_mb - reserve_mb)
    free = max(0.0, mem_available_mb - reserve_mb - sum(c.mem_mb for c in in_flight))
    used = max(committed_cpu, cpu_busy or 0.0) + sum(c.cpu for c in in_flight)
    return HostLoad(mem_free_mb=free, mem_capacity_mb=capacity, cpu_used=used,
                    cpu_capacity=max(MIN_COST.cpu, cpus * cpu_target))
