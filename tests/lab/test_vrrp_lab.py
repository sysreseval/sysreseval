"""Offline tests of the VRRP lab (lab/sre/_DRAFT_misc/vrrp.py): the data (fixed host parts, VRIDs,
MAC addresses, dual stack), the topology (two systemd routers, the hidden mirror, a managed LAN
switch), the state ops (the single point of failure of `initial`, the reference solution of
`final`), the multi-pass grading contract with a small model of the routers (nothing done: 0 in one
step; the solution of the parts 1..N: exactly their points; the full solution minus one feature:
exactly its elements lost; one router only: no failover credit), the archive gate, the re-evaluation
contract, the texts in both languages, the numbered course, the stripped file and the English
identifiers.

No Docker: the outputs of the containers are rendered from the generated data in the format of the
real tools (ip -j, tcpdump -e -n -v, curl of the echo server, the ARP / IPv6 / VRRP probes).  The
totals asserted here are the ones measured live on 2026-11-11 (z04, keepalived 2.2.7).
"""
import ast
import base64
import datetime
import importlib.util
import io
import json
import re
import sys
import tarfile
from pathlib import Path

import pytest

from SRE import params
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import vrrp as vr  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'vrrp.py'
PEER = {'r1': 'r2', 'r2': 'r1'}
#: points of the non-form elements of each part, and of the forms (filled by the cheat answers)
PART_POINTS = {1: 18, 2: 12, 3: 12, 4: 10, 5: 11, 6: 8, 7: 14}
FORM_POINTS = 15
QUESTIONS = 16


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('vrrp_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _running_name():
    return params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')


def _text(t, lang='fr'):
    return t.resolve(lang) if hasattr(t, 'resolve') else str(t)


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault((step, machine), []).extend(op_list)
    return ops


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str)}


def _tar_b64(files: dict) -> str:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name, (content, mode) in files.items():
            info = tarfile.TarInfo(name)
            raw = content.encode()
            info.size, info.mode = len(raw), mode
            archive.addfile(info, io.BytesIO(raw))
    return base64.b64encode(buffer.getvalue()).decode()


# ---------------------------------------------------------------------------
# a model of the routers: what the machines answer
# ---------------------------------------------------------------------------


class Mockup:
    """The lab with the reference solution of the parts 1..*part* (0: as `initial` left it), minus
    the features named in *without* (group, check, auth, track, vmac, v6), configured on *routers*.

    ``mockup(machine, step, command)`` gives ``(output, code)`` for a command of the evaluation;
    the virtual addresses move between the steps of the mirror scenario as they did live."""

    def __init__(self, lab, ns, part=7, without=(), routers=('r1', 'r2')):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.part, self.without, self.routers = part, set(without), tuple(routers)
        grouped = part >= 2 and 'group' not in self.without
        self.f = {
            'lan': part >= 1, 'wan': part >= 2, 'group': grouped,
            # the check and the notification are declared on the group
            'check': part >= 3 and grouped and 'check' not in self.without,
            'notify': part >= 3 and grouped,
            'auth': part >= 4 and 'auth' not in self.without, 'unicast': part >= 4,
            'lan2': part >= 5, 'track': part >= 5 and 'track' not in self.without,
            'vmac': part >= 6 and 'vmac' not in self.without,
            'v6': part >= 7 and 'v6' not in self.without, 'wan6': part >= 7,
        }
        self.commands = []          # (machine, step, command) seen

    # -- the files of a router ----------------------------------------------------------

    def keepalived_conf(self, router):
        lab, conf = self.lab, self.ns.keepalived_conf(router, self.part)
        if 'group' in self.without:
            conf = re.sub(r'\nvrrp_sync_group ' + lab.GROUP + r' \{\n(?:    .*\n)*?\}\n', '\n', conf)
        if 'check' in self.without:
            conf = conf.replace(f"    track_script {{\n        {lab.CHECK_NAME}\n    }}\n", "")
        if 'auth' in self.without:
            conf = re.sub(r'    authentication \{\n(?:        .*\n)*?    \}\n', '', conf)
        if 'track' in self.without:
            conf = conf.replace("    track_interface {\n        eth1\n    }\n", "")
        if 'vmac' in self.without:
            conf = conf.replace("    use_vmac\n", "")
        if 'v6' in self.without:
            conf = re.sub(r'\nvrrp_instance ' + lab.VI_LAN6 + r' \{\n(?:    .*\n)*?\}\n', '\n', conf)
            conf = conf.replace(f"        {lab.VI_LAN6}\n", "")
        return conf

    def files(self, router):
        lab = self.lab
        if self.part == 0 or router not in self.routers:
            return {}
        files = {lab.KEEPALIVED_CONF.lstrip('/'): (self.keepalived_conf(router), 0o644)}
        if self.part >= 3:
            files[lab.CHECK_SCRIPT.lstrip('/')] = (self.ns.check_script(), 0o755)
            files[lab.NOTIFY_SCRIPT.lstrip('/')] = (self.ns.notify_script(), 0o755)
        if self.f['v6']:
            files[lab.RADVD_CONF.lstrip('/')] = (self.ns.radvd_conf(), 0o644)
        return files

    def archive(self, router):
        files = self.files(router)
        return _tar_b64(files) if files else ''

    # -- who holds what ---------------------------------------------------------------------

    def holders(self, step):
        """``{key: router | None}`` once *step* has settled (1: the real network, nominal)."""
        f = self.f
        lan_down = 'r1' if step == 3 else None
        wan_down = 'r2' if step == 5 else None
        check_failed = 'r1' if step == 6 and f['check'] else None

        def pick(preferred, usable):
            return next((r for r in (preferred, PEER[preferred]) if r in self.routers and usable(r)), None)

        def edge(r):          # r can be the master of the grouped instances
            return r not in (lan_down, wan_down, check_failed)

        result = {}
        if f['lan']:
            result['vip'] = pick('r1', edge if f['group'] else (lambda r: r != lan_down))
        if f['wan']:
            result['wan'] = pick('r1', edge if f['group'] else (lambda r: r != wan_down))
            if f['wan6']:
                result['wan6'] = result['wan']
        if f['v6']:
            result['lan6'] = pick('r1', edge if f['group'] else (lambda r: r != lan_down))
        if f['lan2']:
            result['vip2'] = pick('r2', lambda r: r != lan_down and (r != wan_down or not f['track']))
        if step == 7 and not f['auth'] and 'vip' in result:
            result['vip'] = None          # the forged advertisements won
        return result

    def address(self, key):
        d = self.d
        return {'vip': d.ips.vip_lan, 'wan': d.ips.vip_wan, 'vip2': d.ips.vip_lan2, 'wan6': d.ips6.vip_wan,
                'lan6': self.lab.VIP6_LAN + '/64'}[key]

    def mac(self, router, side='lan', clone=False):
        if clone:       # the clones have random MAC addresses: any stable value will do
            return f"02:aa:00:00:0{router[-1]}:{'01' if side == 'lan' else '02'}"
        return vr_mac(getattr(self.d.macs, f"{router}_{side}"))

    def vip2_mac(self, holder, clone):
        return vr.virtual_mac(self.d.vrid_lan2) if self.f['vmac'] else self.mac(holder, clone=clone)

    # -- outputs of a router ----------------------------------------------------------------

    def addr4(self, router, held):
        d, lab = self.d, self.lab
        interfaces = {'eth0': [getattr(d.ips, router + '_lan')], 'eth1': [getattr(d.ips, router + '_wan')]}
        vmac_iface = f"{lab.VMAC_PREFIX}{d.vrid_lan2}"
        if self.f['vmac'] and router in self.routers:
            interfaces[vmac_iface] = []
        if held.get('vip') == router:
            interfaces['eth0'].append(d.ips.vip_lan)
        if held.get('wan') == router:
            interfaces['eth1'].append(d.ips.vip_wan)
        if held.get('vip2') == router:
            interfaces[vmac_iface if self.f['vmac'] else 'eth0'].append(d.ips.vip_lan2)
        return json.dumps([{'ifname': name, 'addr_info': [{'family': 'inet', 'local': str(a.ip),
                                                           'prefixlen': a.network.prefixlen} for a in addresses]}
                           for name, addresses in interfaces.items()])

    def addr6(self, router, held):
        d = self.d
        eth0 = [(str(getattr(d.ips6, router + '_lan').ip), 'global'), (f"fe80::{router[-1]}:1", 'link')]
        eth1 = [(str(getattr(d.ips6, router + '_wan').ip), 'global'), (f"fe80::{router[-1]}:2", 'link')]
        if held.get('lan6') == router:
            eth0.append((self.lab.VIP6_LAN, 'link'))
        if held.get('wan6') == router:
            eth1.append((str(d.ips6.vip_wan.ip), 'global'))
        return json.dumps([{'ifname': name, 'addr_info': [{'family': 'inet6', 'local': a, 'prefixlen': 64,
                                                           'scope': scope} for a, scope in addresses]}
                           for name, addresses in (('eth0', eth0), ('eth1', eth1))])

    def links(self, router):
        links = [{'ifname': 'eth0', 'flags': ['UP'], 'address': self.mac(router)},
                 {'ifname': 'eth1', 'flags': ['UP'], 'address': self.mac(router, 'wan')}]
        if self.f['vmac'] and router in self.routers:
            links.append({'ifname': f"{self.lab.VMAC_PREFIX}{self.d.vrid_lan2}", 'link': 'eth0', 'flags': ['UP'],
                          'address': vr.virtual_mac(self.d.vrid_lan2), 'linkinfo': {'info_kind': 'macvlan'}})
        return json.dumps(links)

    def notify_log(self, router):
        """The lines the notify script of the group wrote on the clone of *router* up to step 6."""
        if not self.f['notify'] or router not in self.routers:
            return ''
        states, lines = ['BACKUP'], []
        for step in range(2, 7):
            failed = (step == 3 and router == 'r1') or (step == 5 and router == 'r2') \
                or (step == 6 and router == 'r1' and self.f['check'])
            state = 'MASTER' if self.holders(step).get('vip') == router else 'FAULT' if failed else 'BACKUP'
            if state != states[-1]:
                states.append(state)
        for state in states:
            lines.append(f"2026-11-11 20:00:00 GROUP {self.lab.GROUP} {state} 0")
        return "\n".join(lines) + "\n"

    # -- captures ---------------------------------------------------------------------------

    def lan_capture(self):
        d, f, lab, held = self.d, self.f, self.lab, self.holders(1)
        lines = []
        for second in range(4):
            stamp = f"20:00:0{second}.000100"
            if held.get('vip'):
                r = held['vip']
                auth = f'authtype simple, intvl 1s, length 20, addrs: {d.ips.vip_lan.ip} auth "{d.auth_pass}"' \
                    if f['auth'] else f"authtype none, intvl 1s, length 20, addrs: {d.ips.vip_lan.ip}"
                lines.append(f"{stamp} {self.mac(r)} > 01:00:5e:00:00:12, ethertype IPv4 (0x0800), length 60: "
                             "(tos 0xc0, ttl 255, id 1, offset 0, flags [none], proto VRRP (112), length 40)\n"
                             f"    {getattr(d.ips, r + '_lan').ip} > 224.0.0.18: VRRPv2, Advertisement, "
                             f"vrid {d.vrid_lan}, prio {lab.PRIORITY_MASTER}, {auth}")
            if held.get('vip2'):
                r = held['vip2']
                lines.append(f"{stamp} {self.vip2_mac(r, False)} > 01:00:5e:00:00:12, ethertype IPv4 (0x0800), "
                             "length 60: (tos 0xc0, ttl 255, id 1, offset 0, flags [none], proto VRRP (112), "
                             f"length 40)\n    {getattr(d.ips, r + '_lan').ip} > 224.0.0.18: VRRPv2, "
                             f"Advertisement, vrid {d.vrid_lan2}, prio {lab.PRIORITY_MASTER}, authtype none, "
                             f"intvl 1s, length 20, addrs: {d.ips.vip_lan2.ip}")
            if held.get('lan6'):
                r = held['lan6']
                lines.append(f"{stamp} {self.mac(r)} > 33:33:00:00:00:12, ethertype IPv6 (0x86dd), length 78: "
                             "(class 0xc0, flowlabel 0x3bca5, hlim 255, next-header VRRP (112) payload length: 24) "
                             f"fe80::{r[-1]}:1 > ff02::12: VRRPv3, Advertisement, vrid {d.vrid_lan6}, "
                             f"prio {lab.PRIORITY_MASTER}, intvl 100cs, length 24, addrs: {lab.VIP6_LAN}")
        return "\n".join(lines) + "\n"

    def wan_capture(self):
        d, lab, held = self.d, self.lab, self.holders(1)
        if not held.get('wan'):
            return ''
        r = held['wan']
        source = getattr(d.ips, r + '_wan').ip
        target = getattr(d.ips, PEER[r] + '_wan').ip if self.f['unicast'] else '224.0.0.18'
        target_mac = self.mac(PEER[r], 'wan') if self.f['unicast'] else '01:00:5e:00:00:12'
        return "".join(
            f"20:00:0{second}.000200 {self.mac(r, 'wan')} > {target_mac}, ethertype IPv4 (0x0800), length 60: "
            "(tos 0xc0, ttl 255, id 1, offset 0, flags [none], proto VRRP (112), length 40)\n"
            f"    {source} > {target}: VRRPv2, Advertisement, vrid {d.vrid_wan}, prio {lab.PRIORITY_MASTER}, "
            f"authtype none, intvl 1s, length 20, addrs: {d.ips.vip_wan.ip}\n" for second in range(4))

    # -- what a client sees -------------------------------------------------------------------

    def gateway_key(self, client, clone):
        """Key of the virtual address *client* uses as its gateway (None: the address of r1)."""
        if clone:
            return 'vip' if client == 'pc1' else 'vip2'
        if self.part == 0:
            return None
        return 'vip2' if client == 'pc2' and self.part >= 5 else 'vip'

    def reaches_isp(self, client, step, clone, family=4):
        """A request of *client* gets to isp and its answer comes back."""
        held = self.holders(step)
        lan_down = 'r1' if step == 3 else None
        wan_down = 'r2' if step == 5 else None
        if family == 6:
            forward = held.get('lan6')
            back = held.get('wan6') if (clone or self.part >= 7) else None
        else:
            key = self.gateway_key(client, clone)
            forward = held.get(key) if key else 'r1'
            back = held.get('wan') if (clone or self.part >= 2) else 'r1'
        return bool(forward and back) and forward != wan_down and back != lan_down

    def echo(self, client, target, step, clone):
        d = self.d
        held = self.holders(step)
        if target == str(d.ips.isp.ip):
            if not self.reaches_isp(client, step, clone):
                return '', 28
            return (f"SERVER=isp\nSERVER_IP={target}\nSERVER_PORT=80\nCLIENT_IP={getattr(d.ips, client).ip}\n"
                    "CLIENT_PORT=40000\nTTL=63\n"), 0
        holder = next((held.get(key) for key in ('vip', 'vip2') if target == str(self.address(key).ip)), None)
        if not holder:
            return '', 28
        return (f"SERVER={holder}\nSERVER_IP={target}\nSERVER_PORT=80\nCLIENT_IP={getattr(d.ips, client).ip}\n"
                "CLIENT_PORT=40000\nTTL=64\n"), 0

    def routes(self, machine):
        d = self.d
        if machine == 'isp':
            via = d.ips.vip_wan.ip if self.part >= 2 else d.ips.r1_wan.ip
            return (f"{d.nets.lan} via {via} dev eth0 \n"
                    f"{d.nets.wan} dev eth0 proto kernel scope link src {d.ips.isp.ip} \n")
        key = self.gateway_key(machine, clone=False)
        gateway = self.address(key).ip if key else d.ips.r1_lan.ip
        return (f"default via {gateway} dev eth0 \n"
                f"{d.nets.lan} dev eth0 proto kernel scope link src {getattr(d.ips, machine).ip} \n")

    def routes6(self, machine):
        d = self.d
        routes = [{'dst': str(d.nets6.wan if machine == 'isp' else d.nets6.lan), 'dev': 'eth0', 'protocol': 'kernel'}]
        if machine == 'isp' and self.f['v6']:
            routes.append({'dst': str(d.nets6.lan), 'gateway': str(d.ips6.vip_wan.ip), 'dev': 'eth0', 'metric': 1024})
        if machine == 'pc1' and self.holders(1).get('lan6'):
            routes.append({'dst': 'default', 'gateway': self.lab.VIP6_LAN, 'dev': 'eth0', 'protocol': 'ra'})
        return json.dumps(routes)

    def ping6(self, client, step, clone):
        if self.reaches_isp(client, step, clone, family=6):
            return f"64 bytes from {self.d.ips6.isp.ip}: icmp_seq=1 ttl=63 time=0.5 ms\n", 0
        return "ping: connect: Network is unreachable\n", 2

    def arp_reply(self, step):
        holder = self.holders(step).get('vip2')
        replies = [{'operation': 'reply', 'sender_ip': str(self.d.ips.vip_lan2.ip),
                    'sender_mac': self.vip2_mac(holder, True)}] if holder else []
        return json.dumps({'errors': [], 'result': {'replies': replies, 'target_ip': str(self.d.ips.vip_lan2.ip)}})

    def neigh(self, client):
        holder = self.holders(1).get('vip2')
        entries = [{'dst': str(self.d.ips.r1_lan.ip), 'dev': 'eth0', 'lladdr': self.mac('r1'), 'state': ['STALE']}]
        if holder and client == 'pc2' and self.part >= 5:
            entries.append({'dst': str(self.d.ips.vip_lan2.ip), 'dev': 'eth0',
                            'lladdr': self.vip2_mac(holder, False), 'state': ['REACHABLE']})
        return json.dumps(entries)

    # -- dispatch -----------------------------------------------------------------------------

    def __call__(self, machine, step, command):
        self.commands.append((machine, step, command))
        lab, d = self.lab, self.d
        clone = machine.endswith(lab.MIRROR)
        name = machine.removesuffix(lab.MIRROR)
        configured = name in self.routers and self.part >= 1
        held = self.holders(step)
        if machine in lab.LAN_SWITCHES:
            return '', 0
        if name in lab.ROUTERS:
            if command.startswith("systemctl is-active"):
                unit = command.split()[2]
                active = configured and (unit == lab.KEEPALIVED_UNIT or self.f['v6'])
                return ("active\nenabled\n" if active else "inactive\ndisabled\n"), 0
            if command == vr.config_archive_cmd():
                return self.archive(name), 0
            if command == lab.CONFIG_TEST_CMD:
                return ("rc=0\n" if configured else "rc=1\n"), 0
            if command.endswith("ip -j -4 addr show") or command == "ip -j -4 addr show 2>/dev/null":
                return self.addr4(name, held if configured else {}), 0
            if command == "ip -j -6 addr show":
                return self.addr6(name, held if configured else {}), 0
            if "link show" in command:
                return self.links(name), 0
            if command.startswith("cat " + lab.NOTIFY_LOG):
                return self.notify_log(name), 0
            return '', 0          # journal, resets, replay, injected failures, waits
        if "tcpdump" in command:
            return (self.lan_capture() if name == 'pc1' else self.wan_capture()), 124
        if command == "ip route":
            return self.routes(name), 0
        if command == "ip -j -6 route show":
            return self.routes6(name), 0
        if command.startswith("curl "):
            target = re.search(r'http://([0-9.]+):', command)[1]
            return self.echo(name, target, step, clone)
        if command.startswith("ping "):
            return self.ping6(name, step, clone)
        if command == "ip -j neigh show":
            return self.neigh(name), 0
        if "arp_probe" in command:
            return self.arp_reply(step), 0
        if "ipv6_probe" in command:
            ra = [{'src': lab.VIP6_LAN, 'router_lifetime': 30, 'hop_limit': 64, 'prefixes': []}] \
                if held.get('lan6') else []
            return json.dumps({'dhcp6': {}, 'errors': [], 'ra': ra}), 0
        if "vrrp_probe" in command:
            return json.dumps({'sent': 8, 'error': None, 'heard': []}), 0
        return '', 0              # resets, waits, the nft rules on isp_h


def vr_mac(mac) -> str:
    return str(mac).replace('-', ':').lower()


def _simulate(lab, data, tmp_pub_dir, part=7, without=(), routers=('r1', 'r2'), instructor_mode=False,
              answers=True, mockup=None):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme, mockup).  The tests grow
    once, after step 1 (the mirror scenario waits for the archives), and are stable afterwards."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    mock = mockup(lab, ns) if mockup else Mockup(lab, ns, part, without, routers)
    previous, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if previous is None:
            if answers:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            for key, cmds in previous.items():
                assert cmds <= current.get(key, set()), "a registered test vanished between two passes"
            if step > 2:
                assert current == previous, "the registered tests changed after the archives were read"
        previous = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = mock(m, s, key[0])
        step += 1
    return grade, ns, mock


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


def _lost(grade):
    """{title: points missing} of the elements that are not forms and do not have their maximum."""
    return {t: e.max_grade - e.grade for t, e in _by_title(grade).items()
            if e.grade != e.max_grade and not t.endswith('_form')}


def _regrade(grade):
    grade.reset_before_grade()
    grade.grade()
    return _by_title(grade)


def _set_answer(grade, field, value):
    for q in grade.get_questions_ordered():
        if any(f['name'] == field for f in (getattr(q, 'fields', None) or [])):
            form = json.loads(grade._answers[q.question_hash])
            form[field] = value
            grade._answers[q.question_hash] = json.dumps(form)
            return
    raise KeyError(field)


def _all_texts(grade, ns, lang='fr'):
    yield 'informations', _text(ns.informations, lang)
    for q in grade.get_questions_ordered():
        yield f"title:{_text(q.title)}", _text(q.title, lang)
        yield f"description:{_text(q.title)}", _text(q.description, lang)


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, data):
        back = lab.Data.from_json(data.to_json())
        assert back.to_dict() == data.to_dict()

    def test_addresses(self, lab, data):
        ips, ips6 = vars(data.ips), vars(data.ips6)
        assert set(ips) == set(lab.ADDRESSED) and set(ips6) == set(lab.ADDRESSED) - set(lab.IPV4_ONLY)
        for key, net in lab.ADDRESSED.items():
            address = ips[key]
            assert address.network == getattr(data.nets, net)
            assert int(address.ip) - int(address.network.network_address) == lab.HOST_PARTS[key]
        assert str(data.ips6.pc1.ip).endswith('::11') and str(data.ips6.vip_wan.ip).endswith('::254')
        assert data.nets.wan in lab.WAN_NETWORKS and data.nets.lan.is_private and data.nets.lan.prefixlen == 24
        assert not data.nets.lan.overlaps(lab.IPv4Network("172.17.0.0/16"))
        assert data.nets6.lan.prefixlen == 64 and data.nets6.lan != data.nets6.wan

    def test_instance_values(self, lab, data):
        vrids = [data.vrid_lan, data.vrid_wan, data.vrid_lan2, data.vrid_lan6]
        assert len(set(vrids)) == 4 and all(10 <= v < 250 for v in vrids)
        assert re.fullmatch(r'[A-Za-z0-9]{8}', data.auth_pass)
        macs = {key: vr_mac(mac) for key, mac in vars(data.macs).items()}
        assert set(macs) == set(lab.MAC_KEYS.values()) and len(set(macs.values())) == 4
        assert all(mac.startswith(lab.MAC_PREFIX) for mac in macs.values())


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        names = ns.get_machine_names()
        assert sorted(names) == sorted([m + s for m in ('pc1', 'pc2', 'r1', 'r2', 'isp') for s in ('', '_h')])
        specs = lab.NetScheme._machine_specs
        for r in lab.ROUTERS:
            for machine in (r, lab.H(r)):
                assert specs[machine]['privileged'] is True and specs[machine]['entrypoint'] == "/sbin/init"
                assert 'net.ipv4.conf.all.arp_announce=2' in specs[machine]['sysctls']
                assert 'net.ipv6.conf.all.keep_addr_on_down=1' in specs[machine]['sysctls']
        for machine in names:
            hidden = machine.endswith('_h')
            assert bool(specs[machine].get('hidden')) is hidden
            assert specs[machine].get('allow_connection', True) is not hidden
        assert [m.name for m in ns.get_visibles_machines()] == ['pc1', 'pc2', 'r1', 'r2', 'isp']

    def test_networks(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        topology = ns._topology
        assert set(topology) == {'lan', 'wan', 'lan_h', 'wan_h'}
        # the fixed MAC addresses go to the visible routers only
        assert topology['lan']['r1'] == (0, data.macs.r1_lan) and topology['wan']['r2'] == (1, data.macs.r2_wan)
        assert topology['lan_h'] == {'pc1_h': 0, 'pc2_h': 0, 'r1_h': 0, 'r2_h': 0}
        # a virtual MAC address needs a switch; the console is closed to the students
        for network in lab.LAN_SWITCHES:
            assert ns.get_network(network).is_managed() and lab.NetScheme._network_specs[network]['allow_connection'] is False
        assert not ns.get_network('wan').is_managed()

    def test_net_config(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        default = lab.IPv4Network("0.0.0.0/0")
        # at the start everything goes through r1; the clones already use the virtual addresses
        assert ns.net_config['pc1'][0][1] == [(default, data.ips.r1_lan.ip)]
        assert ns.net_config['pc2'][0][1] == [(default, data.ips.r1_lan.ip)]
        assert ns.net_config['isp'][0][1] == [(data.nets.lan, data.ips.r1_wan.ip)]
        assert ns.net_config['pc1_h'][0][1] == [(default, data.ips.vip_lan.ip)]
        assert ns.net_config['pc2_h'][0][1] == [(default, data.ips.vip_lan2.ip)]
        assert ns.net_config['isp_h'][0][1] == [(data.nets.lan, data.ips.vip_wan.ip),
                                                (data.nets6.lan, data.ips6.vip_wan.ip)]
        assert ns.net_config['r1_h'] == ns.net_config['r1'] and ns.net_config['r1'][0][1] == []


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        assert {step for step, _ in ops} == {1}
        r1 = _cmds(ops, 1, 'r1')
        assert f"ip addr add {data.ips.r1_lan} dev eth0" in r1 and f"ip addr add {data.ips6.r1_wan} dev eth1" in r1
        assert "sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1" in r1
        assert not any('keepalived' in c for c in r1)
        assert f"ip route add 0.0.0.0/0 via {data.ips.r1_lan.ip}" in _cmds(ops, 1, 'pc1')
        assert f"ip route add 0.0.0.0/0 via {data.ips.vip_lan2.ip}" in _cmds(ops, 1, 'pc2_h')
        # the echo server names the router that answers at a virtual address
        for machine in ('r1', 'r2', 'isp', 'r1_h', 'r2_h', 'isp_h'):
            assert any('sre_server_echo.py' in c and f" {machine.removesuffix('_h')} 80" in c
                       for c in _cmds(ops, 1, machine)), machine
        assert not any('sre_server_echo' in c for c in _cmds(ops, 1, 'pc1'))
        # the probes are on the hidden clients only
        assert vr.VRRP_PROBE_PATH in _files(ops, 1, 'pc1_h') and '/usr/local/sbin/ipv6_probe.py' in _files(ops, 1, 'pc1_h')
        assert any(path.endswith('arp_probe.py') for path in _files(ops, 1, 'pc2_h'))
        assert not any('probe' in path for path in _files(ops, 1, 'pc1'))
        assert ns._host_ops == {}          # no switch command at the start (see SWITCH_NO_HOLD)
        for (step, machine), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert '\n' not in op and '@@@' not in op, (machine, op)

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        assert {step for step, _ in ops} == {1, 2, 3}
        for r in lab.ROUTERS:
            files = _files(ops, 2, r)
            assert set(files) == {lab.KEEPALIVED_CONF, lab.CHECK_SCRIPT, lab.NOTIFY_SCRIPT, lab.RADVD_CONF}
            assert files[lab.KEEPALIVED_CONF] == ns.keepalived_conf(r)
            assert any("systemctl restart keepalived radvd" in c for c in _cmds(ops, 3, r))
        assert _cmds(ops, 3, 'pc1') == [f"ip route replace default via {data.ips.vip_lan.ip}"]
        assert _cmds(ops, 3, 'pc2') == [f"ip route replace default via {data.ips.vip_lan2.ip}"]
        assert _cmds(ops, 3, 'isp') == [f"ip route replace {data.nets.lan} via {data.ips.vip_wan.ip}",
                                        f"ip -6 route replace {data.nets6.lan} via {data.ips6.vip_wan.ip}"]
        assert not any(machine.endswith('_h') for _, machine in ops)      # the mirror is the grader's

    def test_reference_configuration(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        r1, r2 = (vr.parse_keepalived_conf(ns.keepalived_conf(r)) for r in lab.ROUTERS)
        assert r1['errors'] == [] and r2['errors'] == []
        assert list(r1['instances']) == [lab.VI_LAN, lab.VI_WAN, lab.VI_LAN2, lab.VI_LAN6]
        assert r1['groups'][lab.GROUP]['members'] == [lab.VI_LAN, lab.VI_WAN, lab.VI_LAN6]
        assert [r1['instances'][n]['priority'] for n in r1['instances']] == [150, 150, 100, 150]
        assert [r2['instances'][n]['priority'] for n in r2['instances']] == [100, 100, 150, 100]
        assert r1['instances'][lab.VI_WAN]['unicast_peers'] == [str(data.ips.r2_wan.ip)]
        assert r2['instances'][lab.VI_WAN]['unicast_src_ip'] == str(data.ips.r2_wan.ip)
        assert r2['instances'][lab.VI_LAN2]['use_vmac'] and r1['instances'][lab.VI_LAN6]['version'] == 3
        assert f"AdvRASrcAddress {{ {lab.VIP6_LAN}; }};" in ns.radvd_conf() and str(data.nets6.lan) in ns.radvd_conf()
        assert str(data.ips.isp.ip) in ns.check_script() and lab.NOTIFY_LOG in ns.notify_script()

    def test_solution_grows_part_by_part(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        expected = {1: [lab.VI_LAN], 2: [lab.VI_LAN, lab.VI_WAN], 5: [lab.VI_LAN, lab.VI_WAN, lab.VI_LAN2],
                    7: [lab.VI_LAN, lab.VI_WAN, lab.VI_LAN2, lab.VI_LAN6]}
        for part in range(1, 8):
            conf = vr.parse_keepalived_conf(ns.keepalived_conf('r1', part))
            assert conf['errors'] == []
            assert list(conf['instances']) == expected[max(p for p in expected if p <= part)], part
            assert bool(conf['groups']) is (part >= 2) and bool(conf['scripts']) is (part >= 3)
            assert bool(conf['instances'][lab.VI_LAN]['auth_type']) is (part >= 4)
            assert (part >= 6) is bool(conf['instances'].get(lab.VI_LAN2, {}).get('use_vmac'))


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _, mock = _simulate(lab, data, tmp_pub_dir, part=0, answers=False)
        assert _totals(grade) == (0, 100)
        # a fresh project is graded in one step: the mirror scenario is not even registered
        assert grade.max_step == 1 and all(step == 1 for _, step in grade.get_tests())
        assert len(grade.get_grade_list()) == 40 and len(grade.get_questions_ordered()) == QUESTIONS

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, ns, mock = _simulate(lab, data, tmp_pub_dir)
        assert _totals(grade) == (100, 100) and grade.max_step == lab.LAST_STEP == 8
        tests = grade.get_tests()
        # the files of the students are replayed on the clones at step 2, byte for byte
        for r in lab.ROUTERS:
            (replay,) = [c for c, _ in tests[(lab.H(r), 2)] if c.startswith("rm -rf /etc/keepalived")]
            assert replay == vr.apply_archive_cmd(mock.archive(r))
        # nothing ever changes a real machine: every injected failure is on a clone
        intrusive = re.compile(r'ip link set|systemctl (re)?start|systemctl stop|nft (add|delete)|rm -rf|vrrp_probe')
        for (machine, step), cmds in tests.items():
            for command, _ in cmds:
                assert '\n' not in command and '@@@' not in command
                if not machine.endswith('_h'):
                    assert not intrusive.search(command), (machine, command)
        # the clones are reset at the first and at the last step
        for machine in ('r1_h', 'r2_h'):
            assert any(c == lab.router_reset_cmd(data, machine[:2]) for c, _ in tests[(machine, 1)])
            assert any(c == lab.router_reset_cmd(data, machine[:2]) for c, _ in tests[(machine, 8)])
        assert sorted(title for title in _by_title(grade) if title.endswith('_form')) == [
            'check_form', 'lan2_form', 'lan_form', 'secure_form', 'v6_form', 'vmac_form', 'wan_form']

    def test_each_part_earns_its_points(self, lab, data, tmp_pub_dir):
        """The reference solution of the parts 1..N earns exactly their elements (the totals
        measured live: 33, 45, 57, 67, 78, 86 and 100 with the forms)."""
        earned = 0
        for part in range(1, 8):
            grade, _, _ = _simulate(lab, data, tmp_pub_dir, part=part)
            earned += PART_POINTS[part]
            assert _totals(grade) == (earned + FORM_POINTS, 100), part
            parts = {str(e.grade_part) for t, e in _by_title(grade).items() if e.grade and not t.endswith('_form')}
            assert parts == {f"part{i}" for i in range(1, part + 1)}, part

    @pytest.mark.parametrize("without, lost", [
        ('group', {'wan_config': 1, 'wan_mirror_sync': 4, 'check_config': 2, 'notify_config': 2, 'check_mirror': 4,
                   'notify_mirror': 3, 'v6_config': 1, 'v6_mirror_failover': 1}),
        ('check', {'check_config': 2, 'check_mirror': 4}),
        ('auth', {'auth_config': 2, 'auth_live': 2, 'auth_mirror': 3}),
        ('track', {'lan2_track': 1, 'lan2_mirror_track': 3}),
        ('vmac', {'vmac_config': 2, 'vmac_live': 3, 'vmac_mirror': 3}),
        ('v6', {'v6_config': 3, 'v6_wan': 1, 'v6_radvd': 2, 'v6_live': 3, 'v6_mirror_nominal': 2,
                'v6_mirror_failover': 2}),
    ])
    def test_one_feature_missing(self, lab, data, tmp_pub_dir, without, lost):
        """The full solution minus one feature loses its elements and nothing else (live: 82,
        94, 93, 96, 92 and 87)."""
        grade, _, _ = _simulate(lab, data, tmp_pub_dir, without=(without,))
        assert _lost(grade) == lost
        assert _totals(grade) == (100 - sum(lost.values()), 100)

    def test_one_router_alone_earns_no_failover(self, lab, data, tmp_pub_dir):
        """With r2 alone configured, r2 holds every address at every step: nothing moved."""
        grade, _, _ = _simulate(lab, data, tmp_pub_dir, routers=('r2',))
        by = _by_title(grade)
        for title in ('lan_mirror_nominal', 'lan_mirror_failover', 'lan_mirror_preempt', 'wan_mirror_sync',
                      'check_mirror', 'lan2_mirror_track', 'v6_mirror_failover'):
            assert by[title].grade == 0, title
        assert by['lan_config'].grade == 1 and by['lan_service'].grade == 1
        assert grade.max_step == 8          # r2 was replayed

    def test_start_of_the_lab_earns_nothing_live(self, lab, data, tmp_pub_dir):
        """pc1 reaches isp through r1 alone from the start: that path is not the graded one."""
        grade, _, mock = _simulate(lab, data, tmp_pub_dir, part=0, answers=False)
        assert mock.echo('pc1', str(data.ips.isp.ip), 1, clone=False)[1] == 0
        assert _by_title(grade)['wan_live'].grade == 0

    def test_stale_arp_entry_is_not_a_virtual_mac(self, lab, data, tmp_pub_dir):
        """An old entry of pc2 survives the removal of use_vmac: it counts only with a holder."""
        class Stale(Mockup):
            def __init__(self, lab, ns):
                super().__init__(lab, ns, part=5)

            def neigh(self, client):
                return json.dumps([{'dst': str(self.d.ips.vip_lan2.ip), 'dev': 'eth0',
                                    'lladdr': vr.virtual_mac(self.d.vrid_lan2), 'state': ['STALE']}])
        grade, _, _ = _simulate(lab, data, tmp_pub_dir, mockup=Stale)
        assert _by_title(grade)['vmac_live'].grade == 0

    @pytest.mark.parametrize("kind", ['garbage', 'traversal', 'link', 'oversize'])
    def test_invalid_archive_keeps_the_mirror_closed(self, lab, data, tmp_pub_dir, kind):
        class Bad(Mockup):
            def archive(self, router):
                files = self.files(router)
                if kind == 'garbage':
                    return "not a base64 tar archive"
                if kind == 'traversal':
                    files['etc/keepalived/../cron.d/job'] = ("* * * * * root true\n", 0o644)
                    return _tar_b64(files)
                if kind == 'oversize':
                    import random
                    rng = random.Random(7)
                    files['etc/keepalived/big'] = (''.join(chr(rng.randrange(33, 126)) for _ in range(90000)), 0o644)
                    return _tar_b64(files)
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
                    link = tarfile.TarInfo('etc/keepalived/keepalived.conf')
                    link.type, link.linkname = tarfile.SYMTYPE, '/etc/shadow'
                    archive.addfile(link)
                return base64.b64encode(buffer.getvalue()).decode()
        grade, _, _ = _simulate(lab, data, tmp_pub_dir, mockup=Bad)
        assert grade.max_step == 1 and all(step == 1 for _, step in grade.get_tests())
        by = _by_title(grade)
        assert all(e.grade == 0 for t, e in by.items() if '_mirror' in t or t.endswith('_config'))
        # the pass that follows step 1 says why, once per router, in both languages
        grade.step = 1
        grade._errors = []
        grade.reset_before_grade()
        grade.grade()
        warnings = [text for _, text in grade.get_errors()]
        assert len(warnings) == 2
        assert 'r1' in _text(warnings[0]) and 'copie cachée' in _text(warnings[0])
        assert 'hidden copy' in _text(warnings[1], 'en') and lab.KEEPALIVED_DIR in _text(warnings[1], 'en')

    def test_valid_archive_gives_no_warning(self, lab, data, tmp_pub_dir):
        for part in (0, 7):
            grade, _, _ = _simulate(lab, data, tmp_pub_dir, part=part)
            grade.step = 1
            grade._errors = []
            grade.reset_before_grade()
            grade.grade()
            assert grade.get_errors() == [], part

    def test_re_evaluation_gives_the_same_grades(self, lab, data, tmp_pub_dir):
        """`sre re-eval` calls grade() once on archived results: same grades, no new command."""
        grade, ns, _ = _simulate(lab, data, tmp_pub_dir, without=('track',))
        again = lab.Grade(net_scheme=ns)
        again.reset_before_grade()
        again._tests = {key: dict(cmds) for key, cmds in grade.get_tests().items()}
        again._answers = dict(grade._answers)
        again.grade()
        assert {key: set(cmds) for key, cmds in again.get_tests().items()} == {
            key: set(cmds) for key, cmds in grade.get_tests().items()}
        assert {t: e.grade for t, e in _by_title(again).items()} == {t: e.grade for t, e in _by_title(grade).items()}
        # `sre check`: one pass without any result registers the same elements
        fresh = lab.Grade(net_scheme=ns)
        fresh.reset_before_grade()
        fresh.grade()
        assert list(_by_title(fresh)) == list(_by_title(grade)) and fresh.max_step == 1

    def test_waits_are_commands_of_their_own(self, lab, data, tmp_pub_dir):
        grade, _, _ = _simulate(lab, data, tmp_pub_dir)
        waits = [(machine, step, command) for (machine, step), cmds in grade.get_tests().items()
                 for command, _ in cmds if 'for i in $(seq' in command]
        assert waits and all(machine.endswith('_h') and 2 <= step <= 6 for machine, step, _ in waits)
        assert all(command.endswith("done; true") for _, _, command in waits)
        # the routers are read at least SETTLE_SECONDS after their restart (two masters show then)
        for machine in ('r1_h', 'r2_h'):
            assert any(command.startswith(f"sleep {lab.SETTLE_SECONDS}; for i in") for m, step, command in waits
                       if m == machine and step == 2)

    def test_form_scoring(self, lab, data, tmp_pub_dir):
        grade, _, _ = _simulate(lab, data, tmp_pub_dir)
        by = _regrade(grade)
        assert [by[t].grade for t in ('lan_form', 'wan_form', 'check_form', 'secure_form', 'lan2_form', 'vmac_form',
                                      'v6_form')] == [4, 2, 2, 2, 1, 2, 2]
        _set_answer(grade, 'mac_before', vr_mac(data.macs.r1_lan).upper().replace(':', '-'))
        _set_answer(grade, 'down_time', '3,6')
        _set_answer(grade, 'group6', 'FF02:0:0:0:0:0:0:12')
        _set_answer(grade, 'vmac', vr.virtual_mac(data.vrid_lan2).upper())
        by = _regrade(grade)
        assert (by['lan_form'].grade, by['v6_form'].grade, by['vmac_form'].grade) == (4, 2, 2)
        _set_answer(grade, 'mac_after', vr_mac(data.macs.r1_lan))
        _set_answer(grade, 'down_time', '3')
        _set_answer(grade, 'in_group', 'applied')
        _set_answer(grade, 'wan_dst', '224.0.0.18')
        _set_answer(grade, 'iface', 'eth0')
        by = _regrade(grade)
        assert (by['lan_form'].grade, by['check_form'].grade, by['secure_form'].grade, by['vmac_form'].grade) == (
            3, 1.5, 1.5, 1.5)
        assert all(by[t].scope == params.EXO_EVAL_SCOPE for t in by if t.endswith('_form'))

    def test_cheat_answers_match_the_fields(self, lab, data, tmp_pub_dir):
        grade, _, _ = _simulate(lab, data, tmp_pub_dir)
        cheat = grade.get_cheat_answers('final')
        fields = {f['name']: f for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        answered = {}
        for q in grade.get_questions_ordered():
            if q.question_hash in cheat:
                answered.update(json.loads(cheat[q.question_hash]))
        assert set(answered) == set(fields) and len(fields) == 30
        for name, value in answered.items():
            field = fields[name]
            if 'choices' in field:
                assert value in field['choices'], name
            else:
                assert re.fullmatch(field['regex'], value), name


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == QUESTIONS
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == QUESTIONS and 'informations' not in with_fragment
        # the values the students need are in the organisation question, not in the course
        organisation = _text(g0.get_questions_ordered()[0].description)
        assert data.auth_pass in organisation and f"**{data.vrid_lan6}**" in organisation
        assert str(data.ips.vip_wan) in organisation and str(data.ips6.vip_wan) in organisation

    def test_instructor_texts_in_both_languages(self, lab, data, tmp_pub_dir):
        g1, _, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(fr) and has_instructor(en)
            assert fr != en and ('**Solution.**' in en or '**For the instructor.**' in en)
        import check_sre_translations as cst
        tree = ast.parse(_LAB_PATH.read_text())
        assert set(lab._TRANSLATIONS) == {'en'}
        assert set(lab._TRANSLATIONS['en']) == cst.get_tr_strings(tree)
        assert None not in lab._TRANSLATIONS['en'].values()
        assert sum('**Solution.**' in v or '**For the instructor.**' in v
                   for v in lab._TRANSLATIONS['en'].values()) == QUESTIONS

    def test_texts_are_formatted_and_rendered(self, lab, data, tmp_pub_dir):
        g1, ns1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        _, numbering = resolve_informations(ns1.informations)
        for lang in ('fr', 'en'):
            for where, text in _all_texts(g1, ns1, lang):
                assert "{'" not in text, (lang, where)
                unformatted = re.sub(r'```.*?```', '', re.sub(r'@@\{.*?\}@@', '', text), flags=re.S)
                assert not re.search(r"(?<!\{)\{[a-z_][a-z_0-9]*\}(?!\})", unformatted), (lang, where)
                assert '@@{' not in text or where != 'informations'
                assert '`</' not in text and not re.search(r'`[^`\n]*</[^`\n]*`', text), (lang, where)
                resolved = resolve_text(TranslatedText.from_value(text, lang), numbering).resolve(lang) \
                    if where != 'informations' else text
                for shown in (True, False):
                    html = markdown_to_html(resolved, show_instructor=shown)
                    # every fenced block became a <pre>, every table a <table>
                    assert '```' not in html, (lang, where, shown)
                    assert not re.search(r'^\|.*\|$', re.sub(r'<pre>.*?</pre>', '', html, flags=re.S), flags=re.M), (
                        lang, where, shown)

    def test_course_is_numbered_and_generic(self, lab, data, tmp_pub_dir):
        g1, ns1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        resolved, numbering = resolve_informations(ns1.informations)
        tags = ['why', 'protocol', 'keepalived', 'preemption', 'sync-group', 'tracking', 'notify', 'security',
                'load-sharing', 'vmac', 'vrrpv3-ipv6', 'observing']
        for lang in ('fr', 'en'):
            assert [s.number for s in numbering.sections(lang) if s.level == 1] == [str(i) for i in range(1, 13)]
            assert [s.number for s in numbering.sections(lang) if s.level == 2] == [
                '2.1', '2.2', '2.3', '2.4', '3.1', '3.2', '6.1', '6.2', '6.3', '8.1', '8.2', '11.1', '11.2']
            informations = _text(resolved, lang)
            assert '@@' not in informations
            # neither the session specifics nor the values of the instance
            for value in (data.auth_pass, str(data.ips.vip_lan.ip), str(data.nets6.lan), 'Organisation du TP',
                          'Plan du TP', '`pc1`', '`isp`', '`r1`'):
                assert value not in informations, (lang, value)
            for tag in tags:
                assert f'<a id="{tag}"></a>' in informations, (lang, tag)
        assert '## <a id="sync-group"></a>5. Les groupes de synchronisation' in _text(resolved)
        assert '## <a id="sync-group"></a>5. Sync groups' in _text(resolved, 'en')
        assert '(section [6](#tracking))' in _text(resolved) and '(section [7](#notify))' in _text(resolved, 'en')
        # the references of the questions resolve to bare section numbers
        referenced = set()
        for q in g1.get_questions_ordered():
            referenced |= set(re.findall(r'@@ref:([a-z0-9-]+)@@', _text(q.description)))
            description = resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering)
            for lang in ('fr', 'en'):
                assert '@@ref' not in description.resolve(lang)
        assert referenced == {'keepalived', 'protocol', 'sync-group', 'tracking', 'security', 'load-sharing', 'vmac',
                              'vrrpv3-ipv6'}

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for lang in ('fr', 'en'):
            names = []
            for q in g1.get_questions_ordered():
                for m in re.finditer(r'@@\{([^:}]+):([^}]*)\}@@', _text(q.description, lang)):
                    names.append(m.group(1))
                    assert '}' not in m.group(2)
            assert len(names) == len(set(names)) == 30, lang
        kinds = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert kinds['dst'] == {'name': 'dst', 'regex': '[0-9.]+'}
        assert kinds['sender'] == {'name': 'sender', 'choices': ['r1', 'r2', 'both']}
        assert kinds['result']['choices'] == ['ok', 'blackhole', 'gateway']
        assert kinds['interval']['choices'] == ['s', 'cs', 'ms']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == QUESTIONS and result.warnings == []
        stripped = tmp_path / 'vrrp_stripped.py'
        stripped.write_bytes(result.data)
        assert b'_TRANSLATIONS' in result.data and b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('vrrp_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        kept = module._TRANSLATIONS['en']
        assert set(module._TRANSLATIONS) == {'en'} and len(kept) == len(lab._TRANSLATIONS['en']) - QUESTIONS
        assert not any('**Solution.**' in v or '**For the instructor.**' in v for v in kept.values())
        grade, _, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 100)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements and part keys are English."""
        french = re.compile(r'(routeur|passerelle|secours|maitre|reseau|adresse|annonce|bascule|poids|suivi)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.LAN_SWITCHES)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets)) + list(vars(data.macs))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
