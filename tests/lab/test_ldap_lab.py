"""Offline tests of the LDAP lab (lab/em/_DRAFT_/ldap.py): the data (five people, three groups,
the CA and the server certificates), the topology (three init machines, the hidden probe), the
state ops (the fresh server of `initial`, the client defaults, the whole solution of `final`, every
command on one line), the multi-pass grading contract with synthetic outputs (nothing done: 0,
everything done: 100 + 10 bonus, the solution without TLS: the transport falls back to clear
binds, a few scoring details), the instructor texts in both languages, the numbered course, the
stripped lab file and the English identifiers.

No Docker: the outputs of the containers are rendered from the generated data in the format of the
real tools (ldapsearch, ldapwhoami, getent, openssl s_client, the login probe).
"""
import ast
import base64
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import openldap as ol  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'em' / '_DRAFT_' / 'ldap.py'
RC0 = "===RC 0\n"
NO_SUCH_OBJECT = "No such object (32)\n===RC 32\n"
INVALID = "ldap_bind: Invalid credentials (49)\n===RC 49\n"
CONFIDENTIALITY = "ldap_bind: Confidentiality required (13)\n\tadditional info: confidentiality required\n===RC 13\n"
NO_SERVER = "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)\n===RC 255\n"
CSN = "20261105002157.264913Z#000000#000#000000"
COMMON_AUTH_LDAP = ("auth\t[success=2 default=ignore]\tpam_unix.so nullok\n"
                    "auth\t[success=1 default=ignore]\tpam_ldap.so minimum_uid=1000 use_first_pass\n"
                    "auth\trequisite\t\t\tpam_deny.so\nauth\trequired\t\t\tpam_permit.so\n")
COMMON_AUTH_UNIX = ("auth\t[success=1 default=ignore]\tpam_unix.so nullok\nauth\trequisite\t\t\tpam_deny.so\n"
                    "auth\trequired\t\t\tpam_permit.so\n")
COMMON_ACCOUNT_LDAP = ("account\t[success=1 new_authtok_reqd=done default=ignore]\tpam_unix.so \n"
                       "account\trequisite\t\t\tpam_deny.so\naccount\trequired\t\t\tpam_permit.so\n"
                       "account\t[success=ok new_authtok_reqd=done ignore=ignore user_unknown=ignore "
                       "authinfo_unavail=ignore default=bad]\tpam_ldap.so minimum_uid=1000\n")
COMMON_SESSION_LDAP = ("session\t[default=1]\t\t\tpam_permit.so\nsession\trequisite\t\t\tpam_deny.so\n"
                       "session\trequired\t\t\tpam_permit.so\n"
                       "session\trequired\tpam_mkhomedir.so umask=0077 skel=/etc/skel\n"
                       "session\trequired\tpam_unix.so \nsession\t[success=ok default=ignore]\tpam_ldap.so minimum_uid=1000\n")
NSSWITCH_UNIX = "passwd:         files systemd\ngroup:          files systemd\nshadow:         files systemd\nhosts: files dns\n"
S_CLIENT_OK = ("verify return:1\nverify return:1\nCONNECTED(00000003)\nsubject=CN = ldap1.corp.lan\n"
               "issuer=CN = CA corp.lan\nVerify return code: 0 (ok)\n===END\n")
S_CLIENT_NO_TLS = "CONNECTED(00000003)\nVerify return code: 0 (ok)\n===END\n"
S_CLIENT_REFUSED = "connect:errno=111\n===END\n"


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('ldap_lab_under_test', _LAB_PATH)
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


# ---------------------------------------------------------------------------
# synthetic outputs
# ---------------------------------------------------------------------------


def _creds(command):
    m = re.search(r" -D (\S+) -w (\S+)", command)
    return (m.group(1), m.group(2)) if m else (None, None)


def _base(command):
    m = re.search(r" -b (\S+)", command)
    return m.group(1) if m else None


class Scenario:
    """What the synthetic containers answer: ``final`` = the solution applied (``tls=False``: the
    solution without part 5), ``final=False`` = a fresh project."""

    def __init__(self, lab, ns, final=True, tls=True):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.final, self.tls = final, final and tls
        d = self.d
        self.people = {p['role']: p for p in d.people}
        self.present = [self.people[r] for r in ('dev1', 'dev2', 'helpdesk', 'staff')]
        self.temp = lab.TEMP_PASSWORD + d.probe_token
        # (dn, password) accepted by the solution's server
        self.valid = {(lab.ADMIN_DN, d.admin_password), (lab.NSLCD_DN, d.nslcd_password),
                      (lab.REPLICATOR_DN, d.replicator_password), (lab.person_dn(self.people['staff']['login']), self.temp)}
        for p in self.present:
            pw = d.new_password if p['role'] == 'dev1' else p['password']
            self.valid.add((lab.person_dn(p['login']), pw))
        if not final:                       # a fresh directory: nobody but the rootdn
            self.valid = {(lab.ADMIN_DN, d.admin_password)}

    # -- the servers --------------------------------------------------------------
    def config(self, machine):
        lab = self.lab
        text = ol.render_slapd_config_ldif(lab.SUFFIX, lab.ADMIN_DN, ol.ssha_hash(self.d.admin_password))
        if self.final:
            if self.tls:
                text = text.replace("olcToolThreads: 1\n", "olcToolThreads: 1\n"
                                    f"olcTLSCACertificateFile: /etc/ldap/tls/ca.crt\n"
                                    f"olcTLSCertificateFile: /etc/ldap/tls/{machine}.crt\n"
                                    f"olcTLSCertificateKeyFile: /etc/ldap/tls/{machine}.key\n")
            for a in ol.DEFAULT_ACCESS:
                text = text.replace(f"olcAccess: {a}\n", "")
            text += "".join(f"olcAccess: {{{i}}}{a}\n" for i, a in enumerate(lab.solution_access()))
            if self.tls:
                text += "olcSecurity: simple_bind=128\n"
            if machine == 'ldap1':
                text = text.replace("olcModuleLoad: back_mdb\n", "olcModuleLoad: {0}back_mdb\nolcModuleLoad: {1}syncprov\n")
                text += ("\ndn: olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config\nobjectClass: olcOverlayConfig\n"
                         "objectClass: olcSyncProvConfig\nolcOverlay: {0}syncprov\n")
            else:
                text += ("olcSyncrepl: {0}" + ol.render_syncrepl(1, "ldap://ldap1.corp.lan", lab.REPLICATOR_DN,
                                                               self.d.replicator_password, lab.SUFFIX,
                                                               starttls="critical", tls_cacert="/etc/ldap/tls/ca.crt")
                         + "\nolcUpdateRef: ldap://ldap1.corp.lan\n")
        return text + "\n" + RC0

    def tree(self):
        if not self.final:
            return NO_SUCH_OBJECT
        leaver = self.people['leaver']
        entries = [e for e in ol.parse_ldif(self.ns._directory_ldif())
                   if not ol.dn_equal(e['dn'], self.lab.person_dn(leaver['login']))]
        text = ""
        for e in entries:
            attrs = [(k, [v for v in vs if not (k == 'memberUid' and v == leaver['login'])]) for k, vs in e['attrs'].items()]
            text += ol.render_entry_ldif(e['dn'], attrs)
        return text + RC0

    def entries_for(self, command, binddn):
        """The entries a successful search of the solution returns."""
        lab = self.lab
        base = _base(command)
        if base and base.startswith("uid="):
            target = ol.rdn_value(base)
            if command.rstrip().endswith('userPassword 2>&1; echo "===RC $?"'):
                return f"dn: {base}\n\n"
            person = next(p for p in self.d.people if p['login'] == target)
            return f"dn: {base}\nuid: {target}\ncn: {person['first']} {person['last']}\n\n"
        text = ""
        for p in self.present:
            text += f"dn: {lab.person_dn(p['login'])}\nuid: {p['login']}\nuidNumber: {p['uid']}\n"
            if binddn == lab.REPLICATOR_DN:
                text += f"userPassword:: {base64.b64encode(ol.ssha_hash(p['password']).encode()).decode()}\n"
            text += "\n"
        return text

    # -- dispatch ----------------------------------------------------------------
    def __call__(self, machine, command):
        lab, d = self.lab, self.d
        final, tls = self.final, self.tls
        if command.startswith("ldapsearch -LLL -Y EXTERNAL -Q -H ldapi:/// -b cn=config"):
            return self.config(machine), 0
        if "-H ldapi:/// -b dc=corp,dc=lan '(objectClass=*)'" in command:
            return (self.tree() if machine == 'ldap1' or final else NO_SUCH_OBJECT), 0
        if "contextCSN" in command:
            return (f"dn: {lab.SUFFIX}\ncontextCSN: {CSN}\n\n" + RC0) if final else NO_SUCH_OBJECT, 0
        if f"-b {lab.CANARY_DN}" in command:
            return (f"dn: {lab.CANARY_DN}\ndescription: {d.probe_token}\n\n" + RC0) if final else NO_SUCH_OBJECT, 0
        if command == "ss -tlnp 2>&1":
            lines = ["State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess"]
            if machine == 'm1':
                lines.append('LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=47,fd=3))')
            else:
                lines.append('LISTEN 0 2048 0.0.0.0:389 0.0.0.0:* users:(("slapd",pid=263,fd=8))')
                if tls:
                    lines.append('LISTEN 0 2048 0.0.0.0:636 0.0.0.0:* users:(("slapd",pid=263,fd=10))')
            return "\n".join(lines) + "\n", 0
        if command.startswith("stat -c"):
            return "root:openldap 640\n", 0
        # m1
        if command == "cat /etc/nslcd.conf 2>/dev/null":
            if not final:
                return ol.render_nslcd_conf("ldap://127.0.0.1/", "dc=example,dc=com"), 0
            uri = "ldaps://ldap1.corp.lan/" if tls else "ldap://ldap1.corp.lan/"
            return ol.render_nslcd_conf(uri, lab.SUFFIX, lab.NSLCD_DN, d.nslcd_password,
                                        cacert=lab.CLIENT_CA if tls else None, reqcert="demand" if tls else None), 0
        if command == "cat /etc/nsswitch.conf 2>/dev/null":
            return (NSSWITCH_UNIX.replace("systemd\n", "systemd ldap\n") if final else NSSWITCH_UNIX), 0
        if command == "cat /etc/pam.d/common-auth 2>/dev/null":
            return (COMMON_AUTH_LDAP if final else COMMON_AUTH_UNIX), 0
        if command == "cat /etc/pam.d/common-account 2>/dev/null":
            return (COMMON_ACCOUNT_LDAP if final else "account required pam_unix.so\n"), 0
        if command == "cat /etc/pam.d/common-session 2>/dev/null":
            return (COMMON_SESSION_LDAP if final else "session required pam_unix.so\n"), 0
        if command.startswith("getent passwd "):
            login = command.split()[2]
            p = next((p for p in self.present if p['login'] == login), None)
            if final and p:
                return f"{login}:x:{p['uid']}:{d.gid('staff')}:{p['first']} {p['last']}:/home/{login}:/bin/bash\n", 0
            return "", 2
        if command.startswith("getent group dev"):
            return (f"dev:*:{d.gid('dev')}:{','.join(d.group_members('dev'))}\n", 0) if final else ("", 2)
        if command.startswith("id "):
            p = self.people['dev2']
            return (f"uid={p['uid']}({p['login']}) gid={d.gid('staff')}(staff) groups={d.gid('staff')}(staff)\n", 0) \
                if final else (f"id: '{p['login']}': no such user\n", 1)
        if "sre_login_probe.py" in command:
            login = self.people['dev2']['login']
            if final:
                return json.dumps({"ok": True, "login": login, "home": f"/home/{login}", "home_exists": True,
                                   "prompted": True, "exit": 0, "timeout": False, "output": "SRE_LOGIN_OK"}) + "\n", 0
            return json.dumps({"ok": False, "login": "", "home": "", "home_exists": None, "prompted": False,
                               "exit": 1, "timeout": False, "output": f"su: user {login} does not exist"}) + "\n", 1
        if command.startswith("openssl s_client -connect ldap1.corp.lan:636"):
            return (S_CLIENT_OK if tls else S_CLIENT_REFUSED), 0
        if command.startswith("openssl s_client -connect ldap1.corp.lan:389"):
            return (S_CLIENT_OK if tls else S_CLIENT_NO_TLS), 0
        # the ldap-utils commands of the probe and the rootdn operations through ldapi
        binddn, pw = _creds(command)
        over_ldaps = "-H ldaps://" in command
        starttls = " -ZZ " in command
        over_ldapi = "-H ldapi:///" in command
        if (over_ldaps or starttls) and not tls:
            return (NO_SERVER if over_ldaps else "ldap_start_tls: Connect error (-11)\n===RC 1\n"), 0
        if binddn is not None and not over_ldaps and not starttls and not over_ldapi and tls:
            return CONFIDENTIALITY, 0
        if binddn is None:                                    # anonymous
            if command.startswith("ldapsearch"):
                return NO_SUCH_OBJECT, 0
            return RC0, 0
        if (binddn, pw) not in self.valid and not (binddn == lab.ADMIN_DN and pw == d.admin_password):
            return INVALID, 0
        if command.startswith("ldapwhoami"):
            return f"dn:{binddn}\n" + RC0, 0
        if command.startswith("ldapsearch"):
            if not final:
                return NO_SUCH_OBJECT, 0
            return self.entries_for(command, binddn) + RC0, 0
        if "| ldapmodify" in command:
            ldif = base64.b64decode(command.split()[1]).decode()
            target = ldif.splitlines()[0][4:]
            if binddn == lab.person_dn(self.people['dev2']['login']):
                return f'ldap_modify: Insufficient access (50)\nmodifying entry "{target}"\n\n===RC 50\n', 0
            return f'modifying entry "{target}"\n\n' + RC0, 0
        if command.startswith("ldappasswd"):
            return RC0, 0
        if command.startswith("ldapdelete"):
            return RC0, 0
        return "", 0


def _simulate(lab, data, tmp_pub_dir, instructor_mode=False, everything=True, tls=True):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme).  The tests registered may
    grow after step 1 (the behavioural checks of the probe wait for the transport discovery) and
    must be stable afterwards."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    scenario = Scenario(lab, ns, final=everything, tls=tls)
    previous, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if previous is None:
            if everything:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            for key, cmds in previous.items():
                assert cmds <= current.get(key, set()), "a registered test vanished between two passes"
            if step > 2:
                assert current == previous, "the registered tests changed after the discovery step"
        previous = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = scenario(m, key[0])
        step += 1
    return grade, ns


def _regrade(grade):
    grade.reset_before_grade()
    grade.grade()
    return _by_title(grade)


def _totals(grade):
    """(grade, max) of the graded elements and the grade of the bonus ones."""
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.max_grade for e in elements if not e.bonus),
            sum(e.grade for e in elements if e.bonus))


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


def _set_answer(grade, field, value):
    for q in grade.get_questions_ordered():
        fields = getattr(q, 'fields', None) or []
        if any(f['name'] == field for f in fields):
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
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()
        again = lab.Data.from_json(data.to_json())
        assert again.people == data.people and again.gid_base == data.gid_base
        assert isinstance(again.people[0]['uid'], int)

    def test_people_and_groups(self, lab, data):
        for d in [data] + [lab.Data.generate() for _ in range(20)]:
            assert [p['role'] for p in d.people] == list(lab.PEOPLE_ROLES)
            logins = [p['login'] for p in d.people]
            assert len(set(logins)) == 5 and all(re.fullmatch(r'[a-z]+', l) for l in logins)
            for p in d.people:
                assert p['login'] == (p['first'][0] + p['last']).lower()
                assert p['uid'] > d.gid_base + 2 and len(p['password']) == 8
            assert len({p['uid'] for p in d.people}) == 5
            assert d.gid_base % 100 == 0 and 5000 <= d.gid_base < 9000
            assert d.gid('staff') == d.gid_base and d.gid('dev') == d.gid_base + 1 and d.gid('helpdesk') == d.gid_base + 2
            assert d.group_members('staff') == logins
            assert d.group_members('dev') == [d.person('dev1')['login'], d.person('dev2')['login']]
            assert d.group_members('helpdesk') == [d.person('helpdesk')['login']]
            assert len({d.admin_password, d.new_password, d.nslcd_password, d.replicator_password}) == 4
            assert len(d.probe_token) == 12

    def test_certificates(self, lab, data):
        from cryptography import x509
        ca = x509.load_pem_x509_certificate(data.ca_cert.encode())
        assert ca.subject == ca.issuer and ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        for m in ('ldap1', 'ldap2'):
            cert = x509.load_pem_x509_certificate(getattr(data, f"{m}_cert").encode())
            assert cert.issuer == ca.subject
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            assert san.get_values_for_type(x509.DNSName) == [f"{m}.corp.lan"]
            assert "-----BEGIN RSA PRIVATE KEY-----" in getattr(data, f"{m}_key")
        assert "-----BEGIN RSA PRIVATE KEY-----" in data.ca_key

    def test_network(self, lab, data):
        assert set(vars(data.nets)) == {'lan'} and data.nets.lan.prefixlen == 24 and data.nets.lan.is_private
        assert set(vars(data.ips)) == {'ldap1', 'ldap2', 'm1', 'probe'}
        assert len({a.ip for a in vars(data.ips).values()}) == 4
        assert all(a.ip in data.nets.lan for a in vars(data.ips).values())


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'ldap1', 'ldap2', 'm1', 'probe'}
        assert set(ns.get_visible_machine_names()) == {'ldap1', 'ldap2', 'm1'}
        probe = ns.get_machine('probe')
        assert probe.hidden and not probe.allow_connection and not probe.privileged and '/base:' in probe.image
        for m in lab.SYSTEMD_MACHINES:
            machine = ns.get_machine(m)
            assert machine.privileged and machine.entrypoint == "/sbin/init" and '/ldap-mail:' in machine.image, m
        assert {n.name for n in ns.get_visible_networks()} == {'lan'}
        assert lab.SUFFIX == "dc=corp,dc=lan" and lab.ADMIN_DN == "cn=admin,dc=corp,dc=lan"
        assert lab.fqdn('ldap1') == "ldap1.corp.lan"
        assert lab.person_dn('x') == "uid=x,ou=people,dc=corp,dc=lan" and lab.group_dn('g') == "cn=g,ou=groups,dc=corp,dc=lan"

    def test_solution_acls(self, lab):
        acls = [ol.parse_olc_access(a) for a in lab.solution_access()]
        assert len(acls) == 4
        password = ol.acl_for_attribute(acls, 'userPassword')
        assert ol.acl_access(password, 'self') == 'write' and ol.acl_access(password, 'anonymous') == 'auth'
        assert ol.acl_access(password, '*') == 'none'
        assert ol.acl_access(password, f'dn.exact={lab.REPLICATOR_DN}') == 'read'
        helpdesk = lab.helpdesk_set().replace('"', '')
        assert ol.acl_access(password, helpdesk) == 'write'
        phone = ol.acl_for_attribute(acls, 'telephoneNumber')
        assert phone['what_attrs'] == ['telephonenumber', 'mobile', 'mail'] and ol.acl_access(phone, 'users') == 'read'
        rest = ol.acl_for_attribute(acls, 'cn')
        assert rest['what'] == '*' and ol.acl_access(rest, 'users') == 'read' and ol.acl_access(rest, '*') == 'none'
        assert 'memberUid & user/uid' in lab.helpdesk_set()


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------

class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        d = data
        assert set(ops) == {(1, m) for m in ns.get_machine_names()}
        for (step, m), op_list in ops.items():
            for op in op_list:
                assert "\n" not in str(op) or not isinstance(op, str), (m, str(op)[:60])
        for m in ns.get_machine_names():
            cmds = _cmds(ops, 1, m)
            assert "sysctl -w net.ipv4.ip_forward=0" in cmds, m
            files = _files(ops, 1, m)
            assert files['/etc/resolv.conf'] == '' and '/etc/hosts' in files
            assert f"ip addr add {getattr(d.ips, m)} dev eth0" in cmds
        # the servers: a fresh configuration loaded by slapadd, started
        for m in lab.SERVERS:
            cmds, files = _cmds(ops, 1, m), _files(ops, 1, m)
            config = files[lab.CONFIG_LDIF]
            cfg = ol.parse_slapd_config(ol.parse_ldif(config))
            db = cfg.database(lab.SUFFIX)
            assert db['rootdn'] == lab.ADMIN_DN and db['rootpw_hashed'] and ol.check_password(db['rootpw'], d.admin_password)
            assert db['access_raw'] == list(ol.DEFAULT_ACCESS) and cfg.loglevel == 'stats'
            assert ol.entry_value(ol.find_entry(cfg.raw, 'cn=config'), 'olcLocalSSF') == '128'
            assert 'include: file:///etc/ldap/schema/nis.ldif' in config
            assert any(c.startswith("systemctl stop slapd") and "rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*" in c for c in cmds)
            assert f"slapadd -n 0 -F /etc/ldap/slapd.d -l {lab.CONFIG_LDIF} && chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap" in cmds
            assert files['/etc/default/slapd'] == lab.render_slapd_default("ldap:/// ldapi:///")
            assert files['/etc/ldap/ldap.conf'] == f"BASE {lab.SUFFIX}\nURI ldap://{m}.corp.lan\n"
            assert files[f'{lab.CA_DIR}/ca.crt'] == d.ca_cert and files[f'{lab.CA_DIR}/ca.key'] == d.ca_key
            assert "systemctl start slapd; sleep 1" in cmds
            assert not any('ldapadd' in c or 'ldapmodify' in c for c in cmds), m
        # the client: nothing configured, the CA, the probe, sshd
        cmds, files = _cmds(ops, 1, 'm1'), _files(ops, 1, 'm1')
        assert files['/etc/nslcd.conf'] == ol.render_nslcd_conf("ldap://127.0.0.1/", "dc=example,dc=com")
        assert files[lab.CLIENT_CA] == d.ca_cert and ol.LOGIN_PROBE_PATH in files
        assert any("pam-auth-update --package --remove ldap mkhomedir" in c for c in cmds)
        assert any("/etc/nsswitch.conf" in c and "sed -i" in c for c in cmds)
        assert any("pam_loginuid" in c for c in cmds)
        assert "systemctl start ssh; systemctl start rsyslog; true" in cmds
        # the probe: the CA, the client defaults, the login probe
        files = _files(ops, 1, 'probe')
        assert files[lab.CLIENT_CA] == d.ca_cert and ol.LOGIN_PROBE_PATH in files
        assert files['/etc/ldap/ldap.conf'] == f"BASE {lab.SUFFIX}\nTLS_CACERT {lab.CLIENT_CA}\n"
        hosts = files['/etc/hosts']
        for m in ('ldap1', 'ldap2', 'm1'):
            assert f"{getattr(d.ips, m).ip}\t\t{m}" in hosts
        assert 'probe' not in hosts.replace('probe.corp.lan', '').split('127.0.1.1')[0]

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        d = data
        assert set(ops) == {(1, 'ldap1'), (2, 'ldap2'), (2, 'm1')}
        for (step, m), op_list in ops.items():
            for op in op_list:
                assert not isinstance(op, str) or "\n" not in op, (m, op[:60])
        leaver, dev1 = d.person('leaver'), d.person('dev1')
        # ldap1: rebuilt, the directory as the rootdn, the departure, the password, the ACLs, syncprov, TLS, security
        cmds, files = _cmds(ops, 1, 'ldap1'), _files(ops, 1, 'ldap1')
        directory = ol.parse_ldif(files['/root/directory.ldif'])
        dns = [e['dn'] for e in directory]
        assert dns[:3] == [lab.SUFFIX, lab.PEOPLE_DN, lab.GROUPS_DN]
        assert all(lab.person_dn(p['login']) in dns for p in d.people)
        assert all(lab.group_dn(g) in dns for g in lab.GROUPS) and lab.NSLCD_DN in dns and lab.REPLICATOR_DN in dns
        for p in d.people:
            e = ol.find_entry(directory, lab.person_dn(p['login']))
            assert ol.check_password(ol.entry_value(e, 'userPassword'), p['password'])
            assert ol.entry_value(e, 'uidNumber') == str(p['uid']) and ol.entry_value(e, 'mail') == f"{p['login']}@corp.lan"
        staff = ol.find_entry(directory, lab.group_dn('staff'))
        assert ol.entry_values(staff, 'memberUid') == [p['login'] for p in d.people]
        admin = f"-x -H ldapi:/// -D {lab.ADMIN_DN} -w {d.admin_password}"
        assert f"ldapadd {admin} -c -f /root/directory.ldif" in cmds
        assert f"ldapdelete {admin} {lab.person_dn(leaver['login'])}" in cmds
        modifies = [base64.b64decode(c.split()[1]).decode() for c in cmds if c.startswith("echo ") and "| ldapmodify" in c]
        assert any(f"dn: {lab.group_dn('staff')}" in m and f"delete: memberUid\nmemberUid: {leaver['login']}" in m
                   for m in modifies)
        assert ol.ldappasswd_cmd(ol.LDAPI_URI, lab.ADMIN_DN, d.admin_password, d.new_password,
                                 lab.person_dn(dev1['login'])) in cmds
        acl = next(m for m in modifies if "replace: olcAccess" in m)
        assert "dn: olcDatabase={1}mdb,cn=config" in acl
        assert [l[len("olcAccess: "):] for l in acl.splitlines() if l.startswith("olcAccess: ")] == \
            [f"{{{i}}}{a}" for i, a in enumerate(lab.solution_access())]
        assert any("olcModuleLoad: syncprov" in m for m in modifies)
        assert any("olcOverlay: syncprov" in m and "olcSyncProvConfig" in m for m in modifies)
        tls = next(m for m in modifies if "olcTLSCertificateKeyFile" in m)
        assert f"olcTLSCertificateFile: {lab.TLS_DIR}/ldap1.crt" in tls and f"olcTLSCACertificateFile: {lab.TLS_DIR}/ca.crt" in tls
        assert any("olcSecurity: simple_bind=128" in m for m in modifies)
        assert files[f'{lab.TLS_DIR}/ldap1.crt'] == d.ldap1_cert and files[f'{lab.TLS_DIR}/ldap1.key'] == d.ldap1_key
        assert files['/etc/default/slapd'] == lab.render_slapd_default("ldap:/// ldaps:/// ldapi:///")
        assert cmds.index(lab.restart_slapd_cmd()) > cmds.index(f"ldapadd {admin} -c -f /root/directory.ldif")
        # the security after the TLS restart
        security_at = next(i for i, c in enumerate(cmds) if c.startswith("echo ")
                           and "olcSecurity" in base64.b64decode(c.split()[1]).decode())
        assert security_at > cmds.index(lab.restart_slapd_cmd())
        # ldap2: rebuilt, TLS, the consumer
        cmds2, files2 = _cmds(ops, 2, 'ldap2'), _files(ops, 2, 'ldap2')
        modifies2 = [base64.b64decode(c.split()[1]).decode() for c in cmds2 if c.startswith("echo ") and "| ldapmodify" in c]
        syncrepl = next(m for m in modifies2 if "olcSyncrepl" in m)
        parsed = ol.parse_syncrepl(next(l for l in syncrepl.splitlines() if l.startswith("olcSyncrepl: "))[13:])
        assert parsed['provider'] == "ldap://ldap1.corp.lan" and parsed['binddn'] == lab.REPLICATOR_DN
        assert parsed['credentials'] == d.replicator_password and parsed['starttls'] == 'critical'
        assert parsed['tls_cacert'] == f"{lab.TLS_DIR}/ca.crt" and parsed['type'] == 'refreshAndPersist'
        assert "olcUpdateRef: ldap://ldap1.corp.lan" in syncrepl
        assert files2[f'{lab.TLS_DIR}/ldap2.crt'] == d.ldap2_cert
        # m1: nslcd over LDAPS with the service account, NSS, PAM
        cmds3, files3 = _cmds(ops, 2, 'm1'), _files(ops, 2, 'm1')
        conf = ol.parse_nslcd_conf(files3['/etc/nslcd.conf'])
        info = ol.nslcd_tls(conf)
        assert info['ldaps'] and info['cacert'] == lab.CLIENT_CA and info['binddn'] == lab.NSLCD_DN
        assert conf['bindpw'] == [d.nslcd_password] and info['base'] == lab.SUFFIX
        assert files3[lab.MKHOMEDIR_PROFILE] == ol.PAM_MKHOMEDIR_PROFILE
        assert "pam-auth-update --enable ldap" in cmds3 and "pam-auth-update --enable mkhomedir" in cmds3
        assert any("nsswitch.conf" in c and r"\1 ldap" in c for c in cmds3)
        assert cmds3[-1].endswith("systemctl start nslcd")
        states = {name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)}
        assert states == {'initial', 'final', 'save', 'restore'}
        assert not lab.NetScheme.final._sre_state_user_allowed
        assert not getattr(lab, 'allow_save_restore', False) and lab.export_kathara_project is False


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------

class TestGrading:
    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        assert _totals(grade) == (100, 100, 10)
        parts = {}
        for e in grade.get_grade_list():
            if not e.bonus:
                parts[e.grade_part] = parts.get(e.grade_part, 0) + e.max_grade
        assert parts == {'part1': 17, 'part2': 25, 'part3': 22, 'part4': 16, 'part5': 20}
        assert all(e.grade_part == 'bonus' for e in grade.get_grade_list() if e.bonus)
        assert grade.max_step == 3
        tests = {(m, s): [k[0] for k in cmds] for (m, s), cmds in grade.get_tests().items()}
        assert {(m, 1) for m in ('ldap1', 'ldap2', 'm1', 'probe')} <= set(tests)
        assert ('probe', 2) in tests and ('ldap2', 2) in tests and ('ldap1', 3) in tests
        # every behavioural check of the probe at step 2 goes through ldaps://
        assert all("-H ldaps://" in c or " -ZZ " in c for c in tests[('probe', 2)])
        # the staff person is put back as the rootdn at step 3, the canary removed
        assert any(c.startswith("ldappasswd -x -D cn=admin") for c in tests[('ldap1', 3)])
        assert any(c.startswith(f"ldapdelete -x -H ldapi:/// -D {lab.ADMIN_DN}") and lab.CANARY_DN in c
                   for c in tests[('ldap1', 3)])

    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=False)
        assert _totals(grade) == (0, 100, 0)
        tests = {(m, s): [k[0] for k in cmds] for (m, s), cmds in grade.get_tests().items()}
        # a fresh server accepts clear binds: the checks run over ldap://
        assert all("-H ldap://" in c for c in tests[('probe', 2)])

    def test_solution_without_tls(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True, tls=False)
        total, maximum, bonus = _totals(grade)
        assert maximum == 100 and bonus == 10
        by = _by_title(grade)
        zero = {t for t, e in by.items() if not e.grade}
        assert zero == {'tls_ldaps_certificate', 'tls_starttls', 'tls_listen_636', 'tls_ldaps_search',
                        'tls_key_permissions', 'tls_clear_bind_refused', 'tls_nslcd'}
        assert total == 80

    def test_form_scoring(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        by = _regrade(grade)
        assert all(by[f"answer_{k}"].grade == 2 for k in ('rootdn', 'backend', 'dbdir', 'schema', 'rootpw'))
        _set_answer(grade, 'rootdn', ' CN=Admin, dc=corp, dc=lan ')
        _set_answer(grade, 'dbdir', '/var/lib/ldap/')
        assert _regrade(grade)['answer_rootdn'].grade == 2 and by['answer_dbdir'].grade == 2
        _set_answer(grade, 'rootdn', 'cn=admin,cn=config')
        _set_answer(grade, 'backend', 'hdb')
        _set_answer(grade, 'schema', 'core')
        _set_answer(grade, 'rootpw', 'clear')
        by = _regrade(grade)
        assert [by[f"answer_{k}"].grade for k in ('rootdn', 'backend', 'dbdir', 'schema', 'rootpw')] == [0, 0, 2, 0, 0]

    def test_cheat_answers_match_the_fields(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, everything=True)
        cheat = grade.get_cheat_answers('final')
        fields = {f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        answered = set()
        for q in grade.get_questions_ordered():
            if q.question_hash in cheat:
                answered |= set(json.loads(cheat[q.question_hash]))
        assert answered == fields == {'rootdn', 'backend', 'dbdir', 'schema', 'rootpw'}


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 10
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 10 and 'informations' not in with_fragment
        # the passwords of the people are in the organisation dummy (the students need them), the
        # temporary password of the helpdesk test in the instructor text only
        student_texts = "\n".join(t for w, t in _all_texts(g0, ns0))
        assert data.person('dev2')['password'] in student_texts and data.admin_password in student_texts
        assert lab.TEMP_PASSWORD not in student_texts
        assert lab.TEMP_PASSWORD + data.probe_token in "\n".join(t for w, t in _all_texts(g1, ns1))

    def test_instructor_texts_in_both_languages(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(fr) and has_instructor(en)
            assert fr != en and ('**Solution' in en or '**For the instructor.**' in en)
            for lang, text in (('fr', fr), ('en', en)):
                assert "{'" not in text and not re.search(r"(?<!\{)\{[a-z_][a-z_0-9]*\}(?!\})", text), (lang, text[:80])
                markdown_to_html(text, show_instructor=True)
        import check_sre_translations as cst
        tree = ast.parse(_LAB_PATH.read_text())
        assert set(lab._TRANSLATIONS) == {'en'}
        assert set(lab._TRANSLATIONS['en']) == cst.get_tr_strings(tree)
        assert None not in lab._TRANSLATIONS['en'].values()
        assert sum('**Solution' in v or '**For the instructor.**' in v for v in lab._TRANSLATIONS['en'].values()) == 10

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for lang in ('fr', 'en'):
            for where, text in _all_texts(g1, ns1, lang):
                assert "{'" not in text, (lang, where)
                assert not re.search(r"(?<!\{)\{[a-z_][a-z_0-9]*\}(?!\})", text), (lang, where)
                assert '@@{' not in text or where != 'informations'
                markdown_to_html(text, show_instructor=True)
                markdown_to_html(text, show_instructor=False)
        resolved, numbering = resolve_informations(ns1.informations)
        for lang in ('fr', 'en'):
            assert [s.number for s in numbering.sections(lang) if s.level == 1] == [str(i) for i in range(1, 9)]
            assert [s.number for s in numbering.sections(lang) if s.level == 2] == [
                '1.1', '1.2', '1.3', '1.4', '1.5', '2.1', '2.2', '2.3', '4.1', '4.2', '6.1', '6.2', '6.3']
            informations = _text(resolved, lang)
            # the course holds neither the session specifics nor the passwords of the instance
            assert '@@' not in informations and 'Organisation du TP' not in informations, lang
            assert data.admin_password not in informations and data.person('dev1')['login'] not in informations
        informations = _text(resolved)
        assert '## <a id="acl"></a>5. Le contrôle d\'accès (ACL)' in informations
        assert '### <a id="sec.2.2"></a>2.2. Qui administre cn=config ? ldapi et SASL EXTERNAL' in informations
        assert '- [5. Le contrôle d\'accès (ACL)](#acl)' in informations and '(section [5](#acl))' in informations
        english = _text(resolved, 'en')
        assert '## <a id="acl"></a>5. Access control (ACLs)' in english
        # the references of the questions resolve to bare section numbers
        for q in g1.get_questions_ordered():
            description = resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering)
            for lang in ('fr', 'en'):
                assert '@@ref' not in description.resolve(lang)
        q7 = g1.get_questions_ordered()[7]
        assert 'section\n5' in resolve_text(TranslatedText.from_value(q7.description, 'fr'), numbering).resolve('fr') \
            or 'section 5' in resolve_text(TranslatedText.from_value(q7.description, 'fr'), numbering).resolve('fr')

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        fields = 0
        for q in g1.get_questions_ordered():
            for m in re.finditer(r'@@\{([^:}]+):([^}]*)\}@@', _text(q.description)):
                fields += 1
                assert '}' not in m.group(2)
        assert fields == 5
        kinds = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert kinds['rootdn'] == {'name': 'rootdn', 'regex': '.+'}
        assert kinds['backend'] == {'name': 'backend', 'choices': ['mdb', 'hdb', 'bdb', 'ldif']}
        assert kinds['rootpw'] == {'name': 'rootpw', 'choices': ['clear', 'hashed', 'absent']}
        assert set(kinds) == {'rootdn', 'backend', 'dbdir', 'schema', 'rootpw'}

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 10 and result.warnings == []
        stripped = tmp_path / 'ldap_stripped.py'
        stripped.write_bytes(result.data)
        assert b'_TRANSLATIONS' in result.data and b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('ldap_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        kept = module._TRANSLATIONS['en']
        assert set(module._TRANSLATIONS) == {'en'} and len(kept) == len(lab._TRANSLATIONS['en']) - 10
        assert not any('**Solution' in v or '**For the instructor.**' in v for v in kept.values())
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 100, 10)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements and part keys are English."""
        french = re.compile(r'(annuaire|utilisateur|groupe|mot|passe|serveur|client|personne|compte|reseau)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.PEOPLE_ROLES) + list(lab.GROUPS)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
