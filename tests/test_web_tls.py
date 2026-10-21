"""Mutual TLS between the portal and an agent: certificates of one private CA generated here
(cryptography), the agent served with the CA-verified client certificate required, the portal's
pool reaching it with its client certificate and failing without it or with another CA's."""
import asyncio
import datetime
import ipaddress
import logging
import socket
import ssl

import pytest

cryptography = pytest.importorskip('cryptography')
aiohttp = pytest.importorskip('aiohttp')
from aiohttp import web  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID  # noqa: E402

from sreweb.agent.app import Agent  # noqa: E402
from sreweb.config import agent_config_from_dict, HostConfig, web_config_from_dict  # noqa: E402
from sreweb.portal.app import Portal  # noqa: E402
from sreweb.portal.pool import Pool  # noqa: E402

TOKEN = 't' * 32
HEADERS = {'Authorization': f'Bearer {TOKEN}'}


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, key, cert):
    path.with_suffix('.key').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                            serialization.NoEncryption()))
    path.with_suffix('.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_ca(directory, cn):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    _write(directory / 'ca', key, cert)
    return key, cert


def make_cert(directory, name, ca_key, ca_cert, *, server: bool, sans=()):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(ca_cert.subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                            content_commitment=False, key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server
                                                     else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address(s)) for s in sans]), critical=False)
    _write(directory / name, key, builder.sign(ca_key, hashes.SHA256()))


@pytest.fixture
def pki(tmp_path):
    """The CA, the agent's certificate (IP 127.0.0.1), the portal's client certificate, and under
    other/ a client certificate of another CA."""
    d = tmp_path / 'pki'
    d.mkdir()
    ca_key, ca_cert = make_ca(d, 'SRE test CA')
    make_cert(d, 'agent', ca_key, ca_cert, server=True, sans=['127.0.0.1'])
    make_cert(d, 'portal', ca_key, ca_cert, server=False)
    other = d / 'other'
    other.mkdir()
    other_key, other_cert = make_ca(other, 'another CA')
    make_cert(other, 'portal', other_key, other_cert, server=False)
    return d


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


async def run_agent(tmp_path, pki, port):
    """The agent on https://127.0.0.1:port with its certificate, client certificates of the CA required."""
    cfg = agent_config_from_dict({'token': TOKEN, 'sre_exe': '/bin/false', 'tls_cert': str(pki / 'agent.crt'),
                                  'tls_key': str(pki / 'agent.key'), 'tls_ca': str(pki / 'ca.crt')},
                                 sre_exe='/bin/false', state_dir=str(tmp_path / 'state'))
    (tmp_path / 'pub' / 'projects').mkdir(parents=True)
    agent = Agent(cfg, pub_dir=str(tmp_path / 'pub'), projects_dir=str(tmp_path / 'pub' / 'projects'), localedirs=[],
                  hostname='tls-agent')
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=cfg.tls_ca)
    context.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    context.verify_mode = ssl.CERT_REQUIRED
    runner = web.AppRunner(agent.make_app())
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', port, ssl_context=context).start()
    return runner


def portal_context(pki, *, client=True, ca=None):
    cfg = web_config_from_dict({'secret': 's' * 32, 'hosts': [{'name': 'a', 'url': 'https://127.0.0.1:1', 'token': TOKEN}],
                                'pool': {'ca': str(ca or pki / 'ca.crt'),
                                         **({'client_cert': str(pki / 'portal.crt'), 'client_key': str(pki / 'portal.key')}
                                            if client else {})}})
    return Portal(cfg, web_dir=str(pki), localedirs=[]).client_ssl_context()


async def status_through_pool(context, port):
    host = HostConfig('a', f'https://127.0.0.1:{port}', TOKEN)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=context)) as session:
        pool = Pool([host], session)
        return await pool.refresh_host(host)


def test_mutual_tls(tmp_path, pki, caplog):
    async def go():
        port = free_port()
        runner = await run_agent(tmp_path, pki, port)
        try:
            # the portal with its client certificate: the agent answers
            status = await status_through_pool(portal_context(pki), port)
            assert status.reachable and status.hostname == 'tls-agent', status
            # a client without a certificate fails at the handshake
            with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
                status = await status_through_pool(portal_context(pki, client=False), port)
            assert not status.reachable and status.error
            assert 'unreachable' in caplog.text
            # a client certificate of another CA fails too
            status = await status_through_pool(portal_context(pki / 'other', ca=pki / 'ca.crt'), port)
            assert not status.reachable
            # a portal trusting another CA refuses the agent's certificate
            status = await status_through_pool(portal_context(pki, ca=pki / 'other' / 'ca.crt'), port)
            assert not status.reachable
            # plain HTTP on the TLS port fails as well
            async with aiohttp.ClientSession() as session:
                with pytest.raises(aiohttp.ClientError):
                    await session.get(f'http://127.0.0.1:{port}/v1/status', headers=HEADERS,
                                      timeout=aiohttp.ClientTimeout(total=5))
        finally:
            await runner.cleanup()
    asyncio.run(go())


def test_client_context_without_tls_settings(pki):
    cfg = web_config_from_dict({'secret': 's' * 32, 'hosts': [{'name': 'a', 'url': 'http://127.0.0.1:1', 'token': TOKEN}]})
    assert Portal(cfg, web_dir=str(pki), localedirs=[]).client_ssl_context() is None
