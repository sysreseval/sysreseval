"""Tests for lib/tls.py."""
import hashlib
import sys
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['Kathara.manager.Kathara'].Kathara = MagicMock()
sys.modules['Kathara.model.Lab'].Lab = MagicMock()

from tls import (
    eval_rsa_private_key,
    eval_self_signed_certificate,
    eval_certificate,
    eval_certificate_validity,
    eval_https_server,
    set_rsa_private_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PUBKEY = """\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234
-----END PUBLIC KEY-----"""

SUBJECT_CN = "subject=CN=myserver.example.com, O=MyOrg"
ISSUER_CN  = "issuer=CN=myserver.example.com, O=MyOrg"
SUBJECT_DIFFERENT = "subject=CN=myserver.example.com, O=MyOrg"
ISSUER_DIFFERENT  = "issuer=CN=otherCA.example.com, O=OtherOrg"
DATES = "notBefore=Jan  1 00:00:00 2024 GMT\nnotAfter=Jan  1 00:00:00 2025 GMT"
SERIAL = "serial=DEADBEEF"
FINGERPRINT = "SHA256 Fingerprint=AA:BB:CC:DD"

CERT_TEXT_SELF_SIGNED = """\
Certificate:
    Subject: CN=myserver.example.com, O=MyOrg
    Issuer:  CN=myserver.example.com, O=MyOrg
"""

CERT_TEXT_CA_SIGNED = """\
Certificate:
    Subject: CN=myserver.example.com, O=MyOrg
    Issuer:  CN=myCA.example.com, O=MyOrg
"""


def make_grade(responses: dict):
    """Grade mock whose grade.test(machine, command, step=...) dispatches by command."""
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 0))

    grade.test.side_effect = _test
    return grade


# ---------------------------------------------------------------------------
# eval_rsa_private_key
# ---------------------------------------------------------------------------

RSA_KEY_TEXT_4096 = "Private-Key: (4096 bit)\nRSA key stuff"
RSA_KEY_TEXT_2048 = "Private-Key: (2048 bit)\nRSA key stuff"
DEK_AES256 = "DEK-Info: AES-256-CBC,AABBCCDD"
DEK_DES3   = "DEK-Info: DES-EDE3-CBC,AABBCCDD"


class TestEvalRsaPrivateKey:
    def _responses(self, key_text, key_code=0, dek_text=''):
        return {
            "openssl rsa -in /key.pem -passin pass:secret -noout -text 2>&1": (key_text, key_code),
            "grep 'DEK-Info' /key.pem": (dek_text, 0),
        }

    def test_valid_4096_aes256(self):
        grade = make_grade(self._responses(RSA_KEY_TEXT_4096, dek_text=DEK_AES256))
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret') is True

    def test_wrong_bits(self):
        grade = make_grade(self._responses(RSA_KEY_TEXT_2048, dek_text=DEK_AES256))
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret') is False

    def test_expected_bits_match(self):
        grade = make_grade(self._responses(RSA_KEY_TEXT_2048, dek_text=DEK_AES256))
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret', bits=2048) is True

    def test_wrong_cipher(self):
        grade = make_grade(self._responses(RSA_KEY_TEXT_4096, dek_text=DEK_DES3))
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret') is False

    def test_cipher_case_insensitive(self):
        grade = make_grade(self._responses(RSA_KEY_TEXT_4096, dek_text="DEK-Info: aes-256-cbc,AABB"))
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret') is True

    def test_nonzero_exit_code(self):
        grade = make_grade(self._responses(RSA_KEY_TEXT_4096, key_code=1, dek_text=DEK_AES256))
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret') is False

    def test_no_bits_line(self):
        grade = make_grade(self._responses("RSA key, no bit info", dek_text=DEK_AES256))
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret') is False

    def test_no_password_wrong_cipher_still_fails(self):
        # Despite docstring, the code does not skip the cipher check when password=None;
        # if a DEK-Info line is present, the cipher is still validated.
        responses = {
            "openssl rsa -in /key.pem  -noout -text 2>&1": (RSA_KEY_TEXT_4096, 0),
            "grep 'DEK-Info' /key.pem": (DEK_DES3, 0),
        }
        grade = make_grade(responses)
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password=None) is False

    def test_no_dek_info_skips_cipher_check(self):
        # PKCS#8 key — no DEK-Info line
        grade = make_grade(self._responses(RSA_KEY_TEXT_4096, dek_text=''))
        assert eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret') is True

    def test_step_forwarded(self):
        grade = make_grade({})
        grade.test.return_value = ('', 1)
        eval_rsa_private_key(grade, 'r1', '/key.pem', password='secret', step=3)
        for c in grade.test.call_args_list:
            assert c.kwargs.get('step', c.args[2] if len(c.args) > 2 else 1) == 3


# ---------------------------------------------------------------------------
# eval_self_signed_certificate
# ---------------------------------------------------------------------------

def _self_signed_responses(pubkey_match=True, key_code=0, cert_code=0,
                            cert_pubkey_code=0, key_pubkey_code=0,
                            self_signed=True):
    cert_pubkey = PUBKEY
    key_pubkey  = PUBKEY if pubkey_match else PUBKEY + "_DIFFERENT"
    cert_text   = CERT_TEXT_SELF_SIGNED if self_signed else CERT_TEXT_CA_SIGNED
    return {
        "openssl pkey -in /key.pem -passin pass:secret -noout": ('', key_code),
        "openssl x509 -in /cert.pem -noout -text -fingerprint -sha256": (cert_text, cert_code),
        "openssl x509 -in /cert.pem -noout -pubkey": (cert_pubkey, cert_pubkey_code),
        "openssl pkey -in /key.pem -passin pass:secret -pubout": (key_pubkey, key_pubkey_code),
        "openssl x509 -in /cert.pem -noout -subject": (SUBJECT_CN, 0),
        "openssl x509 -in /cert.pem -noout -issuer": (ISSUER_CN, 0),
        "openssl x509 -in /cert.pem -noout -dates": (DATES, 0),
        "openssl x509 -in /cert.pem -noout -serial": (SERIAL, 0),
        "openssl x509 -in /cert.pem -noout -fingerprint -sha256": (FINGERPRINT, 0),
    }


class TestEvalSelfSignedCertificate:
    def _call(self, **kw):
        grade = make_grade(_self_signed_responses(**kw))
        return eval_self_signed_certificate(grade, 'r1', '/key.pem', '/cert.pem', 'secret')

    def test_valid_returns_dict(self):
        assert self._call() is not None

    def test_returns_subject(self):
        result = self._call()
        assert result['subject'] == "CN=myserver.example.com, O=MyOrg"

    def test_returns_issuer(self):
        result = self._call()
        assert result['issuer'] == "CN=myserver.example.com, O=MyOrg"

    def test_returns_common_name(self):
        result = self._call()
        assert result['common_name'] == 'myserver.example.com'

    def test_returns_dates(self):
        result = self._call()
        assert result['not_before'] == 'Jan  1 00:00:00 2024 GMT'
        assert result['not_after']  == 'Jan  1 00:00:00 2025 GMT'

    def test_returns_serial(self):
        result = self._call()
        assert result['serial'] == 'DEADBEEF'

    def test_returns_fingerprint(self):
        result = self._call()
        assert result['fingerprint'] == 'AA:BB:CC:DD'

    def test_key_code_nonzero_returns_none(self):
        assert self._call(key_code=1) is None

    def test_cert_code_nonzero_returns_none(self):
        assert self._call(cert_code=1) is None

    def test_pubkey_mismatch_returns_none(self):
        assert self._call(pubkey_match=False) is None

    def test_not_self_signed_returns_none(self):
        assert self._call(self_signed=False) is None

    def test_cert_pubkey_code_nonzero_returns_none(self):
        assert self._call(cert_pubkey_code=1) is None

    def test_key_pubkey_code_nonzero_returns_none(self):
        assert self._call(key_pubkey_code=1) is None

    def test_all_grade_test_calls_made_regardless_of_failure(self):
        """All test() calls must be issued even when key_code != 0 (registration pass)."""
        grade = make_grade(_self_signed_responses(key_code=1))
        eval_self_signed_certificate(grade, 'r1', '/key.pem', '/cert.pem', 'secret')
        assert grade.test.call_count == 9


# ---------------------------------------------------------------------------
# eval_certificate
# ---------------------------------------------------------------------------

def _cert_responses(pubkey_match=True, cert_code=0,
                    cert_pubkey_code=0, key_pubkey_code=0):
    cert_pubkey = PUBKEY
    key_pubkey  = PUBKEY if pubkey_match else PUBKEY + "_DIFFERENT"
    return {
        "openssl x509 -in /cert.pem -noout -text -fingerprint -sha256": (CERT_TEXT_CA_SIGNED, cert_code),
        "openssl x509 -in /cert.pem -noout -pubkey": (cert_pubkey, cert_pubkey_code),
        "openssl pkey -in /key.pem -pubout": (key_pubkey, key_pubkey_code),
        "openssl x509 -in /cert.pem -noout -subject": (SUBJECT_CN, 0),
        "openssl x509 -in /cert.pem -noout -issuer": (ISSUER_DIFFERENT, 0),
        "openssl x509 -in /cert.pem -noout -dates": (DATES, 0),
        "openssl x509 -in /cert.pem -noout -serial": (SERIAL, 0),
        "openssl x509 -in /cert.pem -noout -fingerprint -sha256": (FINGERPRINT, 0),
    }


class TestEvalCertificate:
    def _call(self, **kw):
        grade = make_grade(_cert_responses(**kw))
        return eval_certificate(grade, 'r1', '/key.pem', '/cert.pem')

    def test_valid_returns_dict(self):
        assert self._call() is not None

    def test_returns_common_name(self):
        result = self._call()
        assert result['common_name'] == 'myserver.example.com'

    def test_ca_signed_issuer_differs_from_subject(self):
        result = self._call()
        assert result['issuer'] != result['subject']

    def test_cert_code_nonzero_returns_none(self):
        assert self._call(cert_code=1) is None

    def test_pubkey_mismatch_returns_none(self):
        assert self._call(pubkey_match=False) is None

    def test_cert_pubkey_code_nonzero_returns_none(self):
        assert self._call(cert_pubkey_code=1) is None

    def test_key_pubkey_code_nonzero_returns_none(self):
        assert self._call(key_pubkey_code=1) is None

    def test_all_grade_test_calls_made_regardless_of_failure(self):
        grade = make_grade(_cert_responses(cert_code=1))
        eval_certificate(grade, 'r1', '/key.pem', '/cert.pem')
        assert grade.test.call_count == 8

    def test_step_forwarded(self):
        grade = make_grade(_cert_responses())
        eval_certificate(grade, 'r1', '/key.pem', '/cert.pem', step=2)
        for c in grade.test.call_args_list:
            assert c.kwargs.get('step', c.args[2] if len(c.args) > 2 else 1) == 2


# ---------------------------------------------------------------------------
# eval_certificate_validity
# ---------------------------------------------------------------------------

class TestEvalCertificateValidity:
    def test_valid(self):
        grade = make_grade({"openssl verify -CAfile /ca.pem /cert.pem": ('', 0)})
        assert eval_certificate_validity(grade, 'r1', '/cert.pem', '/ca.pem') is True

    def test_invalid(self):
        grade = make_grade({"openssl verify -CAfile /ca.pem /cert.pem": ('error', 1)})
        assert eval_certificate_validity(grade, 'r1', '/cert.pem', '/ca.pem') is False

    def test_step_forwarded(self):
        grade = make_grade({})
        grade.test.return_value = ('', 0)
        eval_certificate_validity(grade, 'r1', '/cert.pem', '/ca.pem', step=5)
        grade.test.assert_called_once_with(
            machine_name='r1',
            command='openssl verify -CAfile /ca.pem /cert.pem',
            step=5,
            allow_error=True,
        )


# ---------------------------------------------------------------------------
# eval_https_server
# ---------------------------------------------------------------------------

# Fake DER bytes and the fingerprint that results from them.
_FAKE_DER = b'\x01\x02\x03\x04'
_FAKE_FP_HEX = hashlib.sha256(_FAKE_DER).hexdigest()
CERT_FP = ':'.join(_FAKE_FP_HEX[i:i+2].upper() for i in range(0, len(_FAKE_FP_HEX), 2))
OTHER_FP = "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:" * 2  # different fp

FAKE_PEM = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"

@contextmanager
def _patch_der(der=_FAKE_DER):
    with patch('tls.ssl.PEM_cert_to_DER_cert', return_value=der):
        yield


def _https_responses(http_code=0, server_fp_code=0, fp_match=True):
    server_fp = f"SHA256 Fingerprint={CERT_FP}" if fp_match else f"SHA256 Fingerprint={OTHER_FP}"
    return {
        "curl -k -L --fail --connect-to ::10.0.0.1:443 -s -o /dev/null https://example.com/": ('', http_code),
        "openssl s_client -connect 10.0.0.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256": (server_fp, server_fp_code),
    }


class TestEvalHttpsServer:
    def _call(self, **kw):
        grade = make_grade(_https_responses(**kw))
        with _patch_der():
            return eval_https_server(grade, 'r1', 'https://example.com/', '10.0.0.1', FAKE_PEM)

    def test_valid(self):
        assert self._call() is True

    def test_http_failure(self):
        assert self._call(http_code=1) is False

    def test_server_fp_failure(self):
        assert self._call(server_fp_code=1) is False

    def test_fingerprint_mismatch(self):
        assert self._call(fp_match=False) is False

    def test_invalid_pem_returns_false(self):
        grade = make_grade(_https_responses())
        # No patch — real ssl.PEM_cert_to_DER_cert will raise on invalid PEM
        assert eval_https_server(grade, 'r1', 'https://example.com/', '10.0.0.1', 'not-a-cert') is False

    def test_all_grade_test_calls_made_on_http_failure(self):
        """Both test() calls must be issued even when http_code != 0 (registration pass)."""
        grade = make_grade(_https_responses(http_code=1))
        with _patch_der():
            eval_https_server(grade, 'r1', 'https://example.com/', '10.0.0.1', FAKE_PEM)
        assert grade.test.call_count == 2

    def test_custom_port(self):
        responses = {
            "curl -k -L --fail --connect-to ::10.0.0.1:8443 -s -o /dev/null https://example.com/": ('', 0),
            "openssl s_client -connect 10.0.0.1:8443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256": (f"SHA256 Fingerprint={CERT_FP}", 0),
        }
        grade = make_grade(responses)
        with _patch_der():
            assert eval_https_server(grade, 'r1', 'https://example.com/', '10.0.0.1', FAKE_PEM, server_port=8443) is True

    def test_step_forwarded(self):
        grade = make_grade(_https_responses())
        with _patch_der():
            eval_https_server(grade, 'r1', 'https://example.com/', '10.0.0.1', FAKE_PEM, step=4)
        for c in grade.test.call_args_list:
            assert c.kwargs.get('step') == 4

    def test_cert_pem_not_used_as_path(self):
        """The cert argument must not appear in any grade.test() command."""
        grade = make_grade(_https_responses())
        with _patch_der():
            eval_https_server(grade, 'r1', 'https://example.com/', '10.0.0.1', FAKE_PEM)
        for c in grade.test.call_args_list:
            assert FAKE_PEM not in c.kwargs.get('command', '')


# ---------------------------------------------------------------------------
# set_rsa_private_key
# ---------------------------------------------------------------------------

class TestSetRsaPrivateKey:
    def test_generates_key_command(self):
        ns = MagicMock()
        set_rsa_private_key(ns, 'r1', '/key.pem', password='secret')
        ns.cmd.assert_called_once_with(
            'r1',
            'openssl genrsa -aes-256-cbc -passout pass:secret -out /key.pem 4096',
        )

    def test_custom_bits_and_cipher(self):
        ns = MagicMock()
        set_rsa_private_key(ns, 'r1', '/key.pem', password='pw', bits=2048, cipher='DES-EDE3-CBC')
        ns.cmd.assert_called_once_with(
            'r1',
            'openssl genrsa -des-ede3-cbc -passout pass:pw -out /key.pem 2048',
        )


# ---------------------------------------------------------------------------
# Helpers shared by the tests of the new functions
# ---------------------------------------------------------------------------

from tls import (  # noqa: E402
    HttpResult,
    cert_sha256_hex,
    certificate_validity_days,
    eval_crl,
    eval_firefox_certificate,
    eval_pkcs12,
    get_certificate_san,
    get_crl_revoked_serials,
    get_nss_certificate_hashes,
    get_stepca_config,
    get_tls_server_certificate,
    https_get,
    normalize_serial,
    nss_hashes_command,
    parse_crl_text,
    parse_curl_output,
    parse_openssl_date,
    parse_san,
    parse_stepca_config,
)


def make_recording_grade(responses: dict | None = None, default=('', 0)):
    """Grade mock that records every call and dispatches by exact command string."""
    grade = MagicMock()
    responses = responses or {}

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, default)

    grade.test.side_effect = _test
    return grade


def commands_of(grade) -> list[str]:
    return [c.kwargs.get('command', c.args[1] if len(c.args) > 1 else '') for c in grade.test.call_args_list]


# ---------------------------------------------------------------------------
# eval_certificate_validity: -untrusted
# ---------------------------------------------------------------------------

class TestEvalCertificateValidityUntrusted:
    def test_untrusted_added(self):
        grade = make_grade({"openssl verify -CAfile /root.crt -untrusted /web3.crt /web3.crt": ('', 0)})
        assert eval_certificate_validity(grade, 'r1', '/web3.crt', '/root.crt', untrusted='/web3.crt') is True

    def test_untrusted_none_keeps_command(self):
        grade = make_grade({"openssl verify -CAfile /ca.pem /cert.pem": ('', 0)})
        assert eval_certificate_validity(grade, 'r1', '/cert.pem', '/ca.pem', untrusted=None) is True


# ---------------------------------------------------------------------------
# SAN / validity
# ---------------------------------------------------------------------------

SAN_OUT = "X509v3 Subject Alternative Name: \n    DNS:web.tp, DNS:www.web.tp\n"


class TestSan:
    def test_parse_two_dns(self):
        assert parse_san(SAN_OUT) == ['web.tp', 'www.web.tp']

    def test_parse_ip_entry(self):
        assert parse_san("    DNS:pki.tp, IP Address:10.1.2.3\n") == ['pki.tp', '10.1.2.3']

    def test_parse_empty(self):
        assert parse_san('') == []
        assert parse_san("No extensions matched with subjectAltName\n") == []

    def test_get_certificate_san(self):
        grade = make_grade({"openssl x509 -in /web.crt -noout -ext subjectAltName": (SAN_OUT, 0)})
        assert get_certificate_san(grade, 'ca', '/web.crt') == ['web.tp', 'www.web.tp']

    def test_get_certificate_san_error(self):
        grade = make_grade({"openssl x509 -in /web.crt -noout -ext subjectAltName": ('unable to load', 1)})
        assert get_certificate_san(grade, 'ca', '/web.crt') == []

    def test_step_forwarded(self):
        grade = make_recording_grade()
        get_certificate_san(grade, 'ca', '/web.crt', step=2)
        assert grade.test.call_args.kwargs['step'] == 2


class TestValidityDays:
    def test_parse_openssl_date(self):
        assert parse_openssl_date('Jan  1 00:00:00 2024 GMT').year == 2024
        assert parse_openssl_date('Oct  2 10:25:01 2026 GMT') == datetime(2026, 10, 2, 10, 25, 1)
        assert parse_openssl_date('bad') is None
        assert parse_openssl_date('Foo  2 10:25:01 2026 GMT') is None

    def test_parse_openssl_date_is_locale_independent(self):
        import locale
        try:
            locale.setlocale(locale.LC_TIME, 'fr_FR.UTF-8')
        except locale.Error:
            pytest.skip('fr_FR.UTF-8 locale not installed')
        try:
            assert parse_openssl_date('Oct  2 10:25:01 2026 GMT') == datetime(2026, 10, 2, 10, 25, 1)
        finally:
            locale.setlocale(locale.LC_TIME, 'C')

    def test_1825_days(self):
        cert = {'not_before': 'Mar  9 10:00:00 2026 GMT', 'not_after': 'Mar  8 10:00:00 2031 GMT'}
        assert certificate_validity_days(cert) == 1825

    def test_365_days(self):
        cert = {'not_before': 'Mar  9 10:00:00 2026 GMT', 'not_after': 'Mar  9 10:00:00 2027 GMT'}
        assert certificate_validity_days(cert) == 365

    def test_none(self):
        assert certificate_validity_days(None) is None
        assert certificate_validity_days({'not_before': 'x', 'not_after': 'y'}) is None


# ---------------------------------------------------------------------------
# CRL
# ---------------------------------------------------------------------------

CRL_TEXT = """\
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = ca.tp
        Last Update: Oct  2 12:00:00 2026 GMT
        Next Update: Nov  1 12:00:00 2026 GMT
        CRL extensions:
            X509v3 CRL Number: 
                4096
Revoked Certificates:
    Serial Number: 0B5C3A1F
        Revocation Date: Oct  2 11:59:00 2026 GMT
    Serial Number: 53524550524F4245
        Revocation Date: Oct  2 11:59:30 2026 GMT
    Signature Algorithm: sha256WithRSAEncryption
"""


class TestCrl:
    def test_normalize_serial(self):
        assert normalize_serial('0B:5C:3A:1F') == 'B5C3A1F'
        assert normalize_serial('0x0b5c3a1f') == 'B5C3A1F'
        assert normalize_serial(' 00 ') == '0'
        assert normalize_serial('') == '0'

    def test_parse_two_serials(self):
        assert parse_crl_text(CRL_TEXT) == ['B5C3A1F', '53524550524F4245']

    def test_parse_no_revoked(self):
        assert parse_crl_text("Certificate Revocation List (CRL):\nNo Revoked Certificates.\n") == []

    def test_get_crl_revoked_serials(self):
        grade = make_grade({"openssl crl -in /ca.crl -noout -text": (CRL_TEXT, 0)})
        assert get_crl_revoked_serials(grade, 'ca', '/ca.crl') == ['B5C3A1F', '53524550524F4245']

    def test_get_crl_revoked_serials_error(self):
        grade = make_grade({"openssl crl -in /ca.crl -noout -text": ('', 1)})
        assert get_crl_revoked_serials(grade, 'ca', '/ca.crl') == []

    def test_eval_crl_ok(self):
        grade = make_grade({"openssl crl -in /ca.crl -CAfile /ca.pem -noout 2>&1": ('verify OK\n', 0)})
        assert eval_crl(grade, 'ca', '/ca.crl', '/ca.pem') is True

    def test_eval_crl_failure(self):
        grade = make_grade({"openssl crl -in /ca.crl -CAfile /ca.pem -noout 2>&1": ('verify failure\n', 1)})
        assert eval_crl(grade, 'ca', '/ca.crl', '/ca.pem') is False
        grade = make_grade({"openssl crl -in /ca.crl -CAfile /ca.pem -noout 2>&1": ('verify failure\n', 0)})
        assert eval_crl(grade, 'ca', '/ca.crl', '/ca.pem') is False


# ---------------------------------------------------------------------------
# PKCS#12
# ---------------------------------------------------------------------------

P12_CERT_OUT = "subject=CN=alice42\nSHA256 Fingerprint=AA:BB:CC:DD\n"
P12_CA_OUT = f"Bag Attributes\n    friendlyName: ca.tp\n{FAKE_PEM}\n"


def _p12_responses(cert_code=0, key_code=0, ca_out=P12_CA_OUT, cert_out=P12_CERT_OUT):
    base = "openssl pkcs12 -in /client.p12 -passin pass:p12pw"
    return {
        f"{base} -nokeys -clcerts 2>/dev/null | openssl x509 -noout -subject -fingerprint -sha256": (cert_out, cert_code),
        f"{base} -nokeys -cacerts 2>/dev/null": (ca_out, 0),
        f"{base} -nocerts -nodes 2>/dev/null | openssl pkey -noout": ('', key_code),
    }


class TestEvalPkcs12:
    def test_valid(self):
        grade = make_grade(_p12_responses())
        with _patch_der():
            result = eval_pkcs12(grade, 'ca', '/client.p12', 'p12pw')
        assert result['common_name'] == 'alice42'
        assert result['fingerprint'] == 'AA:BB:CC:DD'
        assert result['ca_fingerprints'] == [CERT_FP]
        assert result['has_key'] is True

    def test_wrong_password(self):
        grade = make_grade(_p12_responses(cert_code=1, cert_out=''))
        assert eval_pkcs12(grade, 'ca', '/client.p12', 'p12pw') is None

    def test_no_ca_bag(self):
        grade = make_grade(_p12_responses(ca_out=''))
        result = eval_pkcs12(grade, 'ca', '/client.p12', 'p12pw')
        assert result['ca_fingerprints'] == []

    def test_no_key(self):
        grade = make_grade(_p12_responses(key_code=1))
        with _patch_der():
            assert eval_pkcs12(grade, 'ca', '/client.p12', 'p12pw')['has_key'] is False

    def test_all_calls_made(self):
        grade = make_grade(_p12_responses(cert_code=1))
        eval_pkcs12(grade, 'ca', '/client.p12', 'p12pw', step=2)
        assert grade.test.call_count == 3
        assert all(c.kwargs['step'] == 2 for c in grade.test.call_args_list)


# ---------------------------------------------------------------------------
# get_tls_server_certificate
# ---------------------------------------------------------------------------

S_CLIENT_OUT = "subject=CN=web3.tp\nissuer=O=ca tp, CN=ca tp Intermediate CA\nSHA256 Fingerprint=11:22\n"


class TestGetTlsServerCertificate:
    CMD = ("openssl s_client -connect 10.0.0.3:443 -servername web3.tp </dev/null 2>/dev/null"
           " | openssl x509 -noout -subject -issuer -fingerprint -sha256")

    def test_parse(self):
        grade = make_grade({self.CMD: (S_CLIENT_OUT, 0)})
        result = get_tls_server_certificate(grade, 'h1', '10.0.0.3', 443, servername='web3.tp')
        assert result == {'subject': 'CN=web3.tp', 'issuer': 'O=ca tp, CN=ca tp Intermediate CA',
                          'common_name': 'web3.tp', 'fingerprint': '11:22'}

    def test_no_sni(self):
        cmd = ("openssl s_client -connect 10.0.0.3:9000 </dev/null 2>/dev/null"
               " | openssl x509 -noout -subject -issuer -fingerprint -sha256")
        grade = make_grade({cmd: (S_CLIENT_OUT, 0)})
        assert get_tls_server_certificate(grade, 'h1', '10.0.0.3', 9000)['common_name'] == 'web3.tp'

    def test_failure(self):
        grade = make_grade({self.CMD: ('unable to load certificate', 1)})
        assert get_tls_server_certificate(grade, 'h1', '10.0.0.3', 443, servername='web3.tp') is None


# ---------------------------------------------------------------------------
# https_get / parse_curl_output
# ---------------------------------------------------------------------------

CURL_200 = ("HTTP/1.1 200 OK\r\nServer: nginx\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains\r\n"
            "\r\n<html>the secret</html>\n===SRE_CODE 200")
CURL_400 = ("HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n<html>\n<head><title>400 No required SSL certificate "
            "was sent</title></head>\n</html>\n===SRE_CODE 400")
CURL_60 = "curl: (60) SSL certificate problem: unable to get local issuer certificate\n===SRE_CODE 000"


class TestParseCurlOutput:
    def test_200(self):
        r = parse_curl_output(CURL_200, 0)
        assert r.code == 200 and r.ok
        assert r.headers['strict-transport-security'].startswith('max-age=63072000')
        assert r.body == '<html>the secret</html>\n'

    def test_400(self):
        r = parse_curl_output(CURL_400, 22)
        assert r.code == 400 and not r.ok
        assert 'No required SSL certificate' in r.body

    def test_tls_failure(self):
        r = parse_curl_output(CURL_60, 60)
        assert r.code is None and r.headers == {} and r.exit_code == 60
        assert 'certificate problem' in r.body

    def test_empty(self):
        r = parse_curl_output('', 0)
        assert r == HttpResult(code=None, headers={}, body='', exit_code=0)


class TestHttpsGet:
    def test_command_and_result(self):
        grade = make_recording_grade(default=(CURL_200, 0))
        r = https_get(grade, 'h1', 'https://web.tp/', '10.0.0.2', cacert='/tmp/sre_tls/ca.tp.pem',
                      cert='/tmp/sre_tls/c.crt', key='/tmp/sre_tls/c.key', step=2, timeout=15)
        assert r.code == 200
        cmd = grade.test.call_args.kwargs['command']
        assert "--resolve web.tp:443:10.0.0.2" in cmd
        assert "--cacert /tmp/sre_tls/ca.tp.pem --cert /tmp/sre_tls/c.crt --key /tmp/sre_tls/c.key" in cmd
        assert "--max-time 12" in cmd and cmd.endswith("https://web.tp/ 2>&1")
        assert "-k" not in cmd.split()
        assert grade.test.call_args.kwargs['step'] == 2
        assert grade.test.call_args.kwargs['timeout'] == 15

    def test_insecure_and_port(self):
        grade = make_recording_grade(default=(CURL_60, 60))
        r = https_get(grade, 'h1', 'https://pki.tp:9000/health', '10.0.0.9', port=9000, insecure=True)
        assert r.code is None and r.exit_code == 60
        cmd = grade.test.call_args.kwargs['command']
        assert "--resolve pki.tp:9000:10.0.0.9" in cmd and " -k " in cmd


# ---------------------------------------------------------------------------
# Firefox NSS store
# ---------------------------------------------------------------------------

class TestFirefoxCertificate:
    def test_command_is_a_one_liner(self):
        cmd = nss_hashes_command('/home/etudiant')
        assert "\n" not in cmd and "@@@" not in cmd
        assert cmd.startswith('python3 -c "import base64; exec(base64.b64decode(')
        import base64 as _b64
        script = _b64.b64decode(cmd.split("b64decode('", 1)[1].split("')", 1)[0]).decode()
        assert "'/home/etudiant'" in script and "mode=ro&immutable=1" in script
        assert "nssPublic" in script and "b'\\x30'" in script
        compile(script, 'nss', 'exec')

    def test_hashes_parsed(self):
        h = 'a' * 64
        grade = make_recording_grade(default=(f"{h}\nnot a hash\n{'b' * 64}\n", 0))
        assert get_nss_certificate_hashes(grade, 'm1') == {h, 'b' * 64}

    def test_hashes_error(self):
        grade = make_recording_grade(default=('a' * 64, 1))
        assert get_nss_certificate_hashes(grade, 'm1') == set()

    def test_eval_firefox_certificate(self):
        with _patch_der():
            wanted = cert_sha256_hex(FAKE_PEM)
            grade = make_recording_grade(default=(wanted + "\n", 0))
            assert eval_firefox_certificate(grade, 'm1', FAKE_PEM) is True
            grade = make_recording_grade(default=('c' * 64 + "\n", 0))
            assert eval_firefox_certificate(grade, 'm1', FAKE_PEM) is False

    def test_invalid_pem(self):
        grade = make_recording_grade(default=('', 0))
        assert cert_sha256_hex('nope') == ''
        assert eval_firefox_certificate(grade, 'm1', 'nope') is False


# ---------------------------------------------------------------------------
# step-ca configuration
# ---------------------------------------------------------------------------

CA_JSON = """{
  "root": "/home/ca/.step/certs/root_ca.crt",
  "address": ":9000",
  "dnsNames": ["pki.tp", "ca.tp"],
  "authority": {"provisioners": [
    {"type": "JWK", "name": "admin@ca.tp", "key": {"kty": "EC"}},
    {"type": "ACME", "name": "acme"}
  ]}
}"""


class TestStepcaConfig:
    def test_parse(self):
        cfg = parse_stepca_config(CA_JSON)
        assert cfg['address'] == ':9000'
        assert cfg['dns_names'] == ['pki.tp', 'ca.tp']
        assert cfg['root'].endswith('root_ca.crt')
        assert cfg['provisioners'] == [{'name': 'admin@ca.tp', 'type': 'JWK'}, {'name': 'acme', 'type': 'ACME'}]

    def test_parse_invalid(self):
        assert parse_stepca_config('') is None
        assert parse_stepca_config('[1, 2]') is None
        assert parse_stepca_config('{}') == {'address': '', 'dns_names': [], 'root': '', 'provisioners': []}

    def test_get_stepca_config(self):
        grade = make_grade({"cat /home/ca/.step/config/ca.json": (CA_JSON, 0)})
        assert get_stepca_config(grade, 'ca')['address'] == ':9000'

    def test_get_stepca_config_missing(self):
        grade = make_grade({"cat /home/ca/.step/config/ca.json": ('No such file', 1)})
        assert get_stepca_config(grade, 'ca') is None


class TestOpenssl3Fingerprint:
    """OpenSSL 3 prints the digest name in lower case."""

    def test_served_certificate_lowercase(self):
        cmd = ("openssl s_client -connect 10.0.0.3:443 -servername web.tp </dev/null 2>/dev/null"
               " | openssl x509 -noout -subject -issuer -fingerprint -sha256")
        grade = make_grade({cmd: ("subject=CN = web.tp\nissuer=CN = ca.tp\nsha256 Fingerprint=AA:BB\n", 0)})
        r = get_tls_server_certificate(grade, 'h1', '10.0.0.3', 443, servername='web.tp')
        assert r['fingerprint'] == 'AA:BB' and r['common_name'] == 'web.tp'

    def test_empty_subject_acme_certificate(self):
        cmd = ("openssl s_client -connect 10.0.0.3:443 -servername web3.tp </dev/null 2>/dev/null"
               " | openssl x509 -noout -subject -issuer -fingerprint -sha256")
        grade = make_grade({cmd: ("subject=\nissuer=O = ca tp, CN = ca tp Intermediate CA\nsha256 Fingerprint=56:20\n", 0)})
        r = get_tls_server_certificate(grade, 'h1', '10.0.0.3', 443, servername='web3.tp')
        assert r == {'subject': '', 'issuer': 'O = ca tp, CN = ca tp Intermediate CA', 'common_name': '',
                     'fingerprint': '56:20'}

    def test_eval_certificate_lowercase_fingerprint(self):
        responses = _cert_responses()
        responses["openssl x509 -in /cert.pem -noout -fingerprint -sha256"] = ("sha256 Fingerprint=AA:BB:CC:DD", 0)
        grade = make_grade(responses)
        assert eval_certificate(grade, 'r1', '/key.pem', '/cert.pem')['fingerprint'] == 'AA:BB:CC:DD'


# ---------------------------------------------------------------------------
# Real outputs captured on 2026-10-02 in sysreseval/base:1.28 containers (OpenSSL 3.0.20,
# nginx 1.22, apache2 2.4, step-ca 0.30.2) during the live validation of the TLS lab.
# ---------------------------------------------------------------------------

from pathlib import Path as _Path  # noqa: E402

_FIXTURES = _Path(__file__).parent / 'mock_data' / 'tls'


def _fixture(name: str) -> str:
    return (_FIXTURES / name).read_text()


class TestLiveFixtures:
    def test_crl_lists_the_revoked_serial_of_index_txt(self):
        serials = parse_crl_text(_fixture('crl_text.txt'))
        revoked = [normalize_serial(l.split('\t')[3]) for l in _fixture('index.txt').splitlines() if l.startswith('R')]
        assert len(serials) == 1 and serials == revoked

    def test_san_openssl3(self):
        assert parse_san(_fixture('san.txt')) == ['web.tp', 'www.web.tp']

    def test_stepca_config(self):
        cfg = parse_stepca_config(_fixture('ca.json'))
        assert cfg['address'] == ':9000' and 'pki.tp' in cfg['dns_names']
        assert {'name': 'admin@ca.tp', 'type': 'JWK'} in cfg['provisioners']
        assert {'name': 'acme', 'type': 'ACME'} in cfg['provisioners']

    def test_nginx_400_without_client_certificate(self):
        r = parse_curl_output(_fixture('curl_400_no_client_cert.txt'), 22)
        assert r.code == 400 and 'No required SSL certificate was sent' in r.body
        assert r.headers['server'].startswith('nginx')

    def test_apache_200_with_hsts(self):
        r = parse_curl_output(_fixture('curl_200_hsts.txt'), 0)
        assert r.ok and 'max-age=63072000' in r.headers['strict-transport-security']
        assert '<p>' in r.body

    def test_acme_certificate_has_empty_subject(self):
        cmd = ("openssl s_client -connect 10.0.0.3:443 -servername web3.tp </dev/null 2>/dev/null"
               " | openssl x509 -noout -subject -issuer -fingerprint -sha256")
        grade = make_grade({cmd: (_fixture('s_client_acme.txt'), 0)})
        r = get_tls_server_certificate(grade, 'h1', '10.0.0.3', 443, servername='web3.tp')
        assert r['subject'] == '' and r['common_name'] == ''
        assert r['issuer'] == 'O = ca tp, CN = ca tp Intermediate CA'
        assert len(r['fingerprint']) == 95

    def test_pkcs12_client_certificate_openssl3(self):
        base = "openssl pkcs12 -in /client.p12 -passin pass:pw"
        grade = make_grade({
            f"{base} -nokeys -clcerts 2>/dev/null | openssl x509 -noout -subject -fingerprint -sha256":
                (_fixture('pkcs12_clcerts.txt'), 0),
            f"{base} -nokeys -cacerts 2>/dev/null": ('', 0),
            f"{base} -nocerts -nodes 2>/dev/null | openssl pkey -noout": ('', 0),
        })
        r = eval_pkcs12(grade, 'ca', '/client.p12', 'pw')
        assert r['common_name'] and r['fingerprint'] and r['has_key'] and r['ca_fingerprints'] == []


class TestEvalHttpsServerIPv6:
    def test_ipv6_server_ip_is_bracketed(self):
        responses = {
            "curl -k -L --fail --connect-to ::[fd00::1]:443 -s -o /dev/null https://example.com/": ('', 0),
            "openssl s_client -connect [fd00::1]:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256": (f"SHA256 Fingerprint={CERT_FP}", 0),
        }
        grade = make_grade(responses)
        with _patch_der():
            assert eval_https_server(grade, 'r1', 'https://example.com/', 'fd00::1', FAKE_PEM) is True

    def test_interface_objects_accepted(self):
        from ipaddress import IPv4Interface, IPv6Interface
        grade = make_grade(_https_responses())
        with _patch_der():
            assert eval_https_server(grade, 'r1', 'https://example.com/', IPv4Interface('10.0.0.1/24'), FAKE_PEM) is True
        responses = {
            "curl -k -L --fail --connect-to ::[fd00::1]:8443 -s -o /dev/null https://example.com/": ('', 0),
            "openssl s_client -connect [fd00::1]:8443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256": (f"SHA256 Fingerprint={CERT_FP}", 0),
        }
        grade = make_grade(responses)
        with _patch_der():
            assert eval_https_server(grade, 'r1', 'https://example.com/', IPv6Interface('fd00::1/64'), FAKE_PEM,
                                     server_port=8443) is True


def test_generate_ca_pem():
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from tls import generate_ca_pem
    cert_pem, key_pem = generate_ca_pem("ca.tp", days=30)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    assert cert.subject.rfc4514_string() == "CN=ca.tp" and cert.issuer == cert.subject
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----") and key_pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
