"""Tests for lib/tls.py."""
import hashlib
import sys
from contextlib import contextmanager
from pathlib import Path
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
