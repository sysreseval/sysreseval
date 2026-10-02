import base64
import hashlib
import json
import re
import shlex
import ssl
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv6Interface
from datetime import datetime
from urllib.parse import urlparse

from SRE.lib_sre import Grade0, NetScheme0


def _cert_fingerprint_sha256(pem: str) -> str:
    """Return the SHA256 fingerprint of a PEM certificate as XX:XX:... uppercase hex."""
    der = ssl.PEM_cert_to_DER_cert(pem.strip())
    digest = hashlib.sha256(der).hexdigest()
    return ':'.join(digest[i:i + 2].upper() for i in range(0, len(digest), 2))


def _val(line, prefix):
    # OpenSSL 3 prints "sha256 Fingerprint=", OpenSSL 1.1 "SHA256 Fingerprint=": ignore the case.
    m = re.search(rf'{prefix}=(.+)', line, flags=re.IGNORECASE)
    return m.group(1).strip() if m else ''


def _cert_dict(subject_out, issuer_out, dates_out, serial_out, fingerprint_out):
    not_before_m = re.search(r'notBefore=(.+)', dates_out)
    not_after_m  = re.search(r'notAfter=(.+)',  dates_out)
    subject = _val(subject_out, "subject")
    cn_m = re.search(r'(?:^|[,/]\s*)CN\s*=\s*([^,/]+)', subject)
    return {
        "subject":      subject,
        "issuer":       _val(issuer_out,      "issuer"),
        "common_name":  cn_m.group(1).strip() if cn_m else '',
        "not_before":   not_before_m.group(1).strip() if not_before_m else '',
        "not_after":    not_after_m.group(1).strip()  if not_after_m  else '',
        "serial":       _val(serial_out,      "serial"),
        "fingerprint":  _val(fingerprint_out, "SHA256 Fingerprint"),
    }


def eval_rsa_private_key(grade: Grade0, machine_name: str, key_file: str,
                         password: str | None = None, bits: int = 4096,
                         cipher: str = "AES-256-CBC",
                         step: int = 1) -> bool:
    """Check that key_file is an RSA private key with the expected properties.

    Verifies:
    - The file is an RSA private key (decryptable with password if provided).
    - The key size matches bits.
    - The encryption cipher in the PEM header matches cipher (case-insensitive).
      This applies to traditional PEM format (BEGIN RSA PRIVATE KEY); for
      PKCS#8 (BEGIN ENCRYPTED PRIVATE KEY) the cipher check is skipped.
      The cipher check is also skipped when password is None.

    Args:
        grade:        the Grade0 instance.
        machine_name: name of the virtual machine to inspect.
        key_file:     absolute path to the private key file on the machine.
        password:     passphrase protecting the private key, or None if unencrypted.
        bits:         expected RSA key size (default: 4096).
        cipher:       expected PEM encryption cipher (default: 'AES-256-CBC').
        step:         step number passed to grade.test() (default: 1).

    Returns:
        True if all checks pass, False otherwise.
    """
    passin = f"-passin {shlex.quote(f'pass:{password}')}" if password is not None else ""
    q_key_file = shlex.quote(key_file)
    key_text, key_code = grade.test(
        machine_name=machine_name,
        command=f"openssl rsa -in {q_key_file} {passin} -noout -text 2>&1",
        step=step,
        allow_error=True,
    )
    dek_info, _ = grade.test(
        machine_name=machine_name,
        command=f"grep 'DEK-Info' {q_key_file}",
        step=step,
        allow_error=True,
    )

    if key_code != 0:
        return False

    bits_m = re.search(r'Private-Key:\s*\((\d+)\s*bit', key_text)
    if not bits_m or int(bits_m.group(1)) != bits:
        return False

    # DEK-Info line only present in traditional PEM format; skip cipher check for PKCS#8
    if dek_info.strip():
        dek_m = re.search(r'DEK-Info:\s*([^,\s]+)', dek_info)
        if not dek_m or dek_m.group(1).upper() != cipher.upper():
            return False

    return True


def set_rsa_private_key(net_scheme: NetScheme0, machine_name: str, key_file: str,
                        password: str, bits: int = 4096,
                        cipher: str = "AES-256-CBC"):
    """Generate an RSA private key on machine_name.

    Args:
        net_scheme:   the NetScheme0 instance.
        machine_name: name of the virtual machine.
        key_file:     absolute path where the key will be written on the machine.
        password:     passphrase to protect the key.
        bits:         RSA key size in bits (default: 4096).
        cipher:       PEM encryption cipher (default: 'AES-256-CBC').
    """
    net_scheme.cmd(machine_name,
                   f"openssl genrsa -{shlex.quote(cipher.lower())} -passout {shlex.quote(f'pass:{password}')} -out {shlex.quote(key_file)} {bits}")


def eval_self_signed_certificate(grade: Grade0, machine_name: str,
                                 key_file: str, cert_file: str,
                                 password: str,
                                 step: int = 1) -> dict | None:
    """Check that key_file and cert_file are a password-protected TLS key and
    a matching self-signed certificate on machine_name.

    Verifies:
    - key_file is a valid PEM private key decryptable with password.
    - cert_file is a valid PEM certificate whose Issuer equals its Subject
      (self-signed).
    - The public key in the certificate matches the private key.

    Args:
        grade:        the Grade0 instance.
        machine_name: name of the virtual machine to inspect.
        key_file:     absolute path to the private key file on the machine.
        cert_file:    absolute path to the certificate file on the machine.
        password:     passphrase protecting the private key.
        step:         step number passed to grade.test() (default: 1).

    Returns:
        A dict with certificate fields (subject, issuer, not_before, not_after,
        serial, fingerprint) if all checks pass, None otherwise.
    """
    # All grade.test() calls must be made unconditionally so they are registered
    # in the first (registration) pass and carry real results in the second pass.
    q_key_file = shlex.quote(key_file)
    q_cert_file = shlex.quote(cert_file)
    q_passin = shlex.quote(f'pass:{password}')
    _, key_code = grade.test(
        machine_name=machine_name,
        command=f"openssl pkey -in {q_key_file} -passin {q_passin} -noout",
        step=step,
        allow_error=True,
    )
    cert_text, cert_code = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -text -fingerprint -sha256",
        step=step,
        allow_error=True,
    )
    cert_pubkey, cert_pubkey_code = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -pubkey",
        step=step,
        allow_error=True,
    )
    key_pubkey, key_pubkey_code = grade.test(
        machine_name=machine_name,
        command=f"openssl pkey -in {q_key_file} -passin {q_passin} -pubout",
        step=step,
        allow_error=True,
    )
    subject_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -subject",
        step=step,
        allow_error=True,
    )
    issuer_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -issuer",
        step=step,
        allow_error=True,
    )
    dates_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -dates",
        step=step,
        allow_error=True,
    )
    serial_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -serial",
        step=step,
        allow_error=True,
    )
    fingerprint_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -fingerprint -sha256",
        step=step,
        allow_error=True,
    )

    if key_code != 0 or cert_code != 0 or cert_pubkey_code != 0 or key_pubkey_code != 0:
        return None

    if cert_pubkey.strip() != key_pubkey.strip():
        return None

    # Check self-signed: Subject must equal Issuer
    subject_m = re.search(r'Subject:\s*(.+)', cert_text)
    issuer_m  = re.search(r'Issuer:\s*(.+)',  cert_text)
    if not subject_m or not issuer_m:
        return None
    if subject_m.group(1).strip() != issuer_m.group(1).strip():
        return None

    return _cert_dict(subject_out, issuer_out, dates_out, serial_out, fingerprint_out)


def eval_certificate(grade: Grade0, machine_name: str,
                     key_file: str, cert_file: str,
                     step: int = 1) -> dict | None:
    """Check that key_file and cert_file are a matching TLS key pair on machine_name.

    Verifies:
    - cert_file is a valid PEM certificate.
    - The public key in the certificate matches the private key in key_file.

    Args:
        grade:        the Grade0 instance.
        machine_name: name of the virtual machine to inspect.
        key_file:     absolute path to the private key file on the machine.
        cert_file:    absolute path to the certificate file on the machine.
        step:         step number passed to grade.test() (default: 1).

    Returns:
        A dict with certificate fields (subject, issuer, common_name,
        not_before, not_after, serial, fingerprint) if all checks pass,
        None otherwise.
    """
    # All grade.test() calls must be made unconditionally so they are registered
    # in the first (registration) pass and carry real results in the second pass.
    q_key_file = shlex.quote(key_file)
    q_cert_file = shlex.quote(cert_file)
    _, cert_code = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -text -fingerprint -sha256",
        step=step,
        allow_error=True,
    )
    cert_pubkey, cert_pubkey_code = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -pubkey",
        step=step,
        allow_error=True,
    )
    key_pubkey, key_pubkey_code = grade.test(
        machine_name=machine_name,
        command=f"openssl pkey -in {q_key_file} -pubout",
        step=step,
        allow_error=True,
    )
    subject_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -subject",
        step=step,
        allow_error=True,
    )
    issuer_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -issuer",
        step=step,
        allow_error=True,
    )
    dates_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -dates",
        step=step,
        allow_error=True,
    )
    serial_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -serial",
        step=step,
        allow_error=True,
    )
    fingerprint_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {q_cert_file} -noout -fingerprint -sha256",
        step=step,
        allow_error=True,
    )

    if cert_code != 0 or cert_pubkey_code != 0 or key_pubkey_code != 0:
        return None

    if cert_pubkey.strip() != key_pubkey.strip():
        return None

    return _cert_dict(subject_out, issuer_out, dates_out, serial_out, fingerprint_out)


def eval_certificate_validity(grade: Grade0, machine_name: str,
                              cert_file: str, ca_cert_file: str,
                              step: int = 1, untrusted: str | None = None) -> bool:
    """Check that cert_file is signed by ca_cert_file on machine_name.

    Args:
        grade:        the Grade0 instance.
        machine_name: name of the virtual machine to inspect.
        cert_file:    absolute path to the certificate file on the machine.
        ca_cert_file: absolute path to the CA certificate file on the machine.
        step:         step number passed to grade.test() (default: 1).
        untrusted:    optional PEM file of intermediate certificates (``-untrusted``),
                      e.g. the leaf bundle written by step-ca whose second block is the
                      intermediate CA.

    Returns:
        True if cert_file is a valid certificate chaining to ca_cert_file,
        False otherwise.
    """
    untrusted_opt = f" -untrusted {shlex.quote(untrusted)}" if untrusted else ""
    _, verify_code = grade.test(
        machine_name=machine_name,
        command=f"openssl verify -CAfile {shlex.quote(ca_cert_file)}{untrusted_opt} {shlex.quote(cert_file)}",
        step=step,
        allow_error=True,
    )
    return verify_code == 0


def _bracketed(ip) -> str:
    """The address for curl / openssl: an IPv6 address goes between brackets.

    *ip* may be a string or an ``ipaddress`` Address / Interface object (prefix stripped).
    """
    host = str(ip.ip) if isinstance(ip, (IPv4Interface, IPv6Interface)) else str(ip)
    return f'[{host}]' if ':' in host else host


def _host_port(ip, port: int) -> str:
    """``host:port`` for curl / openssl, with the brackets an IPv6 address needs."""
    return f'{_bracketed(ip)}:{port}'


def eval_https_server(grade: Grade0, machine_name: str, url: str,
                      server_ip, cert: str,
                      server_port: int = 443, step: int = 1) -> bool:
    """Check that an HTTPS server at server_ip responds correctly and presents
    the expected certificate.

    Verifies:
    - A GET request to url (routed to server_ip:server_port) succeeds (2xx).
    - The certificate presented by the server matches cert.

    Args:
        grade:        the Grade0 instance.
        machine_name: name of the virtual machine from which to connect.
        url:          full URL to request (e.g. https://myserver/index.html).
        server_ip:    IP address of the HTTPS server to connect to (IPv4 or IPv6, as a
                      string or an ``ipaddress`` object; IPv6 is bracketed automatically).
        cert:         PEM certificate content to verify against the server.
        server_port:  HTTPS port (default: 443).
        step:         step number passed to grade.test() (default: 1).

    Returns:
        True if all checks pass, False otherwise.
    """
    # All grade.test() calls must be made unconditionally so they are registered
    # in the first (registration) pass and carry real results in the second pass.
    _, http_code = grade.test(
        machine_name=machine_name,
        command=f"curl -k -L --fail --connect-to ::{_host_port(server_ip, server_port)}"
                f" -s -o /dev/null {url}",
        step=step,
        allow_error=True,
    )
    server_fp, server_fp_code = grade.test(
        machine_name=machine_name,
        command=f"openssl s_client -connect {_host_port(server_ip, server_port)}"
                f" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256",
        step=step,
        allow_error=True,
    )

    if http_code != 0:
        return False
    if server_fp_code != 0:
        return False

    try:
        cert_fp_val = _cert_fingerprint_sha256(cert)
    except Exception:
        return False

    server_fp_val = _val(server_fp, "SHA256 Fingerprint")
    return bool(server_fp_val) and server_fp_val == cert_fp_val


# ---------------------------------------------------------------------------
# Certificate details: SAN, validity period
# ---------------------------------------------------------------------------

def parse_san(text: str) -> list[str]:
    """Return the DNS and IP entries of an ``openssl x509 -ext subjectAltName`` output.

    ``DNS:web.tp, DNS:www.web.tp, IP Address:10.0.0.1`` -> ``['web.tp', 'www.web.tp', '10.0.0.1']``.
    """
    return [m.group(1).strip() for m in re.finditer(r'(?:DNS|IP Address)\s*:\s*([^,\s]+)', text or '')]


def get_certificate_san(grade: Grade0, machine_name: str, cert_file: str,
                        step: int = 1) -> list[str]:
    """DNS/IP names of the subjectAltName extension of cert_file (``[]`` when absent or on error)."""
    out, code = grade.test(
        machine_name=machine_name,
        command=f"openssl x509 -in {shlex.quote(cert_file)} -noout -ext subjectAltName",
        step=step,
        allow_error=True,
    )
    if code != 0:
        return []
    return parse_san(out)


_MONTHS = {m: i + 1 for i, m in enumerate(('jan', 'feb', 'mar', 'apr', 'may', 'jun',
                                            'jul', 'aug', 'sep', 'oct', 'nov', 'dec'))}
_OPENSSL_DATE_RE = re.compile(r'([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})')


def parse_openssl_date(text: str) -> datetime | None:
    """Parse an OpenSSL date such as ``Jan  1 00:00:00 2024 GMT`` (English month names,
    whatever the locale of the grading process: ``strptime('%b')`` would not do)."""
    m = _OPENSSL_DATE_RE.search(text or '')
    if not m:
        return None
    month = _MONTHS.get(m.group(1).lower())
    if month is None:
        return None
    try:
        return datetime(int(m.group(6)), month, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
    except ValueError:
        return None


def certificate_validity_days(cert: dict | None) -> int | None:
    """Validity period in days of a certificate dict (``not_before``/``not_after`` keys
    as returned by :func:`eval_certificate`), ``None`` when the dates cannot be read."""
    if not cert:
        return None
    start = parse_openssl_date(cert.get('not_before', ''))
    end = parse_openssl_date(cert.get('not_after', ''))
    if start is None or end is None:
        return None
    return round((end - start).total_seconds() / 86400)


# ---------------------------------------------------------------------------
# CRL
# ---------------------------------------------------------------------------

def normalize_serial(serial: str) -> str:
    """Canonical form of a certificate serial number: upper-case hex, no colons, no
    ``0x`` prefix, no leading zeros (``'0'`` for zero)."""
    s = re.sub(r'[\s:]', '', (serial or '')).upper()
    if s.startswith('0X'):
        s = s[2:]
    s = s.lstrip('0')
    return s or '0'


def parse_crl_text(text: str) -> list[str]:
    """Serial numbers (normalised) listed as revoked in an ``openssl crl -text`` output."""
    if 'Revoked Certificates' not in (text or ''):
        return []
    body = text.split('Revoked Certificates', 1)[1]
    return [normalize_serial(m.group(1)) for m in re.finditer(r'Serial Number:\s*([0-9A-Fa-f:]+)', body)]


def get_crl_revoked_serials(grade: Grade0, machine_name: str, crl_file: str,
                            step: int = 1) -> list[str]:
    """Revoked serial numbers of the CRL *crl_file* (``[]`` when unreadable)."""
    out, code = grade.test(
        machine_name=machine_name,
        command=f"openssl crl -in {shlex.quote(crl_file)} -noout -text",
        step=step,
        allow_error=True,
    )
    if code != 0:
        return []
    return parse_crl_text(out)


def eval_crl(grade: Grade0, machine_name: str, crl_file: str, ca_cert_file: str,
             step: int = 1) -> bool:
    """True when *crl_file* is a CRL whose signature verifies against *ca_cert_file*."""
    out, code = grade.test(
        machine_name=machine_name,
        command=f"openssl crl -in {shlex.quote(crl_file)} -CAfile {shlex.quote(ca_cert_file)} -noout 2>&1",
        step=step,
        allow_error=True,
    )
    return code == 0 and 'verify failure' not in (out or '').lower()


# ---------------------------------------------------------------------------
# PKCS#12
# ---------------------------------------------------------------------------

_PEM_CERT_RE = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)
_CN_RE = re.compile(r'(?:^|[,/]\s*)CN\s*=\s*([^,/]+)')


def cert_sha256_hex(pem: str) -> str:
    """Lower-case hex SHA-256 of the DER form of a PEM certificate (``''`` if unparsable)."""
    try:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.strip())).hexdigest()
    except Exception:
        return ''


def eval_pkcs12(grade: Grade0, machine_name: str, p12_file: str, password: str,
                step: int = 1) -> dict | None:
    """Open the PKCS#12 file *p12_file* with *password* on machine_name.

    Returns ``None`` when the file cannot be opened (missing file or wrong password),
    otherwise ``{'subject', 'common_name', 'fingerprint'}`` of the client certificate,
    ``'ca_fingerprints'`` (SHA-256 fingerprints of the CA certificates bundled in the file)
    and ``'has_key'`` (a private key is present).
    """
    q_file = shlex.quote(p12_file)
    q_pass = shlex.quote(f'pass:{password}')
    cert_out, cert_code = grade.test(
        machine_name=machine_name,
        command=f"openssl pkcs12 -in {q_file} -passin {q_pass} -nokeys -clcerts 2>/dev/null"
                f" | openssl x509 -noout -subject -fingerprint -sha256",
        step=step,
        allow_error=True,
    )
    ca_out, _ = grade.test(
        machine_name=machine_name,
        command=f"openssl pkcs12 -in {q_file} -passin {q_pass} -nokeys -cacerts 2>/dev/null",
        step=step,
        allow_error=True,
    )
    _, key_code = grade.test(
        machine_name=machine_name,
        command=f"openssl pkcs12 -in {q_file} -passin {q_pass} -nocerts -nodes 2>/dev/null"
                f" | openssl pkey -noout",
        step=step,
        allow_error=True,
    )
    if cert_code != 0 or 'subject=' not in (cert_out or ''):
        return None
    subject = _val(cert_out, 'subject')
    cn_m = _CN_RE.search(subject)
    ca_fps = []
    for pem in _PEM_CERT_RE.findall(ca_out or ''):
        try:
            ca_fps.append(_cert_fingerprint_sha256(pem))
        except Exception:
            continue
    return {
        'subject': subject,
        'common_name': cn_m.group(1).strip() if cn_m else '',
        'fingerprint': _val(cert_out, 'SHA256 Fingerprint'),
        'ca_fingerprints': ca_fps,
        'has_key': key_code == 0,
    }


# ---------------------------------------------------------------------------
# Live TLS servers
# ---------------------------------------------------------------------------

def get_tls_server_certificate(grade: Grade0, machine_name: str, server_ip: str,
                               port: int = 443, servername: str | None = None,
                               step: int = 1) -> dict | None:
    """Certificate presented by the TLS server at *server_ip*:*port* (SNI *servername*),
    as ``{'subject', 'issuer', 'common_name', 'fingerprint'}``; ``None`` when no
    certificate could be read."""
    sni = f" -servername {shlex.quote(servername)}" if servername else ""
    out, code = grade.test(
        machine_name=machine_name,
        command=f"openssl s_client -connect {_host_port(server_ip, int(port))}{sni} </dev/null 2>/dev/null"
                f" | openssl x509 -noout -subject -issuer -fingerprint -sha256",
        step=step,
        allow_error=True,
    )
    if code != 0 or 'subject=' not in (out or ''):
        return None
    subject = _val(out, 'subject')
    cn_m = _CN_RE.search(subject)
    return {
        'subject': subject,
        'issuer': _val(out, 'issuer'),
        'common_name': cn_m.group(1).strip() if cn_m else '',
        'fingerprint': _val(out, 'SHA256 Fingerprint'),
    }


_CURL_CODE_MARK = '===SRE_CODE '


@dataclass
class HttpResult:
    """Result of :func:`https_get`: *code* is the HTTP status (``None`` when the request
    failed before an answer, e.g. a certificate error), *headers* are lower-cased."""
    code: int | None = None
    headers: dict = field(default_factory=dict)
    body: str = ''
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        return self.code is not None and 200 <= self.code < 300


def parse_curl_output(out: str, exit_code: int = 0) -> HttpResult:
    """Parse the output of ``curl -D - -o - -w '\\n===SRE_CODE %{http_code}'``."""
    text = out or ''
    code = None
    if _CURL_CODE_MARK in text:
        text, _, tail = text.rpartition(_CURL_CODE_MARK)
        try:
            code = int(tail.strip())
        except ValueError:
            code = None
        if code == 0:
            code = None
    headers: dict = {}
    body = text
    if text.startswith('HTTP/'):
        m = re.search(r'\r?\n\r?\n', text)
        head, body = (text[:m.start()], text[m.end():]) if m else (text, '')
        for line in head.splitlines()[1:]:
            if ':' in line:
                name, value = line.split(':', 1)
                headers[name.strip().lower()] = value.strip()
    return HttpResult(code=code, headers=headers, body=body, exit_code=exit_code)


def https_get(grade: Grade0, machine_name: str, url: str, server_ip: str,
              port: int = 443, cacert: str | None = None, cert: str | None = None,
              key: str | None = None, insecure: bool = False,
              step: int = 1, timeout: int = 15) -> HttpResult:
    """GET *url* from machine_name, connecting to *server_ip*:*port* for the URL's host
    name (``curl --resolve``: no DNS needed, SNI and Host header come from the URL).

    *cacert* / *cert* / *key* are paths on the machine (``--cacert``, ``--cert``, ``--key``);
    *insecure* adds ``-k``. The status code, headers and body are returned in an
    :class:`HttpResult` (``code`` is ``None`` when the TLS handshake or the connection failed).
    """
    host = urlparse(url).hostname or ''
    opts = [f"--resolve {shlex.quote(f'{host}:{int(port)}:{_bracketed(server_ip)}')}"]
    if insecure:
        opts.append("-k")
    if cacert:
        opts.append(f"--cacert {shlex.quote(cacert)}")
    if cert:
        opts.append(f"--cert {shlex.quote(cert)}")
    if key:
        opts.append(f"--key {shlex.quote(key)}")
    max_time = max(1, timeout - 3)
    cmd = (f"curl -s -S --max-time {max_time} {' '.join(opts)} -D - -o - "
           f"-w '\\n{_CURL_CODE_MARK}%{{http_code}}' {shlex.quote(url)} 2>&1")
    out, code = grade.test(machine_name=machine_name, command=cmd, step=step,
                           timeout=timeout, allow_error=True)
    return parse_curl_output(out, code)


# ---------------------------------------------------------------------------
# Firefox (NSS) certificate store
# ---------------------------------------------------------------------------

def nss_hashes_command(home: str = '/root') -> str:
    """One-line shell command printing the SHA-256 (hex) of every certificate stored in the
    Firefox profiles under *home* (``cert9.db``, SQLite table ``nssPublic``, column ``a11`` =
    CKA_VALUE). The databases are opened read-only and immutable so a running Firefox is
    not disturbed. One hash per line; nothing when no profile exists.

    The script is base64-encoded into a ``python3 -c`` one-liner: the exetests runner only
    supports single-line commands."""
    script = (
        "import glob, hashlib, sqlite3\n"
        "seen = set()\n"
        f"for db in glob.glob({home!r} + '/.mozilla/firefox*/*/cert9.db'):\n"
        "    try:\n"
        "        con = sqlite3.connect('file:' + db + '?mode=ro&immutable=1', uri=True)\n"
        "        for (blob,) in con.execute('SELECT a11 FROM nssPublic WHERE a11 IS NOT NULL'):\n"
        "            if isinstance(blob, bytes) and blob[:1] == b'\\x30':\n"
        "                seen.add(hashlib.sha256(blob).hexdigest())\n"
        "        con.close()\n"
        "    except Exception:\n"
        "        pass\n"
        "print('\\n'.join(sorted(seen)))\n"
    )
    b64 = base64.b64encode(script.encode()).decode()
    return f'python3 -c "import base64; exec(base64.b64decode(\'{b64}\').decode())"'


def get_nss_certificate_hashes(grade: Grade0, machine_name: str, home: str = '/root',
                               step: int = 1) -> set[str]:
    """SHA-256 hashes of the certificates in the Firefox profiles of *home* on machine_name."""
    out, code = grade.test(machine_name=machine_name, command=nss_hashes_command(home),
                           step=step, allow_error=True)
    if code != 0:
        return set()
    return {line.strip() for line in (out or '').splitlines() if re.fullmatch(r'[0-9a-f]{64}', line.strip())}


def eval_firefox_certificate(grade: Grade0, machine_name: str, cert_pem: str,
                             home: str = '/root', step: int = 1) -> bool:
    """True when the PEM certificate *cert_pem* has been imported into a Firefox profile of
    *home* on machine_name (any trust setting)."""
    hashes = get_nss_certificate_hashes(grade, machine_name, home=home, step=step)
    wanted = cert_sha256_hex(cert_pem)
    return bool(wanted) and wanted in hashes


# ---------------------------------------------------------------------------
# step-ca
# ---------------------------------------------------------------------------

def parse_stepca_config(text: str) -> dict | None:
    """Summary of a step-ca ``ca.json``: ``{'address', 'dns_names', 'root', 'provisioners':
    [{'name', 'type'}, ...]}``; ``None`` when the text is not a JSON object."""
    try:
        cfg = json.loads(text or '')
    except (ValueError, TypeError):
        return None
    if not isinstance(cfg, dict):
        return None
    provisioners = (cfg.get('authority') or {}).get('provisioners') or []
    return {
        'address': cfg.get('address', ''),
        'dns_names': list(cfg.get('dnsNames') or []),
        'root': cfg.get('root', ''),
        'provisioners': [{'name': p.get('name', ''), 'type': p.get('type', '')}
                         for p in provisioners if isinstance(p, dict)],
    }


def get_stepca_config(grade: Grade0, machine_name: str,
                      config_file: str = '/home/ca/.step/config/ca.json',
                      step: int = 1) -> dict | None:
    """Parsed step-ca configuration of machine_name (see :func:`parse_stepca_config`)."""
    out, code = grade.test(machine_name=machine_name, command=f"cat {shlex.quote(config_file)}",
                           step=step, allow_error=True)
    if code != 0:
        return None
    return parse_stepca_config(out)
