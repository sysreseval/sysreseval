import hashlib
import re
import shlex
import ssl

from SRE.lib_sre import Grade0, NetScheme0


def _cert_fingerprint_sha256(pem: str) -> str:
    """Return the SHA256 fingerprint of a PEM certificate as XX:XX:... uppercase hex."""
    der = ssl.PEM_cert_to_DER_cert(pem.strip())
    digest = hashlib.sha256(der).hexdigest()
    return ':'.join(digest[i:i + 2].upper() for i in range(0, len(digest), 2))


def _val(line, prefix):
    m = re.search(rf'{prefix}=(.+)', line)
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
                              step: int = 1) -> bool:
    """Check that cert_file is signed by ca_cert_file on machine_name.

    Args:
        grade:        the Grade0 instance.
        machine_name: name of the virtual machine to inspect.
        cert_file:    absolute path to the certificate file on the machine.
        ca_cert_file: absolute path to the CA certificate file on the machine.
        step:         step number passed to grade.test() (default: 1).

    Returns:
        True if cert_file is a valid certificate signed by ca_cert_file,
        False otherwise.
    """
    _, verify_code = grade.test(
        machine_name=machine_name,
        command=f"openssl verify -CAfile {shlex.quote(ca_cert_file)} {shlex.quote(cert_file)}",
        step=step,
        allow_error=True,
    )
    return verify_code == 0


def eval_https_server(grade: Grade0, machine_name: str, url: str,
                      server_ip: str, cert: str,
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
        server_ip:    IP address of the HTTPS server to connect to.
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
        command=f"curl -k -L --fail --connect-to ::{server_ip}:{server_port}"
                f" -s -o /dev/null {url}",
        step=step,
        allow_error=True,
    )
    server_fp, server_fp_code = grade.test(
        machine_name=machine_name,
        command=f"openssl s_client -connect {server_ip}:{server_port}"
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
