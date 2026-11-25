"""Issue short-lived certificates under a single-use laboratory CA."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def provision(root):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())

    def subject(label):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])

    def builder(label, key, expired=False):
        return (
            x509.CertificateBuilder()
            .subject_name(subject(label))
            .issuer_name(subject("disposable-ca"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(hours=2))
            .not_valid_after(now + timedelta(hours=-1 if expired else 2))
        )

    ca = (
        builder("disposable-ca", ca_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(ca_key, hashes.SHA256())
    )
    pins = {}
    for role in ("reader", "alice", "bob", "expired"):
        directory = root / role
        directory.mkdir(mode=0o700)
        key = ec.generate_private_key(ec.SECP256R1())
        cert = builder(role, key, role == "expired")
        purpose = ExtendedKeyUsageOID.CLIENT_AUTH
        if role == "reader":
            purpose = ExtendedKeyUsageOID.SERVER_AUTH
            cert = cert.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("reader")]), False
            )
        cert = (
            cert.add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([purpose]), False)
            .sign(ca_key, hashes.SHA256())
        )
        (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (directory / "cert.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        secret = directory / "key.pem"
        secret.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        secret.chmod(0o600)
        pins[role] = cert.fingerprint(hashes.SHA256()).hex()
    return pins


def context(server):
    files = Path("/identity")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=files / "ca.pem")
    ctx.load_cert_chain(files / "cert.pem", files / "key.pem")
    if server:
        ctx.num_tickets = 0
    return ctx
