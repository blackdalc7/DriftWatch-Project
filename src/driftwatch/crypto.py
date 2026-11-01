"""Signing and PKI.

* **Bundle signing (Ed25519).** Every test bundle sent to an agent is canonical JSON signed with the
  server's Ed25519 key. The agent pins the public key at install time and rejects unsigned, re-signed or
  expired bundles, so mTLS compromise alone is not enough to make an agent run something.
* **Agent PKI (ECDSA P-256).** A small internal CA issues the server certificate and, during enrollment,
  short-lived client certificates for agents from the CSR the agent generated. Agent private keys never
  leave the endpoint.
* **Evidence signing.** Evidence bundle manifests are signed with the same Ed25519 key.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CryptoError(Exception):
    """Raised for invalid keys, CSRs and signatures."""


def canonical_json(payload: Any) -> bytes:
    """Deterministic JSON (sorted keys, no whitespace) used for every signature in Driftwatch.

    Bundles travel as ``base64(canonical_json(payload))`` next to the signature, so the Go agent verifies
    the exact bytes that were signed and never has to reproduce Python's JSON encoding.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - Windows file systems
        pass


# --- Ed25519 bundle signing -----------------------------------------------------------------------


class Signer:
    """Signs payloads with an Ed25519 private key."""

    def __init__(self, key: ed25519.Ed25519PrivateKey) -> None:
        self._key = key

    @classmethod
    def generate(cls) -> Signer:
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: Path) -> Signer:
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        except (OSError, ValueError) as exc:
            raise CryptoError(f"cannot load signing key {path}: {exc}") from exc
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise CryptoError(f"{path} is not an Ed25519 private key")
        return cls(key)

    @classmethod
    def load_or_create(cls, path: Path) -> Signer:
        if path.exists():
            return cls.load(path)
        signer = cls.generate()
        signer.save(path)
        return signer

    def save(self, path: Path) -> None:
        pem = self._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        _write_private(path, pem)
        (path.with_suffix(".pub")).write_text(self.public_key_b64() + "\n", encoding="ascii")

    def public_key_b64(self) -> str:
        raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def sign(self, payload: Any) -> str:
        """Base64 signature over the canonical JSON of ``payload``."""
        return base64.b64encode(self._key.sign(canonical_json(payload))).decode("ascii")


def verify_signature(public_key_b64: str, payload: Any, signature_b64: str) -> bool:
    """Verify an Ed25519 signature produced by :meth:`Signer.sign`."""
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        key.verify(base64.b64decode(signature_b64, validate=True), canonical_json(payload))
    except (InvalidSignature, ValueError):
        return False
    return True


# --- Agent PKI ------------------------------------------------------------------------------------


@dataclass
class CertificateAuthority:
    """The internal CA that issues the server certificate and agent client certificates."""

    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @classmethod
    def create(cls, common_name: str = "Driftwatch Lab CA", days: int = 3650) -> CertificateAuthority:
        """Generate a new self-signed P-256 CA valid for ``days``."""
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Driftwatch")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        return cls(cert, key)

    @classmethod
    def load(cls, cert_path: Path, key_path: Path) -> CertificateAuthority:
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        except (OSError, ValueError) as exc:
            raise CryptoError(f"cannot load CA from {cert_path}: {exc}") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CryptoError("CA key must be an EC private key")
        return cls(cert, key)

    def save(self, cert_path: Path, key_path: Path) -> None:
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
        _write_private(key_path, self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def _builder(self, subject: x509.Name, public_key: Any, days: int) -> x509.CertificateBuilder:
        now = datetime.now(timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                           critical=False)
        )

    def issue_server_cert(self, hostnames: list[str], days: int = 825) -> tuple[bytes, bytes]:
        """Return (cert PEM, key PEM) for the TLS endpoint, valid for the given DNS names and IPs."""
        key = ec.generate_private_key(ec.SECP256R1())
        sans: list[x509.GeneralName] = []
        for host in hostnames:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(host)))
            except ValueError:
                sans.append(x509.DNSName(host))
        cert = (
            self._builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]), key.public_key(), days)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        return cert.public_bytes(serialization.Encoding.PEM), key_pem

    def sign_agent_csr(self, csr_pem: str, agent_id: str, days: int) -> tuple[str, str]:
        """Issue a client certificate for ``agent_id``; return (cert PEM, SHA-256 fingerprint hex).

        The subject is forced to ``CN=<agent_id>`` whatever the CSR asked for, and only the clientAuth
        usage is granted.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        except ValueError as exc:
            raise CryptoError(f"invalid CSR: {exc}") from exc
        if not csr.is_signature_valid:
            raise CryptoError("CSR signature is invalid")
        public_key = csr.public_key()
        if not isinstance(public_key, (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
            raise CryptoError("agent keys must be ECDSA or Ed25519")
        if isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.curve.key_size < 256:
            raise CryptoError("agent EC keys must be at least P-256")
        cert = (
            self._builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                                     x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "driftwatch-agent")]),
                          public_key, days)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode("ascii"), fingerprint(cert)


def fingerprint(cert: x509.Certificate) -> str:
    """Lowercase hex SHA-256 of the DER certificate.

    nginx's ``$ssl_client_fingerprint`` is SHA-1, so the proxy forwards the full verified PEM instead and
    the server computes SHA-256 itself.
    """
    return cert.fingerprint(hashes.SHA256()).hex()


def fingerprint_from_pem(pem: str) -> str:
    """SHA-256 fingerprint of a PEM certificate (accepts nginx's URL-escaped ``$ssl_client_escaped_cert``)."""
    from urllib.parse import unquote

    text = unquote(pem) if "%" in pem else pem
    try:
        cert = x509.load_pem_x509_certificate(text.encode("ascii"))
    except ValueError as exc:
        raise CryptoError(f"invalid client certificate: {exc}") from exc
    return fingerprint(cert)


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def init_pki(directory: Path, hostnames: list[str]) -> dict[str, Path]:
    """Create the CA, the server certificate and the bundle signing key if they do not exist yet."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "ca_cert": directory / "ca.crt",
        "ca_key": directory / "ca.key",
        "server_cert": directory / "server.crt",
        "server_key": directory / "server.key",
        "signing_key": directory / "bundle-signing.key",
        "signing_pub": directory / "bundle-signing.pub",
    }
    if paths["ca_cert"].exists() and paths["ca_key"].exists():
        ca = CertificateAuthority.load(paths["ca_cert"], paths["ca_key"])
    else:
        ca = CertificateAuthority.create()
        ca.save(paths["ca_cert"], paths["ca_key"])
    if not paths["server_cert"].exists():
        cert_pem, key_pem = ca.issue_server_cert(hostnames)
        paths["server_cert"].write_bytes(cert_pem)
        _write_private(paths["server_key"], key_pem)
    Signer.load_or_create(paths["signing_key"])
    return paths
