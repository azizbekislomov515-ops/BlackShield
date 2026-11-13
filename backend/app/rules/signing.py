"""ECDSA P-256 signatures for YARA rulesets.

The signed message binds the version to the exact rule text through its SHA-256:

    blackshield-yara-rules\n<version>\n<sha256 hex of the UTF-8 rules>

Devices verify it with the public keys built into the app (``RulesetVerifier`` on Android), so
the private key is needed only where rulesets are published, never by the API server.
"""

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

MESSAGE_PREFIX = "blackshield-yara-rules"


class SigningKeyError(ValueError):
    """The signing key is missing, malformed, or not an EC P-256 private key."""


@dataclass(frozen=True)
class GeneratedKey:
    private_pem: str
    #: ``keyId:base64(SubjectPublicKeyInfo DER)``, the format the app's Gradle property expects.
    public_spec: str


def sha256_hex(rules: str) -> str:
    return hashlib.sha256(rules.encode("utf-8")).hexdigest()


def signed_message(version: int, sha256: str) -> bytes:
    return f"{MESSAGE_PREFIX}\n{version}\n{sha256}".encode()


def generate_key(key_id: str) -> GeneratedKey:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return GeneratedKey(private_pem=pem, public_spec=public_spec(key_id, key.public_key()))


def public_spec(key_id: str, public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return f"{key_id}:{base64.b64encode(der).decode()}"


def load_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError(f"not an unencrypted PEM private key ({exc})") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SigningKeyError("the signing key must be an EC P-256 (secp256r1) key")
    return key


def sign(key: ec.EllipticCurvePrivateKey, version: int, sha256: str) -> str:
    """Base64 DER ECDSA signature, as Java's SHA256withECDSA verifies it."""
    signature = key.sign(signed_message(version, sha256), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()


def verify(
    public_key: ec.EllipticCurvePublicKey, version: int, sha256: str, signature: str
) -> bool:
    try:
        public_key.verify(
            base64.b64decode(signature, validate=True),
            signed_message(version, sha256),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError):
        return False
    return True
