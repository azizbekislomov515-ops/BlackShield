"""Signed YARA rulesets: signing, publishing, GET /v1/rules and the CLI."""

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.cli import main
from app.rules.signing import (
    SigningKeyError,
    generate_key,
    load_private_key,
    sha256_hex,
    sign,
    signed_message,
    verify,
)
from app.rules.store import InvalidRuleset, check_rules, publish_ruleset

RULES_V1 = 'rule one { strings: $a = "one" condition: $a }\n'
RULES_V2 = 'import "dex"\nrule two : test { meta: severity = "high" condition: true }\n'


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def publish(engine: Engine, rules: str, key: ec.EllipticCurvePrivateKey, **kwargs: object) -> int:
    with Session(engine) as db:
        return publish_ruleset(db, rules, key_id="k1", key=key, **kwargs).version  # type: ignore[arg-type]


def public_key_from_spec(spec: str) -> ec.EllipticCurvePublicKey:
    _, encoded = spec.split(":", 1)
    loaded = serialization.load_der_public_key(base64.b64decode(encoded))
    assert isinstance(loaded, ec.EllipticCurvePublicKey)
    return loaded


# --- signing -------------------------------------------------------------------------------------


def test_signature_round_trip_and_tampering(key: ec.EllipticCurvePrivateKey) -> None:
    digest = sha256_hex(RULES_V1)
    signature = sign(key, 3, digest)
    assert verify(key.public_key(), 3, digest, signature)
    assert not verify(key.public_key(), 4, digest, signature)
    assert not verify(key.public_key(), 3, sha256_hex(RULES_V2), signature)
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    assert not verify(other, 3, digest, signature)
    assert not verify(key.public_key(), 3, digest, "not base64!")


def test_signed_message_matches_the_app() -> None:
    # RulesetVerifier.message() on Android builds exactly these bytes.
    assert signed_message(7, "ab" * 32) == f"blackshield-yara-rules\n7\n{'ab' * 32}".encode()
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_generated_key_spec_and_loading() -> None:
    generated = generate_key("k9")
    assert generated.public_spec.startswith("k9:")
    private = load_private_key(generated.private_pem)
    public = public_key_from_spec(generated.public_spec)
    digest = sha256_hex(RULES_V1)
    assert verify(public, 1, digest, sign(private, 1, digest))


def test_rejects_unusable_signing_keys() -> None:
    with pytest.raises(SigningKeyError):
        load_private_key("not a key")
    p384 = ec.generate_private_key(ec.SECP384R1())
    pem = p384.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    with pytest.raises(SigningKeyError, match="P-256"):
        load_private_key(pem)


# --- publishing ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rules", "message"),
    [
        ("", "1 byte"),
        ("rule a { condition: true }\x00", "NUL"),
        ('include "other.yar"\nrule a { condition: true }', "include"),
        ('import "pe"\nrule a { condition: pe.is_pe }', "pe"),
        ("// only a comment", "no rule"),
    ],
)
def test_check_rules_refuses_what_devices_would_reject(rules: str, message: str) -> None:
    with pytest.raises(InvalidRuleset, match=message):
        check_rules(rules)


def test_check_rules_size_limit() -> None:
    with pytest.raises(InvalidRuleset, match="bytes"):
        check_rules("rule a { condition: true }\n" + "//" + "x" * (1024 * 1024))


def test_publish_increments_versions_and_honours_min_version(
    engine: Engine, key: ec.EllipticCurvePrivateKey
) -> None:
    assert publish(engine, RULES_V1, key, min_version=5) == 5
    assert publish(engine, RULES_V2, key) == 6
    assert publish(engine, RULES_V1, key, min_version=2) == 7


def test_publish_refuses_invalid_rules(engine: Engine, key: ec.EllipticCurvePrivateKey) -> None:
    with pytest.raises(InvalidRuleset):
        publish(engine, 'import "elf"\nrule a { condition: true }', key)


# --- GET /v1/rules -------------------------------------------------------------------------------


def test_no_rules_published_is_404(client: TestClient) -> None:
    response = client.get("/v1/rules")
    assert response.status_code == 404
    assert response.json()["detail"] == "no rules published"


def test_latest_ruleset_is_signed_and_verifiable(
    client: TestClient, engine: Engine, key: ec.EllipticCurvePrivateKey
) -> None:
    publish(engine, RULES_V1, key)
    publish(engine, RULES_V2, key)

    response = client.get("/v1/rules")
    assert response.status_code == 200
    assert response.headers["etag"] == '"rules-2"'
    assert "no-cache" in response.headers["cache-control"]
    body = response.json()
    assert set(body) == {"version", "sha256", "key_id", "signature", "rules", "published_at"}
    assert (body["version"], body["key_id"], body["rules"]) == (2, "k1", RULES_V2)
    assert body["sha256"] == sha256_hex(RULES_V2)
    assert verify(key.public_key(), 2, body["sha256"], body["signature"])


def test_unchanged_ruleset_is_304(
    client: TestClient, engine: Engine, key: ec.EllipticCurvePrivateKey
) -> None:
    publish(engine, RULES_V1, key)
    assert client.get("/v1/rules", headers={"If-None-Match": '"rules-1"'}).status_code == 304
    assert client.get("/v1/rules", headers={"If-None-Match": 'W/"rules-1"'}).status_code == 304
    assert client.get("/v1/rules", headers={"If-None-Match": '"x", "rules-1"'}).status_code == 304

    publish(engine, RULES_V2, key)
    changed = client.get("/v1/rules", headers={"If-None-Match": '"rules-1"'})
    assert changed.status_code == 200
    assert changed.json()["version"] == 2


def test_rules_are_gzipped_when_accepted(
    client: TestClient, engine: Engine, key: ec.EllipticCurvePrivateKey
) -> None:
    publish(engine, RULES_V1, key)
    response = client.get("/v1/rules", headers={"Accept-Encoding": "gzip"})
    assert response.headers["content-encoding"] == "gzip"
    # TestClient decodes transparently; the body is still the JSON document.
    assert response.json()["rules"] == RULES_V1


def test_rules_require_an_api_key(
    app_factory, engine: Engine, key: ec.EllipticCurvePrivateKey
) -> None:  # type: ignore[no-untyped-def]
    publish(engine, RULES_V1, key)
    with TestClient(app_factory()) as anonymous:
        assert anonymous.get("/v1/rules").status_code == 401


# --- CLI -----------------------------------------------------------------------------------------


def test_cli_keygen_publish_and_status(
    engine: Engine, tmp_path: Path, capsys: pytest.CaptureFixture[str], client: TestClient
) -> None:
    key_file = tmp_path / "rules-key.pem"
    assert main(["rules-keygen", "--id", "k7", "--output", str(key_file)]) == 0
    spec = next(
        line.strip()
        for line in capsys.readouterr().out.splitlines()
        if line.strip().startswith("k7:")
    )
    assert main(["rules-keygen", "--id", "k7", "--output", str(key_file)]) == 1  # never overwrites

    rules_file = tmp_path / "rules.yar"
    rules_file.write_text(RULES_V1, encoding="utf-8")
    args = ["rules-publish", str(rules_file), "--key-file", str(key_file), "--key-id", "k7"]
    assert main([*args, "--min-version", "3"], engine=engine) == 0
    published = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert (published["version"], published["key_id"]) == (3, "k7")

    assert main(["rules-status"], engine=engine) == 0
    status = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert (status["version"], status["sha256"]) == (3, sha256_hex(RULES_V1))

    # What the device receives verifies with the key the app is configured with.
    body = client.get("/v1/rules").json()
    assert verify(public_key_from_spec(spec), body["version"], body["sha256"], body["signature"])


def test_cli_publish_failures(engine: Engine, tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.yar"
    rules_file.write_text('import "pe"\nrule a { condition: true }', encoding="utf-8")
    key_file = tmp_path / "key.pem"
    key_file.write_text(generate_key("k1").private_pem, encoding="utf-8")

    assert main(["rules-publish", str(rules_file)], engine=engine) == 1  # no key configured
    assert main(["rules-publish", str(rules_file), "--key-file", str(key_file)], engine=engine) == 1
    assert (
        main(
            ["rules-publish", str(tmp_path / "missing.yar"), "--key-file", str(key_file)],
            engine=engine,
        )
        == 1
    )
