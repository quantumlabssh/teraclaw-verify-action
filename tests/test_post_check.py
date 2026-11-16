"""Receipt verification and check derivation for the reusable verify action."""

from __future__ import annotations

import base64
import json

import pytest

cryptography = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

import post_check  # noqa: E402

SHA = "a" * 40


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _envelope(statement: dict, key: ed25519.Ed25519PrivateKey) -> dict:
    payload = json.dumps(statement).encode("utf-8")
    signature = key.sign(post_check._pae(post_check.PAYLOAD_TYPE, payload))
    public = key.public_key().public_bytes_raw()
    return {
        "payloadType": post_check.PAYLOAD_TYPE,
        "payload": _b64(payload),
        "signatures": [
            {"sig": _b64(signature), "public_key_b64": _b64(public)}
        ],
    }


def _statement(level: str = "verified") -> dict:
    return {
        "_type": post_check.STATEMENT_TYPE,
        "subject": [{"name": "git+acme/repo@a", "digest": {"gitCommit": SHA}}],
        "predicateType": post_check.PREDICATE_TYPE,
        "predicate": {
            "assurance": {"level": level, "reasons": []},
            "repository": "acme/repo",
            "repository_id": 42,
        },
    }


def _write(tmp_path, envelope: dict) -> str:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return str(path)


def test_verified_receipt_maps_to_success(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    path = _write(tmp_path, _envelope(_statement("verified"), key))
    verdict = post_check.verify_receipt(
        path, head_sha=SHA, repository="acme/repo", repository_id=42
    )
    assert verdict["conclusion"] == "success"
    assert verdict["level"] == "verified"
    assert SHA in verdict["summary"]


@pytest.mark.parametrize(
    ("level", "conclusion"),
    [
        ("failed", "failure"),
        ("weak", "action_required"),
        ("capped", "action_required"),
        ("accepted", "action_required"),
    ],
)
def test_non_verified_levels_never_pass(tmp_path, level, conclusion):
    key = ed25519.Ed25519PrivateKey.generate()
    path = _write(tmp_path, _envelope(_statement(level), key))
    assert post_check.verify_receipt(path, head_sha=SHA)["conclusion"] == conclusion


def test_receipt_for_another_commit_is_refused(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    path = _write(tmp_path, _envelope(_statement(), key))
    with pytest.raises(ValueError, match="not the event head"):
        post_check.verify_receipt(path, head_sha="b" * 40)


def test_tampered_payload_breaks_the_signature(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    envelope = _envelope(_statement("verified"), key)
    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["predicate"]["assurance"]["level"] = "failed"
    envelope["payload"] = _b64(json.dumps(payload).encode("utf-8"))
    path = _write(tmp_path, envelope)
    with pytest.raises(ValueError, match="signature is invalid"):
        post_check.verify_receipt(path, head_sha=SHA)


def test_unexpected_statement_type_is_refused(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    statement = _statement()
    statement["_type"] = "https://example.test/Other/v1"
    path = _write(tmp_path, _envelope(statement, key))
    with pytest.raises(ValueError, match="unexpected statement type"):
        post_check.verify_receipt(path, head_sha=SHA)


def test_repository_mismatch_is_refused(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    path = _write(tmp_path, _envelope(_statement(), key))
    with pytest.raises(ValueError, match="repository"):
        post_check.verify_receipt(
            path, head_sha=SHA, repository="other/repo"
        )
    with pytest.raises(ValueError, match="repository id"):
        post_check.verify_receipt(path, head_sha=SHA, repository_id=7)
