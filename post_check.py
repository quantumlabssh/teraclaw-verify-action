#!/usr/bin/env python3
"""Verify a signed TeraClaw receipt and post the GitHub check run.

The check conclusion is derived from the DSSE envelope, never from a
workspace-writable ``check.json``. The subject commit must equal the event's
head SHA, so a receipt for another commit cannot post ``success``.

This helper is standalone so the public action repo does not depend on the
private engine package.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://teraclaw.org/attestation/verify/v1"
MAX_OUTPUT = 60000
ALLOWED_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "success",
    "timed_out",
}
CONCLUSION_FOR_LEVEL = {
    "verified": "success",
    "failed": "failure",
}


def _truncate(value: object, limit: int) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _b64decode(value: str) -> bytes:
    """Decode standard or URL-safe base64 (the engine writes standard)."""
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded)
    except Exception:
        return base64.urlsafe_b64decode(padded)


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode()
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def verify_receipt(
    path: str,
    *,
    head_sha: str,
    repository: str = "",
    repository_id: int = 0,
) -> dict[str, Any]:
    """Verify the envelope and return the check conclusion plus a summary."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(envelope, dict):
        raise ValueError("receipt must be a JSON object")
    if str(envelope.get("payloadType") or "") != PAYLOAD_TYPE:
        raise ValueError("unexpected payloadType")
    payload_b64 = str(envelope.get("payload") or "")
    if not payload_b64:
        raise ValueError("receipt has no payload")
    payload = _b64decode(payload_b64)

    signatures = envelope.get("signatures") or []
    if not signatures or not isinstance(signatures[0], dict):
        raise ValueError("receipt has no signature")
    entry = signatures[0]
    public_b64 = str(entry.get("public_key_b64") or "")
    signature_b64 = str(entry.get("sig") or "")
    if not public_b64 or not signature_b64:
        raise ValueError("receipt signature is incomplete")
    public = ed25519.Ed25519PublicKey.from_public_bytes(_b64decode(public_b64))
    try:
        public.verify(_b64decode(signature_b64), _pae(PAYLOAD_TYPE, payload))
    except Exception as exc:
        raise ValueError(f"receipt signature is invalid: {exc}") from exc

    statement = json.loads(payload.decode("utf-8"))
    if not isinstance(statement, dict):
        raise ValueError("receipt payload is not a statement")
    if str(statement.get("_type") or "") != STATEMENT_TYPE:
        raise ValueError("unexpected statement type")
    if str(statement.get("predicateType") or "") != PREDICATE_TYPE:
        raise ValueError("unexpected predicate type")

    subject = ((statement.get("subject") or [{}])[0]) or {}
    digest = subject.get("digest") or {}
    subject_commit = str(digest.get("gitCommit") or "").lower()
    if not subject_commit:
        raise ValueError("receipt subject has no gitCommit")
    if subject_commit != head_sha.lower():
        raise ValueError(
            f"receipt is for {subject_commit[:12]}, not the event head {head_sha[:12]}"
        )

    predicate = statement.get("predicate") or {}
    receipt_repository = str(predicate.get("repository") or "")
    if repository and receipt_repository and receipt_repository != repository:
        raise ValueError(
            f"receipt repository {receipt_repository} does not match {repository}"
        )
    if repository_id:
        receipt_repository_id = int(predicate.get("repository_id") or 0)
        if receipt_repository_id != repository_id:
            raise ValueError(
                f"receipt repository id {receipt_repository_id} does not match {repository_id}"
            )

    assurance = predicate.get("assurance") or {}
    level = str(assurance.get("level") or "failed")
    conclusion = CONCLUSION_FOR_LEVEL.get(level, "action_required")
    reasons = assurance.get("reasons") or []
    summary = f"TeraClaw assurance: {level}"
    if reasons:
        summary += "\n\n" + "\n".join(f"- {reason}" for reason in reasons[:20])
    summary += f"\n\nSubject: {subject_commit}"
    return {
        "conclusion": conclusion,
        "level": level,
        "summary": summary,
        "subject_commit": subject_commit,
    }


def _payload(
    *, name: str, title: str, summary: str, conclusion: str, head_sha: str
) -> dict[str, Any]:
    if conclusion not in ALLOWED_CONCLUSIONS:
        raise ValueError(f"unsupported conclusion {conclusion!r}")
    head = head_sha.strip().lower()
    if len(head) != 40 or any(char not in "0123456789abcdef" for char in head):
        raise ValueError("head_sha must be a 40-character commit SHA")
    return {
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "head_sha": head,
        "output": {
            "title": _truncate(title, 255),
            "summary": _truncate(summary, MAX_OUTPUT),
            "text": _truncate(summary, MAX_OUTPUT),
        },
    }


def _post(payload: dict[str, Any], *, token: str, repository: str, api: str) -> int:
    request = urllib.request.Request(
        f"{api}/repos/{repository}/check-runs",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "teraclaw-verify-action",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"GitHub check-run failed: HTTP {exc.code}: {detail}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"GitHub check-run failed: {exc}", file=sys.stderr)
        return 1
    data = json.loads(body) if body.strip() else {}
    print(
        json.dumps(
            {
                "check_run_id": data.get("id"),
                "conclusion": payload["conclusion"],
                "head_sha": payload["head_sha"],
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--receipt", default="", help="Signed receipt produced by the verifier"
    )
    parser.add_argument("--head-sha", required=True, help="Tested commit SHA")
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="owner/name recorded in the receipt",
    )
    parser.add_argument(
        "--repository-id",
        type=int,
        default=int(os.environ.get("REPOSITORY_ID", "0") or 0),
    )
    parser.add_argument("--name", default="TeraClaw verified work")
    parser.add_argument("--title", default="TeraClaw verify")
    parser.add_argument(
        "--summary",
        default="TeraClaw verify did not produce a signed receipt",
        help="Summary used when no receipt exists (setup failure)",
    )
    parser.add_argument(
        "--conclusion",
        default="action_required",
        choices=sorted(ALLOWED_CONCLUSIONS),
        help="Conclusion used when no receipt exists (setup failure)",
    )
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repository = args.repository.strip()
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").strip().rstrip("/")
    if not token or not repository:
        print("GITHUB_TOKEN and GITHUB_REPOSITORY are required", file=sys.stderr)
        return 1

    if args.receipt:
        try:
            verdict = verify_receipt(
                args.receipt,
                head_sha=args.head_sha,
                repository=repository,
                repository_id=args.repository_id,
            )
        except Exception as exc:
            print(f"receipt verification failed: {exc}", file=sys.stderr)
            verdict = {
                "conclusion": "action_required",
                "summary": f"Receipt verification failed: {exc}",
            }
        conclusion = verdict["conclusion"]
        summary = verdict["summary"]
    else:
        conclusion = args.conclusion
        summary = args.summary

    try:
        payload = _payload(
            name=args.name,
            title=args.title,
            summary=summary,
            conclusion=conclusion,
            head_sha=args.head_sha,
        )
    except Exception as exc:
        print(f"invalid check payload: {exc}", file=sys.stderr)
        return 1

    posted = _post(payload, token=token, repository=repository, api=api)
    if posted:
        return posted
    return 0 if conclusion == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
