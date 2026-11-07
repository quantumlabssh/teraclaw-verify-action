#!/usr/bin/env python3
"""Verify a Sigstore bundle for the TeraClaw verify runner.

The runner is signed in the private build workflow with GitHub OIDC. This script
pins the certificate identity and the DSSE subject digest before the file is
allowed to run. It is intentionally standalone so this public repo does not
depend on the private package.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path


def _extension_text(certificate, oid: str) -> str:
    from cryptography.x509.oid import ObjectIdentifier

    try:
        ext = certificate.extensions.get_extension_for_oid(ObjectIdentifier(oid))
    except Exception:
        return ""
    raw = getattr(ext.value, "value", b"")
    if not raw:
        return ""
    if raw[0] == 0x0C and len(raw) >= 2:
        raw = raw[2 : 2 + raw[1]]
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return ""


def _workflow_ref(value: str) -> str:
    """Fulcio writes the absolute URL form; accept the short owner/repo form too."""
    value = value.strip()
    prefix = "https://github.com/"
    return value[len(prefix) :] if value.startswith(prefix) else value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--issuer", default="https://token.actions.githubusercontent.com")
    parser.add_argument("--signer-workflow", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-repository-id", required=True, type=int)
    parser.add_argument("--source-repository", default="")
    args = parser.parse_args(argv)

    from sigstore.models import Bundle
    from sigstore.verify import Verifier, policy

    expected = args.expected_sha256.strip().lower()
    actual = hashlib.sha256(Path(args.file).read_bytes()).hexdigest()
    if actual != expected:
        print(f"runner sha256 mismatch: {actual} != {expected}", file=sys.stderr)
        return 1

    try:
        bundle = Bundle.from_json(Path(args.bundle).read_text(encoding="utf-8"))
        signer_uris = [args.signer_workflow]
        if args.signer_workflow.startswith("https://"):
            signer_uris.append(
                args.signer_workflow[len("https://github.com/") :]
            )
        else:
            signer_uris.append(f"https://github.com/{args.signer_workflow}")
        children = [
            policy.AnyOf(
                [
                    policy.OIDCIssuerV2(args.issuer),
                    policy.OIDCIssuer(args.issuer),
                ]
            ),
            policy.AnyOf([policy.OIDCBuildSignerURI(v) for v in signer_uris]),
            policy.OIDCBuildSignerDigest(args.source_commit),
            policy.OIDCSourceRepositoryIdentifier(str(args.source_repository_id)),
            policy.OIDCSourceRepositoryDigest(args.source_commit),
        ]
        if args.source_repository:
            children.append(
                policy.OIDCSourceRepositoryURI(
                    f"https://github.com/{args.source_repository}"
                )
            )
        Verifier.production().verify_dsse(bundle, policy=policy.AllOf(children))
    except Exception as exc:
        print(f"Sigstore bundle verification failed: {exc}", file=sys.stderr)
        return 1

    cert = bundle.signing_certificate
    signer = _extension_text(cert, "1.3.6.1.4.1.57264.1.9")
    if signer and _workflow_ref(signer) != _workflow_ref(args.signer_workflow):
        print(f"signer workflow mismatch: {signer}", file=sys.stderr)
        return 1

    envelope = json.loads(bundle._to_parts()[1].to_json())
    statement = json.loads(base64.b64decode(envelope["payload"]))
    subject = (statement.get("subject") or [{}])[0]
    digest = (subject.get("digest") or {}).get("sha256")
    if digest != expected:
        print(f"statement subject mismatch: {digest} != {expected}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "verified": True,
                "sha256": expected,
                "signer_workflow": signer or args.signer_workflow,
                "source_commit": args.source_commit,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
