#!/usr/bin/env python3
"""Post a GitHub check run for the reusable TeraClaw verify action.

The action runs the signed verifier, which writes a check-run body that is
safe for required checks (only ``verified`` is ``success``). This helper posts
that body, or a generic ``action_required`` check when the verifier could not
produce a signed receipt. It is standalone so the public action repo does not
depend on the private package.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

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
MAX_OUTPUT = 60000


def _truncate(value: object, limit: int) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _load_payload(args) -> dict:
    if args.file:
        parsed = json.loads(Path(args.file).read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("check file must be a JSON object")
        payload = parsed
    else:
        payload = {
            "name": args.name,
            "status": "completed",
            "conclusion": args.conclusion,
            "head_sha": args.head_sha,
            "output": {
                "title": args.title,
                "summary": args.summary,
                "text": args.summary,
            },
        }
    payload.setdefault("name", args.name)
    if args.head_sha:
        payload.setdefault("head_sha", args.head_sha)
    payload["status"] = "completed"
    conclusion = str(payload.get("conclusion") or args.conclusion)
    if conclusion not in ALLOWED_CONCLUSIONS:
        raise ValueError(f"unsupported conclusion {conclusion!r}")
    payload["conclusion"] = conclusion
    head = str(payload.get("head_sha") or "")
    if len(head) != 40 or any(char not in "0123456789abcdefABCDEF" for char in head):
        raise ValueError("head_sha must be a 40-character commit SHA")
    payload["head_sha"] = head
    output = payload.get("output")
    if not isinstance(output, dict):
        output = {}
    output["title"] = _truncate(output.get("title") or args.title, 255)
    output["summary"] = _truncate(output.get("summary") or args.summary, MAX_OUTPUT)
    output["text"] = _truncate(output.get("text") or output["summary"], MAX_OUTPUT)
    payload["output"] = output
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="", help="Check-run body from the verifier")
    parser.add_argument("--head-sha", default="", help="Tested commit SHA")
    parser.add_argument(
        "--conclusion",
        default="action_required",
        choices=sorted(ALLOWED_CONCLUSIONS),
    )
    parser.add_argument("--name", default="TeraClaw verified work")
    parser.add_argument("--title", default="TeraClaw verify")
    parser.add_argument("--summary", default="TeraClaw verify result")
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").strip().rstrip("/")
    if not token or not repository:
        print("GITHUB_TOKEN and GITHUB_REPOSITORY are required", file=sys.stderr)
        return 1
    try:
        payload = _load_payload(args)
    except Exception as exc:
        print(f"invalid check payload: {exc}", file=sys.stderr)
        return 1

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


if __name__ == "__main__":
    sys.exit(main())
