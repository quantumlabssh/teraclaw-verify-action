"""Structural contracts for the reusable verify workflow.

These are text assertions on purpose: the workflow is the shipped artifact and
there is no runtime here without a licensed runner and a real repo.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "verify.yml"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_fork_pull_requests_are_refused_before_checkout():
    text = _text()
    guard = text.index("Refuse fork pull requests")
    checkout = text.index("Check out the verify action")
    assert guard < checkout
    assert "github.event.pull_request.head.repo.full_name != github.repository" in text


def test_license_key_stays_in_the_exchange_step():
    import re

    text = _text()
    # A job-level env entry (6-space indent) would hand the key to every step,
    # including the verifier.
    assert not re.search(r"^ {6}LICENSE_CI_KEY:", text, re.MULTILINE)
    assert text.count("LICENSE_CI_KEY: ${{ secrets.TERACLAW_LICENSE_CI_KEY }}") == 2
    # The verifier step inherits only the license file, not the key.
    verify = text.split("Run the verifier", 1)[1].split("Upload the receipt", 1)[0]
    assert "LICENSE_CI_KEY" not in verify


def test_the_verifier_never_receives_a_github_token():
    text = _text()
    verify = text.split("Run the verifier", 1)[1].split("Upload the receipt", 1)[0]
    assert "GITHUB_TOKEN" not in verify


def test_write_token_is_scoped_to_the_post_job():
    text = _text()
    head, post = text.split("post-check:", 1)
    assert "checks: write" not in head
    assert "checks: write" in post


def test_the_check_is_derived_from_the_signed_receipt():
    text = _text()
    post = text.split("post-check:", 1)[1]
    assert "--receipt" in post
    assert "--head-sha" in post
    # A workspace check.json must never be the source of the check.
    assert "check.json" not in post
    script = (ROOT / "post_check.py").read_text(encoding="utf-8")
    assert "--file" not in script
    assert "not the event head" in script


def test_runner_download_host_is_restricted():
    text = _text()
    assert "*.r2.cloudflarestorage.com" in text
    assert "runner_download_host must be an R2 storage host" in text


def test_workflow_metadata_never_uses_pull_request_target():
    assert "pull_request_target" not in _text()


def test_actions_are_pinned_to_full_commit_shas():
    import re

    for ref in re.findall(r"uses:\s*(\S+)", _text()):
        if ref.startswith("./"):
            continue
        assert re.search(r"@[0-9a-f]{40}$", ref), f"unpinned action: {ref}"
