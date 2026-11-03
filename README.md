# TeraClaw verify action

Public reusable Level 2 runner for TeraClaw merge-queue receipts.

This repository is intentionally small. The caller supplies a signed,
version-pinned runner tarball URL and SHA-256. The workflow checks the hash,
runs the runner, and lets the runner post the check run and sign the receipt
keylessly through GitHub OIDC.

## Caller contract

```yaml
jobs:
  verify:
    on: [merge_group, pull_request]
    permissions:
      contents: read
      checks: write
      id-token: write
    uses: quantumlabssh/teraclaw-verify-action/.github/workflows/verify.yml@v0.1.0
    with:
      head_sha: ${{ github.event.merge_group.head_sha || github.sha }}
      base_ref: ${{ github.event.merge_group.base_ref || format('refs/heads/{0}', github.event.pull_request.base.ref) }}
      base_sha: ${{ github.event.merge_group.base_sha }}
      scope: ${{ github.event.merge_group.head_sha && 'merge_group' || 'pr_merge' }}
      repository_id: ${{ github.event.repository.id }}
      runner_url: https://releases.teraclaw.org/verify/teraclaw-verify-<version>.tar.gz
      runner_sha256: <published sha256>
      workflow_tag: v0.1.0
    secrets:
      TERACLAW_LICENSE_TOKEN: ${{ secrets.TERACLAW_LICENSE_TOKEN }}
```

## Trust rules

- The reusable workflow repo must be public, or private in the same
  organization/enterprise with access granted.
- Pin the caller to a tag and publish the workflow commit for that tag. The
  verifier requires the certificate `job_workflow_sha`, not just the tag.
- The runner tarball is hash-checked. A wrong hash refuses to run.
- Missing or invalid `TERACLAW_LICENSE_TOKEN` posts `action_required` with
  “TeraClaw license invalid or missing”; it never posts nothing or `neutral`.
- A short offline grace period covers a transient teraclaw.org outage.

## Staging

`teraclaw/verify-action` is the production identity. This repository is the
staging copy until the `teraclaw` organization grants repository-create access.
The workflow commit and tag must be pinned in the release notes/key list.
