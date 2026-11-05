# TeraClaw verify action

Public reusable Level 2 runner for TeraClaw merge-queue receipts.

This repository is intentionally small. The caller supplies a signed,
version-pinned runner tarball URL, SHA-256, Sigstore bundle URL, and a
`license:ci` dashboard key. Each run exchanges the key for a fresh signed v2 CI
license, verifies the runner bundle, runs the verifier, and posts a GitHub
check run from the signed receipt.

## Caller contract

```yaml
jobs:
  verify:
    on: [merge_group, pull_request]
    permissions:
      contents: read
      checks: write
      id-token: write
    uses: quantumlabssh/teraclaw-verify-action/.github/workflows/verify.yml@v0.1.1
    with:
      head_sha: ${{ github.event.merge_group.head_sha || github.sha }}
      base_ref: ${{ github.event.merge_group.base_ref || format('refs/heads/{0}', github.event.pull_request.base.ref) }}
      base_sha: ${{ github.event.merge_group.base_sha }}
      scope: ${{ github.event.merge_group.head_sha && 'merge_group' || 'pr_merge' }}
      repository_id: ${{ github.event.repository.id }}
      runner_url: https://releases.teraclaw.org/verify/teraclaw-verify-linux-x86_64.tar.gz
      runner_sha256: <published sha256>
      runner_bundle_url: https://releases.teraclaw.org/verify/teraclaw-verify-linux-x86_64.tar.gz.sigstore.json
      runner_source_commit: <private repo commit recorded at release>
      runner_signer_workflow: quantumlabssh/teraclaw/.github/workflows/release-verify-runner.yml
      runner_source_repository_id: <private repo numeric id>
      workflow_tag: v0.1.1
    secrets:
      TERACLAW_LICENSE_CI_KEY: ${{ secrets.TERACLAW_LICENSE_CI_KEY }}
```

Create the key in the TeraClaw account console: **Settings → License →
CI credential** (Complete plan only). The key has the `license:ci` scope, is
bound to the account, and can be revoked without rotating the runner.

## Trust rules

- The reusable workflow repo must be public, or private in the same
  organization/enterprise with access granted.
- Pin the caller to a tag and publish the workflow commit for that tag. The
  verifier requires the certificate `job_workflow_sha`, not just the tag.
- The runner tarball is hash-checked and its Sigstore bundle is verified before
  execution. A wrong hash or an unexpected signer refuses to run.
- The `license:ci` key is exchanged for a signed `kind: ci` document bound to
  the caller's numeric `repository_id`. A missing, expired, revoked, or
  wrong-repository license posts `action_required` and fails the job.
- The check run is built from the signed receipt. Only `verified` is `success`;
  `weak`, `capped`, and `accepted` are `action_required`; `failed` is
  `failure`. A missing receipt is `action_required`, never `neutral`.
- The action does not cache a license across runs. A teraclaw.org outage fails
  the run instead of reusing an old document.

## Staging

`quantumlabssh/teraclaw-verify-action` is the current production identity in
the private engine's `verify_action_identities.json`. The entry must name the
tag, the exact workflow commit, `environment: production`, and `status:
active`. A `staging` entry is refused by production receipt verification.

After the signed runner release, append the emitted
`runner-signer-*.json` record to the engine's `runner_signers` list and pin
the source commit + SHA-256. Do not accept an arbitrary `v*` tag without a
matching signer record.
