# TeraClaw verify action

> **Not released for production.** The only published tag is `v0.1.0`, and it
> is a **staging** identity. `v0.1.1` does not exist yet. Do not point a
> production branch-protection check at this action until the hardening branch
> is merged, a runner for the release commit is downloadable through the licence
> gate, the identity is flipped to production, and the tag is created once.
> Tags are immutable under the repository ruleset.

Public reusable Level 2 runner for TeraClaw merge-queue receipts.

This repository is intentionally small. The caller supplies the pinned runner
SHA-256, architecture, signer identity, download host, and a `license:ci`
dashboard key. Each run exchanges the key for a fresh signed v2 CI license and
short-lived presigned runner URLs, verifies the runner bundle, runs the
verifier, and posts a GitHub check run from the signed receipt.

## Caller contract (staging only)

```yaml
jobs:
  verify:
    on: [merge_group, pull_request]
    permissions:
      contents: read
      checks: write
    uses: quantumlabssh/teraclaw-verify-action/.github/workflows/verify.yml@v0.1.0
    with:
      head_sha: ${{ github.event.merge_group.head_sha || github.sha }}
      base_ref: ${{ github.event.merge_group.base_ref || format('refs/heads/{0}', github.event.pull_request.base.ref) }}
      base_sha: ${{ github.event.merge_group.base_sha || github.event.pull_request.base.sha }}
      scope: ${{ github.event.merge_group.head_sha && 'merge_group' || 'pr_merge' }}
      repository_id: ${{ github.event.repository.id }}
      runner_sha256: <published sha256>
      runner_arch: x86_64
      runner_download_host: <account>.r2.cloudflarestorage.com
      runner_source_commit: <private repo commit recorded at release>
      runner_signer_workflow: quantumlabssh/teraclaw/.github/workflows/release-verify-runner.yml@<full release ref, e.g. refs/heads/main or refs/tags/v0.9.16>
      runner_source_repository_id: <private repo numeric id>
      workflow_tag: v0.1.0
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
- The runner and bundle are served from a private bucket through short-lived
  presigned URLs returned by the license exchange. The workflow pins the
  download host, refuses redirects, and never uses a public GitHub release.
- The `license:ci` key is exchanged for a signed `kind: ci` document bound to
  the caller's numeric `repository_id`. A missing, expired, revoked, or
  wrong-repository license posts `action_required` and fails the job.
- The check run is built from the signed receipt. Only `verified` is `success`;
  `weak`, `capped`, and `accepted` are `action_required`; `failed` is
  `failure`. A missing receipt is `action_required`, never `neutral`.
- The action does not cache a license across runs. A teraclaw.org outage fails
  the run instead of reusing an old document.

## Staging — not released

`quantumlabssh/teraclaw-verify-action` has **no production identity** yet. The
only tag is `v0.1.0`, and its entry in the private engine's
`verify_action_identities.json` is `environment: staging`. Production receipt
verification refuses it. Do not use it as a required check.

Release order (owner-controlled):

1. Merge the hardening branch.
2. Build and sign a runner for the release commit; make it downloadable through
   the licence gate.
3. Append the emitted `runner-signer-*.json` to the engine's `runner_signers`
   list and pin the source commit + SHA-256.
4. Update the identity to the exact workflow commit and `environment:
   production`.
5. Create `v0.1.1` **once**, after all of the above. Never move or delete it.

Do not accept an arbitrary `v*` tag without a matching signer record.
