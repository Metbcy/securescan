# Verifying signed artifacts

Every tagged release of SecureScan publishes signed artifacts:

- **Wheel + sdist** — signed with `sigstore-python`, bundle ships as
  a GitHub Release asset.
- **Container image** — signed by digest with `cosign` keyless
  (Sigstore via OIDC).

Both identities are pinned to `refs/tags/<tag>` — that is why the
release workflow is tag-triggered only and does **not** offer
`workflow_dispatch` (a manual run would publish under a
`refs/heads/...` identity and break these verification commands).

<!-- toc -->

## Wheel + sdist (sigstore)

Install `sigstore`:

```bash
pip install sigstore
```

Download the wheel and its sigstore bundle from the GitHub Release
page (both ship as Release assets):

```bash
gh release download v0.10.3 \
  --repo Metbcy/securescan \
  --pattern 'securescan-0.10.3-py3-none-any.whl' \
  --pattern 'securescan-0.10.3-py3-none-any.whl.sigstore.json'
```

Verify:

```bash
sigstore verify identity \
  --cert-identity 'https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.10.3' \
  --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle securescan-0.10.3-py3-none-any.whl.sigstore.json \
  securescan-0.10.3-py3-none-any.whl
```

You should see:

```text
OK: securescan-0.10.3-py3-none-any.whl
```

Same shape for the sdist:

```bash
sigstore verify identity \
  --cert-identity 'https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.10.3' \
  --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle securescan-0.10.3.tar.gz.sigstore.json \
  securescan-0.10.3.tar.gz
```

## Container image (cosign keyless)

Install cosign (≥ v2.0).

Verify by tag:

```bash
cosign verify ghcr.io/metbcy/securescan:v0.10.3 \
  --certificate-identity 'https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.10.3' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Verify by digest (the recommended pattern for production — tags can
be re-pointed; digests cannot):

```bash
DIGEST="$(crane digest ghcr.io/metbcy/securescan:v0.10.3)"
cosign verify "ghcr.io/metbcy/securescan@${DIGEST}" \
  --certificate-identity 'https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.10.3' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Successful output is JSON:

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "ghcr.io/metbcy/securescan"
      },
      "image": {
        "docker-manifest-digest": "sha256:..."
      },
      "type": "cosign container image signature"
    },
    "optional": {
      "Bundle": { "...": "..." },
      "Issuer": "https://token.actions.githubusercontent.com",
      "Subject": "https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.10.3"
    }
  }
]
```

## What the verification proves

- The artifact was produced **by the SecureScan release workflow at
  the v0.10.3 tag** running on GitHub Actions.
- The Sigstore transparency log (Rekor) has an immutable record of
  the signature.
- The artifact has not been tampered with since signing.

It does **not** prove:

- That the v0.10.3 source tree itself is bug-free or malware-free.
- That the artifact you have was downloaded from the official source
  (verify the registry / release URL too).

## Pinning in production

```admonish important title="Pin by digest, not tag"
Tags are mutable references. A registry compromise (or a careless
re-push) could re-point `v0.10.3` to a different image. **Pin by
digest** in production manifests:

​    image: ghcr.io/metbcy/securescan@sha256:abcdef...

The `cosign verify ...@sha256:...` command above ties the running
image to the v0.10.3 release identity, regardless of what a tag now
points at.
```

For Kubernetes, an admission controller like
[Sigstore Policy Controller](https://docs.sigstore.dev/policy-controller/overview/)
or [Kyverno's `verifyImages`](https://kyverno.io/policies/?policytypes=verifyImages)
can enforce verification at admission time so an unsigned image
never starts.

## Why these specific identities

The cert identity is the workflow file path **at the tagged ref**:

```text
https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.10.3
```

That URL is self-describing:

| Segment                    | Meaning                                       |
| -------------------------- | --------------------------------------------- |
| `Metbcy/securescan`        | The repository.                               |
| `.github/workflows/release.yml` | The workflow that signed the artifact.   |
| `refs/tags/v0.10.3`         | The git ref the workflow ran against.         |

The OIDC issuer is GitHub Actions' fixed token issuer:

```text
https://token.actions.githubusercontent.com
```

Together they prove "this artifact was signed by Metbcy/securescan's
release workflow when run against the v0.10.3 tag." Re-running the
workflow against a different tag, branch, or repository would
produce a different identity that fails the verification.

## Troubleshooting

### `error: tlog entry not found`

Sigstore cached transparency entries can lag a few seconds after
signing. Retry. If it persists past a minute, the artifact may have
been signed against an unsupported transparency log; check the
Sigstore status page.

### `subject mismatch`

The `--cert-identity` does not match the actual signature. Most
common causes:

- Wrong tag in the URL (`v0.10.3` vs `v0.10.4`).
- Verifying a `latest` image — `latest` is built from main and
  *not* signed via the tagged-release path.
- Forking SecureScan and re-running `release.yml` from your fork.
  Your fork's signatures will use *your* org/repo in the identity.

### `error: bundle does not match`

The `--bundle` file does not correspond to the `securescan-*.whl`
on disk. Make sure you downloaded both from the same GitHub Release.

## Source

- Release workflow:
  [`.github/workflows/release.yml`](https://github.com/Metbcy/securescan/blob/main/.github/workflows/release.yml)
- The exact verification commands are also appended to each GitHub
  Release's notes (auto-generated from the `release.yml` template),
  with `<tag>` and `<version>` substituted in.

## Next

- [Release process](../reference/release-process.md) — what produces these signatures.
- [Production checklist](./production-checklist.md) — verification is on it.
- [Docker](./docker.md) — the image we just verified.
