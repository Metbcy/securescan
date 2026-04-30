# SBOM

SecureScan generates a Software Bill of Materials in two formats:

- **CycloneDX 1.5** — JSON; the default for tooling integrations.
- **SPDX 2.3** — JSON; the format some compliance auditors require.

The generator runs against the same scanned target as the dependency
scanners, so the SBOM and the `dependency` findings reference the
same component set.

<!-- toc -->

## API

```bash
curl -H "X-API-Key: $K" \
  "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/sbom?format=cyclonedx" \
  > sbom.cyclonedx.json

curl -H "X-API-Key: $K" \
  "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/sbom?format=spdx" \
  > sbom.spdx.json
```

`format` defaults to `cyclonedx`. Both endpoints require the `read`
scope.

Source:
[`backend/securescan/api/sbom.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/sbom.py).

## Component shape (CycloneDX excerpt)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "components": [
    {
      "bom-ref": "pkg:pypi/requests@2.31.0",
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0",
      "licenses": [{"license": {"id": "Apache-2.0"}}]
    },
    {
      "bom-ref": "pkg:npm/axios@1.6.7",
      "type": "library",
      "name": "axios",
      "version": "1.6.7",
      "purl": "pkg:npm/axios@1.6.7"
    }
  ]
}
```

The component set is unioned across:

- Python: `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`.
- Node: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`.
- Go: `go.sum`.
- Rust: `Cargo.lock`.
- Ruby: `Gemfile.lock`.
- PHP: `composer.lock`.

Detection follows what the underlying scanners (Trivy, Safety,
npm-audit) already parse — adding a manifest format is a follow-up
that lands first in those scanners.

## Dashboard view

`/sbom`:

```text
PageHeader: SBOM · scan_id [picker ▾]

[ CycloneDX ] [ SPDX ]   <- segmented format toggle

Ecosystem stats
  ●●● PyPI    21 components
  ●●  npm     14 components
  ●   Crates   3 components

Component table (paginated; sortable)
  Name              Version    Ecosystem    License        bom-ref
  requests          2.31.0     PyPI         Apache-2.0     pkg:pypi/requests@2.31.0
  axios             1.6.7      npm          MIT            pkg:npm/axios@1.6.7
  ...
```

The format toggle is a no-cost view re-render — the API call returns
the chosen format, the dashboard parses it and renders the same
component table.

Source: `frontend/src/app/sbom/page.tsx`.

## Use in CI

The SBOM is most useful as an artifact attached to a release build:

```yaml
- name: Run SecureScan
  run: securescan scan . --type dependency --output json --output-file findings.json
- name: Upload SBOM
  run: |
    curl -H "X-API-Key: $K" \
      "https://securescan.internal/api/v1/scans/${SCAN_ID}/sbom" \
      > sbom.cyclonedx.json
- uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.cyclonedx.json
```

For supply-chain attestations (sigstore-cosign attestation), the
CycloneDX file is the right input — the format has stable
canonicalization rules.

## What this is not

```admonish important
SecureScan's SBOM generator is a **convenience surface** built on top
of the dependency scanners. For production-grade SBOMs that need to
be canonical for compliance audits, use a dedicated tool —
[Syft](https://github.com/anchore/syft) and
[`cyclonedx-cli`](https://github.com/CycloneDX/cyclonedx-cli) are the
references. SecureScan deliberately does **not** try to be an SBOM
generator (see README "Non-goals").
```

The trade-off: SecureScan's SBOM is "good enough" for human review
and for tying to the same scan that produced your vulnerability
findings. It is not a replacement for Syft when an auditor requires a
canonical SBOM.

## Next

- [Findings & severity](../scanning/findings-severity.md) — the matched dependency vulns.
- [Compliance](../scanning/compliance.md) — license risk surfaces here too.
- [API endpoints](../api/endpoints.md) — full list.
