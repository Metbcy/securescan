# Scan types

A `scan_type` selects which **family** of scanners runs. The orchestrator
expands `["code", "dependency"]` into the union of every scanner whose
`scan_type` matches.

You can pass any subset; if none are passed the CLI defaults to `code`
for fast PR feedback. There are six families.

<!-- toc -->

## Type table

| Type         | Default for `securescan diff` | Scanners                                                | Typical target          |
| ------------ | :---------------------------: | ------------------------------------------------------- | ----------------------- |
| `code`       | ✅ yes                        | semgrep, bandit, secrets, git-hygiene                   | Source tree             |
| `dependency` |                               | trivy, safety, npm-audit, licenses                      | Source tree (manifests) |
| `iac`        |                               | checkov, dockerfile                                     | Source tree             |
| `baseline`   |                               | baseline (built-in)                                     | Host or filesystem      |
| `dast`       |                               | builtin_dast, zap                                       | URL                     |
| `network`    |                               | nmap                                                    | Hostname / IP / range   |

The mapping lives in
[`backend/securescan/scanners/__init__.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/__init__.py)
(`ALL_SCANNERS` registry) and each scanner's `scan_type` class
attribute.

## `code`

Static analysis of source files in the target tree. Picks up:

- **SAST** issues (SQL injection, XSS, command injection, path
  traversal) via Semgrep with `--config auto` plus any custom rule
  packs you declare in `.securescan.yml`.
- **Python-specific** insecure imports and bandit's signatures.
- **Secrets** (hardcoded API keys, tokens, private keys) via the
  built-in regex bank and Gitleaks.
- **Git hygiene** — sensitive files committed to the repo,
  missing `.gitignore` entries.

Example:

```bash
securescan scan ./your-repo --type code --output text
```

```text
[HIGH]   semgrep        backend/api.py:42      Use of eval()
[HIGH]   bandit         backend/db.py:12       SQL injection via str.format
[MEDIUM] secrets        config/local.yml:5     AWS access key
```

The same call via the API:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $K" \
  -d '{"target_path":"/abs/path/to/repo","scan_types":["code"]}'
```

## `dependency`

Manifest + lockfile vulnerability scanning:

- `trivy` — handles `requirements.txt`, `package.json`, `Gemfile.lock`,
  `Cargo.lock`, `go.sum`, `composer.lock`, `Pipfile.lock`, etc.
- `safety` — Python dependencies against the safety DB.
- `npm-audit` — npm advisories on transitive deps.
- `licenses` — copyleft / unknown-license risks via `pip-licenses`.

Example:

```bash
securescan scan ./node-project --type dependency --output sarif \
  --output-file deps.sarif
```

```admonish note
The `licenses` scanner reports compliance findings (unknown / GPL /
AGPL detected), not CVEs. It is part of the `dependency` family
because the data source is the manifest. Filter it out with
`.securescan.yml`'s `ignored_rules` if your org has explicit
copyleft approval.
```

## `iac`

Infrastructure-as-code misconfigurations:

- `checkov` — Terraform, Kubernetes manifests, Helm charts,
  CloudFormation, Dockerfiles. Hundreds of policies out of the box.
- `dockerfile` — opinionated checks for `:latest` base images,
  running as root, `curl | sh` patterns, secrets in `ENV`.

```bash
securescan scan ./infra --type iac --output text
```

The dockerfile scanner is fast and runs even when checkov is not
installed; checkov is the heavyweight, broader source.

## `baseline`

Host-config audit: SSH daemon settings, `/etc/passwd` /
`/etc/shadow` perms, `~/.ssh` perms, kernel parameters, password
policy.

The behavior depends on `target_path`:

- `target_path = "/"` — host-wide probes (the default behavior).
- Anything else — probes `<target>/etc/ssh/sshd_config`,
  `<target>/etc/passwd`, `<target>/etc/shadow`. Skips host-only
  checks like `~/.ssh` perms. If none of those files are present,
  emits one info-severity finding pointing at
  `--baseline-host-probes`.

```bash
# Audit the running host (requires read access to /etc/...)
securescan scan / --type baseline

# Audit a chrooted filesystem
securescan scan /mnt/snapshot --type baseline

# Force host-scope probes alongside a target scan
securescan scan ./my-config --type code --baseline-host-probes
```

Every baseline finding gets a `metadata.baseline_scope` tag of
`host` or `target` so the audit trail records which mode produced
the finding.

## `dast`

Dynamic application security testing — runs against a **live** URL:

- `builtin_dast` — header / cookie / info-disclosure checks. No
  external dependency. Fast.
- `zap` — full ZAP active+passive scan. Requires a running ZAP
  daemon at `SECURESCAN_ZAP_ADDRESS`.

```bash
securescan scan https://staging.example.com \
  --type dast \
  --output text
```

For the ZAP scanner, set credentials in
[`~/.config/securescan/.env`](../deployment/local-config.md):

```bash
SECURESCAN_ZAP_ADDRESS=http://127.0.0.1:8090
SECURESCAN_ZAP_API_KEY=your-key
```

```admonish warning
Only run DAST against systems you own or have explicit authorization
to test. ZAP active mode is intrusive. The default `securescan diff`
in CI does **not** include `dast` — you have to opt in with
`--type dast` (or `scan-types: code,dast` on the GitHub Action).
```

## `network`

Network-perimeter probe via `nmap`. Reports open ports, detected
service banners, and a coarse risk classification (telnet, RDP, SMB,
exposed databases, etc.).

```bash
securescan scan 10.0.0.1 --type network --output text
```

Or a CIDR / hostname:

```bash
securescan scan example.com --type network
securescan scan 10.0.0.0/24 --type network --output sarif --output-file net.sarif
```

```admonish important title="Scope authorization required"
nmap is **not** a passive tool. Run it only against networks you own
or have written authorization to scan. The scanner does not enforce
this; you are responsible.
```

## Combining types

Comma-separated list — all are unioned together:

```bash
securescan scan ./your-repo --type code --type dependency --type iac
```

Or in `.securescan.yml`:

```yaml
scan_types:
  - code
  - dependency
  - iac
```

The PR-mode default is `scan-types: code` because it produces fast
feedback on every push. Adding `dependency` is the most common
upgrade for a busy repo.

## Picking what to run

```admonish tip title="Decision tree"
- Scanning a **PR diff**? `code` (default) — adds dependency / iac as your team adopts them.
- Scanning a **release tag** before publishing? `code,dependency,iac`.
- Auditing a **production host**? `baseline` against `/`.
- Verifying a **deployed service**? `dast` against the URL.
- Surveying a **subnet**? `network` (with authorization).
```

## Next

- [Supported scanners](./supported-scanners.md) — what each tool produces.
- [Suppression](./suppression.md) — silencing rules across types.
- [Compliance](./compliance.md) — how findings map to OWASP / SOC 2 / PCI-DSS.
