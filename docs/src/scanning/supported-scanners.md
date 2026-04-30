# Supported scanners

SecureScan ships **14 scanners**. Each is a Python class that subclasses
`BaseScanner` and shells out to the underlying tool. The registry is
[`backend/securescan/scanners/__init__.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/__init__.py);
each module is named after the scanner.

<!-- toc -->

## Registry

| Scanner          | Module                                                                                                                                | `scan_type`  | What it finds                                                                              |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------ |
| **semgrep**      | [`scanners/semgrep.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/semgrep.py)                         | `code`       | SQLi, XSS, command injection, hardcoded secrets via Semgrep's rule library.                |
| **bandit**       | [`scanners/bandit.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/bandit.py)                           | `code`       | Python-specific security issues, insecure imports.                                         |
| **secrets**      | [`scanners/secrets.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/secrets.py)                         | `code`       | Hardcoded credentials, API keys, tokens, private keys.                                     |
| **git-hygiene**  | [`scanners/gitleaks.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/gitleaks.py)                       | `code`       | Sensitive files committed to repo, gitleaks rules, missing `.gitignore` protections.       |
| **trivy**        | [`scanners/trivy.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/trivy.py)                             | `dependency` | Known CVEs in package manifests and lockfiles across many ecosystems.                      |
| **safety**       | [`scanners/safety.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/safety.py)                           | `dependency` | Python dependency vulnerabilities from the safety DB.                                      |
| **npm-audit**    | [`scanners/npm_audit.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/npm_audit.py)                     | `dependency` | npm package advisories and transitive vulns.                                               |
| **licenses**     | [`scanners/license_checker.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/license_checker.py)         | `dependency` | Copyleft / unknown / restricted license findings via `pip-licenses` and the `license` field of npm packages. |
| **checkov**      | [`scanners/checkov.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/checkov.py)                         | `iac`        | Terraform, Kubernetes, Helm, CloudFormation, Dockerfile misconfigurations.                 |
| **dockerfile**   | [`scanners/dockerfile.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/dockerfile.py)                   | `iac`        | Insecure Docker patterns: `:latest`, root user, `curl \| sh`, secrets in `ENV`.            |
| **baseline**     | [`scanners/baseline.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/baseline.py)                       | `baseline`   | SSH config, `/etc/passwd` perms, password policy, kernel params.                           |
| **builtin_dast** | [`scanners/dast_builtin.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/dast_builtin.py)               | `dast`       | Missing security headers, info disclosure, insecure cookie flags. No external dep.         |
| **zap**          | [`scanners/zap_scanner.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/zap_scanner.py)                 | `dast`       | OWASP ZAP active + passive scan against a URL.                                             |
| **nmap**         | [`scanners/nmap_scanner.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/nmap_scanner.py)               | `network`    | Open ports, service detection, risk classification.                                        |

To see what is installed and reachable on the current host:

```bash
$ securescan status
Scanner       Type         Available  Version    Notes
semgrep       code         yes        1.71.0
bandit        code         yes        1.7.5
trivy         dependency   yes        0.49.1
safety        dependency   yes        2.3.5
checkov      iac          no                    pip install checkov
npm-audit     dependency   yes        npm 10.x   uses ambient `npm` on PATH
zap           dast         no                    /usr/share/zaproxy/zap.sh; recommended port 8090
nmap          network      yes        7.94
...
```

The same data is at `GET /api/v1/dashboard/status` — the dashboard's
`/scan` page reads it on mount and disables categories whose scanners
are all unavailable. See [Dashboard tour](../dashboard/tour.md).

## Per-scanner notes

### Semgrep

- Uses `--config auto` by default. To override, set `semgrep_rules` in
  `.securescan.yml`:

  ```yaml
  semgrep_rules:
    - .securescan/rules/secrets.yml
    - .securescan/rules/unsafe-deserialization.yml
  ```

  When set, replaces `--config auto` with one `--config <path>` per
  entry. Paths are relative to the config file.

- Rule IDs surface as `python.lang.security.audit.eval-detected` etc.
  Use them in `severity_overrides:` and `ignored_rules:` to tune.

### Bandit

- Runs against Python files only. Rule IDs are `B<NNN>` (e.g. `B106` =
  hardcoded password).
- One bandit gotcha: it scans `__init__.py` and test files too. Use
  inline `# securescan: ignore B106` on test fixtures to silence
  intentional-by-design findings.

### Trivy

- The heavyweight dependency scanner. Picks up most ecosystems out of
  the box (`requirements.txt`, `package-lock.json`, `Cargo.lock`,
  `go.sum`, `composer.lock`, `Pipfile.lock`).
- Updates its DB on first run; allow ~30s extra latency on a cold
  cache.

### ZAP

- Requires a separately running ZAP daemon. The scanner connects to
  the daemon's HTTP API.

  ```bash
  # ~/.config/securescan/.env
  SECURESCAN_ZAP_ADDRESS=http://127.0.0.1:8090
  SECURESCAN_ZAP_API_KEY=your-key
  ```

- The Arch Linux launcher is auto-detected at
  `/usr/share/zaproxy/zap.sh`. The scanner's `install_hint` recommends
  port `8090` because `8080` is commonly busy.

### nmap

- Default scan is non-intrusive (TCP connect, top 1000 ports, service
  banners). Risk classification flags exposed databases (3306, 5432,
  6379, 27017), unencrypted protocols (telnet 23, FTP 21), and SMB
  (445).

```admonish important
nmap is **not** passive. Only run it against networks you own or
have explicit written authorization to scan. SecureScan does not
enforce scope authorization — that is your responsibility.
```

### baseline

- The only built-in scanner (no external CLI). Implements every
  probe directly in Python.
- Probes are categorised as `host` or `target` scope; see
  [Scan types](./scan-types.md#baseline) for how `target_path`
  selects between them.
- Surfaces `metadata.baseline_scope = "host" | "target"` on every
  finding for audit trail.

## Adding scanners

Adding a new scanner means dropping a new module under
`backend/securescan/scanners/` that subclasses `BaseScanner` and
appending an instance to `ALL_SCANNERS`. The base class handles:

- Subprocess spawn + cancellation.
- Stdout / stderr capture.
- `install_hint` + availability detection.
- Wrapping returned dicts into `Finding` instances with the right
  `scan_type`, `scanner` name, and severity normalization.

The `BaseScanner` interface lives in
[`backend/securescan/scanners/base.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scanners/base.py).
That said, **the v0.9.0 contract treats the registry as fixed** — new
scanners should land via PR rather than runtime registration.

## Next

- [Findings & severity](./findings-severity.md) — the normalized shape every scanner outputs.
- [Suppression](./suppression.md) — silencing a noisy scanner / rule.
- [Compliance](./compliance.md) — mapping rule IDs to frameworks.
