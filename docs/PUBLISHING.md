# Publishing to PyPI

SecureScan publishes to PyPI via [OIDC Trusted Publishers](https://docs.pypi.org/trusted-publishers/) — the release workflow mints a short-lived token from GitHub Actions and PyPI verifies the OIDC claims. **No `PYPI_TOKEN` secret is required.**

## Per-release

No action needed. The `publish-pypi` job in `.github/workflows/release.yml` runs automatically on every `vX.Y.Z` tag push and uploads the wheel + sdist to <https://pypi.org/project/securescan/>.

## Verifying a release

After a release tag is pushed:

1. Watch the `release` workflow run in the Actions tab.
2. `pip install securescan==<version>` in a clean environment.
3. The corresponding sigstore bundle (`securescan-<version>-py3-none-any.whl.sigstore.json`) is attached to the GitHub Release. PyPI does not host sigstore bundles — see [Verifying signed artifacts](https://metbcy.github.io/securescan/deployment/verifying-artifacts.html).

## One-time setup (forks / new owners only)

The canonical project is already configured. If you fork the repo and want to publish under a different PyPI name:

1. At <https://pypi.org/manage/account/publishing/>, scroll to *Add a new pending publisher* and fill:
   - **PyPI Project Name:** your project name
   - **Owner:** your GitHub org/user
   - **Repository name:** your repo
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
2. Push your first `vX.Y.Z` tag. PyPI creates the project on first successful upload and the pending publisher auto-promotes.
