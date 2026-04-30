# Publishing to PyPI

SecureScan publishes to PyPI via [OIDC Trusted Publishers](https://docs.pypi.org/trusted-publishers/) — the release workflow mints a short-lived token from GitHub Actions and PyPI verifies the OIDC claims. No `PYPI_TOKEN` secret is required.

## One-time setup

1. Create the project on PyPI: log in at <https://pypi.org/manage/projects/> and click *Publish a project*.
2. Or, if the project doesn't exist yet, configure a *pending* publisher under *Your account → Publishing → Add a new pending publisher*:
   - **PyPI Project Name:** `securescan`
   - **Owner:** `Metbcy`
   - **Repository name:** `securescan`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
3. The first time the `release` workflow runs against a `vX.Y.Z` tag with the matching environment, PyPI will create the project and accept the upload.

## Per-release

No action needed. The `publish-pypi` job in `.github/workflows/release.yml` runs automatically on every `vX.Y.Z` tag push.

## Verifying

After a release tag is pushed:
1. Watch the `release` workflow run in the Actions tab.
2. Verify the published package: `pip install securescan==<tag>` in a clean environment.
3. The corresponding sigstore bundle (`securescan-<version>-py3-none-any.whl.sigstore.json`) is attached to the GitHub Release. PyPI does not host sigstore bundles — see [Verifying signed artifacts](https://metbcy.github.io/securescan/deployment/verifying-artifacts.html).
