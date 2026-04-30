# Release cadence

SecureScan releases predictably so adopters can plan upgrades.

## Schedule

- **Minor releases (`vX.Y.0`):** first Monday of every month. New features, deprecations, larger refactors.
- **Patch releases (`vX.Y.Z`, Z>0):** as needed, typically same-day for fixes worth shipping.
- **Major releases (`vX.0.0`):** when breaking API/CLI changes accumulate. No fixed schedule; called out at least one minor release in advance.

## What's a breaking change?

Anything that requires a user to change a command, config file, or CI workflow to keep working:
- Removed or renamed CLI flags
- Removed or renamed `.securescan.yml` keys (gated by `version:` field)
- Removed REST API endpoints (we keep `/api/v1/...` stable; `/api/...` legacy is `Deprecation`-headered for 1 year before removal)
- Container image entrypoint changes

Adding new options, new endpoints, or new env vars is NOT breaking.

## Pinning

- `Metbcy/securescan@v1` — floating major; safe for most users.
- `Metbcy/securescan@v0.10.3` — exact pin; safe for fully-deterministic CI.
- `pip install securescan` — pulls the latest stable from PyPI.
- `pip install securescan==0.10.3` — exact pin.

## Deprecation policy

When a feature is deprecated:
1. Documented in CHANGELOG under a `### Deprecated` section.
2. Runtime warning emitted (Python: `DeprecationWarning`; CLI: stderr message).
3. Removal scheduled at least 2 minors out (≥60 days notice).
