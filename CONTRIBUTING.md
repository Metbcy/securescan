# Contributing to SecureScan

Thanks for considering a contribution! SecureScan is Apache-2.0 licensed and welcomes external PRs.

## Development setup

```bash
# Clone and install
git clone https://github.com/Metbcy/securescan.git
cd securescan/backend
python -m venv venv && source venv/bin/activate
pip install -e ".[dev,pdf]"

# Run tests
pytest

# Lint + format
ruff check securescan/ tests/
ruff format securescan/ tests/

# Type check
mypy securescan/ --ignore-missing-imports
```

For frontend work:
```bash
cd frontend
npm ci
npm run dev          # development server on :3000
npx tsc --noEmit     # type check
npm run lint         # ESLint
npm run build        # production build
```

## Pull request process

1. Open an issue first if proposing a non-trivial change. Tag with `proposal`.
2. Branch from `main`. Conventional Commits in PR titles (`feat:`, `fix:`, `docs:`, `chore:`, etc.).
3. Add tests for new behavior. The CI gate is `--cov-fail-under=77` — keep it green.
4. Run `ruff check` and `ruff format` before pushing.
5. CI must pass: `Lint & test`, `SecureScan Security Audit`, and `Container image`.
6. Squash-merge into main. Releases happen on tag pushes.

## Code style

- Python: ruff handles lint + format. Type hints required for public surfaces.
- TypeScript: ESLint + Prettier (via Next.js defaults).
- Determinism is a hard requirement: no wall-clock timestamps, no nondeterministic iteration order in user-facing output. The test suite enforces this for SARIF and JSON.
- Subprocess calls MUST use `asyncio.create_subprocess_exec` with arg-list passing (no `shell=True`).

## What's a good first contribution?

Issues labeled `good first issue` and `help wanted` are scoped for newcomers. The triage workflow (status pills, comments) shipped in v0.7.0 is a complete vertical slice; a similar end-to-end feature is the right size for a first PR.

## Reporting security issues

Don't open a public issue. Email <Amirbredy1@gmail.com> with details. We'll acknowledge within 72 hours.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating you agree to abide by it.
