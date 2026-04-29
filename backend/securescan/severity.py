"""Apply per-rule severity overrides from .securescan.yml.

The user-facing CLI flow is:
  scan -> populate_fingerprints -> apply_severity_overrides -> render

Each finding whose ``rule_id`` matches a key in ``config.severity_overrides``
gets its severity replaced. The original severity is stamped on
``metadata["original_severity"]`` (string value of the enum, e.g. ``"high"``)
so downstream tooling can audit "this was demoted from high to medium".

Why a per-repo knob at all?
---------------------------
Off-the-shelf rule packs (Semgrep, Bandit, etc.) ship with severities tuned
for "the average codebase". A rule that fires ``high`` for, say, a hard-coded
secret pattern is *correct on average* but is noise in a repo where the
matched strings are test fixtures. Without a per-repo dial, teams either
disable the rule entirely (losing real coverage) or learn to ignore the
scanner output (losing the scanner). The override lets them keep the
detection but tune the urgency.

Why stamp the original severity?
--------------------------------
SARIF / JSON consumers (PR comments, dashboards, audit logs) need to show
both the *effective* severity and the *original* severity. Rendering
"medium (was: high)" is the difference between "we triaged this rule" and
"the scanner has always thought this was medium". The stamp is the audit
trail.

Why string and not the enum?
----------------------------
``metadata`` flows through ``json.dumps`` in two renderers (SARIF and the
JSON exporter). Storing ``Severity.HIGH`` would force every renderer to
special-case enum types; storing ``"high"`` is a no-op for ``json.dumps``.

Why is this idempotent?
-----------------------
Both ``securescan scan`` and ``securescan diff`` will eventually call
``apply_severity_overrides`` (TS10 wiring) on the same set of findings —
``diff`` re-loads the previous run from the DB and the current run from
disk, and both must be normalized through the same config. If we re-stamped
on a second pass, ``original_severity`` would silently drift to the value
*after* the first override, destroying the audit trail. The check is on
``metadata[_ORIGINAL_KEY]`` *presence*: once stamped, hands off.
"""
from __future__ import annotations

from .config_file import SecureScanConfig
from .models import Finding

_ORIGINAL_KEY = "original_severity"


def apply_severity_overrides(
    findings: list[Finding],
    config: SecureScanConfig,
) -> tuple[list[Finding], int]:
    """Apply ``config.severity_overrides`` in place.

    Returns ``(findings, n_overridden)`` where ``findings`` is the same list
    object passed in (mutated) and ``n_overridden`` is the number of
    findings whose severity (or audit stamp) was actually written in this
    call -- excluding idempotent skips and rule_id non-matches.

    Edge case: when ``config.severity_overrides[rule_id]`` equals the
    finding's current severity, we **still** stamp ``original_severity``
    and count it as overridden. Rationale: the user pinning a rule at the
    severity it already has is meaningful audit data ("this rule has been
    explicitly held at high"), and treating equal-severity as a no-op
    would create an inconsistent audit trail where some user-pinned rules
    carry the stamp and others do not.

    Idempotent: a second call is a no-op (already-stamped findings are
    skipped). Safe to call from both the ``scan`` and ``diff`` code paths
    on the same finding set without double-stamping.
    """
    if not config.severity_overrides:
        return findings, 0

    overrides = config.severity_overrides
    n_overridden = 0

    for finding in findings:
        rule_id = finding.rule_id
        if rule_id is None:
            continue

        new_severity = overrides.get(rule_id)
        if new_severity is None:
            continue

        if finding.metadata.get(_ORIGINAL_KEY) is not None:
            continue

        finding.metadata[_ORIGINAL_KEY] = finding.severity.value
        finding.severity = new_severity
        n_overridden += 1

    return findings, n_overridden
