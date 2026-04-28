"""Tests for the CI/AI guard rail logic."""
from __future__ import annotations

from securescan.cli import should_run_ai


def test_ai_skipped_when_CI_env_set():
    # Default behaviour: CI=true, neither flag passed -> AI off
    assert should_run_ai(explicit_ai=False, explicit_no_ai=False, ci_env="true") is False
    # Be tolerant of capitalisation and the alternative "1" form some
    # providers use.
    assert should_run_ai(explicit_ai=False, explicit_no_ai=False, ci_env="TRUE") is False
    assert should_run_ai(explicit_ai=False, explicit_no_ai=False, ci_env="1") is False


def test_ai_runs_when_CI_unset():
    # Empty string represents an unset env var
    assert should_run_ai(explicit_ai=False, explicit_no_ai=False, ci_env="") is True
    # Any other value (e.g. a stale "false") also leaves AI on
    assert should_run_ai(explicit_ai=False, explicit_no_ai=False, ci_env="false") is True


def test_explicit_ai_flag_overrides_CI_skip():
    # --ai forces enrichment back on even when CI=true would have disabled it
    assert should_run_ai(explicit_ai=True, explicit_no_ai=False, ci_env="true") is True
    assert should_run_ai(explicit_ai=True, explicit_no_ai=False, ci_env="1") is True
    assert should_run_ai(explicit_ai=True, explicit_no_ai=False, ci_env="") is True


def test_explicit_no_ai_flag_overrides_CI_runs():
    # --no-ai always wins over the "outside CI -> AI on" default
    assert should_run_ai(explicit_ai=False, explicit_no_ai=True, ci_env="") is False
    assert should_run_ai(explicit_ai=False, explicit_no_ai=True, ci_env="false") is False
    assert should_run_ai(explicit_ai=False, explicit_no_ai=True, ci_env="true") is False
