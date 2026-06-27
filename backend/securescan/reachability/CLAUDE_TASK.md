# CLAUDE_TASK: implement the reachability import-closure analyzer

This is a handoff spec. The reachability **scaffold** is already in place,
wired into the pipeline, and tested (15 passing tests + 3 skipped that you
will flip on). Your job is to replace one stubbed function with a real
Python import-closure graph walk, then delete three `@pytest.mark.skip`
markers and make those tests pass.

Do NOT redesign the architecture, the config, the data model, or the pipeline
integration. They are deliberate and tested. Fill in the one stub.

## Context: what reachability is

A finding's reachability answers "is this vulnerable code actually wired into
something that runs?" SecureScan posts NEW findings on a PR; a critical in an
unimported file or a script nothing runs is noise. We classify each finding
REACHABLE / UNREACHABLE / UNKNOWN. We NEVER hide a finding on a guess:
UNKNOWN and unstamped findings are always shown; only an explicit UNREACHABLE
verdict (with `demote_unreachable` enabled) lowers a finding's severity by one
step. That demotion is already implemented and tested in
`securescan/reachability_demote.py` -- you do not touch it.

## The one thing to implement

`securescan/reachability/python_imports.py`:

1. **`PythonImportClosureAnalyzer._build_graph(self, root)`** -- currently
   returns an empty stub `ImportGraph(built=False)`. Implement the real walk:
   - Start from `self._discover_entrypoints(root)` (a partial implementation
     exists -- the convention-name scan; extend it, see step 3).
   - BFS/DFS the module import graph. Parse each reachable module with the
     stdlib `ast` module (NO third-party deps -- the repo tenet is a small dep
     tree; `ast` is stdlib). Collect `ast.Import` and `ast.ImportFrom` targets
     with an `ast.NodeVisitor`. Resolve relative imports (`from . import x`,
     `from ..pkg import y`) against the importing module's package.
   - Map each discovered import back to an in-project module path using the
     existing `_module_for_path` helper (already implemented and tested --
     reuse it, do not rewrite it).
   - Populate and return a real `ImportGraph`:
     - `closure`: set of dotted module paths reachable from any entrypoint.
     - `entrypoints`: from `_discover_entrypoints`.
     - `unresolved_dynamic_imports`: True if ANY reachable module uses
       `importlib`, `__import__`, or a module-level `__getattr__` (these make
       the static closure unsound). When True, every verdict becomes UNKNOWN.
     - `built=True`.
   - Record predecessor edges so `ImportGraph.nearest_entrypoint(module)` can
     return a real entrypoint name for the REACHABLE reason string.

2. **`PythonImportClosureAnalyzer.classify(...)`** -- replace the stubbed body
   (the block under `# TODO(claude):`) with the intended logic already written
   as a comment there:
   ```
   if graph is None or not graph.built:
       return UNKNOWN, "import graph unavailable"
   if graph.unresolved_dynamic_imports:
       return UNKNOWN, "project uses dynamic imports (importlib/__import__)"
   if module in graph.closure:
       entry = graph.nearest_entrypoint(module)
       return REACHABLE, f"imported from entrypoint {entry}" if entry else "in import closure"
   return UNREACHABLE, "no import path from any entrypoint"
   ```

3. **`_discover_entrypoints`** -- extend the existing convention-name scan to
   also find:
   - `if __name__ == "__main__":` blocks (parse with `ast`, look for the
     compare node).
   - `[project.scripts]` and `[project.entry-points."console_scripts"]` in
     `pyproject.toml` (use stdlib `tomllib`).
   - Keep treating test files (`test_*.py`, `*_test.py`, `tests/`) as
     entrypoints -- a vuln exercised only by tests is still "reached".

## Definition of done

1. Delete the three `@pytest.mark.skip(reason=_PENDING)` markers in
   `tests/test_reachability.py` and make these pass:
   - `test_unimported_file_is_unreachable`
   - `test_imported_file_is_reachable`
   - `test_dynamic_import_forces_unknown`
2. Add at least 4 more tests covering: relative imports, a package
   `__init__.py` re-export chain, a `[project.scripts]` entrypoint, and a
   `__name__ == "__main__"` entrypoint.
3. All 15 existing reachability tests still pass (do not change their
   assertions; they encode the contract).
4. The full suite is green except the ONE pre-existing unrelated failure
   `tests/test_nmap_scanner.py::test_not_available_when_nmap_missing` (fails
   because nmap is installed in this container -- not your concern, it fails
   on `main` too).
5. Run the repo's linters before declaring done:
   ```
   cd backend
   python3 -m pytest tests/test_reachability.py -q
   ruff check securescan/reachability* securescan/reachability/  # if ruff is configured
   ```

## Hard constraints

- **stdlib only** for the analysis (`ast`, `tomllib`, `pathlib`). No
  `networkx`, no `grimp`, no `modulegraph`. The whole point vs the SaaS tools
  is a small, auditable, dependency-light implementation.
- **Never return UNREACHABLE on uncertainty.** Syntax error in a file,
  unresolvable import, dynamic import anywhere reachable -> UNKNOWN. A false
  UNREACHABLE hides a real vuln; that is the one unacceptable failure.
- **Performance**: the graph is built once per scan and cached on
  `AnalysisContext.cache[_CACHE_KEY]`. Do not rebuild per finding. A 1000-file
  project should parse in a few seconds, not minutes. (Issue #9 in this repo
  is about 100k-finding memory; do not regress it -- the graph is keyed on
  modules, not findings, so it is bounded by file count not finding count.)
- **Best-effort, never fatal.** `analyze()` already wraps `classify()` in a
  try/except, but your `_build_graph` should also handle a malformed file
  gracefully (skip it, mark the project UNKNOWN-prone if it was an entrypoint).
- Style: this is Mir's repo. Match the surrounding docstring voice (the
  module docstrings are detailed and explain *why*). No em dashes in prose you
  add (use commas/colons/parens) -- Mir's house style. Author commits as
  `Metbcy <amirbredy1@gmail.com>` and do NOT commit/push; leave the tree dirty
  for review (the orchestrator writes the commit + PR body).

## Files

- IMPLEMENT: `securescan/reachability/python_imports.py` (the `_build_graph`,
  `classify` stub body, `_discover_entrypoints`, `ImportGraph.nearest_entrypoint`).
- TESTS: `tests/test_reachability.py` (un-skip 3, add >=4).
- DO NOT TOUCH: `reachability_model.py`, `reachability/__init__.py`,
  `reachability/base.py`, `reachability_demote.py`, `pipeline.py`,
  `config_file.py`. They are the tested contract your implementation plugs into.

## How it all fits (already wired, for your orientation)

```
scan -> findings
  -> apply_pipeline (pipeline.py)
       populate_fingerprints
       IF config.reachability.enabled:
           analyze(findings, target_path)        <- reachability/__init__.py
               -> per finding: analyzer.claims() then analyzer.classify()
                  python_imports.classify()       <- YOU implement the verdict
                  set_reachability(metadata, verdict, reason)
           IF config.reachability.demote_unreachable:
               demote_unreachable_findings(...)    <- done, tested
       apply_severity_overrides
       suppression
  -> render NEW-findings PR comment (verdict + reason surface here later)
```

The dashboard/PR-comment rendering of the verdict badge is a SEPARATE
follow-up (not this task) -- this task lands the engine that produces the
verdict. Stamping `metadata['reachability']` is the deliverable.
