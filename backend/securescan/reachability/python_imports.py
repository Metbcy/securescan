"""Python import-closure reachability analyzer.

The first concrete analyzer. It answers: *is the file a finding lives in
reachable, via the module import graph, from one of the project's
entrypoints?*

This is the cheaper of the two reachability strategies (import-closure, not
full call-graph): it proves a finding's **file** is in the import closure of
some entrypoint. That already kills the biggest noise class -- a Bandit /
Semgrep hit in a script, example, or vendored module that nothing imports.
Symbol-level call-graph precision ("the vulnerable *function* is actually
called") is a future refinement; see ``CLAUDE_TASK.md``.

## Strategy

1. Discover entrypoints (see :meth:`_discover_entrypoints`): ``__main__``
   blocks, ``[project.scripts]`` / ``console_scripts`` in ``pyproject.toml``,
   ``app.py`` / ``main.py`` / ``manage.py`` conventions, and test files.
2. Build a module import graph rooted at those entrypoints by parsing each
   reachable module's ``import`` / ``from ... import`` statements with the
   stdlib :mod:`ast` module (no third-party dep, matching the repo tenet).
3. A finding is REACHABLE if its file's module is in the closure, UNREACHABLE
   if the graph is fully built and the module is absent, UNKNOWN if the file
   has dynamic imports we cannot resolve or parsing failed.

The graph is built once and cached on :class:`AnalysisContext` so classifying
N findings in the same project is one parse pass, not N.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..reachability_model import Reachability
from .base import AnalysisContext, ReachabilityAnalyzer

_CACHE_KEY = "python_imports"

# Filename conventions that are entrypoints even without a __main__ block.
_ENTRYPOINT_NAMES = frozenset(
    {"main.py", "app.py", "manage.py", "__main__.py", "wsgi.py", "asgi.py", "cli.py"}
)


class PythonImportClosureAnalyzer(ReachabilityAnalyzer):
    """Classify Python findings by import-closure reachability."""

    name = "python_imports"

    def claims(self, finding: Finding) -> bool:
        """Claim findings that point at a ``.py`` file.

        We route on the file suffix rather than the scanner name so this works
        for any scanner that can land on Python source (Bandit, Semgrep,
        secrets, etc.). Findings with no ``file_path`` (network, DAST, some
        dependency findings) are left for a dependency-reachability analyzer or
        unclaimed.
        """

        fp = finding.file_path
        return bool(fp) and fp.endswith(".py")

    def classify(
        self, finding: Finding, ctx: AnalysisContext
    ) -> tuple[Reachability, str | None]:
        graph = self._graph(ctx)
        module = _module_for_path(finding.file_path, ctx.target_path)
        if module is None:
            return Reachability.UNKNOWN, "file outside project root"

        # TODO(claude): replace this stub body with the real lookup once
        # _build_graph is implemented. The intended logic:
        #
        #   if graph.unresolved_dynamic_imports:
        #       return UNKNOWN, "project uses dynamic imports (importlib/__import__)"
        #   if module in graph.closure:
        #       entry = graph.nearest_entrypoint(module)
        #       return REACHABLE, f"imported from entrypoint {entry}"
        #   return UNREACHABLE, "no import path from any entrypoint"
        #
        # Until then we return UNKNOWN, which is the safe default: it never
        # hides a finding, so shipping the scaffold cannot cause a missed vuln.
        if graph is None:
            return Reachability.UNKNOWN, "import graph unavailable"
        return Reachability.UNKNOWN, "reachability analysis not yet implemented"

    # ------------------------------------------------------------------ #
    # Graph construction (cached on the context)                          #
    # ------------------------------------------------------------------ #

    def _graph(self, ctx: AnalysisContext) -> ImportGraph | None:
        cached = ctx.cache.get(_CACHE_KEY)
        if cached is not None:
            return cached
        try:
            graph = self._build_graph(ctx.target_path)
        except Exception:  # noqa: BLE001 - graph build is best-effort
            graph = None
        ctx.cache[_CACHE_KEY] = graph
        return graph

    def _build_graph(self, root: Path) -> ImportGraph:
        """Build the import-closure graph rooted at the project's entrypoints.

        TODO(claude): implement. Steps:
          1. entrypoints = self._discover_entrypoints(root)
          2. BFS/DFS from each entrypoint, parsing each module's imports with
             ``ast.parse`` + an ``ast.NodeVisitor`` that collects ``Import`` /
             ``ImportFrom`` targets, resolving relative imports against the
             module's package.
          3. Record the set of reachable module dotted-paths (the closure),
             a flag if any ``importlib`` / ``__import__`` / ``__getattr__``
             dynamic-import escape hatch was seen (forces UNKNOWN for the whole
             project, since the static closure is then unsound), and a
             module -> nearest-entrypoint map for the REACHABLE reason string.
        Return a populated :class:`ImportGraph`.
        """

        entrypoints = self._discover_entrypoints(root)
        # Stub: empty graph. Real implementation walks the import tree.
        return ImportGraph(
            closure=set(),
            entrypoints=entrypoints,
            unresolved_dynamic_imports=False,
            built=False,
        )

    def _discover_entrypoints(self, root: Path) -> set[str]:
        """Find module paths that are program entrypoints.

        TODO(claude): flesh out pyproject ``[project.scripts]`` parsing and
        ``if __name__ == "__main__"`` detection. The convention-name scan below
        is a correct-but-partial starting point; keep it and add to it.
        """

        found: set[str] = set()
        for path in root.rglob("*.py"):
            if _is_vendored(path, root):
                continue
            if path.name in _ENTRYPOINT_NAMES:
                module = _module_for_path(str(path), root)
                if module is not None:
                    found.add(module)
        return found


class ImportGraph:
    """The built import closure for a project (cached per scan).

    Attributes:
        closure: Dotted module paths reachable from any entrypoint.
        entrypoints: Dotted module paths that seed the closure.
        unresolved_dynamic_imports: True if a dynamic-import escape hatch was
            seen anywhere reachable, making the static closure unsound (callers
            should treat every verdict as UNKNOWN).
        built: False for the scaffold stub, True once :meth:`_build_graph` runs
            for real. Lets ``classify`` tell "graph genuinely empty" from "graph
            not built yet".
    """

    def __init__(
        self,
        *,
        closure: set[str],
        entrypoints: set[str],
        unresolved_dynamic_imports: bool,
        built: bool,
    ) -> None:
        self.closure = closure
        self.entrypoints = entrypoints
        self.unresolved_dynamic_imports = unresolved_dynamic_imports
        self.built = built

    def nearest_entrypoint(self, module: str) -> str | None:
        """Return an entrypoint that imports ``module`` (for the reason string).

        TODO(claude): during graph construction, record predecessor edges so
        this can return the actual nearest entrypoint rather than ``None``.
        """

        return None


# ---------------------------------------------------------------------- #
# Path <-> module helpers (dependency-free, safe to use from the stub)    #
# ---------------------------------------------------------------------- #


def _module_for_path(file_path: str | None, root: Path) -> str | None:
    """Convert a file path under ``root`` to a dotted module path.

    ``backend/securescan/api/triage.py`` under root ``backend`` becomes
    ``securescan.api.triage``. Returns ``None`` when the path is not under
    ``root`` or is not a ``.py`` file. Pure string/path math, no I/O beyond
    ``resolve``.
    """

    if not file_path or not file_path.endswith(".py"):
        return None
    try:
        rel = Path(file_path).resolve().relative_to(root.resolve())
    except ValueError:
        return None
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else None


def _is_vendored(path: Path, root: Path) -> bool:
    """True for paths inside common vendor / virtualenv / build dirs.

    Keeps the entrypoint scan from treating a bundled dependency's ``main.py``
    as a project entrypoint.
    """

    skip = {".venv", "venv", "node_modules", "site-packages", ".git", "build", "dist", "__pycache__"}
    return any(part in skip for part in path.parts)
