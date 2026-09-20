"""Process-wide runtime state: the parts of the system that are expensive to
build and safe to share.

Before this module existed, every ``/simulate`` request constructed a fresh
``RulesEvaluator``, which re-read 42 control catalogues and every mapping pack
from disk — roughly 3,400 controls parsed to answer one question about one
device. Handlers now ask :data:`STATE` for what they need and get a cached
object back.

The cache is not a plain memo, because two of PS 26155's five capabilities are
promises about *change taking effect without a restart*:

* **C2** — a mapping taught in the GUI must apply to the next parse. The learned
  pattern provider fingerprints the mapping table, so it does.
* **C5** — a new vendor pack or standard must apply without code changes.
  ``PatternLibrary`` and ``RulePackLoader`` fingerprint their directories, so
  dropping a YAML file in is enough.

So each holder re-reads when its source changed and returns the cache otherwise.
"Cheap fingerprint, rebuild on mismatch" is the whole design; the alternative —
an explicit ``/reload`` endpoint — puts the burden of remembering on the operator
and is silently wrong every time they forget.

Catalogues are the exception: they are built by ``scripts/build_catalog.py`` from
publisher documents, so they change when someone runs a script, not while the
service is live. They are loaded once and kept.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from backend.ai.mapping_store import LearnedPatternProvider, LoadResult
from backend.db.connection import get_connection, init_database
from backend.frameworks.catalog import ControlCatalog
from backend.ingest.generic import PatternAdapterRegistry
from backend.rules.evaluator import RulesEvaluator
from backend.rules.loader import RulePackLoader


class RuntimeState:
    """Holds the shared, hot-reloading objects a request handler needs.

    One instance per process. Tests build their own against a temporary database
    so they never touch the operator's ledger — which is why the database path is
    a constructor argument rather than read from config at each call site.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path
        self.learned = LearnedPatternProvider(self.connect)
        self.registry = PatternAdapterRegistry()
        # The seam that makes taught mappings live. The registry calls this on
        # every adapter build and the provider answers from cache unless the
        # mapping table moved, so the cost is one COUNT/MAX query per parse.
        self.registry.set_learned_provider(self.learned)
        self.rule_packs = RulePackLoader()
        self._catalogs: list[ControlCatalog] | None = None
        self._evaluator: RulesEvaluator | None = None
        self._evaluator_version = -1
        self._lock = threading.RLock()

    # -- database ---------------------------------------------------------- #

    def connect(self) -> sqlite3.Connection:
        """Open a connection with the schema present and migrations applied.

        A connection per request rather than one shared: SQLite connections are
        not safe to use from several threads by default, and WAL mode makes
        opening one cheap. Callers close theirs.
        """
        conn = get_connection(self.db_path)
        init_database(conn)
        return conn

    # -- parsing ----------------------------------------------------------- #

    def detect(self, raw_text: str, filename: str):
        """Return the best adapter for a configuration, or None."""
        return self.registry.detect(raw_text, filename)

    def for_vendor(self, vendor: str):
        """Return the adapter for a named vendor, raising if there is no pack."""
        return self.registry.for_vendor(vendor)

    def vendors(self) -> list[str]:
        """Every vendor the loaded packs can parse, for the UI's picker."""
        self.registry.library.reload_if_changed()
        return sorted(self.registry.library.packs())

    def learned_status(self, vendor: str = "*") -> LoadResult:
        """Taught patterns in force for a vendor, plus any that failed to compile."""
        return self.learned.load(vendor)

    # -- rules ------------------------------------------------------------- #

    def catalogs(self) -> list[ControlCatalog]:
        """The control catalogues, loaded once per process."""
        with self._lock:
            if self._catalogs is None:
                from backend.rules.evaluator import load_catalogs

                self._catalogs = load_catalogs()
            return self._catalogs

    def evaluator(self) -> RulesEvaluator:
        """A ``RulesEvaluator``, rebuilt only when the mapping packs changed.

        Rebuilding on a pack change is what makes C5 real: an author drops a new
        mapping pack under ``rules/mappings/`` and the next audit evaluates it,
        with the pack's schema validation and the evaluator's
        control-exists check both applied — so a broken pack is a loud error on
        the next request, not a corrupted verdict.
        """
        with self._lock:
            self.rule_packs.reload_if_changed()
            if (
                self._evaluator is None
                or self._evaluator_version != self.rule_packs.version
            ):
                self._evaluator = RulesEvaluator(
                    catalogs=self.catalogs(),
                    rules=self.rule_packs.rules(),
                )
                self._evaluator_version = self.rule_packs.version
            return self._evaluator

    # -- introspection ----------------------------------------------------- #

    def versions(self) -> dict[str, Any]:
        """Loaded-artefact versions, surfaced by ``/health``.

        An auditor's first question about a verdict is "which rules produced
        it". These counters are the cheapest honest answer, and they change when
        a hot reload happens, which makes the reload observable rather than
        something the operator has to take on faith.
        """
        self.registry.library.reload_if_changed()
        packs = self.registry.library.packs()
        evaluator = self.evaluator()
        return {
            "pattern_library_version": self.registry.library.version,
            "pattern_packs": len(packs),
            "vendors": sorted(packs),
            "rule_pack_version": self.rule_packs.version,
            "rules_loaded": len(evaluator.rules),
            "catalogs_loaded": len(evaluator.catalogs),
            "controls_total": sum(len(c.controls) for c in evaluator.catalogs),
        }


#: The process-wide instance the API handlers use.
STATE = RuntimeState()
