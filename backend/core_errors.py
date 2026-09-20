"""Core exceptions for the PRAMAN auditor.

All custom exceptions inherit from SentinelError so callers can
catch the entire hierarchy with one base class.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for all PRAMAN / SENTINEL-NDC errors."""


class ArtifactMissingError(SentinelError):
    """Raised when a heavy artifact (model, index, framework data) is absent.

    The message MUST name the exact MANUAL_COMMANDS.md step that produces
    the artifact so the operator gets an actionable instruction, not a crash.

    Example:
        raise ArtifactMissingError(
            "Embedding index not found at data/index/templates.sqlite3. "
            "Run Step 7 in MANUAL_COMMANDS.md, then re-run this command."
        )
    """


class ParseError(SentinelError):
    """Raised when a config file cannot be parsed at all."""


class RedactionError(SentinelError):
    """Raised when the secret-redaction pre-filter encounters an unrecoverable issue."""


class RuleValidationError(SentinelError):
    """Raised when a YAML rule pack fails schema validation."""


class RuleEvaluationError(SentinelError):
    """Raised when the deterministic rules engine cannot complete evaluation."""


class LedgerIntegrityError(SentinelError):
    """Raised when the tamper-evident ledger chain is broken."""


class SchemaViolationError(SentinelError):
    """Raised when data violates the Canonical Model schema contract."""


class ExportError(SentinelError):
    """Raised when an audit cannot be rendered into a machine-readable export.

    Reserved for the cases where emitting *something* would be worse than
    emitting nothing: a timestamp that would not satisfy OSCAL's
    ``DateTimeWithTimezoneDatatype``, a finding whose result is outside the XCCDF
    enum. A GRC platform rejecting a schema-invalid document is a good outcome;
    a GRC platform silently ingesting one is not, so this fails loudly at the
    boundary instead.
    """
