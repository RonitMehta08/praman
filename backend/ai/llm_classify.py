"""AI Escalation Ladder — Tier 3: Local LLM classifier via llama-server.

Qwen3-4B-Instruct-2507 Q4_K_M via llama-server HTTP API.

SPINE §18.1: Runs when Tier 2 confidence < tau_setfit.
The LLM's answer is a SUGGESTION for human confirmation, never an applied mapping.

Not yet grammar-constrained. §18.2 calls for GBNF-constrained decoding so the
model cannot emit a string outside the canonical path enum; what this module
actually does is ask for JSON in the prompt and then check the answer against
``valid_paths``, rejecting a miss by returning confidence 0.0 (which abstains).
That is a weaker guarantee with the same safety outcome — an invented path is
discarded rather than prevented — and it costs generated tokens on answers that
were never usable. See scripts/emit_gbnf.py in the backlog.
"""

from __future__ import annotations

import json

from backend.app.config import (
    LLM_HOST,
    LLM_PORT,
    LLM_TIMEOUT_S,
    SENTINEL_AI_BACKEND,
    TAU_LLM,
)
from backend.core_errors import ArtifactMissingError

#: Budget for the /health probe, which is a different question from LLM_TIMEOUT_S
#: (30 s) — that one covers token generation, this one only asks whether anything
#: is listening. A loaded llama-server answers /health in about a millisecond.
#:
#: It has to be short because on Windows a connect to a closed local port is
#: *dropped rather than refused*: measured on this machine, 127.0.0.1 with nothing
#: bound consumes the whole timeout (2.00 s at timeout=2, 0.50 s at timeout=0.5,
#: on every port tried). So this value is not a worst case, it is the price of
#: every probe taken while Tier 3 is down — which is the normal state until
#: MANUAL_COMMANDS.md Step 6 has been run. 0.5 s leaves headroom for a server
#: that is bound but busy under GPU load, while keeping the ladder responsive.
HEALTH_PROBE_TIMEOUT_S = 0.5


class LLMClassifier:
    """Tier 3 — Local LLM classifier via llama-server.

    The LLM never issues a pass/fail verdict (SPINE thesis).
    It classifies unrecognised config lines to suggest a canonical path.
    Answers outside the build-time canonical path enum are discarded.
    """

    def __init__(self) -> None:
        self._base_url = f"http://{LLM_HOST}:{LLM_PORT}"

    def is_available(self) -> bool:
        """Check if the llama-server is running.

        Callers in a loop must not call this per item — see the availability
        cache in backend/ai/escalation.py. Even at HEALTH_PROBE_TIMEOUT_S this
        costs 0.5 s every time Tier 3 is down.
        """
        if SENTINEL_AI_BACKEND == "none":
            return False
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._base_url}/health")
            with urllib.request.urlopen(req, timeout=HEALTH_PROBE_TIMEOUT_S) as resp:
                return resp.status == 200
        except Exception:
            return False

    def predict(self, line: str, valid_paths: list[str]) -> tuple[str, float]:
        """Ask the LLM to classify a config line.

        Args:
            line: The unrecognised config line.
            valid_paths: The build-time canonical path enum.

        Returns:
            (suggested_path, confidence) where confidence < 1.0 always.
        """
        if not self.is_available():
            raise ArtifactMissingError(
                "llama-server is not running. "
                "Run Step 6 in MANUAL_COMMANDS.md to install and start llama-server."
            )

        prompt = self._build_prompt(line, valid_paths)

        try:
            import urllib.request

            payload = json.dumps({
                "prompt": prompt,
                "n_predict": 64,
                "temperature": 0.1,
                "top_p": 0.9,
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self._base_url}/completion",
                data=payload,
                headers={"Content-Type": "application/json"},
            )

            with urllib.request.urlopen(req, timeout=LLM_TIMEOUT_S) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            content = result.get("content", "").strip()

            # Parse the JSON response
            try:
                parsed = json.loads(content)
                path = parsed.get("path", content)
            except json.JSONDecodeError:
                path = content

            # Validate against the enum
            if path not in valid_paths:
                return path, 0.0  # Will trigger ABSTAIN

            # Derive confidence (< 1.0 always)
            confidence = min(0.85, 0.999)  # Conservative default
            return path, confidence

        except Exception as err:
            raise ArtifactMissingError(
                "llama-server request failed. "
                "Ensure Step 6 in MANUAL_COMMANDS.md is complete."
            ) from err

    def confidence_threshold(self) -> float:
        return TAU_LLM

    @staticmethod
    def _build_prompt(line: str, valid_paths: list[str]) -> str:
        """Build the classification prompt."""
        paths_str = ", ".join(valid_paths[:50])
        return (
            "You are a network configuration classifier. "
            "Given a config line, identify which canonical path it belongs to.\n\n"
            f"Valid canonical paths: [{paths_str}]\n\n"
            f"Config line: {line}\n\n"
            'Respond with JSON: {"path": "<canonical_path>"}'
        )
