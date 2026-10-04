"""The CPU hosting profile must run classifiers without a hidden LLM dependency."""

from __future__ import annotations

from backend.ai import escalation, readiness
from backend.app import config
from backend.app.main import _ai_status


def test_cpu_profile_still_suggests_from_setfit_and_never_constructs_llm(monkeypatch):
    monkeypatch.setattr(escalation, "SENTINEL_AI_BACKEND", "classifiers")
    called = []

    class Classifier:
        def __init__(self, tier):
            self.tier = tier

        def is_available(self):
            return True

        def predict(self, line):
            called.append(self.tier)
            return "mgmt.ssh.version", 0.9 if self.tier == "tier2" else 0.1

    monkeypatch.setattr(escalation, "_tier", lambda tier: type(
        "Cached", (), {"get": lambda _: Classifier(tier)},
    )())
    result = escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
    assert result.path == "mgmt.ssh.version" and result.tier == 2
    assert called == ["tier1", "tier2"]

    def forbidden(_):
        raise AssertionError("The CPU profile must not instantiate the LLM")

    monkeypatch.setattr(escalation, "_build_tier3", forbidden)
    # Force both classifiers to abstain and check there is no fallback HTTP call.
    monkeypatch.setattr(Classifier, "predict", lambda *_: ("", 0.0))
    original_tier = escalation._tier
    monkeypatch.setattr(escalation, "_tier", lambda tier: (
        forbidden(tier) if tier == "tier3" else original_tier(tier)
    ))
    assert escalation.escalate_line("unknown", ["mgmt.ssh.version"]).abstained


def test_missing_dependencies_are_not_reported_as_loaded_models(monkeypatch):
    monkeypatch.setattr(config, "SENTINEL_AI_BACKEND", "classifiers")
    monkeypatch.setattr(readiness, "find_spec", lambda name: None if name == "setfit" else object())

    def forbidden():
        raise AssertionError("Health must not probe llama-server in CPU mode")

    monkeypatch.setattr(escalation, "llm_availability", forbidden)
    status = _ai_status()
    assert status["tiers"]["tier1_tfidf"]
    assert not status["tiers"]["tier2_setfit"]
    assert not status["tiers"]["tier3_llm"]
    assert status["classifier_readiness"]["tier2_setfit"]["missing_dependencies"] == ["setfit"]


def test_missing_neighbour_guard_makes_setfit_not_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(readiness, "SETFIT_MODEL_PATH", tmp_path)
    monkeypatch.setattr(readiness, "find_spec", lambda _: object())
    status = readiness.classifier_readiness()["tier2_setfit"]
    assert not status["ready"]
    assert str(tmp_path / "neighbour_index.npz") in status["missing_files"]
