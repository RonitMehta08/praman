# ADR 0003 — The AI tier abstains rather than guessing, and a human confirms

**Status:** accepted · **Date:** 2026-08

## Context

PRAMAN's AI-powered training module lets an operator teach
the tool a configuration format it has not seen, through a GUI, without a backend
redeploy. The AI's job is to look at a line the pattern packs did not recognise
and propose which canonical path it belongs to.

The temptation is to make this impressive: a model that confidently maps every
unparsed line, with a high accuracy number attached.

## The thing that makes this different from ordinary classification

A wrong canonical path is not a wrong label. It becomes a **fact at the wrong
path**, which a rule then reads, which produces a **compliance verdict about a
control the line has nothing to do with**. The error does not stay in the AI
layer; it launders itself into an audit finding and arrives at the operator with
the same confidence as a deterministic one.

So the cost asymmetry is severe: a missing fact yields `notchecked` (visible, and
ADR 0002 keeps it out of the score), while a wrong fact yields a false verdict
that looks exactly like a real one.

## Options considered

**A. Always return the model's best guess.** Highest coverage, best demo, and it
makes the accuracy metric the headline. Rejected on the asymmetry above: at 90%
accuracy, one line in ten becomes a silent wrong verdict, and there is no
downstream signal that distinguishes it.

**B. Auto-accept above a confidence threshold, queue the rest.** Tempting middle
ground. Rejected because the tier-3 classifier reads **configuration text**,
which is attacker-influenced input — auto-accept turns a prompt-injection into a
parser change with no human in the path. It also requires calibrated
confidences, and the current tiers are not calibrated (see costs).

**C. Escalate through tiers, abstain below threshold, always confirm with a
human.** Chosen.

## Decision

Three tiers, cheapest first, stopping at the first one that clears its threshold
(`backend/ai/escalation.py`):

1. **TF-IDF + linear classifier** — milliseconds, no GPU, ships in the repo.
2. **SetFit few-shot** — sentence-transformer embeddings, better on rare paths.
3. **Local quantised LLM** (Qwen3-4B, Q4_K_M, ~2.4 GB) — last resort.

Below threshold a tier **abstains** and escalates. If every tier abstains, the
line stays in the unparsed queue and is reported as unparsed. Nothing is
guessed.

Whatever a tier does propose goes to the operator in the Training GUI as a
**suggestion**. The operator confirms or corrects it; only then is the mapping
written to the pattern store and hot-reloaded via
`RulePackLoader.reload_if_changed()`. No redeploy, no restart — asserted by
`tests/acceptance/test_training_hot_reload.py`.

**Every tier reports its own absence.** With no models installed, all three
abstain and the deterministic engine is unaffected — `tests/test_cold_start.py`
asserts a fresh clone with zero models is a supported configuration. This is why
the ~2.4 GB download is in `MANUAL_COMMANDS.md` rather than in setup.

## Costs we accepted

**The demo is less impressive.** "The AI abstained" is a worse slide than "the AI
mapped 40 lines." We think it is the correct behaviour to demonstrate, and the
abstention *is* the feature — but it costs a wow moment.

**Coverage depends on operator effort.** Unparsed lines do not shrink on their
own. The tool makes the work cheap and reviewable rather than making it disappear.

**Confidence is not yet calibrated.** The current thresholds are hand-set and
tier 3 returns a hardcoded confidence — so "below threshold" is a heuristic, not
a probability. This is a real debt: proper conformal abstention would give the
threshold a meaning. It is tracked as such, and the human-in-the-loop is what
makes an uncalibrated threshold survivable in the meantime.

**Tier 3 output is not schema-constrained.** A `json_schema` or GBNF grammar
should bound the decoder to the 330-path vocabulary. Until it is, malformed
suggestions are possible; they are visible to the operator rather than silent,
which is why this ranks below authentication in priority.
