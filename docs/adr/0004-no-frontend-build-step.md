# ADR 0004 — No frontend build step

**Status:** accepted · **Date:** 2026-08 · **Deviates from:** the project brief's
suggested stack

## Context

The project brief specified React + Vite + Tailwind + shadcn/ui + Monaco +
xyflow. That is a good stack and a reasonable default for a tool with ten views,
a config viewer and a topology map — which is exactly what PRAMAN has.

The deliverable, though, is a compliance tool that an assessor clones and runs.
Likely on a locked-down machine. Possibly air-gapped. Judged in a fixed time
window during which "it doesn't build on my machine" is indistinguishable from
"it doesn't work."

## The property that decided it

Every other optional dependency in PRAMAN **degrades honestly**:

- No signing key → report still renders, header says `unsigned`.
- No AI models → tiers abstain, deterministic engine unaffected.
- No catalogs for a benchmark → its controls come back `notchecked` with a reason.

A build toolchain cannot do this. There is no partial `npm install`. Either it
succeeded on a machine with network access and a compatible Node, or **there is
no UI at all** — a binary failure, in the one component through which a
non-technical evaluator sees everything else. It is the only dependency in the
project whose absence takes the whole product with it.

Node v24 is also a moving target against a `package-lock.json` pinned months
earlier, and `node_modules` for that stack is larger than the quantised LLM.

## Options considered

**A. The suggested stack, committed `node_modules`.** Removes the install step.
Rejected: hundreds of megabytes of vendored third-party code in the repo, and the
provenance story collapses — `scripts/verify_sources.py` pins digests for every
catalog precisely so PRAMAN can say where its content came from, and vendoring an
unauditable dependency tree next to that is incoherent.

**B. The suggested stack, committed `dist/` build output.** Smaller, but the
shipped UI is then a minified artifact nobody can read or modify, in a project
whose entire argument is auditability. An assessor cannot check that the UI shows
what the API returned.

**C. Dependency-free ES modules.** Chosen. 10 views, ~8,200 lines across 20 files,
native `import`/`export`, hand-written CSS, SVG charts.

## Decision

`frontend/` is plain ES modules served by the same FastAPI process as the API.
The whole deployment story is:

```bash
.venv/Scripts/python.exe scripts/serve.py
```

No build, no bundler, no `node_modules`, no lockfile drift. The source an
assessor reads is the code the browser runs.

## Costs we accepted — and these are real

**Components are hand-written.** No shadcn means every control is bespoke, which
costs both effort and consistency. `frontend/js/dom.js` and `palette.js` exist to
claw some of that back.

**No Monaco.** The config viewer is a custom highlighter, so no minimap, no
find-in-file, no folding. For read-only config display with finding annotations
this is an acceptable trade; it would not be if editing were a feature.

**No xyflow.** The topology view is hand-rolled SVG, so layout is simpler than a
force-directed graph would give.

**No TypeScript.** The largest cost. There is no type checking across 8,200 lines
of frontend JavaScript, and the backend is fully typed and ruff-clean by contrast.
Discipline substitutes for a compiler, which is a worse guarantee. If the frontend
grows much past its current size this decision should be revisited — with a
build step whose *output* is committed, so the no-install property survives.

## Note for reviewers

This is a **deliberate deviation from the brief**, not an oversight, and it is
recorded here so it can be argued with. The one-line version: we traded
component quality for the guarantee that the tool runs from a clone on a machine
with no network.
