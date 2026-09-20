# Architecture decision records

Only the decisions that were **close calls** are recorded here — the ones with a
real losing option, where a reviewer might reasonably have chosen differently.
Decisions with no alternative worth naming are not ADRs, they are just how the
code works, and padding this directory with them would bury the four that matter.

Each record names the options considered, why the chosen one won, and **what it
cost**. The cost section is the part that makes an ADR worth keeping: a decision
recorded without its downside is advocacy, and it gives the next person nothing
to weigh when the trade shifts.

| ADR | Decision | The cost we took |
|---|---|---|
| [0001](0001-canonical-fact-model.md) | A canonical 330-path fact model sits between parsers and rules | The vocabulary is a bottleneck; flat paths lose within-record structure, which blocks 4 CIS controls |
| [0002](0002-notchecked-excluded-from-score.md) | `notchecked` is a real verdict, excluded from the score both ways | The headline number is worse — 71 of 90 instead of 71 of 71 |
| [0003](0003-ai-abstains-human-confirms.md) | The AI tier abstains rather than guessing; a human confirms every mapping | Less impressive demo; coverage depends on operator effort; thresholds are uncalibrated |
| [0004](0004-no-frontend-build-step.md) | No frontend build step, plain ES modules | No TypeScript, no Monaco, no shadcn — hand-written components across 8,200 lines |
| [0005](0005-remediation-extracted-not-generated.md) | Remediation CLI is extracted from the publisher, never generated | Coverage bounded by publisher fix text; no dependency ordering |

## The thread connecting them

All five are the same trade in different clothes: **prefer the output that can be
checked over the output that looks better.**

0002 and 0005 are the sharpest cases — both give up a more impressive number or a
more complete-looking artifact to avoid making a claim the evidence does not
support. 0003 gives up a demo moment for the same reason. 0004 gives up component
quality to keep the tool runnable, which is the precondition for anyone checking
anything at all. 0001 is the enabling one: the canonical model is what makes
"checked consistently" a property the test suite can assert rather than a claim
in a README.

If a future change makes the tool look better while making a claim harder to
verify, these are the five documents to argue with first.

## Adding one

Number it sequentially, and include: **Context** (the forces, not the solution),
**Options considered** (with the strongest case *for* each rejected one — a
straw-man alternative fools nobody and teaches nothing), **Decision**, and
**Costs we accepted**.

If you cannot write a genuine losing option, it is not an ADR.
