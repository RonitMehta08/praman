# 0006 — Host the model-enabled demo on one Linux VM

## Context

The Render deployment has failed health checks and returned 502 on Simulate
examples. Its logs have not established whether this is memory exhaustion,
blocked request handling or another failure. The operator has obtained $100 of
Azure student credits and wants a host for the CPU classifiers and optional Qwen.

## Options considered

- **Managed web service:** simplest Git-based deployment and HTTPS, with little
  operating-system administration. Model memory and durable local SQLite require
  provider resources beyond many small free tiers; a separate model server also
  needs lifecycle management.
- **One Linux VM:** supports persistent SQLite, signing keys, native llama.cpp and
  two supervised processes. It keeps the existing one-process job-queue design.
- **Separate hosted database and inference services:** independent resource scaling
  and managed durability, but changes application boundaries and the offline-first
  deployment contract for a demo that already runs on a single machine.

## Decision

Prepare Ubuntu 22.04 x64 VM deployment with one application service, optional
CPU llama.cpp service and the existing nginx HTTPS proxy. Start with
Standard_D2as_v5 (2 vCPUs, 8 GiB), subject to subscription quota and displayed cost.
Verify the classifier workflow before enabling Qwen. Model availability is not
evidence of acceptable generation latency; use the backend's actual timeout in
the acceptance check.

## Costs we accepted

The VM spends student credit while allocated; disk and public IP also have costs.
The operator manages patches, certificate renewal and backups. CPU Qwen performance
is not established. Persistent storage does not make in-memory jobs durable or add
multi-tenancy. Migration does not fix request-handler blocking; runtime checks and
logs must establish whether the original 502 failure is resolved.
