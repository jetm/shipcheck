# Audits

This document tracks conceptual audits of shipcheck's approach, complementing `pilots/` (which validates against real Yocto builds).

## Active audit

- [0001 - CRA compliance approach re-examination](audits/0001-cra-approach/REPORT.md) - DRAFT. Covers problem framing, solution architecture, coverage boundaries, trust model, and the readiness-vs-compliance distinction. Pending manufacturer sign-off.

## Signed-off audits

None yet.

## Workflow

Audits mirror the `pilots/` directory convention: `audits/NNNN-<short-name>/REPORT.md`. Sign-off is a single line at the end of each REPORT:

```text
Reviewed-by: Name <email>, YYYY-MM-DD, commit <hash>
```

Findings surfaced during an audit bundle into ONE devspec change per audit (not per-finding changes). See `docs/pilot.md` for the parallel pilot methodology.
