# N2 Handover (Phase 1) — Neighbor Configuration & CLI Contract (Artifact)

## 1. Purpose
Define the **configuration data** and **CLI contract** required to drive Phase‑1 N2-based handover in a deterministic, debuggable way, while keeping refactor cost low.

This artifact is simulator-specific (especially the Phase‑1 execution hints) but should be stable enough for operators and integration tests.

## 2. gNB Neighbor Model (Source-side)
The source gNB must be able to:
- Populate NGAP `Target ID` (TS 38.413) for the chosen target.
- Provide the UE with a deterministic way to reach the target in Phase 1 (RLS hint).

### 2.1 Required neighbor fields
For each neighbor entry:

| Field | Purpose |
|---|---|
| `name` | Human-friendly identifier used by CLI `--target-name`. |
| `nci` | Used for CLI `--target-nci` and to derive `gnbId` for NGAP `Target ID`. |
| `idLength` | gNB ID bit length (22..32). Used to derive `gnbId` from `nci`. Defaults to the local gNB `idLength` if omitted. |
| `mcc`, `mnc` | Used in `GlobalRANNodeID` and `selectedTAI`. Defaults to the local gNB PLMN if omitted. |
| `tac` | Used in `selectedTAI`. Defaults to the local gNB `tac` if omitted. |

Notes:
- Phase 1 does **not** require `rlsLinkIp` in the source neighbor model: the target gNB returns its `linkIp` via the NGAP transparent container, and the source forwards it to the UE in `HO_CMD`.
- The neighbor list is a **source-side** concept; the target gNB is configured independently as usual.

Example:
```yaml
neighbors:
  - name: gnb-t
    nci: 0x000000020
    idLength: 32
    tac: 1
    mcc: '999'
    mnc: '70'
```

### 2.2 Ambiguity rules
Reject configuration at startup (or refuse `ho-start`) if:
- two neighbors share the same `(plmn, gnbId, idLength)` tuple, or
- two neighbors share the same `nci` in the same PLMN, or
- `name` is duplicated.

This prevents “handover to the wrong node” failures that are hard to debug.

## 2.3 NGAP Timer Configuration (Source + Target)
The following timers are defined by 3GPP TS 38.413 and are configurable in the gNB YAML under `ngapTimers` (values in **milliseconds**):

```yaml
ngapTimers:
  TNGRELOCprep: 5000
  TNGRELOCoverall: 15000
```

Notes:
- These keys intentionally match the 3GPP timer names (`TNGRELOCprep`, `TNGRELOCoverall`).
- Additional simulator-only TTLs may also exist (e.g. `preparedTtlMs`) but are not 3GPP timers.

## 3. CLI Contract (Source gNB)
### 3.1 Commands
Minimum command set:
- `ho-start <ue-id> --target-nci <hex|dec>`
- `ho-start <ue-id> --target-name <name>`
- `ho-start <ue-id> --target-cell-id <cellId>`
- `ho-status`
- `ho-cancel <ue-id>`

### 3.2 Target selection precedence
Current Phase‑1 CLI requires **exactly one** target selector per `ho-start` (fail-fast if multiple are provided).

### 3.3 CLI validation rules
`ho-start` must fail fast with actionable errors if:
- UE does not exist, or is not NGAP-associated, or has no AMF association.
- UE already has an active HO in progress.
- Target selector is missing or cannot be resolved.
- Target resolves to the source itself (unless explicitly allowed for testing).

### 3.4 Debug outputs
`ho-status` should display at least:
- `ueId`, `ranUeNgapId`, `amfUeNgapId` (if known)
- HO `state`, `token`
- resolved target (`name`, `nci`, `rlsLinkIp` if used)
- current timer status (remaining time for `TNGRELOCprep`/`TNGRELOCoverall` when active)

Optional: `ho-metrics` output listing counters described in `N2-Handover-Design.md`.

## 4. CLI Contract (Target gNB) (optional but useful)
Target-side visibility helps triage:
- `ho-prepared-list` (tokens currently prepared)
- `ho-prepared-info --token <…>` (age, associated AMF UE NGAP ID, TTL remaining)

These can be implemented later, but should be kept in mind to avoid painting ourselves into a corner.
