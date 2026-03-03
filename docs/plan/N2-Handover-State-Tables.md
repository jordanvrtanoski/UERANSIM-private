# N2 Handover (Phase 1) — Procedure State Tables & Timer Policies (Artifact)

## 1. Purpose
Provide an implementable, testable specification of **state transitions, events, and timer policies** for Phase‑1 N2-based handover (NGAP per TS 38.413) with private execution over RLS `DATA`.

This artifact is intended to prevent “implicit behavior” and reduce race-condition bugs during implementation.

## 2. Concurrency Model (UERANSIM tasks)
UERANSIM task modules typically process messages on a single-threaded event loop. The handover design relies on this:
- All **NGAP UE context** and **handover state** mutations happen inside `nr::gnb::NgapTask`’s message loop.
- RLS and CLI interactions feed handover events into `NgapTask` via existing task-to-task messaging, avoiding shared-memory races.

Design constraint:
- Never mutate `preparedByToken` or per-UE HO state from outside `NgapTask`’s thread.

## 3. Timers and TTLs
### 3.1 NGAP timers (per TS 38.413 behavior)
- `TNGRELOCprep`: started when `HANDOVER REQUIRED` is sent; stopped when `HANDOVER COMMAND` is received or `HANDOVER PREPARATION FAILURE` occurs.
- `TNGRELOCoverall`: started when `HANDOVER COMMAND` is received; stopped when handover is considered complete or canceled/failed.

Timer value policy (Phase 1):
- Make both timers **operator-configurable** (defaults aligned with common practice). Expose via gNB config or CLI flags for testing.
- On expiry, fail safely:
  - `prep` expiry: treat as preparation failure and cleanup.
  - `overall` expiry: treat as execution failure and cleanup/cancel.

### 3.2 Target-side TTLs (local robustness)
- `prepared_context_ttl`: how long the target keeps a prepared HO context if UE never arrives.
- `unmatched_complete_ttl`: how long to cache unmatched `HO_COMPLETE(token)` events (small, e.g., a few seconds) to tolerate reordering.

## 4. States and Events

### 4.1 Source gNB (per UE) — State Machine
States:
- `IDLE`
- `PREP_SENT` (prep timer running)
- `CMD_RCVD` (overall timer running; mobility command not yet sent)
- `EXECUTING` (HO_CMD sent; awaiting evidence of completion)
- `COMPLETED`
- `FAILED`

Events:
- `CLI_HO_START(targetSpec, cause)`
- `NGAP_HO_COMMAND(tgtToSrcContainer, admittedList, releaseList, …)`
- `NGAP_HO_PREP_FAILURE(cause)`
- `TIMER_PREP_EXPIRE`
- `TIMER_OVERALL_EXPIRE`
- Optional (Phase 1 debug): `PRIVATE_EXECUTION_FEEDBACK(token, status)` if we add a source-side “ack” later.

Transition table (source):

| Current | Event | Guard | Actions | Next |
|---|---|---|---|---|
| IDLE | CLI_HO_START | UE in NGAP-associated state; not already in HO | Resolve target (nci/name/cellId). Generate `token`. Send `HANDOVER REQUIRED` (container includes token). Start `TNGRELOCprep`. | PREP_SENT |
| PREP_SENT | NGAP_HO_PREP_FAILURE | — | Stop `TNGRELOCprep`. Log (token + cause). Cleanup HO state. | FAILED → IDLE (after cleanup) |
| PREP_SENT | NGAP_HO_COMMAND | — | Stop `TNGRELOCprep`. Start `TNGRELOCoverall`. Store `tgtToSrcContainer`. Trigger private execution: send `HO_CMD` over RLS DATA to UE. | EXECUTING |
| PREP_SENT | TIMER_PREP_EXPIRE | — | Log expiry. Cleanup HO state. Optionally send NGAP cancel (policy-driven). | FAILED → IDLE |
| EXECUTING | TIMER_OVERALL_EXPIRE | — | Log expiry; consider UE did not complete HO. Cleanup HO state; policy: keep UE service on source if still connected. Optionally send NGAP cancel. | FAILED → IDLE |

Notes:
- Phase 1 does not require the source to receive any explicit “HO complete” indication; completion is finalized by the target via `PATH SWITCH` and AMF-driven release. However, for debug we should expose observable state (e.g., “HO in progress”).
- Enforce “one HO at a time per UE”: reject `CLI_HO_START` unless source state is `IDLE`.

### 4.2 Target gNB — Prepared Context State
States:
- `IDLE`
- `PREPARED` (received `HANDOVER REQUEST`, resources reserved)
- `UE_ATTACHED` (received `HO_COMPLETE(token)` and bound to prepared context)
- `PATH_SWITCHING`
- `COMPLETED`
- `FAILED`

Events:
- `NGAP_HO_REQUEST(srcContainer(token,…), amfUeNgapId, …)`
- `PRIVATE_HO_COMPLETE(token, ueHint)`
- `NGAP_PATH_SWITCH_ACK` / `NGAP_PATH_SWITCH_FAIL`
- `PREPARED_TTL_EXPIRE(token)`

Transition table (target):

| Current | Event | Guard | Actions | Next |
|---|---|---|---|---|
| IDLE | NGAP_HO_REQUEST | token present & unique | Allocate prepared NGAP UE context + target `RAN_UE_NGAP_ID`. Store `preparedByToken[token]`. Reply `HANDOVER REQUEST ACK` (includes `Target→Source` container). Start `prepared_context_ttl`. | PREPARED |
| PREPARED | PRIVATE_HO_COMPLETE | token exists in `preparedByToken` | Bind arriving UE identity to prepared context. Stop `prepared_context_ttl`. Send `HANDOVER NOTIFY`. Send `PATH SWITCH REQUEST` with new DL NG-U info. | PATH_SWITCHING |
| PREPARED | PREPARED_TTL_EXPIRE | — | Log “UE never arrived”. Release prepared context. | FAILED → IDLE |
| PATH_SWITCHING | NGAP_PATH_SWITCH_ACK | — | Update session tunnel state if needed. Mark HO completed and ready for traffic. | COMPLETED |
| PATH_SWITCHING | NGAP_PATH_SWITCH_FAIL | — | Log failure; release target context or keep based on policy. | FAILED → IDLE |

Unmatched `HO_COMPLETE` handling:
- If `PRIVATE_HO_COMPLETE(token)` arrives in `IDLE` or token missing:
  - increment `ho_complete_unmatched_total`,
  - cache in `unmatched_complete_cache` for `unmatched_complete_ttl` (optional),
  - do not allocate a new NGAP UE context from this signal alone.

## 5. CLI / Operator Trigger Contract (Source gNB)
Minimum CLI semantics:
- `ho-start` requires:
  - UE exists and is NGAP-associated,
  - target resolvable (nci/name/cellId),
  - no active HO for that UE.
- `ho-start` accepts any of:
  - `--target-nci`
  - `--target-name`
  - `--target-cell-id`
- `ho-status` reports:
  - per-UE HO state + token + resolved target.
- Optional `ho-cancel` (source-side):
  - valid only if state is `PREP_SENT` or `EXECUTING`.
  - should send NGAP cancel where applicable and cleanup.

## 6. Debug/Telemetry Requirements (testability)
Required log fields on every HO event:
- `ueId`, `token`, `amfUeNgapId` (if known), and both gNB identifiers (source/target resolved).

Required counters:
- Source: `ho_required_tx`, `ho_command_rx`, `ho_prep_fail_rx`, `ho_prep_timer_exp`, `ho_overall_timer_exp`
- Target: `ho_request_rx`, `ho_req_ack_tx`, `ho_complete_rx`, `ho_complete_unmatched`, `path_switch_tx`, `path_switch_ack_rx`, `path_switch_fail_rx`

## 7. What “Done” Looks Like (Phase‑1 acceptance)
- Two gNBs connected to the same AMF.
- UE registers and has an active PDU session on source.
- `ho-start` triggers NGAP preparation (seen in AMF logs) and private execution (seen in RLS logs).
- Target completes `HANDOVER NOTIFY` + `PATH SWITCH` and user-plane continues via target.
- No crashes on malformed/unmatched private messages; failures are bounded by timers.
