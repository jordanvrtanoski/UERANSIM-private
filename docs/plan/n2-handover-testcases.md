# N2 Handover (Phase 1) — Integration Testcases (Open5GS + UERANSIM)

## 1. Purpose
Define atomic, testable integration scenarios to validate **Phase‑1 N2-based handover**:
- NGAP procedure correctness (TS 38.413 message sequence + timers)
- Private execution correctness (temporary mobility over RLS `DATA`)
- Robustness under races, retries, and parallel handovers

This document assumes the Phase‑1 design artifacts:
- `docs/plan/N2-Handover-Design.md`
- `docs/plan/N2-Handover-Private-Execution.md`
- `docs/plan/N2-Handover-State-Tables.md`
- `docs/plan/N2-Handover-Config-CLI.md`

## 2. Topology & Constraints (single host)
### 2.1 Two gNBs on one machine
Run **two gNB processes** on the same host by binding them to **different local IPs**:
- `linkIp` (RLS / simulated radio)
- `ngapIp` (N2 / SCTP)
- `gtpIp` (N3 / UDP 2152)

On Linux, distinct loopback addresses (e.g. `127.0.0.1`, `127.0.0.2`, `127.0.0.3`) can be used without extra interfaces.

### 2.2 UE search list
UE must be able to “see” both gNBs in RLS:
- Configure UE `gnbSearchList` to include both `linkIp` values.

### 2.3 Core network
Both gNBs must connect to the **same AMF** (intra-AMF mobility), and the AMF/SMF/UPF must be configured for a working baseline PDU session.

## 3. Preconditions (baseline acceptance)
Before running handover tests, verify:
1. gNB-S and gNB-T both successfully complete NG Setup with AMF.
2. UE registers on gNB-S.
3. UE establishes at least one PDU session and can pass traffic (e.g., ping through UPF).

If baseline fails, do not proceed with handover tests.

## 4. Observability (what to capture)
### 4.1 Required log fields
All HO-related logs must include:
- `ueId`
- `token` (handover token)
- `ranUeNgapId`
- `amfUeNgapId` (when present)
- resolved target selectors (`nci`, `name`, `cellId` when provided)

### 4.2 Counters to track (per process)
- Source gNB: `ho_required_tx`, `ho_command_rx`, `ho_prep_fail_rx`, `ho_prep_timer_exp`, `ho_overall_timer_exp`
- Target gNB: `ho_request_rx`, `ho_req_ack_tx`, `ho_complete_rx`, `ho_complete_unmatched`, `path_switch_tx`, `path_switch_ack_rx`, `path_switch_fail_rx`

**Normative key/counter names (Phase 1):**
- For stable log keys and counter names to use in automated assertions, see `docs/plan/N2-Handover-Phase1-Appendix.md`.

### 4.3 Packet capture (optional but recommended)
- NGAP/SCTP: capture on `ngapIp` / AMF address (port 38412).
- RLS/UDP: capture on both gNB `linkIp` ports used by RLS.
- GTP-U/UDP: capture on `gtpIp` (port 2152) of both gNBs and UPF.

## 5. Configuration Matrix (minimum)
Maintain two gNB configs:
- gNB-S: distinct `{linkIp, ngapIp, gtpIp}`, includes neighbor entry for gNB-T with `rlsLinkIp`.
- gNB-T: distinct `{linkIp, ngapIp, gtpIp}`.

Maintain one UE config:
- `gnbSearchList` contains both gNB `linkIp` values.
- UE default session is established on gNB-S (initial attach should prefer gNB-S by radio conditions or deterministic setup).

## 6. Testcases

### TC-01: Successful Phase‑1 N2 handover (happy path)
**Goal:** End-to-end success with `HANDOVER REQUIRED → … → PATH SWITCH ACK`, traffic continues via target.

Steps:
1. Start Open5GS (AMF/SMF/UPF).
2. Start gNB-T, then gNB-S.
3. Start UE; ensure registration + PDU session established on gNB-S.
4. On gNB-S, trigger `ho-start` selecting gNB-T by **NCI**.

Expected:
- gNB-S logs `HANDOVER REQUIRED` sent with token; starts `TNGRELOCprep`.
- gNB-T logs `HANDOVER REQUEST` received; allocates prepared context by token; sends `HANDOVER REQUEST ACK`.
- gNB-S logs `HANDOVER COMMAND` received; sends private `HO_CMD` over RLS `DATA`; starts `TNGRELOCoverall`.
- UE logs receipt of `HO_CMD` and resolution path; attaches to gNB-T; sends `HO_COMPLETE(token)`.
- gNB-T logs `HO_COMPLETE(token)` matched; sends `HANDOVER NOTIFY` and `PATH SWITCH REQUEST`.
- AMF/SMF logs show Path Switch success; gNB-T receives `PATH SWITCH REQUEST ACKNOWLEDGE`.
- Traffic check: a new ping flow passes after handover (verify by GTP-U counters/pcap or application-level ping).

Pass/Fail:
- PASS if the complete NGAP sequence completes and traffic is functional on target.
- FAIL if timers expire, `HO_COMPLETE` mismatches, or path switch fails.

### TC-01a: Selector precedence (all three provided)
**Goal:** Ensure `--target-nci` wins over `--target-name` and `--target-cell-id` and is logged.

Steps:
1. Trigger `ho-start` with all three selectors pointing to different neighbors.

Expected:
- gNB-S rejects ambiguous/mismatched selector combinations with a clear error, or
- gNB-S explicitly logs precedence resolution and uses NCI deterministically (preferred).

### TC-02: Target selection by name
**Goal:** Same as TC-01, but select target using `--target-name`.

Expected:
- gNB-S logs show selector precedence and resolved target spec.
- All other behavior matches TC-01.

### TC-03: Target selection by RLS cell id
**Goal:** Select target using `--target-cell-id` (local testing path).

Expected:
- UE uses `cellId` resolution path first.
- All other behavior matches TC-01.

### TC-04: Unmatched `HO_COMPLETE` handling
**Goal:** Ensure target gNB does not crash or corrupt state when receiving an unknown token.

Steps:
1. With gNB-T running, inject or simulate a private `HO_COMPLETE(token=unknown)` arrival.

Expected:
- gNB-T increments `ho_complete_unmatched`.
- gNB-T logs the anomaly with token and sender endpoint.
- No new NGAP context is created solely from this signal.

### TC-05: Duplicate `HO_COMPLETE` idempotency
**Goal:** UE may retry; target should treat duplicates as idempotent.

Steps:
1. Run TC-01 until target receives `HO_COMPLETE`.
2. Force UE to resend `HO_COMPLETE(token)` once more (or simulate retry).

Expected:
- Target logs a single state transition to “attached”.
- Duplicate is ignored after logging (or logged at debug without state changes).

### TC-06: Preparation timer expiry (`TNGRELOCprep`)
**Goal:** If `HANDOVER COMMAND` is never received, source times out safely.

Setup:
- Configure AMF to drop/deny preparation or simulate loss of `HANDOVER COMMAND`.

Expected:
- Source gNB logs `TNGRELOCprep` expiry and cleans up HO state.
- No private `HO_CMD` is sent after expiry.
- UE remains served by source (service continuity policy explicit in logs).

### TC-06a: gNB-T prepared TTL expiry
**Goal:** Target cleans up prepared contexts if UE never arrives.

Steps:
1. Force preparation to complete (target prepared), then prevent UE from switching (no `HO_COMPLETE`).
2. Wait for `prepared_context_ttl` to elapse.

Expected:
- gNB-T logs “UE never arrived” with token and releases prepared context.

### TC-07: Overall timer expiry (`TNGRELOCoverall`) — UE never arrives
**Goal:** If UE does not attach to target, source times out safely.

Setup:
- After `HO_CMD`, prevent UE from switching cell (e.g., misconfigure target link hint).

Expected:
- Source logs `TNGRELOCoverall` expiry and cleans up.
- Target prepared context TTL eventually expires; logs “UE never arrived”.
- No crash; UE may continue on source if still connected (policy-driven).

### TC-08: Handover Preparation Failure (AMF-driven)
**Goal:** Validate handling of `HANDOVER PREPARATION FAILURE`.

Setup:
- Configure core (or force target) to reject HO preparation.

Expected:
- Source receives `HANDOVER PREPARATION FAILURE`, stops prep timer, logs cause, cleans up.
- No private `HO_CMD` is sent.

### TC-09: Path Switch failure
**Goal:** Validate behavior when `PATH SWITCH REQUEST FAILURE` is returned.

Setup:
- Misconfigure SMF/UPF so path switch cannot complete (intentional).

Expected:
- Target logs path switch failure and cleans up or enters failed state per policy.
- Counters reflect `path_switch_fail_rx`.

### TC-10: Parallel handovers (multiple UEs)
**Goal:** Demonstrate multiple concurrent HO attempts without cross-UE contamination.

Steps:
1. Start N UEs (N≥2), each with an active PDU session on gNB-S.
2. Trigger `ho-start` for two different UEs close in time.

Expected:
- Tokens are unique per attempt; logs never mix tokens across UEs.
- Target maps `preparedByToken` entries correctly; each `HO_COMPLETE` binds to the correct prepared context.
- No deadlocks or map corruption symptoms.

### TC-10a: Parallel + out-of-order robustness
**Goal:** Validate no crashes under reordering and retries.

Steps:
1. Run TC-10.
2. During the run, force one UE to retry `HO_COMPLETE` multiple times and delay another UE’s `HO_COMPLETE` significantly.

Expected:
- Idempotency holds; unmatched cache (if enabled) does not bind wrong contexts.
- All anomalies are logged with token and counted.

### TC-11: “One HO per UE” enforcement
**Goal:** Ensure `ho-start` is rejected if a HO is already in progress for the same UE.

Expected:
- Second `ho-start` returns an error referencing current state/token.

### TC-12: Debug completeness audit
**Goal:** Ensure debuggability requirements are met in practice.

Checklist (pass if all true):
- Every HO log line includes token and UE identifiers.
- Target selector precedence is logged when multiple selectors provided.
- Unmatched/duplicate behavior is explicitly logged and countered.
- Timers are reported with expiry reasons.

## 7. Exit Criteria
Phase‑1 is considered ready for Phase‑2 RRC work when:
- TC‑01, TC‑06, TC‑07, TC‑08, TC‑10 pass reliably.
- Debug completeness audit (TC‑12) passes.
