# Xn Handover Plan (Developer-Executable, Spec-Driven)

This repo currently has NGAP (N2), a simplified RRC, and RLS for signal/coverage simulation. There is **no XnAP/Xn-U** and no handover state machines. This plan is a developer-executable breakdown to add **Xn-based inter-gNB handover** with:
- Explicit trigger over `nr-cli`
- gNB↔gNB coordination over XnAP
- UE move over RRC (no “fake HO via RLF”)
- AMF coordination via NGAP Path Switch so sessions continue

The process is “spec first / spec after”: every epic has (1) pre-research, (2) design artifacts, (3) implement tasks, (4) post-research verification + delta log.

## Spec Sources (Pinned to Local Rel-17 Library)

All spec citations are from `/home/jordan/3GPP_R17/Rel-17/`:
- Architecture & procedures: `23_series/23502-ha0.md` (TS 23.502)
- NGAP: `38_series/38413-h60.md` (TS 38.413)
- XnAP: `38_series/38423-h60.md` (TS 38.423)
- RRC: `38_series/38331-h60.md` (TS 38.331)
- Overall NR: `38_series/38300-h60.md` (TS 38.300)

**How to anchor requirements**
- For each procedure/message, record:
  - Spec file + section heading + key terms (so it’s greppable)
  - Mandatory IEs (M) and conditional IEs (C) for the MVP scope
  - Timer names and values (if specified or implied)

## Global MVP Scope (First “Full-Working” Milestone)

**Supported**
- NR→NR Xn handover, intra-AMF, same PLMN
- Single UE, single PDU session, IPv4
- Brief user plane interruption allowed (no Xn-U forwarding)

**Not supported (explicitly deferred)**
- Xn-U forwarding (Phase 6)
- Inter-AMF handover
- Dual connectivity / split bearers
- Multi-session / multi-slice complexity beyond basic correctness

**Definition of Done (global)**
- One CLI command triggers HO and completes:
  - XnAP request/ack exchange between gNBs
  - UE RRC move to target
  - Target sends NGAP Path Switch and AMF accepts
  - Source releases UE context
- Reproducible with deterministic logs and a packet capture filterable by procedure names.

## Epic 0 — Guardrails, Traceability, and Test Harness

### Deliverables
- `docs/plan/xn-handover-compliance.md`:
  - Procedure checklists (per spec) + “Implemented/Not implemented/Deviations”
- `docs/plan/xn-handover-testcases.md`:
  - Atomic, repeatable testcases with commands + expected logs

### Tasks
1. Compliance scaffold
   - Create checklist tables for:
     - XnAP: HO Request/ACK, UE Context Release (+ failure/cancel minimal)
     - NGAP: Path Switch
     - RRC: HO command / completion indicators
2. Logging contract
   - Define structured log fields used by all HO code:
     - `ue`, `hoTxn`, `srcGnb`, `tgtGnb`, `phase`, `result`
3. Capture recipe
   - Document tcpdump/Wireshark filters for:
     - NGAP (SCTP port 38412 in configs)
     - XnAP (new configurable port)

### Acceptance (testable)
- Developer can run a “smoke harness” and collect:
  - gNB logs with `hoTxn` identifiers
  - pcap showing expected XnAP/NGAP procedures (even before UE actually moves)

## Epic 1 — CLI Trigger + Neighbor Config + Internal HO API

### Pre-research (spec anchors)
- 23.502: HO procedure overview (triggering is implementation-specific; we align terminology/states)
- 38.300: high-level HO concept (source/target roles)

### Deliverables
- gNB config supports Xn peers and target-cell IDs
- `nr-cli` can issue HO start/cancel and query status

### Tasks
1. YAML config extension (atomic)
   - Add `xnNeighbors` and `xnPort` to gNB config model.
   - Parse in `src/gnb.cpp` (follow existing YAML parse patterns).
   - Acceptance: gNB logs show `xnPeers=N` on startup and `xnPort`.
2. CLI command surface (atomic)
   - Add gNB CLI commands:
     - `ho start --ue <id> --target <peer-name>`
     - `ho status [--ue <id>]`
     - `ho cancel --ue <id>`
     - `xn peers`
   - Touch points:
     - `src/lib/app/cli_cmd.cpp` (command enum + help)
     - `src/gnb/app/cmd_handler.cpp` (dispatch)
   - Acceptance: `nr-cli <gnb> ho status` returns structured YAML.
3. Internal HO request message (atomic)
   - Add an `NtsMessage` type for “start HO” and “cancel HO” routed to the Xn module.
   - Acceptance: issuing CLI produces a log “HO requested” with `hoTxn`.

### Post-research
- Ensure naming and state terms in logs match spec roles (source/target).

## Epic 2 — Xn Transport (SCTP) + Peer State Machine (No XnAP Yet)

### Pre-research (spec anchors)
- 38.423: Xn interface overview, association assumptions

### Deliverables
- gNBs can establish and maintain SCTP associations over Xn ports.

### Tasks
1. Add `XnSctpTask` / reuse `SctpTask` pattern (atomic)
   - Implement connect/reconnect/backoff.
   - Acceptance: `xn peers` shows `CONNECTED`/`NOT_CONNECTED`.
2. Peer table + keepalive (atomic)
   - Track per-peer: addr/port, assocId, stream counts, state.
   - Acceptance: state transitions are logged deterministically.

### Post-research
- Document any spec deviations (e.g., keepalive mechanics are implementation-defined).

## Epic 3 — XnAP ASN.1 Integration (38.423) + Encode/Decode Plumbing

### Pre-research (spec anchors)
- 38.423 sections for:
  - PDU structure
  - Message definitions: `HandoverRequest`, `HandoverRequestAcknowledge`, `UEContextRelease`
  - Mandatory IEs for MVP

### Deliverables
- Buildable XnAP module with:
  - APER encode/decode
  - Constraint checking
  - Optional XER dump for debug (similar to NGAP)

### Tasks
1. ASN module layout (atomic)
   - Add `src/asn/xnap/` with generated C and CMake wiring.
   - Add `src/lib/asn/xnap.*` encode/decode helpers mirroring NGAP patterns.
   - Acceptance: `make build` succeeds and a unit “encode/decode roundtrip” tool/test program can run (if no test framework, add a small `tools/` binary or gated debug path).
2. XnAP transport integration (atomic)
   - `XnTask` decodes inbound XnAP PDUs, dispatches by procedure code.
   - Acceptance: sending a synthetic XnAP PDU produces a decoded log line with procedure code.

### Post-research
- Compare the generated/used message structures to the spec’s IE lists for the MVP set.

## Epic 4 — XnAP Handover Control Plane: Source↔Target (No UE Move Yet)

### Pre-research (spec anchors)
- 38.423: HO Preparation / Resource Coordination (exact names in spec)
- Identify:
  - Required identifiers (UE XnAP IDs, cell IDs)
  - Required transparent containers exchanged between gNBs

### Deliverables
- CLI-triggered HO executes XnAP exchange:
  - Source sends HO Request
  - Target replies HO Request ACK (or Reject)
  - Source can cancel

### Tasks
1. HO transaction table (atomic)
   - Keyed by `(ueId, hoTxn)`; states:
     - `IDLE`, `REQ_SENT`, `ACK_RCVD`, `FAILED`, `CANCELED`, `DONE`
   - Acceptance: `ho status` reflects state transitions.
2. Build HO Request (atomic)
   - Populate mandatory IEs only (per compliance checklist).
   - Include enough UE context to let target “accept” and return an RRC container placeholder.
   - Acceptance: pcap shows a valid XnAP HO Request passing ASN constraints.
3. Target HO admission + HO ACK (atomic)
   - Accept/reject decision is deterministic (e.g., always accept in MVP unless config says otherwise).
   - Acceptance: pcap shows HO ACK; logs include `result=accepted`.
4. Timeouts and cancel (atomic)
   - Timeout transitions `REQ_SENT -> FAILED`.
   - `ho cancel` triggers cancel message (if in scope) or local abort with proper logs.
   - Acceptance: cancel removes txn and logs cleanup.

### Post-research
- Compare message ordering and mandatory IE presence; record deviations in compliance doc.

## Epic 5 — RRC HO Execution: UE Actually Moves to Target

### Pre-research (spec anchors)
- 38.331: identify HO command/reconfiguration requirements and completion triggers.

### Deliverables
- After HO ACK, source sends RRC HO command to UE and UE connects to target gNB.

### Tasks
1. Define HO command representation (atomic)
   - If full 38.331 HO container is too large for MVP, define a minimal internal container but document the deviation.
2. Source gNB → UE HO command (atomic)
   - Add RRC message plumbing to send HO command (new RRC message type or reuse encode helpers).
   - Acceptance: UE logs “HO command received”, and stops using the source cell.
3. UE → target attach (atomic)
   - UE switches current cell to target and performs RRC setup with target.
   - Acceptance: target gNB logs new RRC setup for same UE identity.
4. State coherency (atomic)
   - Source gNB marks UE as “HO in progress” and blocks new session procedures.
   - Acceptance: no duplicate UE contexts; deterministic cleanup if target attach fails.

### Post-research
- Compare UE state transitions and required RRC elements; document what’s simplified.

## Epic 6 — AMF Coordination: NGAP Path Switch + UP Context Update

### Pre-research (spec anchors)
- 38.413: `PathSwitchRequest` procedure and IEs
- 23.502: ordering relative to HO completion

### Deliverables
- Target gNB requests Path Switch; AMF accepts; PDU session continues on target.

### Tasks
1. Implement Path Switch (atomic)
   - Add NGAP build/send + receive ack handlers.
   - Acceptance: pcap shows `PathSwitchRequest` and `PathSwitchRequestAcknowledge`.
2. Update UP/N3 mapping (atomic)
   - Update gNB GTP task to associate the UE’s tunnel to target gNB.
   - Acceptance: downlink/uplink data works after HO (basic ping over UE tunnel).
3. Source release (atomic)
   - After Path Switch ack, target tells source to release context (`UEContextRelease`) and source deletes UE state.
   - Acceptance: source gNB has no UE context; `nr-cli` shows UE on target only.

### Post-research
- Confirm NGAP IE presence/order and procedure sequencing.

## Epic 7 — Optional: Xn-U Forwarding (If “No Interruption” Required)

### Deliverables
- User plane forwarding during HO window.

### Tasks (MVP for forwarding)
1. Add an Xn-U tunnel between gNBs (UDP first, then align to spec if needed).
2. Forward packets source→target until Path Switch ack.
3. Acceptance: packet loss minimized (measured by ping/iperf counters).

## Project Conventions (Must Follow)

- New control-plane modules should follow `NtsTask` patterns (see `src/gnb/ngap/task.*`).
- ASN modules live under `src/asn/*`, with encode/decode helpers under `src/lib/asn/*`.
- Keep responsibilities split:
  - gNB: `src/gnb/*` (Xn + NGAP + RRC)
  - UE: `src/ue/*` (RRC behavior + NAS triggers)
- Every procedure boundary must log:
  - `ue`, `hoTxn`, `srcGnb`, `tgtGnb`, procedure name, result.
