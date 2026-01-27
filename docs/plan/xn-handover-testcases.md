# Xn Handover Testcases (Atomic, Repeatable)

These testcases are the gating criteria for marking items “Implemented” in `docs/plan/xn-handover-compliance.md`.

## Common Setup

- Build: `make build`
- Run core (Open5GS/free5GC) + AMF reachable from gNBs.
- Start two gNBs with distinct node names and Xn neighbor config.
- Start UE attached to source gNB, with 1 IPv4 session established.

## TC-00: Baseline Sanity (No HO)

**Goal**: Confirm both gNBs and the UE can run, attach, and maintain a session.

**Steps**
1. Start source gNB + target gNB.
2. Start UE (configured to find both cells, but attach to source first).
3. Verify session is active.

**Expected**
- gNB logs show NG setup + PDU session established.
- `nr-cli <ue> status` shows one active PDU session.

## TC-10: CLI Trigger Wiring

**Goal**: Prove `nr-cli` can request HO and gNB reports the request.

**Steps**
1. `nr-cli <source-gnb> ho start --ue 1 --target <target-peer>`
2. `nr-cli <source-gnb> ho status --ue 1`

**Expected**
- Source gNB log: “HO requested” including `ue` and `hoTxn`.
- `ho status` returns state `REQ_SENT` (or equivalent).

## TC-20: XnAP HO Request/ACK Exchange (No UE Move Yet)

**Goal**: Observe a valid XnAP exchange in logs and pcap.

**Steps**
1. Run tcpdump on source/target Xn port.
2. Trigger HO.

**Expected**
- Source logs: “XnAP HandoverRequest sent”
- Target logs: “XnAP HandoverRequest received”
- Target logs: “XnAP HandoverRequestAcknowledge sent”
- Source logs: “XnAP HandoverRequestAcknowledge received”
- ASN constraints pass (no encode/decode errors).

## TC-30: UE Moves to Target (RRC HO Execution)

**Goal**: UE switches from source to target due to HO command (not RLF).

**Steps**
1. Trigger HO.
2. Watch UE logs and target gNB logs.

**Expected**
- UE log: “HO command received” + “switching to target”
- Target gNB: new RRC setup for the same UE identity.
- Source gNB: marks UE as moved / HO complete.

## TC-40: NGAP Path Switch and Session Continuity

**Goal**: Session continues via target after HO (Path Switch accepted).

**Steps**
1. Trigger HO.
2. Observe NGAP messages (pcap on N2).
3. Run a basic data check (ping over UE tunnel if supported).

**Expected**
- Target gNB logs: “PathSwitchRequest sent” then “PathSwitchRequestAcknowledge received”
- Source gNB releases UE context and stops forwarding.
- Data works after HO (allow brief interruption during HO).

## TC-50: Timeout/Failure Handling

**Goal**: HO fails deterministically and cleans up state.

**Steps**
1. Configure target to reject HO (or stop target gNB).
2. Trigger HO.

**Expected**
- Source gNB transitions to `FAILED` with error cause.
- `ho status` reflects failure.
- No leaked UE/txn contexts after timeout.

