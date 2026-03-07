# Xn Handover Rel-17 Gap Analysis (Normative Baseline)

## Normative Sources (Only)

All requirements below are derived only from:

- `/home/jordan/3GPP_R17/Rel-17/23_series/23502-ha0.md` (TS 23.502)
  - `4.9.1.2.2` Xn based inter NG-RAN handover without UPF re-allocation
- `/home/jordan/3GPP_R17/Rel-17/38_series/38423-h60.md` (TS 38.423)
  - `8.2.1` Handover Preparation
  - `8.2.2` SN Status Transfer
  - `8.2.3` Handover Cancel
  - `8.2.7` UE Context Release
- `/home/jordan/3GPP_R17/Rel-17/38_series/38413-h60.md` (TS 38.413)
  - `8.4.3` Handover Notification
  - `8.4.4` Path Switch Request
- `/home/jordan/3GPP_R17/Rel-17/38_series/38331-h60.md` (TS 38.331)
  - `5.3.5.3` Reception of `RRCReconfiguration` by UE

## Mandatory End-to-End Sequence (Xn HO, Intra-AMF)

1. Source gNB starts Xn Handover Preparation using XnAP `HANDOVER REQUEST` (`38.423` `8.2.1.2`) and starts `TXnRELOCprep`.
2. Target gNB allocates resources and answers XnAP `HANDOVER REQUEST ACKNOWLEDGE` (or `HANDOVER PREPARATION FAILURE`) (`38.423` `8.2.1.2/8.2.1.3`).
3. Source gNB executes handover to UE using RRC reconfiguration (`38.331` `5.3.5.3`) and starts `TXnRELOCoverall` (`38.423` `8.2.1.2`).
4. Source gNB sends XnAP `SN STATUS TRANSFER` to target when status preservation applies (`38.423` `8.2.2`).
5. After UE arrival, target sends NGAP `HANDOVER NOTIFY` and `PATH SWITCH REQUEST` to AMF (`38.413` `8.4.3`, `8.4.4`; `23.502` `4.9.1.2.2` step 1b).
6. After successful path switch, target sends XnAP `UE CONTEXT RELEASE` to source (`38.423` `8.2.7`).
7. Source releases UE context; on timer expiry/failure, cancellation and cleanup follow `TXnRELOCprep/TXnRELOCoverall` behavior (`38.423` `8.2.1.3`, `8.2.7.4`).

## Current Code Baseline vs Spec

- `src/gnb/ngap/handover.cpp`: implements **N2-based handover path** (`HandoverRequired`, `HandoverRequest`, `HandoverCommand`, `PathSwitch`), not XnAP control plane.
- `src/gnb/ngap/task.hpp:225`: explicitly marks current flow as **“Handover (Phase 1: private mobility)”**.
- `src/lib/rls/ho_phase1.hpp` + `src/ue/rls/ctl_task.cpp`: uses private HO DATA TLVs (`HO_CMD`, `HO_COMPLETE`, `HO_FAIL`) for execution signaling.
- `src/gnb/rls/*` and `src/ue/rrc/*`: radio simulation can switch serving cell and complete deferred RRC handover logic.
- **Missing for full Xn compliance**:
  - XnAP ASN.1 integration and Xn transport task.
  - XnAP procedures (`HANDOVER REQUEST/ACK/FAILURE/CANCEL`, `SN STATUS TRANSFER`, `UE CONTEXT RELEASE`).
  - Xn timers in config (`TXnRELOCprep`, `TXnRELOCoverall`) as Xn-domain timers (current timers are named/used in NGAP handover path).
  - Source/target UE-XnAP-ID based transaction model required by `38.423`.

## Foundation Progress (Current Branch)

- Added gNB config for Xn peer transport (`xnPort`, `xnNeighbors`) and runtime visibility in `info`.
- Added Xn SCTP peer manager task with reconnect loop and per-peer state (`NOT_CONNECTED|CONNECTING|CONNECTED`).
- Added `nr-cli` command `xn-peers` to inspect configured peers and SCTP status.
- Added mode eligibility checks for `ho-start --mode auto|xn` against configured/connected Xn peers.
- Added a bootstrap XnAP codec module (`src/lib/asn/xnap.*`) and Xn Setup request/response exchange logs over Xn SCTP.
- Added Xn HO preparation transaction scaffolding (`ho-start --mode xn`) with request/ack/failure and timeout handling.
- Added Xn HO cancel scaffolding (`ho-cancel`) with cancel/cancel-ack exchange and source/target transaction cleanup.
- Added typed HO preparation payload fields in bootstrap codec (`oldUEXnAP-ID`, `newUEXnAP-ID`, `cause`,
  source/target NCI) to reduce future refactor cost toward TS 38.423 IE mapping.
- Added bootstrap control-plane sequencing for `SN STATUS TRANSFER` and timer-driven `UE CONTEXT RELEASE` cleanup
  messages.
- Added source-side UE move trigger after Xn HO preparation ACK (private HO command + RRC HO command) and target-side
  private HO complete/fail handling hooks.
- Added target-side NGAP handover completion (`HandoverNotify` + `PathSwitchRequest`) for Xn-triggered preparation
  context and Xn `UE CONTEXT RELEASE` trigger on Path Switch ACK success.
- Added source-side NGAP context release trigger on Xn `UE CONTEXT RELEASE` reception with success/failure cause mapping.

These changes are still scaffolding. Full TS 38.423 ASN.1 is not integrated yet; current codec is a transitional wire
format used only to validate Xn control-plane plumbing before full ASN.1 integration.

## Implementation Order (Spec-Strict)

1. Add Xn transport + XnAP codec module (foundation).
2. Implement `8.2.1` with strict timer behavior and failure handling.
3. Integrate UE execution trigger with RRC handover completion path.
4. Implement `8.2.2` SN status transfer.
5. Keep NGAP `HandoverNotify + PathSwitchRequest` on target per `38.413`.
6. Implement `8.2.7` UE Context Release from target to source.
7. Add clause-mapped negative-path tests for timer expiry, cancel, and unknown-context handling.
