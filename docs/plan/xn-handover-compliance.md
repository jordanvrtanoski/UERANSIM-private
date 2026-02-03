# Xn Handover Compliance Checklist (Rel-17)

This file is the phase-by-phase compliance tracker. Do not implement before populating the “Spec Anchor” fields. Do not mark items as “Implemented” until there is an accompanying testcase in `docs/plan/xn-handover-testcases.md`.

## Spec Files (Local)

- TS 23.502: `/home/jordan/3GPP_R17/Rel-17/23_series/23502-ha0.md`
- TS 38.300: `/home/jordan/3GPP_R17/Rel-17/38_series/38300-h60.md`
- TS 38.331: `/home/jordan/3GPP_R17/Rel-17/38_series/38331-h60.md`
- TS 38.413: `/home/jordan/3GPP_R17/Rel-17/38_series/38413-h60.md`
- TS 38.423: `/home/jordan/3GPP_R17/Rel-17/38_series/38423-h60.md`

## Legend

- **M**: Mandatory for MVP scope
- **C**: Conditional (document condition)
- **D**: Deferred (explicitly not implemented in MVP)

## Procedure: XnAP Handover Request / Acknowledge (Source↔Target)

**Spec anchor**
- File:
- Section heading:
- Key terms to grep:

**Checklist**
- [ ] (M) Source initiates HO request
- [ ] (M) Target returns HO request acknowledge (or reject)
- [ ] (M) UE and cell identifiers populated as required by spec
- [ ] (M) “Transparent container” handling defined (even if simplified, document deviation)
- [ ] (C) Reject path implemented and logged
- [ ] (C) Cancel path implemented and logged
- [ ] (M) Timers/timeouts implemented (name + value documented)

**Deviations**
- None recorded

## Procedure: XnAP UE Context Release (Cleanup)

**Spec anchor**
- File:
- Section heading:
- Key terms to grep:

**Checklist**
- [ ] (M) Source releases UE context when instructed by target (or after completion)
- [ ] (M) Resource cleanup is deterministic and idempotent
- [ ] (C) Failure handling if release message missing/late

**Deviations**
- None recorded

## Procedure: RRC Handover Command / Execution (UE Move)

**Spec anchor**
- File:
- Section heading:
- Key terms to grep:

**Checklist**
- [ ] (M) UE receives HO command/reconfiguration and switches to target cell
- [ ] (M) Target gNB completes RRC setup/resume
- [ ] (C) UE failure to attach target triggers defined recovery behavior

**Deviations**
- None recorded

## Procedure: NGAP Path Switch (Target↔AMF)

**Spec anchor**
- File:
- Section heading:
- Key terms to grep:

**Checklist**
- [ ] (M) Target sends PathSwitchRequest after UE is on target
- [ ] (M) Target handles PathSwitchRequestAcknowledge
- [ ] (C) Reject/failure handling implemented and logged
- [ ] (M) UP tunnel mapping updated to target

**Deviations**
- None recorded

