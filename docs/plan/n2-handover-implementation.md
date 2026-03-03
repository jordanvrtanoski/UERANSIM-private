# N2 Handover (Phase 1) — Implementation Progress

Status date: 2026-02-10
Branch: `feature/n2-ho-phase1`

This document tracks implementation progress against the Phase‑1 architecture:
- `docs/plan/N2-Handover-Design.md`
- `docs/plan/N2-Handover-Phase1-Appendix.md`
- `docs/plan/N2-Handover-State-Tables.md`
- `docs/plan/n2-handover-testcases.md`

## 0) Repo hygiene
- [ ] Add design/plan documents to git (currently untracked on branch)
- [ ] Keep changes isolated to this feature branch

## 1) Private mobility over RLS `DATA` (Phase 1)
### 1.1 Wire contract
- [x] Implement encoder/decoder for `UERANSIM_HO1` header + TLVs (v1)
- [x] Add CRC32 implementation
- [x] Add TLVs required by `HO_CMD/HO_COMPLETE/HO_FAIL` (parser supports unknown TLVs)

### 1.2 UE demux and execution
- [ ] Intercept downlink `EPduType::DATA` in `nr::ue::RlsControlTask`:
  - [x] If private `HO_CMD`: select target cell (Phase‑1: link-ip hint) and assign serving cell
  - [x] Send `HO_COMPLETE(token)` uplink (psi=0) after switching
  - [x] If not private: deliver to NAS unchanged
- [ ] Add structured logs per `N2-Handover-Phase1-Appendix.md`

### 1.3 gNB demux (target side)
- [ ] Intercept uplink `EPduType::DATA` in `nr::gnb::RlsControlTask`:
  - [x] If private `HO_COMPLETE/HO_FAIL`: route to NGAP task (not to GTP)
  - [x] If not private: deliver to GTP unchanged
- [x] Add `preparedByToken` bind path once NGAP prepared context exists

### 1.4 RLS STI binding for prepared contexts
- [x] Expose “reserve sti → ueId” mapping in `nr::gnb::RlsUdpTask`
- [x] Include `ue_sti` TLV in `NGAP Src→Tgt container` and/or `HO_CMD`
- [x] On target `HANDOVER REQUEST`: pre-register STI mapping to the prepared UE id

## 2) NGAP N2 handover (TS 38.413)
### 2.1 Message handlers (gNB)
- [ ] Receive:
  - [x] `HANDOVER REQUEST` (initiating message, target)
  - [x] `HANDOVER COMMAND` (successful outcome, source)
  - [x] `HANDOVER PREPARATION FAILURE` (unsuccessful outcome, source)
  - [x] `PATH SWITCH REQUEST ACKNOWLEDGE/FAILURE` (successful/unsuccessful outcome, target)
- [ ] Send:
  - [x] `HANDOVER REQUIRED` (source)
  - [x] `HANDOVER REQUEST ACKNOWLEDGE` (target)
  - [x] `HANDOVER NOTIFY` (target)
  - [x] `PATH SWITCH REQUEST` (target)

### 2.2 Per-UE HO state + timers
- [ ] Add per-UE HO state (`PREP_SENT`, `EXECUTING`, etc.)
- [x] Implement `TNGRELOCprep` and `TNGRELOCoverall` behaviors (housekeeping + `HandoverCancel` on prep expiry)
- [x] Add prepared TTL and unmatched-complete TTL (target robustness)

### 2.3 Transparent containers (Phase 1 private)
- [x] Encode/decode `NGAP_SRC_TO_TGT` / `NGAP_TGT_TO_SRC` payloads using the Phase‑1 appendix
- [x] Ensure token is logged and recoverable for debug

## 3) CLI (nr-cli → gNB)
- [ ] Add CLI parser commands:
  - [x] `ho-start` with selectors: `--target-nci|--target-name|--target-cell-id`
  - [x] `ho-status`
  - [x] `ho-cancel`
- [x] Add gNB command handling + routing to `NgapTask`
- [ ] Ensure selector precedence is logged and deterministic

## 4) Build + validation
- [x] `make build`
- [ ] Smoke: existing attach + PDU session still works
- [ ] Execute `TC-01` happy path (manual) and record expected logs
- [ ] Follow `docs/plan/N2-Handover-Smoke-Runbook.md`
