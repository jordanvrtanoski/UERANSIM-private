# N2 Handover (UERANSIM)

This project supports an N2-based handover flow with RRC reconfiguration (Phase 2). This guide explains how to
configure, trigger, and verify a handover between two gNBs.

## Configuration

Each gNB must list the other as a neighbor and use distinct `nci`, `linkIp`, `ngapIp`, and `gtpIp`.

Example (gNB A, `config/open5gs-gnb-1.yaml`):
- `nci`, `idLength`, `tac`, `mcc/mnc` set for the cell.
- `linkIp`: radio-link simulation IP (used by UE search).
- `ngapIp`/`gtpIp`: N2/N3 addresses toward the core.
- `neighbors`: add the target gNB (name, nci, idLength, tac, plmn).

UE config must include **both** gNB `linkIp` addresses so the UE can reselect the target cell:
- `gnbSearchList: [127.0.0.1, 127.0.0.2]` (example)

Optional: tune NGAP timers in gNB config:
- `ngap-timers: { TNGRELOCprep: 5000, TNGRELOCoverall: 15000, preparedTtlMs: 15000, unmatchedCompleteTtlMs: 5000 }`

Optional: restrict allowed security algorithms (Rel‑17 38.413 §8.4.2.4).  
These lists are algorithm **indexes** (0–15). If configured, the target gNB rejects HO when there is **no overlap**
between UE capabilities and the allowed list (while still honoring mandatory algorithm “0” support):
```
security:
  allowedNREncryptionAlgorithms: [0,1,2]
  allowedNRIntegrityAlgorithms: [0,1,2]
  allowedEUTRAEncryptionAlgorithms: [0,1,2]
  allowedEUTRAIntegrityAlgorithms: [0,1,2]
```

## CLI Commands

From `nr-cli` connected to a gNB:
- `info` — prints gNB identity (includes `nci`, `gnb-id`, `cell-id`)
- `ue-list` — list UEs
- `ho-start <ue-id> --target-nci <nci>`  
  `ho-start <ue-id> --target-name <neighbor-name>`  
  `ho-start <ue-id> --target-cell-id <cell-id>`
- `ho-status` — active handover state, timers
- `ho-cancel <ue-id>` — cancel an in-progress handover

## Test Flow (A → B)

1. Start core (AMF/SMF/UPF), then gNB A and gNB B.
2. Start UE and verify it attaches to gNB A (`ue-list` on gNB A).
3. Trigger HO from gNB A:
   - `ho-start <ue-id> --target-nci 0x...` (or `--target-name` / `--target-cell-id`)
4. Watch logs:
   - Source: `ho_required_tx` → `ho_command_rx`
   - Target: `ho_request_rx` → `ho_req_ack_tx` → `ho_notify_tx` → `path_switch_tx` → `path_switch_ack_rx`
5. Verify UE is now listed on gNB B.

## Troubleshooting

- **Target not found**: ensure `neighbors` match and UE `gnbSearchList` includes both `linkIp`s.
- **TNGRELOCoverall expiry**: check that the UE received the RRC Reconfiguration and sent RRC Reconfiguration Complete.
- **No UE on target**: verify radio link (RLS) reachability between UE and target `linkIp`.
