# N2 Handover (UERANSIM)

This project supports an N2-based handover flow with RRC reconfiguration (Phase 2). This guide explains how to
configure, trigger, and verify a handover between two gNBs.

## Configuration

Each gNB must list the other as a neighbor and use distinct `nci`, `linkIp`, `ngapIp`, and `gtpIp`.

Example (source gNB):
```yaml
mcc: '999'
mnc: '001'
nci: '0x000000010'
idLength: 32
tac: 1

linkIp: 127.0.0.1
ngapIp: 192.168.88.45
gtpIp: 192.168.88.45

neighbors:
  - name: gnb-20
    nci: 0x000000020
    idLength: 32
    tac: 1
    mcc: '999'
    mnc: '001'
```

UE config must include **both** gNB `linkIp` addresses so the UE can reselect the target cell:
- `gnbSearchList: [127.0.0.1, 127.0.0.2]` (example)

Optional: tune NGAP timers in gNB config:
- `ngap-timers: { TNGRELOCprep: 5000, TNGRELOCoverall: 15000, preparedTtlMs: 15000, unmatchedCompleteTtlMs: 5000 }`

Optional: set handover mode policy:
```yaml
handoverPolicy:
  defaultMode: auto         # auto | n2 | xn
  fallbackToN2: true
  requireSameAmfForXn: true
```

Optional: configure Xn peer transport (used by mode selection/debug visibility):
```yaml
xnPort: 38422
xnNeighbors:
  - name: gnb-20
    nci: 0x000000020
    address: 192.168.88.46
    port: 38422
```

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
- `ho-start <ue-id> --target-nci <nci> [--mode <auto|n2|xn>]`  
  `ho-start <ue-id> --target-name <neighbor-name> [--mode <auto|n2|xn>]`  
  `ho-start <ue-id> --target-cell-id <cell-id> [--mode <auto|n2|xn>]`
- `ho-status` — active handover state, timers
- `ho-cancel <ue-id>` — cancel an in-progress handover
- `xn-peers` — configured Xn peers and current SCTP connection state
  - includes `setup-complete` flag from bootstrap Xn Setup exchange
  - `ho-status` includes `xn-source` and `xn-target` entries with
    `old-ue-xnap-id`/`new-ue-xnap-id`, `sn-status-sent`, `sn-status-received`

Mode behavior:
- `n2`: force N2 handover path.
- `auto`: use `handoverPolicy.defaultMode`; if it resolves to unavailable Xn, fallback to N2 when `fallbackToN2: true`.
- `xn`: requires matching connected/setup-complete `xnNeighbors` entry; runs Xn HO preparation
  (request/ack/failure/cancel), triggers UE move signaling (private HO command + RRC HO command),
  and executes target-side NGAP `HandoverNotify + PathSwitchRequest`.

## Test Flow (A → B)

1. Start core (AMF/SMF/UPF), then gNB A and gNB B.
2. Start UE and verify it attaches to gNB A (`ue-list` on gNB A).
3. Trigger HO from gNB A:
   - `ho-start <ue-id> --target-name gnb-20 --mode n2`
   - or `ho-start <ue-id> --target-name gnb-20 --mode auto`
4. Watch logs:
   - Source: `ho_required_tx` → `ho_command_rx`
   - Target: `ho_request_rx` → `ho_req_ack_tx` → `ho_notify_tx` → `path_switch_tx` → `path_switch_ack_rx`
5. Verify UE is now listed on gNB B.

## Troubleshooting

- **Target not found**: ensure `neighbors` match and UE `gnbSearchList` includes both `linkIp`s.
- **TNGRELOCoverall expiry**: check that the UE received the RRC Reconfiguration and sent RRC Reconfiguration Complete.
- **No UE on target**: verify radio link (RLS) reachability between UE and target `linkIp`.
- **`ho-cancel` during `--mode xn`**: sends Xn Handover Cancel and waits for Xn cancel-ack; use `ho-status` (`xn-source`)
  to verify `CANCEL_SENT` → `CANCELED`.
- **`--mode xn` completion signaling**: verify `ho-status` (`xn-target`) shows `complete-received: true` and then
  `context-release-sent: true` after target `path_switch_ack_rx`; source should log `ho.xn.event=context_release_tx`.
- **`--mode xn` says no matching peer**: ensure target neighbor matches `xnNeighbors` by `name` or `nci`.
- **`--mode xn` says peer not connected**: use `xn-peers` and confirm state becomes `CONNECTED`.
