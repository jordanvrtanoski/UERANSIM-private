# N2 Handover (Phase 1) — Smoke Runbook (Single Host)

Status date: 2026-02-10

Goal: run a **minimal, repeatable** manual smoke test for TC‑01 (happy path) using:
- 2× `nr-gnb` (source + target),
- 1× `nr-ue`,
- 1× core (Open5GS AMF/SMF/UPF).

This runbook assumes the Phase‑1 private execution protocol described in:
- `docs/plan/N2-Handover-Private-Execution.md`

## 1) Topology (loopback IP split)
Use distinct loopback IPs to run both gNBs on the same host without port conflicts:
- gNB‑T (target): `127.0.0.2`
- gNB‑S (source): `127.0.0.1`
- AMF: `127.0.0.5` (adjust to your Open5GS setup)

## 2) Config (example deltas)
Create two gNB configs by copying `config/open5gs-gnb.yaml` and editing:

### 2.1 Target gNB (`config/gnb-t.yaml`)
- `nci`: set to a different value than source (e.g. `0x000000020`)
- `linkIp/ngapIp/gtpIp`: `127.0.0.2`
- `amfConfigs[0].address`: AMF address (e.g. `127.0.0.5`)

### 2.2 Source gNB (`config/gnb-s.yaml`)
- `nci`: source value (e.g. `0x000000010`)
- `linkIp/ngapIp/gtpIp`: `127.0.0.1`
- add `neighbors:` containing the target’s identifiers:
```yaml
neighbors:
  - name: gnb-t
    nci: 0x000000020
    idLength: 32
    tac: 1
    mcc: '999'
    mnc: '001'
```

Optional (for deterministic timer behavior in tests):
```yaml
ngapTimers:
  TNGRELOCprep: 5000
  TNGRELOCoverall: 15000
  preparedTtlMs: 15000
  unmatchedCompleteTtlMs: 5000
```

Optional (explicit handover mode policy for smoke tests):
```yaml
handoverPolicy:
  defaultMode: n2
  fallbackToN2: true
  requireSameAmfForXn: true
```

Optional (Xn peer transport visibility for mode selection/debug):
```yaml
xnPort: 38422
xnNeighbors:
  - name: gnb-t
    nci: 0x000000020
    address: 127.0.0.2
    port: 38422
```

### 2.3 UE (`config/ue-ho.yaml`)
Copy `config/open5gs-ue.yaml` and update:
```yaml
gnbSearchList:
  - 127.0.0.1
  - 127.0.0.2
```

Ensure the UE still establishes at least one PDU session (baseline must pass before HO).

## 3) Build
From repo root:
- `make build`

## 4) Run (3 terminals)
1) Start Open5GS AMF/SMF/UPF (your normal method).
2) Start gNB‑T:
   - `./build/nr-gnb -c config/gnb-t.yaml`
3) Start gNB‑S:
   - `./build/nr-gnb -c config/gnb-s.yaml`
4) Start UE:
   - `./build/nr-ue -c config/ue-ho.yaml`

Baseline acceptance:
- UE registers and establishes a PDU session while served by gNB‑S.

## 5) Trigger handover (nr-cli)
1) List nodes:
   - `./build/nr-cli --dump`
2) Connect to the **source gNB** node name:
   - `./build/nr-cli <source-node-name>`
3) Find a UE id (`ue-list`) and trigger HO:
   - `ho-start <ue-id> --target-name gnb-t --mode n2`
   - or `ho-start <ue-id> --target-name gnb-t --mode auto`
   - `--mode xn` runs Xn preparation + UE move and target-side `HandoverNotify + PathSwitchRequest`.
   - optional debug: `xn-peers`
4) Observe state:
   - `ho-status`

## 6) Expected sequence (high level)
Source gNB:
- sends `HANDOVER REQUIRED`, starts `TNGRELOCprep`
- receives `HANDOVER COMMAND`, sends private `HO_CMD`, starts `TNGRELOCoverall`

UE:
- receives private `HO_CMD(token=...)`
- switches to target (Phase‑1 selection uses the `target_link_ip` hint when needed)
- sends private `HO_COMPLETE(token)` to the target

Target gNB:
- receives `HANDOVER REQUEST`, sends `HANDOVER REQUEST ACKNOWLEDGE`
- matches `HO_COMPLETE(token)`, sends `HANDOVER NOTIFY` + `PATH SWITCH REQUEST`
- receives `PATH SWITCH REQUEST ACKNOWLEDGE`

Pass criterion (Phase‑1):
- `ho-status` returns to idle/none for the UE, and logs show Path Switch ACK received on target.
