# N2 Handover (Phase 1) — Neighbor Configuration & CLI Contract (Artifact)

## 1. Purpose
Define the **configuration data** and **CLI contract** required to drive Phase‑1 N2-based handover in a deterministic, debuggable way, while keeping refactor cost low.

This artifact is simulator-specific (especially the Phase‑1 execution hints) but should be stable enough for operators and integration tests.

## 2. gNB Neighbor Model (Source-side)
The source gNB must be able to:
- Populate NGAP `Target ID` (TS 38.413) for the chosen target.
- Provide the UE with a deterministic way to reach the target in Phase 1 (RLS hint).

### 2.1 Required neighbor fields
For each neighbor entry:

| Field | Purpose |
|---|---|
| `name` | Human-friendly identifier used by CLI `--target-name`. |
| `nci` | Used for CLI `--target-nci` and to derive `gnbId` for NGAP `Target ID`. |
| `idLength` | gNB ID bit length (22..32). Used to derive `gnbId` from `nci`. Defaults to the local gNB `idLength` if omitted. |
| `mcc`, `mnc` | Used in `GlobalRANNodeID` and `selectedTAI`. Defaults to the local gNB PLMN if omitted. |
| `tac` | Used in `selectedTAI`. Defaults to the local gNB `tac` if omitted. |

Notes:
- Phase 1 does **not** require `rlsLinkIp` in the source neighbor model: the target gNB returns its `linkIp` via the NGAP transparent container, and the source forwards it to the UE in `HO_CMD`.
- The neighbor list is a **source-side** concept; the target gNB is configured independently as usual.

Example:
```yaml
neighbors:
  - name: gnb-t
    nci: 0x000000020
    idLength: 32
    tac: 1
    mcc: '999'
    mnc: '001'
```

### 2.2 Ambiguity rules
Reject configuration at startup (or refuse `ho-start`) if:
- two neighbors share the same `(plmn, gnbId, idLength)` tuple, or
- two neighbors share the same `nci` in the same PLMN, or
- `name` is duplicated.

This prevents “handover to the wrong node” failures that are hard to debug.

## 2.3 NGAP Timer Configuration (Source + Target)
The following timers are defined by 3GPP TS 38.413 and are configurable in the gNB YAML under `ngapTimers` (values in **milliseconds**):

```yaml
ngapTimers:
  TNGRELOCprep: 5000
  TNGRELOCoverall: 15000
  n2TargetPathSwitchDelayMs: 0
```

Notes:
- These keys intentionally match the 3GPP timer names (`TNGRELOCprep`, `TNGRELOCoverall`).
- `n2TargetPathSwitchDelayMs` is a simulator-only delay injected on the **target** gNB after UE handover completion and before
  `PATH SWITCH REQUEST`. It is intended for controlled buffering/late-switch testing and is not a 3GPP timer.
- Additional simulator-only TTLs may also exist (e.g. `preparedTtlMs`) but are not 3GPP timers.

## 2.4 Handover Policy Configuration (Mode Selection)
Handover mode policy is configurable in gNB YAML:

```yaml
handoverPolicy:
  defaultMode: auto         # auto | n2 | xn
  fallbackToN2: true        # used when auto resolves to unavailable xn
  requireSameAmfForXn: true # xn eligibility gate (future xn execution path)
```

Current behavior:
- `n2` is executable.
- `xn` executes Xn HO preparation control-plane (request/ack/failure/cancel), UE move trigger, and target-side NGAP
  `HandoverNotify + PathSwitchRequest`.
- `auto` uses `defaultMode` and can fallback to N2 when configured.

## 2.5 Xn Peer Transport Configuration (for mode eligibility/debug)
Xn peer transport is configured in gNB YAML:

```yaml
xnPort: 38422
xnNeighbors:
  - name: gnb-t
    nci: 0x000000020
    address: 192.168.88.46
    port: 38422
```

Current matching rules for mode selection:
- target matches an Xn peer by `name` or `nci`.
- Xn is considered available only when the matched peer is `CONNECTED` and `setup-complete`.
- `xn-peers` CLI command prints configured peers and SCTP state.
- `xn-peers` also exposes `setup-complete` from the current bootstrap Xn Setup exchange.

## 3. CLI Contract (Source gNB)
### 3.1 Commands
Minimum command set:
- `ho-start <ue-id> --target-nci <hex|dec> [--mode <auto|n2|xn>]`
- `ho-start <ue-id> --target-name <name> [--mode <auto|n2|xn>]`
- `ho-start <ue-id> --target-cell-id <cellId> [--mode <auto|n2|xn>]`
- `ho-start <ue-id> ... --mode n2 --n2-target-path-switch-delay-ms <ms>`
- `ho-status`
- `ho-cancel <ue-id>`
- `xn-peers`

### 3.2 Target selection precedence
Current Phase‑1 CLI requires **exactly one** target selector per `ho-start` (fail-fast if multiple are provided).

### 3.3 CLI validation rules
`ho-start` must fail fast with actionable errors if:
- UE does not exist, or is not NGAP-associated, or has no AMF association.
- UE already has an active HO in progress.
- Target selector is missing or cannot be resolved.
- Target resolves to the source itself (unless explicitly allowed for testing).
- `--mode` is not one of `auto|n2|xn`.
- `--n2-target-path-switch-delay-ms` is negative, too large, or used with a selected Xn handover mode.
- `--mode xn` is requested but no matching `xnNeighbors` peer exists.
- `--mode xn` is requested but matching peer is not connected/setup-complete.
- `ho-cancel` is requested but there is no active source-side handover transaction in either N2 or Xn path.

Per-command N2 delay override:
- `--n2-target-path-switch-delay-ms` is a **one-shot** override for the target-side delay inserted after
  `HandoverNotify` and before `PathSwitchRequest`.
- The source gNB arms the override on the target gNB over a simulator-local CLI side channel keyed by the deterministic
  handover token derived from `AMF-UE-NGAP-ID`.
- NGAP message structures remain unchanged; the override is not encoded into any 3GPP IE.

### 3.4 Debug outputs
`ho-status` should display at least:
- `ueId`, `ranUeNgapId`, `amfUeNgapId` (if known)
- HO `state`, `token`
- resolved target (`name`, `nci`, `rlsLinkIp` if used)
- current timer status (remaining time for `TNGRELOCprep`/`TNGRELOCoverall` when active)
- Xn preparation transactions (`xn-source`, `xn-target`) with token/state/failure reason where applicable
- XnAP IDs for preparation path (`old-ue-xnap-id`, `new-ue-xnap-id`)
- Bootstrap sequencing visibility (`sn-status-sent`, `sn-status-received`)
- Target-side private completion visibility (`complete-received`, `context-release-sent`)

`ho-start` command result should include selected mode metadata:
- `mode-source` (`cli` or `config`)
- `reason` (selection reason, e.g. auto fallback)

`ho-cancel` command behavior:
- if N2 source transaction exists, send NGAP Handover Cancel.
- else if Xn source transaction exists, send Xn Handover Cancel and wait for cancel-ack.

Optional: `ho-metrics` output listing counters described in `N2-Handover-Design.md`.

## 4. CLI Contract (Target gNB) (optional but useful)
Target-side visibility helps triage:
- `ho-prepared-list` (tokens currently prepared)
- `ho-prepared-info --token <…>` (age, associated AMF UE NGAP ID, TTL remaining)

These can be implemented later, but should be kept in mind to avoid painting ourselves into a corner.
