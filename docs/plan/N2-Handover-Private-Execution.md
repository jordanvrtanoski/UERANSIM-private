# N2 Handover (Phase 1) — Private Mobility over RLS `DATA` (Artifact)

## 1. Purpose
Specify the **Phase‑1 private mobility protocol** used to execute N2-based NGAP handover without implementing RRC mobility yet. This is a temporary artifact meant to be removed in Phase 2.

Goals:
- Deterministic **demultiplexing** from normal `EPduType::DATA` traffic.
- Strong **debuggability** (token visibility, versioning, corruption detection).
- Safe handling of **parallel handovers** and out-of-order arrivals.

Non-goals:
- Security (no cryptographic integrity; this is a simulator feature)
- Standards alignment (this is deliberately private)

## 2. Placement in Current Architecture
### gNB
- Receive path: `nr::gnb::RlsUdpTask` → deliver to control consumer → `nr::gnb::NgapTask` (target side) for token match.
- Transmit path: `nr::gnb::NgapTask` (source side) → `nr::gnb::RlsUdpTask::send(ueId, …)` to UE.

### UE
- Receive path: `nr::ue::RlsUdpTask` → private mobility demux → `UeMobilityManager`.
- Transmit path: `UeMobilityManager` → `nr::ue::RlsUdpTask::send(cellId, …)` to target gNB.

## 3. Demux Strategy (must not collide with user payload)
Because we use `EPduType::DATA`, the payload requires a unique signature.

### Private header requirements
- Starts with a **fixed magic** (8–16 bytes) unlikely to appear in real IP payload.
- Includes:
  - `version` (1 byte)
  - `message_type` (1 byte)
  - `header_length` / `total_length`
  - `token_length` + token bytes
  - `checksum` (lightweight corruption detection; e.g., CRC32) for debug

Demux rule:
- If `payload` starts with `magic` AND `version` supported AND `total_length` sane → treat as private mobility.
- Otherwise: treat as normal DATA.

**Normative definition (Phase 1):** The exact header/TLV layout, magic bytes, CRC behavior, and versioning rules are defined in:
- `docs/plan/N2-Handover-Phase1-Appendix.md`

## 4. Message Types (Phase 1)
### 4.1 `HO_CMD` (source gNB → UE)
Purpose: tell UE to move to target, and provide correlation token.

Mandatory fields:
- `token` (opaque bytes, globally unique per HO attempt)
- `target selectors`:
  - `target_cell_id` (optional)
  - `target_nci` (optional)
  - `target_name` (optional string)
- `target RLS hint`:
  - `target_link_ip` (recommended in Phase 1 to ensure deterministic attach even if UE cannot map nci/name → cell id)
- `attempt_id` (small integer for UE retry/debug; optional)

Recommended debug fields:
- `source_gnb_name`, `source_ran_ue_ngap_id`, `source_amf_ue_ngap_id` (if known)
- `timestamp_ms` (sender time)

Receiver behavior (UE):
1. Validate header (magic/version/length/checksum).
2. Log `token`, selectors, and chosen resolution path.
3. Perform attach to target (prefer cell-id, then nci, then name; fall back to `target_link_ip` hint if needed).
4. Send `HO_COMPLETE(token)` to the target.

### 4.2 `HO_COMPLETE` (UE → target gNB)
Purpose: signal “UE arrived” and allow target to bind to the prepared HO context.

Mandatory fields:
- `token`
- `ue_identity_hint` for debugging (e.g., UE local id; optional but recommended)

Receiver behavior (target gNB):
1. Validate header.
2. Lookup `preparedByToken[token]`.
3. If found:
   - bind the incoming UE/RLS identity to that prepared context,
   - advance NGAP state to send `HANDOVER NOTIFY` + `PATH SWITCH REQUEST`.
4. If not found:
   - log as **unmatched**, include sender endpoint/cell-id if known,
   - optionally store `(token, received_time)` in a short-lived cache to tolerate reordering,
   - never crash or corrupt state.

### 4.3 `HO_FAIL` (optional, UE → source/target gNB)
Purpose: explicit error reporting when UE cannot resolve/attach.

Fields:
- `token`
- `reason_code` (enumerated)
- `details` (string; optional)

Receiver behavior:
- log and mark HO as failed/cancellable (policy-driven).

## 5. Parallelism + Race Controls
### 5.1 Token uniqueness
Token must be globally unique per HO attempt so:
- multiple UEs can HO concurrently,
- multiple HO attempts for the same UE across time do not collide,
- target matching is unambiguous.

### 5.2 Target-side maps
Maintain:
- `preparedByToken`: token → prepared HO context
- optional `unmatchedCompleteCache`: token → last seen timestamp (short TTL)

This supports the race scenario:
- `HO_COMPLETE` arrives before `HANDOVER REQUEST` is fully processed (unlikely but must be safe).

### 5.3 Idempotency
`HO_COMPLETE` may repeat (UE retries). Treat as idempotent:
- if already completed, ignore after logging once.

## 6. Debug/Observability Checklist (must-have)
- Every private mobility message log includes:
  - `token`
  - `msg_type`, `version`
  - chosen target resolution path (cell-id vs nci vs name)
  - sender/receiver endpoint (RLS address/cell id where applicable)
- Counters:
  - `ho_cmd_tx_total`, `ho_complete_rx_total`, `ho_complete_unmatched_total`, `ho_fail_rx_total`
- Optional trace dump:
  - allow printing the decoded header/fields at debug level (no raw binary spam by default)

## 7. Lifecycle / Removal Plan
This artifact is intentionally temporary:
- Phase 2 replaces `HO_CMD/HO_COMPLETE` with proper RRC mobility procedures.
- The NGAP HO procedure logic and token-based correlation can remain, but token transport shifts into standards-aligned containers or internal mapping.

## 8. Wire Contract / Telemetry (normative for Phase 1)
For the exact wire header/TLV layout and stable log/counter keys used by integration tests, see:
- `docs/plan/N2-Handover-Phase1-Appendix.md`
