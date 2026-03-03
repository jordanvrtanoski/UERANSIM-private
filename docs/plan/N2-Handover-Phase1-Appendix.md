# N2 Handover (Phase 1) — Appendix: Private Wire Contract + Stable Telemetry

## 1. Purpose
This appendix defines two “stability contracts” for Phase‑1 N2 handover:

1) A precise **wire contract** for the private mobility messages carried inside RLS `EPduType::DATA`.
2) A stable **telemetry contract** (log keys + counter names) so integration tests can assert behavior without relying on fragile free-form text.

This is simulator-specific and intentionally temporary; Phase 2 removes the private wire contract and replaces mobility with RRC.

Related docs:
- `docs/plan/N2-Handover-Design.md`
- `docs/plan/N2-Handover-Private-Execution.md`
- `docs/plan/N2-Handover-State-Tables.md`
- `docs/plan/n2-handover-testcases.md`

## 2. Private Mobility Wire Contract (over RLS `DATA`)
### 2.1 Placement
The private payload is transported as:
- `rls::RlsPduTransmission`
  - `pduType = rls::EPduType::DATA`
  - `pdu = <private_payload_bytes>`

Demux requirement:
- The receiver must identify private payloads deterministically without parsing IP headers or relying on context.

### 2.2 Byte order and encoding
- All integer fields are **network byte order** (big-endian).
- Strings are UTF‑8, not null-terminated.
- Variable-length fields use length-prefixes.

### 2.3 Header layout (v1)
All private mobility messages start with this fixed header:

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 12 | `magic` | ASCII bytes: `UERANSIM_HO1` (12 bytes) |
| 12 | 1 | `version` | `0x01` |
| 13 | 1 | `msg_type` | See §2.4 |
| 14 | 2 | `header_len` | Fixed header bytes (excl. TLVs). In v1 this is always `0x001C` (28). |
| 16 | 4 | `total_len` | Full payload length (header + body), must match actual |
| 20 | 4 | `crc32` | CRC32 over payload with this field set to 0 during computation |
| 24 | 2 | `tlv_count` | Number of TLVs following |
| 26 | 2 | `reserved` | Must be `0`, ignore on receive |
| 28 | … | `tlvs[]` | `tlv_count` TLVs (see §2.5) |

Validation rules:
- `magic` must match exactly.
- `version` must be supported.
- `total_len` must equal received payload size.
- `header_len` must be ≤ `total_len` and within sane bounds.
- CRC32 must match (if mismatch: log and drop).

### 2.4 Message types (v1)
| `msg_type` | Name | Direction |
|---:|---|---|
| `0x01` | `HO_CMD` | gNB‑S → UE |
| `0x02` | `HO_COMPLETE` | UE → gNB‑T |
| `0x03` | `HO_FAIL` | UE → gNB‑S and/or gNB‑T |
| `0x11` | `NGAP_SRC_TO_TGT` | gNB‑S → AMF → gNB‑T (inside `SourceToTarget_TransparentContainer`) |
| `0x12` | `NGAP_TGT_TO_SRC` | gNB‑T → AMF → gNB‑S (inside `TargetToSource_TransparentContainer`) |

Unknown `msg_type`:
- log `ho.private.rx_unknown_type=1` (see telemetry), drop.

### 2.5 TLV format
Each TLV is:

| Field | Size | Notes |
|---|---:|---|
| `type` | 2 | big-endian |
| `len` | 2 | big-endian, length of `value` |
| `value` | `len` | raw bytes |

TLVs may appear in any order. Duplicate TLVs:
- keep the first occurrence, log a debug warning.

Unknown TLVs:
- ignore (forward compatibility).

### 2.6 TLV types (v1)
Common TLVs:
- `0x0001` `token` (M): bytes; recommended 16–32 bytes.
- `0x0002` `ue_id_hint` (O): UTF‑8 string.
- `0x0003` `attempt_id` (O): uint32 (len=4).
- `0x0004` `timestamp_ms` (O): uint64 (len=8).
- `0x0005` `ue_sti` (O): uint64 (len=8). RLS STI for binding a “prepared” UE id on the target gNB.

Target selection TLVs (for `HO_CMD`):
- `0x0101` `target_cell_id` (O): int32 (len=4).
- `0x0102` `target_nci` (O): uint64 (len=8) representing 36-bit NCI in low bits.
- `0x0103` `target_name` (O): UTF‑8 string.
- `0x0104` `target_link_ip` (R): UTF‑8 string (Phase 1 reliability hint; e.g., `127.0.0.2`).

Failure TLVs (for `HO_FAIL`):
- `0x0201` `reason_code` (M): uint32 (len=4).
- `0x0202` `reason_detail` (O): UTF‑8 string.

Minimum required TLVs per message:
- `HO_CMD`: `token` + `target_link_ip` (required by current Phase‑1 UE demux implementation).
- `HO_COMPLETE`: `token`.
- `HO_FAIL`: `token` + `reason_code`.

### 2.7 Receiver behaviors (wire-level)
On any validation failure:
- increment `ho.private.rx_drop_total` and a more specific reason counter (see §3).
- log one structured line with `token` if it can be decoded safely (if not, log `token=NA`).

On success:
- emit a structured log line with decoded TLVs (see §3.2).

### 2.8 Backward/Forward compatibility
- Phase 1 version is `1`. Phase 2 removes this protocol.
- Receivers must ignore unknown TLVs and unknown message types (drop unknown types).

## 3. Stable Telemetry Contract
### 3.1 Principles
- Prefer **key=value** structured fields inside log lines for easy parsing.
- Keep field names stable across refactors.
- Always log token and UE identifiers where available.

### 3.2 Stable log keys
All HO-related logs should include these keys when known:
- `ho.token`
- `ho.ue_id` (UERANSIM UE id on that node)
- `ho.ran_ue_ngap_id`
- `ho.amf_ue_ngap_id`
- `ho.role` = `source|target|ue`
- `ho.state` (string state name)

Target resolution keys (source + UE):
- `ho.target.nci`
- `ho.target.name`
- `ho.target.cell_id`
- `ho.target.link_ip`
- `ho.target.selector` = `nci|name|cell_id|link_ip_fallback`

NGAP event keys:
- `ho.ngap.event` = `ho_required_tx|ho_request_rx|ho_req_ack_tx|ho_command_rx|ho_prep_fail_rx|ho_notify_tx|path_switch_tx|path_switch_ack_rx|path_switch_fail_rx`
- `ho.ngap.cause_group` / `ho.ngap.cause_value` (when applicable)

Timer keys:
- `ho.timer.name` = `TNGRELOCprep|TNGRELOCoverall|prepared_ttl|unmatched_complete_ttl`
- `ho.timer.action` = `start|stop|expire`
- `ho.timer.ms_remaining` (optional)

Private wire keys:
- `ho.private.event` = `cmd_tx|cmd_rx|complete_tx|complete_rx|fail_tx|fail_rx|rx_drop|rx_unmatched|rx_dup`
- `ho.private.version`
- `ho.private.msg_type`
- `ho.private.drop_reason` (if drop)

### 3.3 Counter names (must match docs)
Counters are named for test assertions; they can be exported via `nr-cli` later.

Source gNB:
- `ho.required_tx_total`
- `ho.command_rx_total`
- `ho.prep_fail_rx_total`
- `ho.timer_prep_exp_total`
- `ho.timer_overall_exp_total`

Target gNB:
- `ho.request_rx_total`
- `ho.req_ack_tx_total`
- `ho.private.complete_rx_total`
- `ho.private.complete_unmatched_total`
- `ho.path_switch_tx_total`
- `ho.path_switch_ack_rx_total`
- `ho.path_switch_fail_rx_total`
- `ho.prepared_ttl_exp_total`

Private wire (all roles):
- `ho.private.rx_drop_total`
- `ho.private.rx_drop_bad_magic_total`
- `ho.private.rx_drop_bad_version_total`
- `ho.private.rx_drop_bad_length_total`
- `ho.private.rx_drop_bad_crc_total`
- `ho.private.rx_unknown_type_total`

### 3.4 Example structured log line (format only)
All roles should log in this general pattern (content depends on role/event):
- `handover ho.role=source ho.token=… ho.ue_id=… ho.state=… ho.ngap.event=ho_required_tx …`

This document intentionally does not include code; it defines the stable keys and naming.

## 4. How Tests Should Use This
In `docs/plan/n2-handover-testcases.md`, assertions should be phrased using:
- presence of NGAP event keys, timer expiry keys, and private event keys
- counter increments for unmatched/duplicate/drop scenarios

Avoid assertions on:
- exact free-form English text
- pointer values, thread IDs, or transient socket details
