# IPv6 PDU Session Support Plan (Developer-Executable, Spec-Driven)

## Goal (Definition of Done)

“Full IPv6 support” means all of the following work end-to-end:
- UE can request **IPv6** and **IPv4v6** PDU sessions via config (`sessions[].type`).
- Core allocates an IPv6 (or IPv4+IPv6) PDU address; UE accepts it.
- UE brings up a TUN interface with IPv6 (and IPv4 for IPv4v6), installs routing rules, and can pass traffic.
- gNB forwards **IPv6 user plane** over GTP-U (no IPv4-only filtering).
- `nr-cli`/UE status prints IPv6 addresses in readable form (not hex).

## Current Gaps (as of repo state)

These are the concrete blockers found in code:
- UE NAS SM rejects non-IPv4 session types and forces request type to IPv4:
  - `src/ue/nas/sm/establishment.cpp:57` and `src/ue/nas/sm/establishment.cpp:118`
- UE app refuses to set up TUN unless session type is IPv4:
  - `src/ue/app/task.cpp:162`
- UE TUN config/routing is IPv4-only (`AF_INET`, netmask, `ip rule from <v4>`):
  - `src/ue/tun/config.cpp:112` and `src/ue/tun/config.cpp:364`
- gNB drops non-IPv4 uplink packets:
  - `src/gnb/gtp/task.cpp:185`
- Address formatting prints only IPv4, otherwise hex:
  - `src/utils/common.cpp:271`

## Spec Sources (Local Rel-17)

All spec citations are from `/home/jordan/3GPP_R17/Rel-17/`:
- NAS / 5GSM PDU session establishment and IE semantics:
  - `24_series/24501-hc0.md` (TS 24.501)
  - `24_series/24526-h80.md` (TS 24.526) (if needed for 5GSM details/clarifications)
- Architecture and PDU session concepts:
  - `23_series/23501-ha0.md` (TS 23.501)
  - `23_series/23502-ha0.md` (TS 23.502) (procedures)
- GTP-U (for transport expectations; mostly “payload opaque”):
  - `29_series/29281-h40.md` (TS 29.281)

**Per-epic workflow**
1) Pre-research: extract mandatory fields + behavior into a checklist.
2) Design: map spec concepts to UERANSIM structs/functions.
3) Implement: smallest change that passes acceptance tests.
4) Post-research: compare pcap/logs to checklist; document deviations.

## Epic 0 — Compliance + Test Harness (Gatekeeper)

### Deliverables
- `docs/plan/ipv6-support-compliance.md` populated with spec anchors before coding.
- `docs/plan/ipv6-support-testcases.md` with atomic tests (local + with core).

### Tasks (atomic)
1. Add compliance checklist items for:
   - PDU session type negotiation (IPv6, IPv4v6)
   - PDU Address IE length/format expectations
   - PCO/DNS behavior (IPv6 DNS request/response if supported)
2. Add “smoke test” commands to reproduce:
   - IPv6 session establishment and traffic
   - IPv4v6 session establishment and traffic

### Acceptance
- A developer can run the testcase steps and decide pass/fail from logs/pcap.

## Epic 1 — UE NAS: Request IPv6/IPv4v6 Correctly (24.501)

### Pre-research (spec anchors)
- In `24501-hc0.md`, locate:
  - PDU Session Establishment Request message definition
  - PDU session type IE semantics (IPv4 / IPv6 / IPv4v6)
  - PDU Address IE semantics (what the network returns for IPv6/IPv4v6)
  - PCO/Extended PCO parameters relevant to IPv6 (DNSv6, etc.)

### Deliverables
- UE can send establishment requests with `pduSessionType = IPV6` or `IPV4V6`.
- UE accepts establishment accept containing IPv6 addresses.

### Tasks (atomic)
1. Remove IPv4-only gate in SM establishment
   - File: `src/ue/nas/sm/establishment.cpp`
   - Change:
     - Replace `config.type != IPV4` check with an allow-list: `IPV4`, `IPV6`, `IPV4V6`
   - Acceptance:
     - UE no longer logs “PDU session type … not supported” for IPv6 configs.
2. Set requested PDU session type from config
   - File: `src/ue/nas/sm/establishment.cpp`
   - Change:
     - Set `req->pduSessionType->pduSessionType = config.type` instead of forcing IPV4
   - Acceptance:
     - NAS pcap shows the requested PDU session type matches config.
3. Update PCO requests for IPv6
   - File: `src/ue/nas/sm/establishment.cpp`
   - Change:
     - When requesting IPv6 or IPv4v6, request IPv6 DNS server option(s) (and keep IPv4 DNS for IPv4v6).
     - Keep “IP address allocation via NAS signalling” request.
   - Acceptance:
     - UE does not request only IPv4 DNS when session type is IPv6-only (pcap/log).

### Post-research
- Verify requested/selected PDU session type + returned PDU address fields align with the checklist.

## Epic 2 — PDU Address Parsing + Display (Correctness + Debuggability)

### Pre-research (spec anchors)
- In `24501-hc0.md`:
  - Exact encoding/size of PDU Address for IPv6 and IPv4v6.

### Deliverables
- UE can interpret IPv6/IPv4v6 PDU addresses robustly.
- CLI/status displays addresses as IPv4/IPv6 strings.

### Tasks (atomic)
1. Centralize PDU address → printable string conversion
   - File: `src/utils/common.cpp` (or new helper in `src/utils/network.*`)
   - Change:
     - Update `utils::OctetStringToIp()` to support:
       - IPv6 full address (16 bytes) and IPv6 interface identifier (8 bytes → display as link-local `fe80::/64`)
       - IPv4v6 full (20 bytes) and IPv4 + IPv6 IID (12 bytes)
       using `inet_ntop`.
   - Acceptance:
     - `ToJson(IEPduAddress)` prints IPv6 as `xxxx:...` not hex.
2. Validate PDU address length by session type
   - File: `src/ue/app/task.cpp` (before configuring TUN)
   - Change:
     - For IPV6/IPV4V6, log explicit error if address length is unexpected (include length and session type).
   - Acceptance:
     - Bad/unsupported formats fail early with actionable logs.

### Post-research
- Compare observed PDU address lengths from core vs spec; document any differences and adopted behavior.

## Epic 3 — UE TUN: IPv6 Addressing + Routing Rules

### Deliverables
- UE can bring up TUN with:
  - IPv6 address + prefix length (default `/64` unless configurable)
  - IPv4+IPv6 for IPv4v6 sessions
- UE can set routing for IPv6 without breaking existing IPv4 behavior.

### Tasks (atomic)
1. Add IPv6 prefix config
   - Files: `src/ue/types.hpp`, `src/ue.cpp`, and UE YAML examples
   - Add optional config:
     - `tunIpv6Prefix: 64` (default 64 if omitted)
   - Acceptance:
     - UE prints chosen prefix length when configuring IPv6.
2. Extend `tun::ConfigureTun` to support IPv6
   - File: `src/ue/tun/config.cpp`
   - Design constraint:
     - Keep existing IPv4 ioctl path as-is.
     - Add a new IPv6 path using `ip -6` commands (the module already shells out to `ip` for routing rules).
   - Implementation tasks:
     - Add `TunSetIpv6AndUp(ifName, ipv6Addr, prefixLen, mtu)` using `ip -6 addr add ... dev ...` + `ip link set ... up`.
     - Add IPv6 equivalents of:
       - `RemoveExistingIpRules`, `AddNewIpRules`
       - `RemoveExistingIpRoutes`, `AddIpRoutes`
       using `ip -6 rule` and `ip -6 route`.
   - Acceptance:
     - After IPv6 session accept, `ip -6 addr show dev <tun>` includes the assigned IPv6.
     - `ip -6 rule` shows rules for the UE address.
3. Support IPv4v6 dual-stack on the same TUN
   - Files: `src/ue/app/task.cpp`, `src/ue/tun/config.cpp`
   - Change:
     - When PDU address contains IPv4v6, configure both IPv4 and IPv6 addresses on the same TUN.
   - Acceptance:
     - `ip addr` shows IPv4; `ip -6 addr` shows IPv6 for the same interface.

### Post-research
- Confirm routing behavior aligns with 23.501 “PDU session provides IP connectivity” expectations (mechanics are OS-specific).

## Epic 4 — gNB User Plane: Stop Dropping IPv6 (GTP-U Payload Opaque)

### Deliverables
- gNB forwards IPv6 uplink/downlink packets over GTP-U.

### Tasks (atomic)
1. Remove IPv4-only filter in uplink path
   - File: `src/gnb/gtp/task.cpp`
   - Change:
     - Replace `if ((data[0] >> 4 & 0xF) != 4) return;` with:
       - allow 4 and 6; drop others with a debug log including version nibble.
   - Acceptance:
     - IPv6 packets reach UPF (observable by pcap on N3 or core counters).

### Post-research
- Confirm GTP-U encapsulation is unchanged; only payload filtering was removed.

## Epic 5 — UE Connection Setup + Status Output for IPv6/IPv4v6

### Deliverables
- UE app creates TUN tasks for IPv6 and IPv4v6 sessions.
- `nr-cli <ue> status` shows correct address(es) and session type.

### Tasks (atomic)
1. Allow non-IPv4 session types in connection setup
   - File: `src/ue/app/task.cpp`
   - Change:
     - Replace the IPv4-only checks with handling for `IPV6` and `IPV4V6`.
     - Decide mapping:
       - IPV6: configure IPv6 only
       - IPV4V6: configure both
   - Acceptance:
     - UE logs “Connection setup … TUN interface … is up” for IPv6 sessions.
2. Improve address formatting in status outputs
   - Files: `src/lib/nas/ie4.cpp` (`ToJson(IEPduAddress)`), `src/utils/common.cpp`
   - Change:
     - Ensure IPv6 prints as `inet_ntop` string.
   - Acceptance:
     - `nr-cli <ue> status` prints IPv6 with colons.

## Epic 6 — Test Matrix + Example Configs

### Deliverables
- Example configs that exercise IPv6 and IPv4v6.
- Repeatable test matrix documented.

### Tasks (atomic)
1. Add UE config examples
   - Files: `config/*-ue.yaml` (or add `config/*-ue-ipv6.yaml` if you prefer not to modify existing)
   - Include:
     - `sessions: [{ type: "IPv6", ... }]`
     - `sessions: [{ type: "IPv4v6", ... }]`
     - `tunIpv6Prefix: 64`
2. Add testcases
   - File: `docs/plan/ipv6-support-testcases.md`
   - Include:
     - TC: IPv6 establish + ping6
     - TC: IPv4v6 establish + ping + ping6

### Acceptance
- A developer can follow docs and reproduce success/failure reliably.

## Implementation Conventions (Must Follow)

- Keep changes minimal and consistent with existing patterns.
- Prefer adding new helpers over ad-hoc string parsing at call sites.
- Add logs at failure boundaries with enough context (session type, address length, interface name).
