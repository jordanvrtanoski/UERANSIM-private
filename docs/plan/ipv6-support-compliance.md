# IPv6 Support Compliance Checklist (Rel-17)

Do not mark items as “Implemented” until there is a corresponding testcase in `docs/plan/ipv6-support-testcases.md` and at least one pcap/log capture demonstrating the behavior.

## Spec Files (Local)

- TS 23.501: `/home/jordan/3GPP_R17/Rel-17/23_series/23501-ha0.md`
- TS 23.502: `/home/jordan/3GPP_R17/Rel-17/23_series/23502-ha0.md`
- TS 24.501: `/home/jordan/3GPP_R17/Rel-17/24_series/24501-hc0.md`
- TS 24.526: `/home/jordan/3GPP_R17/Rel-17/24_series/24526-h80.md`
- TS 29.281 (GTP-U): `/home/jordan/3GPP_R17/Rel-17/29_series/29281-h40.md`

## Legend

- **M**: Mandatory for “full IPv6 support” in this repo
- **C**: Conditional (document condition)
- **D**: Deferred (explicitly not implemented)

## NAS: PDU Session Establishment Request/Accept (IPv6 / IPv4v6)

**Spec anchor**
- File:
- Section heading:
- Grep terms:

**Checklist**
- [ ] (M) UE can request PDU session type `IPv6`
- [ ] (M) UE can request PDU session type `IPv4v6`
- [ ] (M) UE accepts Establishment Accept containing IPv6 PDU Address
- [ ] (C) UE handles unexpected PDU Address encoding gracefully (clear error + no crash)
- [ ] (C) PCO requests include IPv6 DNS information when IPv6 is requested

**Deviations**
- None recorded

## User Plane: GTP-U Payload Handling (IPv6)

**Spec anchor**
- File: `29281-h40.md`
- Section heading:
- Grep terms:

**Checklist**
- [ ] (M) gNB forwards IPv6 payload over GTP-U without IPv4-only filtering
- [ ] (M) gNB forwards IPv4v6 payload (IPv4 and IPv6 packets) over GTP-U

**Deviations**
- None recorded

## UE OS Integration: TUN + Routing

**Spec anchor**
- File: (23.501 concepts; OS-specific details are not standardized)
- Section heading:
- Grep terms:

**Checklist**
- [ ] (M) UE configures TUN with IPv6 address + prefix length
- [ ] (M) UE configures IPv4+IPv6 for IPv4v6 sessions
- [ ] (M) UE installs routing rules for IPv6 that mirror existing IPv4 behavior (policy routing)
- [ ] (C) Behavior documented for prefix length selection (default `/64` vs configurable)

**Deviations**
- None recorded

