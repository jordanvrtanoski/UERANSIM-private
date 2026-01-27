# IPv6 Support Testcases (Atomic, Repeatable)

These testcases gate marking items “Implemented” in `docs/plan/ipv6-support-compliance.md`.

## Common Setup

- Build: `make build`
- Run UE as root (TUN setup requires it): `sudo ./build/nr-ue -c <ue.yaml>`
- Have a core (Open5GS/free5GC/other) configured to allocate IPv6 and/or IPv4v6 for the DNN/APN used by the UE.

## TC-00: Baseline IPv4 (Control)

**Goal**: Ensure the environment is sane before IPv6 testing.

**Steps**
1. Run gNB + core.
2. Run UE with `sessions[].type: IPv4`.
3. Verify UE creates a TUN and session is ACTIVE.

**Expected**
- UE log: “Connection setup … TUN interface … is up.”
- `nr-cli <ue> status` shows IPv4 address.

## TC-10: IPv6 Session Establishment (NAS)

**Goal**: UE requests an IPv6 PDU session and receives an IPv6 PDU Address.

**Steps**
1. Set UE config: `sessions: [{ type: "IPv6", apn: "...", slice: ... }]`.
2. Start UE.
3. Capture N1/N2 with tcpdump/Wireshark (as available).

**Expected**
- UE does not log “PDU session type … not supported”.
- pcap shows PDU Session Establishment Request with type IPv6.
- UE status shows IPv6 address (contains `:`).

## TC-20: IPv6 TUN Configuration

**Goal**: UE configures IPv6 on the TUN interface.

**Steps**
1. After TC-10, find interface name from UE logs (e.g., `uesimtun0`).
2. Run: `ip -6 addr show dev <tun>`
3. Run: `ip -6 rule | rg <ipv6-addr>`

**Expected**
- Interface has an `inet6` address matching the session PDU address (or documented mapping).
- IPv6 policy rule(s) exist if routing configuration is enabled.

## TC-30: IPv6 User Plane Forwarding (Ping6)

**Goal**: IPv6 packets traverse UE↔gNB↔UPF without being dropped.

**Steps**
1. Identify a reachable IPv6 target in the data network (or UPF-side test host).
2. Run from the host namespace using the UE TUN:
   - `ping -6 -I <tun> <target>`

**Expected**
- ICMPv6 replies received.
- gNB does not drop uplink IPv6 packets (no “ignored non IPv4 packets” behavior).

## TC-40: IPv4v6 Dual-Stack Session

**Goal**: UE requests IPv4v6 and configures both addresses on the same TUN.

**Steps**
1. Set UE config: `sessions[].type: "IPv4v6"`.
2. Start UE.
3. Check:
   - `ip addr show dev <tun>`
   - `ip -6 addr show dev <tun>`
4. Run:
   - `ping -I <tun> <ipv4-target>`
   - `ping -6 -I <tun> <ipv6-target>`

**Expected**
- Both IPv4 and IPv6 are configured.
- Both pings succeed (allow brief convergence delay).

## TC-50: Negative / Unexpected PDU Address Encoding

**Goal**: UE fails gracefully when core provides an unexpected PDU address format/length.

**Steps**
1. Induce a PDU address length mismatch (core config or forced test injection).
2. Observe UE behavior.

**Expected**
- UE logs a clear error containing:
  - session type, address length, and hex dump (or equivalent)
- No crash; session is released/cleaned up.

