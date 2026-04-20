# SDN-Based Access Control System

## Overview

This project implements a Software-Defined Networking (SDN) based access control system using the POX controller and Mininet. The system enforces a whitelist policy on a single-switch topology, selectively allowing communication between authorised hosts while proactively blocking unauthorised hosts using OpenFlow flow rules.

The controller demonstrates core SDN concepts including packet_in event handling, reactive and proactive flow rule installation, ARP-based MAC learning, and priority-driven match-action policy enforcement.

---

## Topology

A single-switch star topology is used. All four hosts connect to one Open vSwitch instance (s1), which is managed by the POX controller running on localhost:6633.

```
h1 (10.0.0.1) ──┐
h2 (10.0.0.2) ──┤
                 s1 ────── POX Controller (127.0.0.1:6633)
h3 (10.0.0.3) ──┤
h4 (10.0.0.4) ──┘  [BLOCKED]
```

The single-switch design ensures every packet traverses s1, making all traffic visible to the controller with no bypass possible. Extending to a multi-switch topology requires no changes to the controller logic, as the whitelist is topology-agnostic.

---

## Whitelist Policy

| Source | Destination | Policy  |
|--------|-------------|---------|
| h1     | h2          | ALLOWED |
| h1     | h3          | ALLOWED |
| h2     | h3          | ALLOWED |
| h4     | any         | BLOCKED |
| any    | h4          | BLOCKED |

All policies are bidirectional. h4 is blocked proactively at connection time using high-priority OpenFlow drop rules, before any packet from h4 reaches the controller.

---

## File Structure

```
.
├── controller.py       # POX controller — whitelist enforcement, ARP learning, flow rule installation
├── topology.py         # Mininet topology — 4 hosts, 1 OVS switch, RemoteController
└── test_scenarios.py   # Automated test suite — 4 scenarios with pass/fail reporting
```

---

## Setup and Execution

### Prerequisites

- Ubuntu 20.04 or 22.04
- Mininet (`sudo apt install mininet`)
- POX controller (`git clone https://github.com/noxrepo/pox`)
- Open vSwitch (installed with Mininet)
- iperf (`sudo apt install iperf`)
- python-is-python3 (`sudo apt install python-is-python3`)

### Step 1 — Install controller into POX

```bash
cp controller.py ~/pox/pox/controller.py
```

### Step 2 — Start the POX controller (Terminal 1)

```bash
cd ~/pox
python pox.py log.level --DEBUG controller
```

Expected output:
```
INFO:controller:AccessController started - whitelist enforcement active
INFO:core:POX 0.7.0 (gar) is up.
DEBUG:openflow.of_01:Listening on 0.0.0.0:6633
```

### Step 3 — Start the Mininet topology (Terminal 2)

```bash
sudo mn -c   # clean any previous state
sudo python topology.py
```

### Step 4 — Run manual tests in Mininet CLI

```bash
mininet> h1 ping -c 4 h2        # should succeed (0% loss)
mininet> h4 ping -c 4 h1        # should fail (100% loss)
mininet> sh ovs-ofctl dump-flows s1
```

### Step 5 — Run automated test suite (Terminal 2, topology must be stopped first)

```bash
sudo mn -c
sudo python test_scenarios.py
```

---

## Flow Rule Design

| Priority | Match | Action | Purpose |
|----------|-------|--------|---------|
| 200 | ip, nw_src=10.0.0.4 | drop | Proactive block h4 outbound |
| 200 | ip, nw_dst=10.0.0.4 | drop | Proactive block h4 inbound |
| 200 | ip, nw_src=blocked, nw_dst=allowed | drop | Reactive drop for unauthorised pairs |
| 100 | ip, nw_src=X, nw_dst=Y | output:port | Allow whitelisted pair (bidirectional) |
| 50  | arp | output:CONTROLLER | Send ARP to controller for MAC learning |
| 1   | (any) | drop | Default deny-all |

Flow rules for allowed pairs are installed with `idle_timeout=120s` and `hard_timeout=600s`. Drop rules for unauthorised pairs use `idle_timeout=60s` and `hard_timeout=300s`.

---

## Test Scenarios

| Scenario | Description | Result |
|----------|-------------|--------|
| 1 | Allowed host communication (h1-h2, h1-h3, h2-h3, all directions) | PASS |
| 2 | Unauthorised host h4 blocked (all directions including h1→h4) | PASS |
| 3 | Regression — allowed pairs still work after block events | PASS |
| 4 | Throughput measurement via iperf for all allowed pairs + h4 blocked | PASS |

---

## Expected Output

### Scenario 1 — Allowed communication

```
[PASS] h1 -> h2     loss=0%  RTT avg=10.173 ms
[PASS] h2 -> h1     loss=0%  RTT avg=0.112 ms
[PASS] h1 -> h3     loss=0%  RTT avg=11.108 ms
[PASS] h2 -> h3     loss=0%  RTT avg=9.194 ms
[PASS] h3 -> h1     loss=0%  RTT avg=0.120 ms
[PASS] h3 -> h2     loss=0%  RTT avg=0.216 ms
```

The higher RTT on the first ping of each pair (e.g. 10.173 ms for h1→h2) reflects the ARP resolution and PacketIn round trip to the controller. Subsequent pings drop to sub-millisecond latency once flow rules are installed in the switch.

### Scenario 2 — Blocked host h4

```
[PASS] h4 -> h1     loss=100%  (expected 100%)
[PASS] h4 -> h2     loss=100%  (expected 100%)
[PASS] h4 -> h3     loss=100%  (expected 100%)
[PASS] h1 -> h4     loss=100%  (expected 100%)
```

### Scenario 3 — Regression after block events

```
[PASS] h1 -> h2     loss=0%  RTT avg=0.215 ms
[PASS] h2 -> h3     loss=0%  RTT avg=0.205 ms
[PASS] h1 -> h3     loss=0%  RTT avg=0.308 ms
```

### Scenario 4 — Throughput (iperf)

```
h1 -> h2    Throughput: 12.5 Gbits/sec
h2 -> h1    Throughput: 12.2 Gbits/sec
h1 -> h3    Throughput: 11.8 Gbits/sec

[INFO] iperf h4 -> h2 (should be blocked)
[PASS] h4 iperf correctly blocked (no connection)
```

### Test suite summary

```
Scenario 1 - Allowed comms:                  PASS
Scenario 2 - Block h4:                       PASS
Scenario 3 - Regression:                     PASS
Scenario 4 - Throughput / h4 blocked:        PASS

Overall: ALL TESTS PASSED
```

---

## POX Controller Logic

The controller implements two event handlers:

**`_handle_ConnectionUp`** — called when a switch connects. Installs four proactive rules: ARP-to-controller (priority 50), default drop-all (priority 1), and two h4 drop rules for src and dst (priority 200).

**`_handle_PacketIn`** — called for every unmatched packet. Learns MAC-to-port mappings from ARP and IP packets, determines src/dst IPs, and either installs a bidirectional allow rule (priority 100) or a drop rule (priority 200) depending on the whitelist.

---
