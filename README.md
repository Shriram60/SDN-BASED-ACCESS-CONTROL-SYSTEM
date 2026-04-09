# SDN-BASED-ACCESS-CONTROL-SYSTEM
**Controller:** POX (OpenFlow 1.0)  
**Emulator:** Mininet  


## Introduction

Software-Defined Networking (SDN) separates the control plane from the data plane, enabling centralized, programmable control of network behavior. In traditional networks, access control is enforced using hardware firewalls or ACLs configured manually on each device — expensive, inflexible, and hard to manage at scale.

This project implements an SDN-Based Access Control System using Mininet and a POX OpenFlow controller. A centralized controller dynamically installs OpenFlow rules directly into switches to enforce network-wide access policies without any per-device manual configuration.

Core idea: Only predefined host pairs are allowed to communicate. All other traffic is silently dropped at the switch level by default.

---

## Objectives

- Design and implement a whitelist-based access control mechanism in an SDN environment
- Simulate a realistic network using Mininet with multiple hosts and an OpenFlow switch
- Implement a POX controller that intercepts `packet_in` events and enforces access policies using OpenFlow flow rules
- Demonstrate allowed vs blocked communication clearly using ping
- Validate the system using both manual and automated test scenarios including regression testing

---

## What is SDN?

In a traditional network, each switch independently decides how to forward packets using its own control logic baked into hardware. SDN decouples this into two separate planes.

The control plane is handled by the POX controller which decides policy. The data plane is handled by the OVS switch which just forwards packets based on installed rules.

OpenFlow is the protocol used by the controller to install flow rules into the switch's flow table. Each rule is a match-action pair. The match fields include source IP, destination IP, protocol, and MAC address. The action is one of: output to a specific port, flood to all ports, or drop.

POX is a lightweight Python-based OpenFlow controller. It handles `packet_in` events — packets the switch sends to the controller because no matching flow rule exists — and responds by installing the appropriate rule so future packets are handled directly by the switch without involving the controller again.

---

## System Architecture

The three main components are:
1. **POX Controller** — enforces access control policies, installs OpenFlow flow rules dynamically on `packet_in` events
2. **Open vSwitch (OVS)** — executes flow rules received from the controller, forwards or drops packets at line rate
3. **Mininet Hosts** — simulated end devices that generate network traffic via the Linux network stack

The controller listens on port 6633. When a new flow arrives at the switch with no matching rule, the switch sends a `packet_in` message to the controller. The controller checks the whitelist, then sends back a `flow_mod` message to install either an allow rule or a drop rule. All subsequent packets matching that flow are handled by the switch directly.

---

## Network Topology

The topology consists of 1 OpenFlow switch (s1), 4 hosts (h1 through h4), and 1 remote POX controller on localhost port 6633. All links use TCLink for realistic link emulation.

| Host | IP Address | Status |
|------|------------|--------|
| h1 | 10.0.0.1 | Authorized |
| h2 | 10.0.0.2 | Authorized |
| h3 | 10.0.0.3 | Authorized |
| h4 | 10.0.0.4 | BLOCKED |

A single switch topology keeps the focus on access control logic. All hosts connect to one switch and the controller enforces policy centrally, mirroring a real campus LAN or datacenter segment where a rogue or untrusted device must be isolated.

---

## Access Control Policy

The system follows a default-deny approach. Only explicitly whitelisted pairs are permitted. All other IP traffic is dropped. ARP packets are flooded freely to allow hosts to resolve MAC addresses before IP-level filtering is applied.

| Source | Destination | Policy |
|--------|-------------|--------|
| h1 (10.0.0.1) | h2 (10.0.0.2) | ALLOW |
| h1 (10.0.0.1) | h3 (10.0.0.3) | ALLOW |
| h2 (10.0.0.2) | h3 (10.0.0.3) | ALLOW |
| h4 (10.0.0.4) | any host | BLOCK |
| any host | h4 (10.0.0.4) | BLOCK |

---

## Project Structure

```text
sdn-access-control/ 
├── controller.py       # POX controller with packet_in handler and flow rule logic 
├── topology.py         # Mininet topology with 4 hosts, 1 switch, remote controller 
├── test_scenarios.py   # Automated test runner with 3 scenarios including regression 
└── README.md           # This file

## Prerequisites

- Linux OS (Ubuntu 20.04 or 22.04 recommended)
- Python 3.x
- Mininet 2.3 or later
- POX controller
- Open vSwitch
- Root/sudo privileges

---

## Installation

Install Mininet and Open vSwitch:
```bash
sudo apt update
sudo apt install mininet openvswitch-switch -y


Working Mechanism
A host sends a packet to another host

The switch has no matching flow rule, so it sends a packet_in to the controller

The controller extracts source and destination IPs from the packet

The controller checks the ALLOWED_PAIRS whitelist

If allowed: installs a flow_mod with action=output to the destination port, priority 100, idle timeout 30s

If blocked: installs a flow_mod with no actions (drop), priority 200, idle timeout 60s

The current packet is also forwarded or dropped accordingly

All future packets matching the same flow are handled by the switch directly without hitting the controller

ARP packets are always flooded so hosts can discover each other's MAC addresses before any IP traffic begins.
