# Mininet Topology for SDN Access Control System
# 4 hosts connected to 1 switch, controller runs separately (POX)
# Author: Shriram Chandrasekar (PES2UG24CS495)
#
# ===================================================================
# TOPOLOGY DESIGN JUSTIFICATION
# ===================================================================
# Single-switch star topology is chosen because:
#   1. All host traffic must traverse s1, so every packet is visible
#      to the SDN controller - no traffic bypasses access control.
#   2. A single switch is the minimal SDN proof-of-concept: it lets
#      us focus on controller logic (packet_in, flow-mod) rather
#      than inter-switch routing complexity.
#   3. Extending to multi-switch is straightforward - the whitelist
#      logic in controller.py is topology-agnostic.
#
# POX is chosen over Ryu because:
#   - Pure Python, no external dependencies beyond POX itself.
#   - Simpler component API (addListeners, registerNew) for fast
#     iteration during development.
#   - OpenFlow 1.0 support matches OVS default configuration.
#
# Network layout:
#
#   h1 (10.0.0.1) ──┐
#   h2 (10.0.0.2) ──┤
#                    s1 ────── POX controller (127.0.0.1:6633)
#   h3 (10.0.0.3) ──┤
#   h4 (10.0.0.4) ──┘  [BLOCKED]
#
# Whitelist (bidirectional):
#   h1 <-> h2   ALLOWED
#   h1 <-> h3   ALLOWED
#   h2 <-> h3   ALLOWED
#   h4 <-> *    BLOCKED  (proactive OpenFlow drop rule, priority 200)
# ===================================================================

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def dump_flow_table(net, switch_name='s1'):
    """
    Print the current OpenFlow flow table for the named switch.
    Call from the Mininet CLI via: py dump_flow_table(net)
    or uncomment the call at the bottom of create_topology().
    """
    sw = net.get(switch_name)
    info("\n*** Flow table for %s ***\n" % switch_name)
    info(sw.cmd("ovs-ofctl dump-flows %s" % switch_name))
    info("\n")


def create_topology():
    """
    Build and start the Mininet topology, then open the interactive CLI.

    Topology: 4 hosts (h1-h4) connected to 1 OVS switch (s1).
    Controller: POX AccessController running on 127.0.0.1:6633.
    Link type: TCLink (allows bandwidth/delay parameters if needed).
    autoSetMacs: assigns deterministic MAC addresses (00:00:00:00:00:0N).

    Useful CLI commands after startup:
        h1 ping h2          -> should succeed (whitelisted)
        h4 ping h1          -> should fail    (blocked)
        h1 iperf -s &; h2 iperf -c 10.0.0.1   -> throughput test
        py dump_flow_table(net)                 -> inspect flow rules
        sh ovs-ofctl dump-flows s1              -> raw flow table
        sh ovs-ofctl dump-ports s1              -> port statistics
    """
    setLogLevel('info')

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Adding controller (POX on localhost:6633)\n")
    net.addController('c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      port=6633)

    info("*** Adding switch\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow10')

    info("*** Adding hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')  # unauthorized - will be blocked

    info("*** Adding links (star topology via s1)\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    info("*** Starting network\n")
    net.start()

    info("\n")
    info("*** Topology ready ***\n")
    info("=" * 55 + "\n")
    info("  Hosts:\n")
    info("    h1  10.0.0.1   ALLOWED (whitelisted with h2, h3)\n")
    info("    h2  10.0.0.2   ALLOWED (whitelisted with h1, h3)\n")
    info("    h3  10.0.0.3   ALLOWED (whitelisted with h1, h2)\n")
    info("    h4  10.0.0.4   BLOCKED (proactive DROP rule)\n")
    info("=" * 55 + "\n")
    info("  Quick tests:\n")
    info("    h1 ping h2          -> should succeed\n")
    info("    h4 ping h1          -> should fail\n")
    info("    sh ovs-ofctl dump-flows s1  -> inspect rules\n")
    info("=" * 55 + "\n\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    create_topology()


