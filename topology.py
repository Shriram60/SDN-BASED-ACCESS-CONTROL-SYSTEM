# Mininet Topology for SDN Access Control System
# 4 hosts connected to 1 switch, controller runs separately
# Author: Shriram Chandrasekar (PES2UG24CS495)

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def create_topology():
    """
    Topology: 4 hosts (h1-h4) connected to 1 switch (s1).
    Controller runs externally (POX) on 127.0.0.1:6633.

    Whitelist:
        h1 (10.0.0.1) <-> h2 (10.0.0.2)  ALLOWED
        h1 (10.0.0.1) <-> h3 (10.0.0.3)  ALLOWED
        h2 (10.0.0.2) <-> h3 (10.0.0.3)  ALLOWED
        h4 (10.0.0.4) <-> anyone          BLOCKED
    """
    setLogLevel('info')

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Adding controller (POX on localhost:6633)\n")
    c0 = net.addController('c0',
                           controller=RemoteController,
                           ip='127.0.0.1',
                           port=6633)

    info("*** Adding switch\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow10')

    info("*** Adding hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')  # unauthorized host

    info("*** Adding links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    info("*** Starting network\n")
    net.start()

    info("\n*** Topology ready ***\n")
    info("Hosts: h1(10.0.0.1), h2(10.0.0.2), h3(10.0.0.3), h4(10.0.0.4-BLOCKED)\n")
    info("Try: h1 ping h2  (should work)\n")
    info("Try: h4 ping h1  (should be blocked)\n\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    create_topology()
