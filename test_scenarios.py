# Automated Test Scenarios for SDN Access Control
# Run AFTER topology + controller are up
# Author: Shriram Chandrasekar (PES2UG24CS495)

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time


def run_tests():
    setLogLevel('warning')

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow10')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    net.start()
    time.sleep(3)  # wait for controller to install default rules

    print("\n" + "="*60)
    print("  SDN ACCESS CONTROL - TEST SCENARIOS")
    print("="*60)

    # -------------------------------------------------------
    # SCENARIO 1: Allowed hosts can communicate
    # -------------------------------------------------------
    print("\n[SCENARIO 1] Allowed host communication (h1 <-> h2, h1 <-> h3, h2 <-> h3)")
    print("-"*60)

    tests = [
        (h1, h2, "h1 -> h2", True),
        (h2, h1, "h2 -> h1", True),
        (h1, h3, "h1 -> h3", True),
        (h2, h3, "h2 -> h3", True),
    ]

    scenario1_pass = True
    for src, dst, label, expect_success in tests:
        result = net.ping([src, dst], timeout=2)
        dropped = result  # ping returns % dropped
        success = dropped == 0.0
        status = "PASS" if success == expect_success else "FAIL"
        if status == "FAIL":
            scenario1_pass = False
        print("  [%s] %s -> %s dropped: %.0f%%" % (status, label, dst.IP(), dropped))

    # -------------------------------------------------------
    # SCENARIO 2: Unauthorized host h4 is blocked
    # -------------------------------------------------------
    print("\n[SCENARIO 2] Unauthorized host blocked (h4 -> anyone should fail)")
    print("-"*60)

    blocked_tests = [
        (h4, h1, "h4 -> h1", False),
        (h4, h2, "h4 -> h2", False),
        (h4, h3, "h4 -> h3", False),
    ]

    scenario2_pass = True
    for src, dst, label, expect_success in blocked_tests:
        result = net.ping([src, dst], timeout=2)
        dropped = result
        success = dropped == 0.0
        status = "PASS" if success == expect_success else "FAIL"
        if status == "FAIL":
            scenario2_pass = False
        print("  [%s] %s -> %s dropped: %.0f%%" % (status, label, dst.IP(), dropped))

    # -------------------------------------------------------
    # SCENARIO 3: Regression - allowed hosts still work after blocked attempts
    # -------------------------------------------------------
    print("\n[SCENARIO 3] Regression - allowed pairs still work after block events")
    print("-"*60)

    regression_pass = True
    result = net.ping([h1, h2], timeout=2)
    status = "PASS" if result == 0.0 else "FAIL"
    if status == "FAIL":
        regression_pass = False
    print("  [%s] h1 -> h2 after h4 block attempts: %.0f%% dropped" % (status, result))

    # -------------------------------------------------------
    # Summary
    # -------------------------------------------------------
    print("\n" + "="*60)
    print("  RESULTS SUMMARY")
    print("="*60)
    print("  Scenario 1 (Allowed comms):  %s" % ("PASS" if scenario1_pass else "FAIL"))
    print("  Scenario 2 (Block h4):       %s" % ("PASS" if scenario2_pass else "FAIL"))
    print("  Scenario 3 (Regression):     %s" % ("PASS" if regression_pass else "FAIL"))
    overall = scenario1_pass and scenario2_pass and regression_pass
    print("\n  Overall: %s" % ("ALL TESTS PASSED ✓" if overall else "SOME TESTS FAILED ✗"))
    print("="*60 + "\n")

    net.stop()


if __name__ == '__main__':
    run_tests()
