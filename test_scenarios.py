# Automated Test Scenarios for SDN Access Control
# Scenarios 1, 2, 3, 4 only
# Author: Shriram Chandrasekar (PES2UG24CS495)
#
# Scenarios
# ---------
#   1. Allowed host communication  (h1<->h2, h1<->h3, h2<->h3)
#   2. Unauthorized host blocked   (h4 -> anyone must fail)
#   3. Regression                  (allowed pairs still work after block events)
#   4. Throughput measurement      (iperf bidirectional h1<->h2, h1<->h3)

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import re


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _ping_stats(src, dst, count=20):
    out = src.cmd("ping -c %d -W 2 %s" % (count, dst.IP()))
    loss_match = re.search(r'(\d+)% packet loss', out)
    dropped_pct = float(loss_match.group(1)) if loss_match else 100.0

    rtt_match = re.search(
        r'rtt min/avg/max/mdev = '
        r'([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', out
    )
    if rtt_match:
        rtt_min, rtt_avg, rtt_max, rtt_mdev = (
            float(rtt_match.group(i)) for i in range(1, 5)
        )
    else:
        rtt_min = rtt_avg = rtt_max = rtt_mdev = None

    return dict(
        dropped_pct=dropped_pct,
        rtt_min=rtt_min, rtt_avg=rtt_avg,
        rtt_max=rtt_max, rtt_mdev=rtt_mdev,
    )


def _dump_flows(switch, label=""):
    print("\n  [FLOW TABLE] %s" % label)
    print("  " + "-" * 56)
    raw = switch.cmd("ovs-ofctl dump-flows %s" % switch.name)
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("NXST") or line.startswith("OFPST"):
            continue
        print("  " + line)
    print()


def _parse_iperf_bandwidth(iperf_output):
    matches = re.findall(
        r'(\d+\.?\d*)\s*(Mbits/sec|Gbits/sec|Kbits/sec)', iperf_output
    )
    if matches:
        val, unit = matches[-1]
        return "%s %s" % (val, unit)
    return "N/A"


def _run_iperf_pair(server_host, client_host, duration=5):
    server_host.cmd("iperf -s -t %d &" % (duration + 2))
    time.sleep(0.5)
    out = client_host.cmd(
        "iperf -c %s -t %d" % (server_host.IP(), duration)
    )
    server_host.cmd("kill %iperf 2>/dev/null")
    return out, _parse_iperf_bandwidth(out)


def _section(title):
    print("\n" + "=" * 60)
    print("  " + title)
    print("=" * 60)


# -----------------------------------------------------------------------
# Main test runner
# -----------------------------------------------------------------------

def run_tests():
    setLogLevel('warning')

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    net.addController('c0', controller=RemoteController,
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
    time.sleep(3)

    _section("SDN ACCESS CONTROL - TEST SCENARIOS 1, 2, 3, 4")

    results = {}

    # -------------------------------------------------------------------
    # SCENARIO 1: Allowed host communication
    # -------------------------------------------------------------------
    _section("SCENARIO 1 - Allowed host communication")
    print("  Expected: h1<->h2, h1<->h3, h2<->h3 all reachable (0% loss)")
    print("-" * 60)

    allowed_tests = [
        (h1, h2, "h1 -> h2"),
        (h2, h1, "h2 -> h1"),
        (h1, h3, "h1 -> h3"),
        (h2, h3, "h2 -> h3"),
        (h3, h1, "h3 -> h1"),
        (h3, h2, "h3 -> h2"),
    ]

    scenario1_pass = True
    for src, dst, label in allowed_tests:
        stats  = _ping_stats(src, dst, count=5)
        lost   = stats['dropped_pct']
        ok     = (lost == 0.0)
        status = "PASS" if ok else "FAIL"
        if not ok:
            scenario1_pass = False
        rtt_str = ("RTT avg=%.3f ms" % stats['rtt_avg']
                   if stats['rtt_avg'] is not None else "RTT N/A")
        print("  [%s] %-12s  loss=%.0f%%  %s"
              % (status, label, lost, rtt_str))

    _dump_flows(s1, "After Scenario 1")
    results['scenario1'] = scenario1_pass

    # -------------------------------------------------------------------
    # SCENARIO 2: Unauthorized host h4 is blocked
    # -------------------------------------------------------------------
    _section("SCENARIO 2 - Unauthorized host h4 blocked")
    print("  Expected: all h4 traffic dropped (100% loss)")
    print("-" * 60)

    blocked_tests = [
        (h4, h1, "h4 -> h1"),
        (h4, h2, "h4 -> h2"),
        (h4, h3, "h4 -> h3"),
        (h1, h4, "h1 -> h4"),
    ]

    scenario2_pass = True
    for src, dst, label in blocked_tests:
        stats  = _ping_stats(src, dst, count=5)
        lost   = stats['dropped_pct']
        ok     = (lost == 100.0)
        status = "PASS" if ok else "FAIL"
        if not ok:
            scenario2_pass = False
        print("  [%s] %-12s  loss=%.0f%%  (expected 100%%)"
              % (status, label, lost))

    _dump_flows(s1, "After Scenario 2 - expect DROP entries for h4")
    results['scenario2'] = scenario2_pass

    # -------------------------------------------------------------------
    # SCENARIO 3: Regression - allowed pairs still work after block events
    # -------------------------------------------------------------------
    _section("SCENARIO 3 - Regression after block events")
    print("  Expected: allowed pairs still work even after h4 block attempts")
    print("-" * 60)

    regression_tests = [
        (h1, h2, "h1 -> h2"),
        (h2, h3, "h2 -> h3"),
        (h1, h3, "h1 -> h3"),
    ]

    regression_pass = True
    for src, dst, label in regression_tests:
        stats  = _ping_stats(src, dst, count=10)
        lost   = stats['dropped_pct']
        ok     = (lost == 0.0)
        status = "PASS" if ok else "FAIL"
        if not ok:
            regression_pass = False
        rtt_str = ("RTT avg=%.3f ms" % stats['rtt_avg']
                   if stats['rtt_avg'] is not None else "RTT N/A")
        print("  [%s] %-12s  loss=%.0f%%  %s"
              % (status, label, lost, rtt_str))

    results['scenario3'] = regression_pass

    # -------------------------------------------------------------------
    # SCENARIO 4: Throughput measurement with iperf (bidirectional)
    # -------------------------------------------------------------------
    _section("SCENARIO 4 - Throughput measurement (iperf)")
    print("  Bidirectional iperf for all allowed pairs")
    print("-" * 60)

    iperf_pairs = [
        (h1, h2, "h1 -> h2"),
        (h2, h1, "h2 -> h1"),
        (h1, h3, "h1 -> h3"),
    ]
    for server, client, label in iperf_pairs:
        _, bw = _run_iperf_pair(server, client, duration=5)
        print("  %-12s  Throughput: %s" % (label, bw))
        time.sleep(1)

    print("\n  [INFO] iperf h4 -> h2 (should be blocked)")
    h2.cmd("iperf -s -t 6 &")
    time.sleep(0.5)
    h4_out = h4.cmd("iperf -c %s -t 3" % h2.IP())
    h2.cmd("kill %iperf 2>/dev/null")
    if "connect failed" in h4_out or h4_out.strip() == "":
        print("  [PASS] h4 iperf correctly blocked (no connection)")
    else:
        print("  [INFO] h4 iperf output: %s" % h4_out.strip())

    # Scenario 4 has no strict pass/fail boolean — it's a measurement
    # but we mark it pass if h4 was correctly blocked
    results['scenario4'] = ("connect failed" in h4_out or h4_out.strip() == "")

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------
    _section("RESULTS SUMMARY")
    labels = {
        'scenario1': "Scenario 1 - Allowed comms",
        'scenario2': "Scenario 2 - Block h4",
        'scenario3': "Scenario 3 - Regression",
        'scenario4': "Scenario 4 - Throughput / h4 blocked",
    }
    overall = True
    for key, label in labels.items():
        passed = results.get(key, False)
        if not passed:
            overall = False
        print("  %-42s %s" % (label + ":", "PASS" if passed else "FAIL"))

    print("\n  Overall: %s"
          % ("ALL TESTS PASSED" if overall else "SOME TESTS FAILED"))
    print("=" * 60 + "\n")

    net.stop()


if __name__ == '__main__':
    run_tests()
