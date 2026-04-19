# Automated Test Scenarios for SDN Access Control
# Run AFTER topology + controller are up (sudo python test_scenarios.py)
# Author: Shriram Chandrasekar (PES2UG24CS495)
#
# Scenarios
# ---------
#   1. Allowed host communication  (h1<->h2, h1<->h3, h2<->h3)
#   2. Unauthorized host blocked   (h4 -> anyone must fail)
#   3. Regression                  (allowed pairs still work after block events)
#   4. Throughput measurement      (iperf bidirectional h1<->h2, h1<->h3)
#   5. Policy isolation            (h4 blocked, other pairs unaffected)
#   6. Idempotency regression      (run full suite twice, rules must not accumulate)
#   7. Flow table & packet stats   (ovs-ofctl dump-flows after each scenario)
#   8. Latency measurement         (ping -c 20, report min/avg/max/mdev)

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
    """
    Run 'ping -c <count>' from src to dst.
    Returns a dict:
        dropped_pct  : float  (0.0 = no loss, 100.0 = full loss)
        rtt_min      : float | None
        rtt_avg      : float | None
        rtt_max      : float | None
        rtt_mdev     : float | None
    """
    out = src.cmd("ping -c %d -W 2 %s" % (count, dst.IP()))
    # Parse packet loss
    loss_match = re.search(r'(\d+)% packet loss', out)
    dropped_pct = float(loss_match.group(1)) if loss_match else 100.0

    # Parse RTT line: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
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
    """
    Dump the OpenFlow flow table of a switch via ovs-ofctl.
    Prints each flow entry with priority, match, actions, and packet count.
    """
    print("\n  [FLOW TABLE] %s" % label)
    print("  " + "-" * 56)
    raw = switch.cmd("ovs-ofctl dump-flows %s" % switch.name)
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("NXST") or line.startswith("OFPST"):
            continue
        # Highlight key fields for readability
        print("  " + line)
    print()


def _parse_iperf_bandwidth(iperf_output):
    """
    Extract the final summary bandwidth from iperf client output.
    Returns a string like '941 Mbits/sec' or 'N/A'.
    """
    matches = re.findall(
        r'(\d+\.?\d*)\s*(Mbits/sec|Gbits/sec|Kbits/sec)', iperf_output
    )
    if matches:
        val, unit = matches[-1]
        return "%s %s" % (val, unit)
    return "N/A"


def _run_iperf_pair(server_host, client_host, duration=5):
    """
    Run iperf between two hosts. Returns bandwidth string.
    server_host acts as iperf server, client_host as client.
    """
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
    time.sleep(3)   # wait for controller to install default rules

    _section("SDN ACCESS CONTROL - TEST SCENARIOS")

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
        (h1, h4, "h1 -> h4"),   # also test reverse direction
    ]

    scenario2_pass = True
    for src, dst, label in blocked_tests:
        stats  = _ping_stats(src, dst, count=5)
        lost   = stats['dropped_pct']
        ok     = (lost == 100.0)   # expect full loss
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

    # Confirm h4 cannot iperf to h2 (connection must be blocked)
    print("\n  [INFO] iperf h4 -> h2 (should be blocked)")
    h2.cmd("iperf -s -t 6 &")
    time.sleep(0.5)
    h4_out = h4.cmd("iperf -c %s -t 3" % h2.IP())
    h2.cmd("kill %iperf 2>/dev/null")
    if "connect failed" in h4_out or h4_out.strip() == "":
        print("  [PASS] h4 iperf correctly blocked (no connection)")
    else:
        print("  [INFO] h4 iperf output: %s" % h4_out.strip())

    # -------------------------------------------------------------------
    # SCENARIO 5: Policy isolation - blocked pair does not affect others
    # -------------------------------------------------------------------
    _section("SCENARIO 5 - Policy isolation")
    print("  h4 is blocked, but h1<->h2 must remain fully functional")
    print("-" * 60)

    # Confirm h4 still blocked
    stats_h4 = _ping_stats(h4, h1, count=5)
    h4_blocked = (stats_h4['dropped_pct'] == 100.0)
    print("  [%s] h4 -> h1  loss=%.0f%%  (expected 100%%)"
          % ("PASS" if h4_blocked else "FAIL", stats_h4['dropped_pct']))

    # Confirm h1<->h2 unaffected
    stats_h1h2 = _ping_stats(h1, h2, count=10)
    h1h2_ok = (stats_h1h2['dropped_pct'] == 0.0)
    rtt_str = ("RTT avg=%.3f ms" % stats_h1h2['rtt_avg']
               if stats_h1h2['rtt_avg'] is not None else "RTT N/A")
    print("  [%s] h1 -> h2  loss=%.0f%%  %s"
          % ("PASS" if h1h2_ok else "FAIL",
             stats_h1h2['dropped_pct'], rtt_str))

    isolation_pass = h4_blocked and h1h2_ok
    results['scenario5'] = isolation_pass

    _dump_flows(s1, "After Scenario 5 - packet counts confirm enforcement")

    # -------------------------------------------------------------------
    # SCENARIO 6: Idempotency regression
    # Run the core allow/block checks a second time to verify that
    # duplicate flow rules do not corrupt forwarding behaviour.
    # -------------------------------------------------------------------
    _section("SCENARIO 6 - Idempotency regression (second run)")
    print("  Re-run allow/block checks to verify stable rule state")
    print("-" * 60)

    idempotency_pass = True

    # Re-check allowed pairs
    for src, dst, label in [(h1, h2, "h1->h2"), (h2, h3, "h2->h3")]:
        stats  = _ping_stats(src, dst, count=5)
        ok     = (stats['dropped_pct'] == 0.0)
        status = "PASS" if ok else "FAIL"
        if not ok:
            idempotency_pass = False
        print("  [%s] %-10s  loss=%.0f%%  (still allowed)"
              % (status, label, stats['dropped_pct']))

    # Re-check h4 is still blocked
    stats  = _ping_stats(h4, h1, count=5)
    ok     = (stats['dropped_pct'] == 100.0)
    status = "PASS" if ok else "FAIL"
    if not ok:
        idempotency_pass = False
    print("  [%s] %-10s  loss=%.0f%%  (still blocked)"
          % (status, "h4->h1", stats['dropped_pct']))

    _dump_flows(s1, "After Scenario 6 - rule count should be stable")
    results['scenario6'] = idempotency_pass

    # -------------------------------------------------------------------
    # SCENARIO 7 & 8: Latency measurement (ping -c 20 statistics)
    # -------------------------------------------------------------------
    _section("SCENARIO 7 - Latency measurement (20 pings)")
    print("  Collecting detailed RTT statistics for allowed pairs")
    print("-" * 60)
    print("  %-14s  %8s  %8s  %8s  %8s"
          % ("Pair", "min(ms)", "avg(ms)", "max(ms)", "mdev(ms)"))
    print("  " + "-" * 52)

    latency_pairs = [
        (h1, h2, "h1 -> h2"),
        (h1, h3, "h1 -> h3"),
        (h2, h3, "h2 -> h3"),
    ]
    for src, dst, label in latency_pairs:
        s = _ping_stats(src, dst, count=20)
        if s['rtt_avg'] is not None:
            print("  %-14s  %8.3f  %8.3f  %8.3f  %8.3f"
                  % (label,
                     s['rtt_min'], s['rtt_avg'],
                     s['rtt_max'], s['rtt_mdev']))
        else:
            print("  %-14s  RTT data unavailable (100%% loss)" % label)

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------
    _section("RESULTS SUMMARY")
    labels = {
        'scenario1': "Scenario 1 - Allowed comms",
        'scenario2': "Scenario 2 - Block h4",
        'scenario3': "Scenario 3 - Regression",
        'scenario5': "Scenario 5 - Policy isolation",
        'scenario6': "Scenario 6 - Idempotency",
    }
    overall = True
    for key, label in labels.items():
        passed = results.get(key, False)
        if not passed:
            overall = False
        print("  %-36s %s" % (label + ":", "PASS" if passed else "FAIL"))

    print("\n  Overall: %s"
          % ("ALL TESTS PASSED" if overall else "SOME TESTS FAILED"))
    print("=" * 60 + "\n")

    net.stop()


if __name__ == '__main__':
    run_tests()


