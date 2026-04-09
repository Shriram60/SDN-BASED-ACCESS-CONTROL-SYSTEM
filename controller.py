# SDN-Based Access Control System
# POX Controller - Implements whitelist-based host filtering
# Author: Shriram Chandrasekar (PES2UG24CS495)

from pox.core import core
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger()

# -------------------------------------------------------------------
# WHITELIST: only these MAC pairs are allowed to communicate.
# We populate this after ARP learning maps IP -> MAC.
# IP-level whitelist (as strings):
# -------------------------------------------------------------------
ALLOWED_PAIRS = [
    ("10.0.0.1", "10.0.0.2"),  # h1 <-> h2
    ("10.0.0.1", "10.0.0.3"),  # h1 <-> h3
    ("10.0.0.2", "10.0.0.3"),  # h2 <-> h3
]

def is_allowed(src_ip, dst_ip):
    """Check if src->dst communication is whitelisted."""
    pair = (str(src_ip), str(dst_ip))
    reverse = (str(dst_ip), str(src_ip))
    return pair in ALLOWED_PAIRS or reverse in ALLOWED_PAIRS


class AccessController(object):
    """
    POX component that enforces access control using OpenFlow flow rules.
    Handles packet_in events, checks whitelist, installs allow/drop rules.
    """

    def __init__(self):
        core.openflow.addListeners(self)
        # MAC -> port mapping per switch
        self.mac_to_port = {}
        # IP -> MAC mapping (learned from ARP/IP packets)
        self.ip_to_mac = {}
        log.info("AccessController started - whitelist enforcement active")

    def _handle_ConnectionUp(self, event):
        """Called when a switch connects to the controller."""
        log.info("Switch %s connected" % dpid_to_str(event.dpid))
        self.mac_to_port[event.dpid] = {}

        # Install a default drop-all rule with lowest priority
        # Specific allow rules will have higher priority
        msg = of.ofp_flow_mod()
        msg.priority = 1  # lowest priority = default drop
        msg.actions = []  # empty actions = drop
        event.connection.send(msg)
        log.info("Default DROP rule installed on switch %s" % dpid_to_str(event.dpid))

    def _handle_PacketIn(self, event):
        """
        Called when switch sends a packet to controller (no matching flow rule).
        We inspect it, check whitelist, and install appropriate flow rules.
        """
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        dpid = event.dpid
        in_port = event.port

        # Learn MAC -> port mapping
        src_mac = packet.src
        self.mac_to_port[dpid][src_mac] = in_port

        # --- Learn IP -> MAC from ARP packets ---
        from pox.lib.packet import arp, ipv4
        if packet.type == packet.ARP_TYPE:
            arp_pkt = packet.payload
            if arp_pkt.protosrc != "0.0.0.0":
                self.ip_to_mac[str(arp_pkt.protosrc)] = src_mac
                log.debug("Learned ARP: %s -> %s" % (arp_pkt.protosrc, src_mac))

        # --- Learn IP -> MAC from IP packets ---
        if packet.type == packet.IP_TYPE:
            ip_pkt = packet.payload
            self.ip_to_mac[str(ip_pkt.srcip)] = src_mac

        # --- Determine source and destination IPs ---
        src_ip = None
        dst_ip = None

        if packet.type == packet.IP_TYPE:
            src_ip = str(packet.payload.srcip)
            dst_ip = str(packet.payload.dstip)
        elif packet.type == packet.ARP_TYPE:
            src_ip = str(packet.payload.protosrc)
            dst_ip = str(packet.payload.protodst)

        # --- Access control decision ---
        if src_ip and dst_ip:
            if src_ip == "0.0.0.0" or dst_ip == "0.0.0.0":
                # Allow ARP probes (needed for network to function)
                self._flood(event)
                return

            if is_allowed(src_ip, dst_ip):
                log.info("[ALLOW] %s -> %s" % (src_ip, dst_ip))
                self._install_allow_rule(event, packet, src_ip, dst_ip)
            else:
                log.warning("[BLOCK] Unauthorized: %s -> %s" % (src_ip, dst_ip))
                self._install_drop_rule(event, packet, src_ip, dst_ip)
                return  # drop this packet, don't forward
        else:
            # Non-IP/ARP packet (e.g. LLDP), flood it
            self._flood(event)

    def _install_allow_rule(self, event, packet, src_ip, dst_ip):
        """Install a flow rule to forward packets between allowed hosts."""
        dst_mac = packet.dst

        # Find output port for destination MAC
        dpid = event.dpid
        out_port = self.mac_to_port[dpid].get(dst_mac)

        if out_port is None:
            # Don't know where dst is yet, flood
            self._flood(event)
            return

        # Install forward rule: src_ip -> dst_ip
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 30
        msg.hard_timeout = 120
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_src = src_ip
        msg.match.nw_dst = dst_ip
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

        # Also forward this current packet
        msg2 = of.ofp_packet_out()
        msg2.data = event.ofp
        msg2.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg2)

        log.info("[FLOW INSTALLED] ALLOW %s -> %s out port %d" % (src_ip, dst_ip, out_port))

    def _install_drop_rule(self, event, packet, src_ip, dst_ip):
        """Install a flow rule to drop packets from unauthorized hosts."""
        msg = of.ofp_flow_mod()
        msg.priority = 200  # higher than allow rules
        msg.idle_timeout = 60
        msg.hard_timeout = 300
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_src = src_ip
        msg.match.nw_dst = dst_ip
        msg.actions = []  # no actions = drop
        event.connection.send(msg)
        log.warning("[FLOW INSTALLED] DROP %s -> %s" % (src_ip, dst_ip))

    def _flood(self, event):
        """Flood packet out all ports except the input port."""
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)


def launch():
    """Entry point for POX."""
    core.registerNew(AccessController)
