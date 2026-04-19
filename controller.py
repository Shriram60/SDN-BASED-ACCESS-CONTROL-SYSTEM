from pox.core import core
from pox.lib.packet import arp, ipv4
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger()

ALLOWED_PAIRS = [
    ("10.0.0.1", "10.0.0.2"),
    ("10.0.0.1", "10.0.0.3"),
    ("10.0.0.2", "10.0.0.3"),
]

def is_allowed(src_ip, dst_ip):
    pair = (str(src_ip), str(dst_ip))
    reverse = (str(dst_ip), str(src_ip))
    return pair in ALLOWED_PAIRS or reverse in ALLOWED_PAIRS


class AccessController(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        log.info("AccessController started - whitelist enforcement active")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected" % dpid_to_str(event.dpid))
        self.mac_to_port[event.dpid] = {}

        msg_arp = of.ofp_flow_mod()
        msg_arp.priority = 50
        msg_arp.match.dl_type = 0x0806
        msg_arp.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg_arp)
        log.info("ARP->controller rule installed on %s" % dpid_to_str(event.dpid))

        msg_drop = of.ofp_flow_mod()
        msg_drop.priority = 1
        msg_drop.actions = []
        event.connection.send(msg_drop)
        log.info("Default DROP rule installed on %s" % dpid_to_str(event.dpid))

        msg_h4src = of.ofp_flow_mod()
        msg_h4src.priority = 200
        msg_h4src.match.dl_type = 0x0800
        msg_h4src.match.nw_src = "10.0.0.4"
        msg_h4src.actions = []
        event.connection.send(msg_h4src)

        msg_h4dst = of.ofp_flow_mod()
        msg_h4dst.priority = 200
        msg_h4dst.match.dl_type = 0x0800
        msg_h4dst.match.nw_dst = "10.0.0.4"
        msg_h4dst.actions = []
        event.connection.send(msg_h4dst)
        log.warning("Proactive DROP rules installed for h4 on %s" % dpid_to_str(event.dpid))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        dpid = event.dpid
        in_port = event.port
        src_mac = packet.src
        self.mac_to_port[dpid][src_mac] = in_port

        if packet.type == packet.ARP_TYPE:
            arp_pkt = packet.payload
            if str(arp_pkt.protosrc) != "0.0.0.0":
                self.ip_to_mac[str(arp_pkt.protosrc)] = src_mac
                log.debug("Learned ARP: %s -> %s" % (arp_pkt.protosrc, src_mac))

        if packet.type == packet.IP_TYPE:
            self.ip_to_mac[str(packet.payload.srcip)] = src_mac

        src_ip = None
        dst_ip = None

        if packet.type == packet.IP_TYPE:
            src_ip = str(packet.payload.srcip)
            dst_ip = str(packet.payload.dstip)
        elif packet.type == packet.ARP_TYPE:
            src_ip = str(packet.payload.protosrc)
            dst_ip = str(packet.payload.protodst)

        if src_ip and dst_ip:
            if src_ip == "0.0.0.0" or dst_ip == "0.0.0.0":
                self._flood(event)
                return
            if is_allowed(src_ip, dst_ip):
                log.info("[ALLOW] %s -> %s" % (src_ip, dst_ip))
                self._install_allow_rule(event, packet, src_ip, dst_ip)
            else:
                log.warning("[BLOCK] Unauthorized: %s -> %s" % (src_ip, dst_ip))
                self._install_drop_rule(event, packet, src_ip, dst_ip)
                return
        else:
            self._flood(event)

    def _install_allow_rule(self, event, packet, src_ip, dst_ip):
        dst_mac = packet.dst
        dpid = event.dpid
        out_port = self.mac_to_port[dpid].get(dst_mac)

        if out_port is None:
            self._flood(event)
            return

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 120
        msg.hard_timeout = 600
        msg.match.dl_type = 0x0800
        msg.match.nw_src = src_ip
        msg.match.nw_dst = dst_ip
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

        src_out_port = self.mac_to_port[dpid].get(packet.src)
        if src_out_port:
            msg_rev = of.ofp_flow_mod()
            msg_rev.priority = 100
            msg_rev.idle_timeout = 120
            msg_rev.hard_timeout = 600
            msg_rev.match.dl_type = 0x0800
            msg_rev.match.nw_src = dst_ip
            msg_rev.match.nw_dst = src_ip
            msg_rev.actions.append(of.ofp_action_output(port=src_out_port))
            event.connection.send(msg_rev)

        msg_out = of.ofp_packet_out()
        msg_out.data = event.ofp
        msg_out.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg_out)

        log.info("[FLOW INSTALLED] ALLOW %s <-> %s" % (src_ip, dst_ip))

    def _install_drop_rule(self, event, packet, src_ip, dst_ip):
        msg = of.ofp_flow_mod()
        msg.priority = 200
        msg.idle_timeout = 60
        msg.hard_timeout = 300
        msg.match.dl_type = 0x0800
        msg.match.nw_src = src_ip
        msg.match.nw_dst = dst_ip
        msg.actions = []
        event.connection.send(msg)
        log.warning("[FLOW INSTALLED] DROP %s -> %s" % (src_ip, dst_ip))

    def _flood(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)


def launch():
    core.registerNew(AccessController)
