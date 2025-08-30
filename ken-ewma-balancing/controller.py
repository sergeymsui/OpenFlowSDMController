# -*- coding: utf-8 -*-

import ipaddress
from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4
from os_ken.lib.dpid import dpid_to_str
from os_ken.lib import hub


class Controller(OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

        self.routing_tables = {
            1: {"10.0.0.2/32": (2, "00:00:00:00:00:02")},
            # ...
            # ...
        }

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_ewma = {3: 0.0, 4: 0.0}
        self.last_bytes = {}
        self.alpha = 0.3
        self.port_threshold = 1000000  # 1 MB/s

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.poll_port_stats(dp)
            hub.sleep(1)

    def poll_port_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath=datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            port_no = stat.port_no
            if port_no in self.port_ewma:
                bw = stat.tx_bytes
                delta = bw - self.last_bytes.get(port_no, 0)
                self.last_bytes[port_no] = bw
                self.port_ewma[port_no] = (
                    self.alpha * delta + (1 - self.alpha) * self.port_ewma[port_no]
                )
                self.logger.info(
                    "[EWMA] Port %s: %.2f bytes/sec", port_no, self.port_ewma[port_no]
                )
                if self.port_ewma[port_no] > self.port_threshold:
                    self.logger.warning("[ALERT] Port %s перегружен!", port_no)

    def __add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        dpid = datapath.id

        if dpid not in self.routing_tables:
            return

        for prefix, (out_port, dst_mac) in self.routing_tables[dpid].items():
            network = ipaddress.ip_network(prefix)
            match = parser.OFPMatch(
                eth_type=0x0800, ipv4_dst=str(network.network_address)
            )
            actions = [
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionOutput(out_port),
            ]
            self.__add_flow(datapath, 10, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            dst_ip = ip_pkt.dst
            self.logger.info("[DPID %s] Packet to %s", dpid_to_str(dpid), dst_ip)

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match["in_port"],
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)
