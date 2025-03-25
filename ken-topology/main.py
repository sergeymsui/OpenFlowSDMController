# -*- coding: utf-8 -*-

import ipaddress
import matplotlib.pyplot as plt
import networkx as nx
import threading

from blessed import Terminal

from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4
from os_ken.lib.dpid import dpid_to_str

from os_ken.topology import event
from os_ken.topology.api import get_switch, get_link

from user_interface import UserInterface


class TopologyAwareController(OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopologyAwareController, self).__init__(*args, **kwargs)

        self.routing_tables = {
            1: {
                "10.0.0.1/32": (1, "00:00:00:00:00:01"),
                "10.0.0.2/32": (2, "00:00:00:00:00:02"),
            },
            2: {
                "10.0.0.3/32": (2, "00:00:00:00:00:03"),
                "10.0.0.4/32": (2, "00:00:00:00:00:04"),
                "10.0.0.1/32": (1, "00:00:00:00:00:01"),
                "10.0.0.2/32": (1, "00:00:00:00:00:02"),
            },
            3: {
                "10.0.0.3/32": (2, "00:00:00:00:00:03"),
                "10.0.0.4/32": (2, "00:00:00:00:00:04"),
                "10.0.0.1/32": (1, "00:00:00:00:00:01"),
                "10.0.0.2/32": (1, "00:00:00:00:00:02"),
            },
            4: {
                "10.0.0.3/32": (2, "00:00:00:00:00:03"),
                "10.0.0.4/32": (2, "00:00:00:00:00:04"),
                "10.0.0.1/32": (1, "00:00:00:00:00:01"),
                "10.0.0.2/32": (1, "00:00:00:00:00:02"),
            },
            5: {
                "10.0.0.3/32": (4, "00:00:00:00:00:03"),
                "10.0.0.4/32": (5, "00:00:00:00:00:04"),
                "10.0.0.1/32": (1, "00:00:00:00:00:01"),
                "10.0.0.2/32": (1, "00:00:00:00:00:02"),
            },
        }

        self.topology_api_app = self
        self.graph = nx.Graph()

        self.ui = UserInterface(self)
        self.ui.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser

        dpid = datapath.id
        if dpid not in self.routing_tables:
            self.logger.warning("No routing table for switch %s", dpid_to_str(dpid))
            return

        for prefix, (out_port, dst_mac) in self.routing_tables[dpid].items():
            network = ipaddress.ip_network(prefix)

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=network.network_address)
            actions = [
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionOutput(out_port),
            ]
            self.__add_flow(datapath, 10, match, actions)

            match = parser.OFPMatch(eth_type=0x0806, arp_tpa=network.network_address)
            actions = [
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionOutput(out_port),
            ]
            self.__add_flow(datapath, 20, match, actions)

        if dpid == 1:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            weights = {
                4: 50,
                5: 50,
            }

            buckets = []
            for port, weight in weights.items():
                actions = [parser.OFPActionOutput(port)]
                buckets.append(parser.OFPBucket(weight=weight, actions=actions))

            group_mod = parser.OFPGroupMod(
                datapath=datapath,
                command=ofproto.OFPGC_ADD,
                type_=ofproto.OFPGT_SELECT,
                group_id=50,
                buckets=buckets,
            )

            datapath.send_msg(group_mod)
            self.logger.info(
                "[DPID %s] Installed probabilistic group table",
                dpid_to_str(datapath.id),
            )

            match_ip = parser.OFPMatch(eth_type=0x0800)
            actions_ip = [parser.OFPActionGroup(group_id=50)]
            self.__add_flow(datapath, 10, match_ip, actions_ip)

            match_ip = parser.OFPMatch(eth_type=0x0806)
            actions_ip = [parser.OFPActionGroup(group_id=50)]
            self.__add_flow(datapath, 10, match_ip, actions_ip)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            dst_ip = ip_pkt.dst
            self.logger.info("[DPID %s] IP packet to %s", datapath.id, dst_ip)

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match["in_port"],
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.logger.info("[TOPOLOGY] Updating topology graph...")

        switch_list = get_switch(self.topology_api_app, None)
        switches = [sw.dp.id for sw in switch_list]
        self.graph.clear()
        self.graph.add_nodes_from(switches)

        link_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid) for link in link_list]
        self.graph.add_edges_from(links)

        self.logger.info("Switches: %s", switches)
        self.logger.info("Links: %s", links)
        self.draw_topology()

    def draw_topology(self):
        plt.clf()
        pos = nx.spring_layout(self.graph)
        nx.draw(
            self.graph,
            pos,
            with_labels=True,
            node_color="lightblue",
            node_size=1500,
            edge_color="gray",
        )
        plt.title("SDN Topology")
        plt.savefig("topology.png")
        self.logger.info("[TOPOLOGY] Graph saved as topology.png")

    def __add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.debug("Added flow: %s", match)
