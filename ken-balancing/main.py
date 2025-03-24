# -*- coding: utf-8 -*-

from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, arp
from os_ken.lib.dpid import dpid_to_str
import ipaddress

class Controller(OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

        # Отдельные таблицы маршрутов для каждого коммутатора (по DPID)
        self.routing_tables = {
            1: {
                "10.0.0.1/32": (1, "00:00:00:00:00:01"),
                "10.0.0.2/32": (2, "00:00:00:00:00:02"),
                # "10.0.0.3/32": (3, "00:00:00:00:00:03"),
                # "10.0.0.4/32": (4, "00:00:00:00:00:04"),
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
                "10.0.0.1/32": (2, "00:00:00:00:00:01"),
                "10.0.0.2/32": (2, "00:00:00:00:00:02"),
            },
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        """
        Handshake: Features Request Response Handler

        Installs a low level (0) flow table modification that pushes packets to
        the controller. This acts as a rule for flow-table misses.
        """
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser

        dpid = datapath.id
        if dpid not in self.routing_tables:
            self.logger.warning("No routing table for switch %s", dpid_to_str(dpid))
            return

    
        # Устанавливаем правила для каждого маршрута
        for prefix, (out_port, dst_mac) in self.routing_tables[dpid].items():
            network = ipaddress.ip_network(prefix)
            
            # Правило для IP-пакетов
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_dst=network.network_address
            )
            actions = [
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionOutput(out_port)
            ]
            self.__add_flow(datapath, 10, match, actions)
            
            # Правило для ARP-запросов
            match = parser.OFPMatch(
                eth_type=0x0806,  # ARP
                arp_tpa=network.network_address
            )
            actions = [
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionOutput(out_port)
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
                buckets=buckets
            )

            datapath.send_msg(group_mod)
            self.logger.info("[DPID %s] Installed probabilistic group table", dpid_to_str(datapath.id))

            match_ip = parser.OFPMatch(eth_type=0x0800)  # IPv4
            actions_ip = [parser.OFPActionGroup(group_id=50)]
            self.__add_flow(datapath, 10, match_ip, actions_ip)

            match_ip = parser.OFPMatch(eth_type=0x0806)  # IPv4
            actions_ip = [parser.OFPActionGroup(group_id=50)]
            self.__add_flow(datapath, 10, match_ip, actions_ip)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Packet In Event Handler

        Takes packets provided by the OpenFlow packet in event structure and
        floods them to all ports. This is the core functionality of the Ethernet
        Hub.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        in_port = msg.match["in_port"]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            dpid = datapath.id
            dst_ip = ip_pkt.dst

            print(f"[*] eth = {eth} dpid = {dpid} dst_ip = {dst_ip}")

            routing_table = self.routing_tables[dpid]

            for prefix in routing_table:
                net = ipaddress.ip_network(prefix)
                if ipaddress.ip_address(dst_ip) in net:
                    out_port, dst_mac = routing_table[prefix]

                    actions = [
                        parser.OFPActionSetField(eth_dst=dst_mac),
                        parser.OFPActionOutput(out_port)
                    ]

                    match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
                    self.__add_flow(datapath, 10, match, actions)

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=msg.buffer_id,
                        in_port=in_port,
                        actions=actions,
                        data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
                    )
                    datapath.send_msg(out)
                    self.logger.info("[DPID %s] IP packet to %s routed via port %s", dpid_to_str(dpid), dst_ip, out_port)
            return

        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
        return

    def __add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        
        datapath.send_msg(mod)
        self.logger.debug("Added flow: %s", match)
