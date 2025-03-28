# -*- coding: utf-8 -*-
from collections import defaultdict

from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import lldp, ether_types, arp, ipv4
from os_ken.lib.dpid import dpid_to_str
import ipaddress
import networkx as nx
from os_ken.lib import hub

import pickle
from os_ken.lib.packet import packet, ethernet, lldp


class Controller(OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)


        self.routing_tables = defaultdict(list)

        # self.routing_tables = {
        #     1: {
        #         "10.0.0.1": (1, "00:00:00:00:00:01"),
        #         "10.0.0.2": (2, "00:00:00:00:00:02"),
        #     }
        # }

        self.topo = nx.DiGraph()

        self.datapaths = {}
        self.hosts = {
            "00:00:00:00:00:01": "h1",
            "00:00:00:00:00:02": "h2",
            "00:00:00:00:00:03": "h3",
            "00:00:00:00:00:04": "h4",
        }

        hub.spawn(self._lldp_loop)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        """
        Handshake: Features Request Response Handler

        Installs a low level (0) flow table modification that pushes packets to
        the controller. This acts as a rule for flow-table misses.
        """

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        eth_types = [0x88CC, 0x0800, 0x0806]
        for eth_type in eth_types:
            match = parser.OFPMatch(eth_type=eth_type)
            actions = [
                parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
                )
            ]
            print("Handshake taken place with {}".format(dpid_to_str(datapath.id)))
            self.__add_flow(datapath, 0, match, actions)

        self.request_port_desc(datapath)  # Запрос информации о портах

    def _lldp_loop(self):
        while True:
            for _, datapath in self.datapaths.items():
                self.send_lldp_packet(datapath)
            hub.sleep(5)

    def request_port_desc(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def send_lldp_packet(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        for port in datapath.ports.values():
            # Пропуск служебных/зарезервированных портов
            if port.port_no > ofproto.OFPP_MAX:
                continue

            pkt = packet.Packet()
            eth = ethernet.ethernet(
                dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
                src=port.hw_addr,
                ethertype=ether_types.ETH_TYPE_LLDP,
            )

            # Создание обязательных TLV (Type-Length-Value)
            chassis_id = lldp.ChassisID(
                subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                chassis_id=str(dpid).encode("utf-8"),
            )
            port_id = lldp.PortID(
                subtype=lldp.PortID.SUB_PORT_COMPONENT,
                port_id=str(port.port_no).encode("utf-8"),
            )
            ttl = lldp.TTL(ttl=120)

            # LLDP содержит минимум 3 обязательных TLV и 1 конечный TLV (EndOfLLDPDU)
            lldp_pkt = lldp.lldp(tlvs=[chassis_id, port_id, ttl, lldp.End()])

            pkt.add_protocol(eth)
            pkt.add_protocol(lldp_pkt)
            pkt.serialize()

            actions = [parser.OFPActionOutput(port.port_no)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=pkt.data,
            )
            datapath.send_msg(out)
            print(f"[LLDP] Sent from DPID={dpid} port={port.port_no}")

    def send_features_request(self, datapath):
        parser = datapath.ofproto_parser

        req = parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)
        print("Отправлен OFPT_FEATURES_REQUEST для коммутатора DPID=%s", datapath.id)

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
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        lldp_pkt = pkt.get_protocol(lldp.lldp)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            print(f"[IPv4] From {src_ip} to {dst_ip}")

        self.topo.add_node(f"s{dpid}", type="switch", dpid=int(dpid))
        if datapath.id not in self.datapaths:
            self.request_port_desc(datapath)

        if datapath.ports.values():
            self.datapaths[datapath.id] = datapath

        if lldp_pkt:
            for tlv in lldp_pkt.tlvs:
                if isinstance(tlv, lldp.ChassisID):
                    neighbor_dpid = int(tlv.chassis_id.decode())
                elif isinstance(tlv, lldp.PortID):
                    neighbor_port = int(tlv.port_id.decode())
            # print(
            #     f"Link discovered: {dpid}:{in_port} -> {neighbor_dpid}:{neighbor_port}"
            # )

            self.topo.add_edge(
                f"s{int(dpid)}",
                f"s{int(neighbor_dpid)}",
                src_port=in_port,
                dst_port=neighbor_port,
            )
            self.topo.add_edge(
                f"s{int(neighbor_port)}",
                f"s{int(dpid)}",
                src_port=neighbor_port,
                dst_port=in_port,
            )

        msg = ev.msg
        parser = msg.datapath.ofproto_parser
        dpid = msg.datapath.id

        eth = pkt.get_protocol(ethernet.ethernet)
        if eth:
            src_mac = eth.src

            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
                src_ip = arp_pkt.src_ip
                print(f"[HOST] IP={src_ip} MAC={src_mac} @ {dpid}:{in_port}")

                self.topo.add_node(self.hosts[src_mac], mac=src_mac, type="host", ip=src_ip)
                self.topo.add_edge(
                    f"s{int(dpid)}", self.hosts[src_mac], src_port=in_port, dst_port=0
                )
                self.topo.add_edge(
                    self.hosts[src_mac], f"s{int(dpid)}", src_port=0, dst_port=in_port
                )

                pickle.dump(self.topo, open("filename.pickle", "wb"))

            if eth.ethertype in (0x0800, 0x0806):  # IPv4 или ARP
                print(
                    f"[HOST] Discovered host {src_mac} on switch {dpid} port {in_port}"
                )

            #
            for switch_name, switch_params in [ (name, params) for name, params in self.topo.nodes(data=True) if "type" in params and params["type"] == "switch" and params["dpid"] == dpid]:
                for host_name, host_params in [ (name, params) for name, params in self.topo.nodes(data=True) if "type" in params and params["type"] == "host" ]:

                    print(host_name)

                    shortest_path = list()
                    try:
                        shortest_path = [node for node in nx.shortest_path(self.topo, source=host_name, target=switch_name)]
                    except nx.exception.NetworkXNoPath:
                        print("nx.exception.NetworkXNoPath")
                    finally:
                        pass

                    print(f"[MSG] switch_name: {switch_name} host_name: {host_name} shortest_path: {shortest_path}")

                    if len(shortest_path) < 2:
                        continue

                    continue

                    src_node, dst_node = shortest_path[-2], shortest_path[-1]
                    for ports in [ ports for (source, target, ports) in self.topo.edges(data=True) if source == src_node and target == dst_node]:
                        match = parser.OFPMatch(
                            eth_type=0x0800, ipv4_dst=host_params["ip"]
                        )
                        actions = [
                            parser.OFPActionSetField(eth_dst=host_params["mac"]),
                            parser.OFPActionOutput(ports["dst_port"]),
                        ]
                        self.__add_flow(datapath, 10, match, actions)

                        ip = host_params["ip"]
                        mac = host_params["mac"]
                        port = ports["dst_port"]
                        print(f"[MSG] dpid: {dpid} ip: {ip} mac: {mac} port: {port}")

                        # Правило для ARP-запросов
                        match = parser.OFPMatch(
                            eth_type=0x0806, arp_tpa=host_params["ip"]
                        )
                        actions = [
                            parser.OFPActionSetField(eth_dst=host_params["mac"]),
                            parser.OFPActionOutput(ports["dst_port"]),
                        ]
                        self.__add_flow(datapath, 20, match, actions)



            #

            # host = self.hosts[src_mac]
            # self.writed_hosts.add(host)  # self.writed_hosts - занесенные хосты

            # visited = set(self.writed_hosts)

            # for switch in [n for n, v in self.topo.nodes(data=True) if "type" in v and v["type"] == "switch"]:
            #     shortest_path = list()
            #     try:
            #         shortest_path = [host] + [node for node in nx.shortest_path(self.topo, source=host, target=switch)]
            #     except nx.exception.NetworkXNoPath:
            #         pass
            #
            #     for src_node, dst_node in zip(shortest_path, shortest_path[1:]):
            #         # Отбрасываем, если запись была занесена
            #         if dst_node in visited:
            #             continue
            #
            #         #
            #         dpid = self.topo.nodes[dst_node]["dpid"]
            #         if dst_node in self.topo.nodes and dpid in self.datapaths:
            #             datapath = self.datapaths[dpid]
            #
            #             edge = [
            #                 (source, target, ports)
            #                 for (source, target, ports) in self.topo.edges(data=True)
            #                 if source == src_node and target == dst_node
            #             ]
            #             if edge:
            #                 (source, target, ports) = edge[0]
            #                 dst_port = ports["dst_port"]
            #
            #                 # if dpid in self.routing_tables and src_ip in self.routing_tables[dpid]:
            #                 #     continue
            #
            #                 print(
            #                     f"[WRITE] src_ip: {src_ip}, src_mac: {src_mac} dst_node: {dst_node} dst_port: {dst_port} dpid: {datapath.id}")
            #
            #                 match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=src_ip)
            #                 actions = [
            #                     parser.OFPActionSetField(eth_dst=src_mac),
            #                     parser.OFPActionOutput(dst_port),
            #                 ]
            #                 self.__add_flow(datapath, 10, match, actions)
            #
            #                 # Правило для IP-пакетов
            #                 match = parser.OFPMatch(eth_type=0x0806, ipv4_dst=src_ip)
            #                 actions = [
            #                     parser.OFPActionSetField(eth_dst=src_mac),
            #                     parser.OFPActionOutput(dst_port),
            #                 ]
            #                 self.__add_flow(datapath, 20, match, actions)
            #
            #                 self.routing_tables[dpid].append(src_ip)
            #
            #                 visited.add(dst_node)
            #
            #         pass
            #     pass


        # if dpid == 1:
        #     ip_addr = ipaddress.ip_address("10.0.0.1")
        #     print(f"[MESSAGE] dpid: {dpid} ip_addr: {ip_addr}")
        #
        #     # Правило для IP-пакетов
        #     match = parser.OFPMatch(
        #         eth_type=0x0800, ipv4_dst=ip_addr
        #     )
        #     actions = [
        #         parser.OFPActionSetField(eth_dst="00:00:00:00:00:01"),
        #         parser.OFPActionOutput(1),
        #     ]
        #     self.__add_flow(datapath, 10, match, actions)
        #
        #     # Правило для ARP-запросов
        #     match = parser.OFPMatch(
        #         eth_type=0x0806, arp_tpa=ip_addr
        #     )
        #     actions = [
        #         parser.OFPActionSetField(eth_dst="00:00:00:00:00:01"),
        #         parser.OFPActionOutput(1),
        #     ]
        #     self.__add_flow(datapath, 20, match, actions)
        #
        #     ip_addr = ipaddress.ip_address("10.0.0.2")
        #
        #     # Правило для IP-пакетов
        #     match = parser.OFPMatch(
        #         eth_type=0x0800, ipv4_dst=ip_addr
        #     )
        #     actions = [
        #         parser.OFPActionSetField(eth_dst="00:00:00:00:00:02"),
        #         parser.OFPActionOutput(2),
        #     ]
        #     self.__add_flow(datapath, 10, match, actions)
        #
        #     # Правило для ARP-запросов
        #     match = parser.OFPMatch(
        #         eth_type=0x0806, arp_tpa=ip_addr
        #     )
        #     actions = [
        #         parser.OFPActionSetField(eth_dst="00:00:00:00:00:02"),
        #         parser.OFPActionOutput(2),
        #     ]
        #     self.__add_flow(datapath, 20, match, actions)
        #
        #     return


        # for dpid, tables in self.routing_tables.items():
        #     for ip, vals in tables.items():
        #         print(f"dpid: {dpid} ip: {ip} vals: {vals}")

        # for u, v, data in self.topo.edges(data=True):
        #     print(f"{u} port {data['src_port']} -> {v} port {data['dst_port']}")

        # if dpid in self.routing_tables:
        #     for prefix, (out_port, dst_mac) in self.routing_tables[dpid].items():
        #         network = ipaddress.ip_network(prefix)
        #
        #         # Правило для IP-пакетов
        #         match = parser.OFPMatch(
        #             eth_type=0x0800, ipv4_dst=network.network_address  # IPv4
        #         )
        #         actions = [
        #             parser.OFPActionSetField(eth_dst=dst_mac),
        #             parser.OFPActionOutput(out_port),
        #         ]
        #         self.__add_flow(datapath, 10, match, actions)
        #
        #         print(f"[VAL] network.network_address: {network.network_address}, dst_mac: {dst_mac} out_port: {out_port}")
        #
        #         # Правило для ARP-запросов
        #         match = parser.OFPMatch(
        #             eth_type=0x0806, arp_tpa=network.network_address  # ARP
        #         )
        #         actions = [
        #             parser.OFPActionSetField(eth_dst=dst_mac),
        #             parser.OFPActionOutput(out_port),
        #         ]
        #         self.__add_flow(datapath, 20, match, actions)
        #
        # return

    def __add_flow(
        self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )

        answer = datapath.send_msg(mod)
        if answer:
            self.logger.debug("Added flow: %s", match)

        return answer
