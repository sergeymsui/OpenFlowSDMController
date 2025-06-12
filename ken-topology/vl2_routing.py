# -*- coding: utf-8 -*-

from pulp import LpProblem, LpMinimize, LpVariable, lpSum, LpStatus
import pickle

from threading import Thread

import networkx as nx
from time import sleep
from collections import defaultdict

from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import lldp, ether_types, arp, ipv4
from os_ken.lib.dpid import dpid_to_str
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, lldp

# Flow state
flowstate = True
topo_name = "vl2_topograph.pickle"


# from utils import (
#     generate_msa_flows,
#     generate_fwa_flows,
#     generate_ustm_flows,
# )

from ilp_flows import generate_ilp_flows
from greedy_flows import generate_greedy_flows


class Controller(OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

        self.topo = pickle.load(open(topo_name, "rb")) if flowstate else nx.DiGraph()
        self.datapaths = dict()
        self.routing_tables = defaultdict(set)

        self.hosts = {
            "00:00:00:00:01:01": "h1_1",
            "00:00:00:00:01:02": "h1_2",
            "00:00:00:00:01:03": "h1_3",
            "00:00:00:00:02:01": "h2_1",
            "00:00:00:00:02:02": "h2_2",
            "00:00:00:00:02:03": "h2_3",
            "00:00:00:00:03:01": "h3_1",
            "00:00:00:00:03:02": "h3_2",
            "00:00:00:00:03:03": "h3_3",
            "00:00:00:00:04:01": "h4_1",
            "00:00:00:00:04:02": "h4_2",
            "00:00:00:00:04:03": "h4_3",
        }

        def process(target):
            print("Wait calculation process")
            sleep(5)
            print("Calculate...")
            target.update_routes()

        self._delayed_update_thread = Thread(target=process, args=(self,))

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
        self.datapaths[datapath.id] = datapath

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

        # Запрос информации о портах
        self.request_port_desc(datapath)

        # Обновление маршрутов в таблице маршрутизации
        #
        # Данный алгоритм использует выбор кратчайшего маршрута
        # через применение алгоритма Дейкстры для каждого хоста
        self.reroute(datapath)

        # В случае если применяется отложенный выбор маршрута
        # то обновление пути осуществляется через таблицу match_flows
        if flowstate:
            self.schedule_update_routes()

    def schedule_update_routes(self):
        # Если уже идёт ожидание — сбрасываем его и запускаем заново
        if self._delayed_update_thread.is_alive():
            pass
        else:
            self._delayed_update_thread.start()

    def update_routes(self):
        match_flows = [
            (src, dst, 100)
            for src in [
                "h1_1",
                "h1_2",
                "h1_3",
                "h2_1",
                "h2_2",
                "h2_3",
                "h3_1",
                "h3_2",
                "h3_3",
                "h4_1",
                "h4_2",
                "h4_3",
            ]
            for dst in [
                "h1_1",
                "h1_2",
                "h1_3",
                "h2_1",
                "h2_2",
                "h2_3",
                "h3_1",
                "h3_2",
                "h3_3",
                "h4_1",
                "h4_2",
                "h4_3",
            ]
            if src != dst
        ]

        demands = match_flows + [(d, s, v) for (s, d, v) in match_flows]

        # flows = generate_b4_flows_paths_pulp(self.topo, demands)
        flows = generate_ilp_flows(self.topo, demands)
        # flows = generate_greedy_flows(self.topo, demands)

        # flows = generate_msa_flows(self.topo, demands)

        # Для каждого потока берем idx и его маршрут
        for idx, path in flows.items():
            tcp_port = None

            print(f"[MSG] idx: {idx} path: {path}")

            # Находим хост получатель - последный в списке маршрутов
            # Для занесения IP адреса и порта используется значение из `host_params`
            for _, host_params in [
                (name, params)
                for name, params in self.topo.nodes(data=True)
                if "type" in params and params["type"] == "host" and name == path[-1]
            ]:
                # Определяем пары коммутаторов
                for src_node, dst_node in zip(path[1:], path):
                    for ports in [
                        ports
                        for (source, target, ports) in self.topo.edges(data=True)
                        if source == src_node and target == dst_node
                    ]:
                        # Находим пары узлов и физические порты подключения
                        for _, switch_params in [
                            (name, params)
                            for name, params in self.topo.nodes(data=True)
                            if "type" in params
                            and params["type"] == "switch"
                            and name == dst_node
                        ]:
                            # Заносим данные в таблицу маршрутизации
                            self.routing_tables[switch_params["dpid"]].add(
                                (
                                    host_params["ip"],
                                    host_params["mac"],
                                    ports["dst_port"],
                                    tcp_port,
                                )
                            )

        pass

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

    def send_features_request(self, datapath):
        parser = datapath.ofproto_parser

        req = parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)
        print("Отправлен OFPT_FEATURES_REQUEST для коммутатора DPID=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Packet In Event Handler
        """

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        lldp_pkt = pkt.get_protocol(lldp.lldp)

        self.topo.add_node(f"s{dpid}", type="switch", dpid=int(dpid))
        if datapath.id not in self.datapaths:
            self.request_port_desc(datapath)

        if lldp_pkt:
            for tlv in lldp_pkt.tlvs:
                if isinstance(tlv, lldp.ChassisID):
                    neighbor_dpid = int(tlv.chassis_id.decode())
                elif isinstance(tlv, lldp.PortID):
                    neighbor_port = int(tlv.port_id.decode())

            self.topo.add_edge(
                f"s{int(dpid)}",
                f"s{int(neighbor_dpid)}",
                src_port=in_port,
                dst_port=neighbor_port,
            )
            self.topo.add_edge(
                f"s{int(neighbor_dpid)}",
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

                self.topo.add_node(
                    self.hosts[src_mac], mac=src_mac, type="host", ip=src_ip
                )
                self.topo.add_edge(
                    f"s{int(dpid)}", self.hosts[src_mac], src_port=in_port, dst_port=0
                )
                self.topo.add_edge(
                    self.hosts[src_mac], f"s{int(dpid)}", src_port=0, dst_port=in_port
                )

                if not flowstate:
                    pickle.dump(self.topo, open(topo_name, "wb"))
                    print("Pickle dump was wrote...")

            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if eth.ethertype in (0x0800, 0x0806):  # IPv4 или ARP
                print(
                    f"[HOST] Discovered host {src_mac} on switch {dpid} port {in_port} ip_pkt {ip_pkt}"
                )

        if dpid in self.routing_tables:
            for ip, mac, out_port, tcp_port in self.routing_tables[dpid]:

                if not flowstate:
                    continue

                if tcp_port:
                    match = parser.OFPMatch(
                        eth_type=0x0800, ipv4_dst=ip, ip_proto=6, tcp_dst=tcp_port
                    )
                else:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip)

                actions = [
                    parser.OFPActionSetField(eth_dst=mac),
                    parser.OFPActionOutput(out_port),
                ]
                self.__add_flow(datapath, 10, match, actions)

                print(
                    f"[SET] dpid: {dpid} ip: {ip} mac: {mac} out_port: {out_port} tcp_port: {tcp_port}"
                )

                # Правило для ARP-запросов
                match = parser.OFPMatch(eth_type=0x0806, arp_tpa=ip)
                actions = [
                    parser.OFPActionSetField(eth_dst=mac),
                    parser.OFPActionOutput(out_port),
                ]
                self.__add_flow(datapath, 10, match, actions)

    def reroute(self, datapath):
        dpid = datapath.id

        for switch_name, _ in [
            (name, params)
            for name, params in self.topo.nodes(data=True)
            if "type" in params
            and params["type"] == "switch"
            and params["dpid"] == dpid
        ]:
            for host_name, host_params in [
                (name, params)
                for name, params in self.topo.nodes(data=True)
                if "type" in params and params["type"] == "host"
            ]:
                shortest_path = list()
                try:
                    shortest_path = [
                        node
                        for node in nx.shortest_path(
                            self.topo, source=host_name, target=switch_name
                        )
                    ]
                except nx.exception.NetworkXNoPath:
                    continue
                except nx.exception.NodeNotFound:
                    continue

                print(
                    f"[MSG] switch_name: {switch_name} host_name: {host_name} shortest_path: {shortest_path}"
                )

                src_node, dst_node = shortest_path[-2], shortest_path[-1]
                for ports in [
                    ports
                    for (source, target, ports) in self.topo.edges(data=True)
                    if source == src_node and target == dst_node
                ]:
                    self.routing_tables[dpid].add(
                        (host_params["ip"], host_params["mac"], ports["dst_port"], None)
                    )

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

        datapath.send_msg(mod)
        self.logger.debug("Added flow: %s", match)
