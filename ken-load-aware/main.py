# -*- coding: utf-8 -*-

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


class Controller(OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

        # Загрузка топологии
        self.topo = (
            pickle.load(open("topograph.pickle", "rb")) if flowstate else nx.DiGraph()
        )
        self.datapaths = dict()
        self.routing_tables = defaultdict(set)
        self.paths = dict()

        self.hosts = {
            "00:00:00:00:00:01": "h1",
            "00:00:00:00:00:02": "h2",
            "00:00:00:00:00:03": "h3",
            "00:00:00:00:00:04": "h4",
        }

        # Периодическая отправка LLDP пакетов
        hub.spawn(self._lldp_loop)

        self.port_stats = defaultdict(dict)
        hub.spawn(self._port_stats_loop)

        def process(_self):
            while True:
                print("[>] Update routers process...")
                sleep(10)

                # for dpid, datapath in _self.datapaths.items():
                #     print(f"[>] dpid: {dpid}, datapath.id: {datapath.id}")

                _self.update_routes()

        self._delayed_update_thread = Thread(target=process, args=(self,))
        self._delayed_update_thread.start()

    def _port_stats_loop(self):
        while True:
            for _, datapath in self.datapaths.items():
                ofp = datapath.ofproto
                ofp_parser = datapath.ofproto_parser

                req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
                datapath.send_msg(req)
            hub.sleep(3)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
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
            # print("Handshake taken place with {}".format(dpid_to_str(datapath.id)))
            self.__add_flow(datapath, 0, match, actions)

        # Запрос информации о портах
        self.request_port_desc(datapath)

        # Устанавливаем дефолтные маршруты - кратчайшие пути
        self.reroute(datapath)

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

                # print(
                #     f"[MSG] switch_name: {switch_name} host_name: {host_name} shortest_path: {shortest_path}"
                # )

                src_node, dst_node = shortest_path[-2], shortest_path[-1]
                for ports in [
                    ports
                    for (source, target, ports) in self.topo.edges(data=True)
                    if source == src_node and target == dst_node
                ]:
                    self.routing_tables[dpid].add(
                        (host_params["ip"], host_params["mac"], ports["dst_port"], None)
                    )

    def _lldp_loop(self):
        while True:
            for _, datapath in self.datapaths.items():
                self.send_lldp_packet(datapath)
            hub.sleep(5)

    def request_port_desc(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def update_routes(self):

        # Обнуляем все правила
        self.routing_tables = defaultdict(set)

        match_flows = [
            ("h1", "h3", 9080),
            ("h1", "h3", 9081),
            ("h1", "h3", 9082),
            ("h1", "h3", 9083),
            ("h1", "h3", 9084),
            ("h1", "h3", 9085),
            ("h1", "h3", 9086),
            ("h1", "h3", 9087),
            ("h1", "h3", 9088),
            ("h1", "h3", 9098),
            #
            ("h2", "h4", 9080),
            ("h2", "h4", 9081),
            ("h2", "h4", 9082),
            ("h2", "h4", 9083),
            ("h2", "h4", 9084),
            ("h2", "h4", 9085),
            ("h2", "h4", 9086),
            ("h2", "h4", 9087),
            ("h2", "h4", 9088),
            ("h2", "h4", 9098),
            # Loopback
            ("h3", "h1", None),
            ("h4", "h2", None),
        ]

        targets_list = list()

        for src, dst, _ in match_flows:
            targets_list.append((src, dst))

        flows = self.generate_load_aware_flows(targets_list)

        # Для каждого потока берем idx и его маршрут
        for idx, path in flows.items():
            _, _, tcp_port = match_flows[idx]

            # print(f"[MSG] idx: {idx} path: {path}")

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
                            if tcp_port is None:
                                continue

                            dpid = switch_params["dpid"]

                            if dpid not in self.paths:
                                self.paths[dpid] = path
                                continue
                            elif dpid in self.paths and self.paths[dpid] != path:
                                print(
                                    f"[>] change path for {dpid} from {self.paths[dpid]} to {path}"
                                )
                                self.paths[dpid] = path

                                # Заносим данные в таблицу маршрутизации
                                ip = host_params["ip"]
                                mac = host_params["mac"]
                                out_port = ports["dst_port"]
                                datapath = self.datapaths[dpid]

                                print(
                                    f"[SET] dpid: {dpid} ip: {ip} mac: {mac} out_port: {out_port} tcp_port: {tcp_port}"
                                )

                                parser = datapath.ofproto_parser

                                match = parser.OFPMatch(
                                    eth_type=0x0800,
                                    ipv4_dst=ip,
                                    ip_proto=6,
                                    tcp_dst=tcp_port,
                                )

                                actions = [
                                    parser.OFPActionSetField(eth_dst=mac),
                                    parser.OFPActionOutput(out_port),
                                ]
                                self.__add_flow(datapath, 10, match, actions)

                                # Правило для ARP-запросов
                                match = parser.OFPMatch(eth_type=0x0806, arp_tpa=ip)
                                actions = [
                                    parser.OFPActionSetField(eth_dst=mac),
                                    parser.OFPActionOutput(out_port),
                                ]
                                self.__add_flow(datapath, 10, match, actions)

        pass

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

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            self.port_stats[dpid][stat.port_no] = (stat.tx_bytes, stat.rx_bytes)

    def generate_load_aware_flows(self, targets):
        flows = dict()
        for idx, (src, dst) in enumerate(targets):
            all_paths = list(nx.all_simple_paths(self.topo, source=src, target=dst))
            best_path = None
            min_load = float("inf")

            for path in all_paths:
                path_load = 0
                for u, v in zip(path, path[1:]):
                    edge = self.topo[u][v]
                    dpid = self.topo.nodes[v].get("dpid")
                    port = edge["dst_port"]
                    txrx = self.port_stats.get(dpid, {}).get(port)

                    if txrx:
                        path_load += txrx[0] + txrx[1]

                if path_load < min_load:
                    min_load = path_load
                    best_path = path

            if best_path:
                flows[idx] = best_path

        return flows

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

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
                    pickle.dump(self.topo, open("topograph.pickle", "wb"))

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

                # print(
                #     f"[SET] dpid: {dpid} ip: {ip} mac: {mac} out_port: {out_port} tcp_port: {tcp_port}"
                # )

                # Правило для ARP-запросов
                match = parser.OFPMatch(eth_type=0x0806, arp_tpa=ip)
                actions = [
                    parser.OFPActionSetField(eth_dst=mac),
                    parser.OFPActionOutput(out_port),
                ]
                self.__add_flow(datapath, 10, match, actions)

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
        # self.logger.debug("Added flow: %s", match)
