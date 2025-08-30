# -*- coding: utf-8 -*-

from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, arp
from os_ken.lib.dpid import dpid_to_str

class ProbabilisticBalancer(OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProbabilisticBalancer, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Настройка только для коммутатора s1 (dpid=1)
        if dpid == 1:
            self.install_probabilistic_group(datapath)

            # Направляем весь IP-трафик на групповую таблицу
            match_ip = parser.OFPMatch(eth_type=0x0800)  # IPv4
            actions_ip = [parser.OFPActionGroup(group_id=50)]
            self.add_flow(datapath, 10, match_ip, actions_ip)

    def install_probabilistic_group(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Настройка вероятностной балансировки на коммутаторы s2(порт 2), s3(порт 3), s4(порт 4)
        weights = {
            2: 50,  # 50% трафика на s2
            3: 30,  # 30% трафика на s3
            4: 20   # 20% трафика на s4
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

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
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
        self.logger.info("[DPID %s] Installed flow: %s", dpid_to_str(datapath.id), match)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )

        datapath.send_msg(out)
