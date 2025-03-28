# -*- coding: utf-8 -*-

from os_ken.base.app_manager import OSKenApp
from os_ken.lib.packet import packet, ethernet, lldp
from os_ken.controller.handler import MAIN_DISPATCHER, set_ev_cls
from os_ken.controller import ofp_event
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub


class LLDPDiscovery(OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LLDPDiscovery, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.link_table = {}
        self.lldp_thread = hub.spawn(self._lldp_loop)

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev):
        datapath = ev.datapath
        self.datapaths[datapath.id] = datapath
        self.logger.info(f"Switch connected: {datapath.id}")

    def _lldp_loop(self):
        while True:
            for dp in self.datapaths.values():
                self.send_lldp(dp)
            hub.sleep(5)  # отправка каждые 5 сек

    def send_lldp(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for port_no in datapath.ports:
            port = datapath.ports[port_no]
            if port_no == ofproto.OFPP_LOCAL:
                continue

            pkt = packet.Packet()
            pkt.add_protocol(
                ethernet.ethernet(
                    ethertype=ethernet.ether.ETH_TYPE_LLDP,
                    dst="00:00:00:00:00:00",
                    src=port.hw_addr,
                )
            )

            chassis_id = lldp.ChassisID(
                subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                chassis_id=str(datapath.id).encode(),
            )
            port_id = lldp.PortID(
                subtype=lldp.PortID.SUB_PORT_COMPONENT, port_id=str(port_no).encode()
            )
            ttl = lldp.TTL(ttl=120)
            end = lldp.End()

            pkt.add_protocol(lldp.lldp(tlvs=[chassis_id, port_id, ttl, end]))
            pkt.serialize()

            data = pkt.data
            actions = [parser.OFPActionOutput(port_no)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=data,
            )
            datapath.send_msg(out)
            self.logger.debug(f"Sent LLDP from dpid {datapath.id} port {port_no}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype != ethernet.ether.ETH_TYPE_LLDP:
            return

        lldp_pkt = pkt.get_protocol(lldp.lldp)
        if lldp_pkt is None:
            return

        src_dpid, src_port_no = self._parse_lldp(lldp_pkt)
        dst_dpid = datapath.id
        dst_port_no = msg.match["in_port"]

        self.logger.info(
            f"Link detected: switch {src_dpid} (port {src_port_no}) <--> switch {dst_dpid} (port {dst_port_no})"
        )

        self.link_table[(src_dpid, src_port_no)] = (dst_dpid, dst_port_no)

        print(self.link_table)

    def _parse_lldp(self, lldp_pkt):
        chassis_id = lldp_pkt.tlvs[0]
        port_id = lldp_pkt.tlvs[1]

        src_dpid = int(chassis_id.chassis_id.decode())
        src_port_no = int(port_id.port_id.decode())

        return src_dpid, src_port_no
