#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class B4GeoTopology(Topo):
    def build(self):
        # Узлы (коммутаторы)
        nodes = {}
        for i in range(1, 20):  # L1 to L19
            sw_name = f"s{i}"
            nodes[sw_name] = self.addSwitch(sw_name)

        # Хосты (по одному на каждый узел)
        for i in range(1, 13):
            host = self.addHost(f"h{i}", mac=f"00:00:00:00:00:{i:02x}")
            print(f" \"00:00:00:00:00:{i:02x}\" : \"h{i}\", ")
            self.addLink(host, nodes[f"s{i}"])

        # Связи (как на карте)
        links = [
            ("s1", "s2"),
            ("s2", "s6"),
            ("s1", "s3"),
            ("s3", "s4"),
            ("s3", "s7"),
            ("s4", "s6"),
            ("s6", "s7"),
            ("s4", "s5"),
            ("s4", "s8"),
            ("s7", "s5"),
            ("s7", "s8"),
            ("s5", "s8"),
            ("s5", "s12"),
            ("s8", "s10"),
            ("s9", "s10"),
            ("s9", "s12"),
            ("s10", "s12"),
            ("s10", "s11"),
            ("s11", "s12"),
        ]

        for n1, n2 in links:
            self.addLink(nodes[n1], nodes[n2], bw=100, delay="30ms")


if __name__ == "__main__":
    setLogLevel("info")
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    topo = B4GeoTopology()
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    net.start()
    CLI(net)
    net.stop()
