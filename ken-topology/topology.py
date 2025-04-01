#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class CustomMeshTopo(Topo):
    def build(self):
        # Хосты
        h1 = self.addHost("h1", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", mac="00:00:00:00:00:04")

        # Коммутаторы
        switches = {}
        for i in range(1, 10):
            switches[f"s{i}"] = self.addSwitch(f"s{i}")

        # Связи хостов
        self.addLink(h1, switches["s1"])
        self.addLink(h2, switches["s2"])
        self.addLink(h3, switches["s9"])
        self.addLink(h4, switches["s8"])

        # Связи коммутаторов по заданной схеме
        links = [
            ("s1", "s3"),
            ("s3", "s6"),
            ("s6", "s9"),
            ("s2", "s4"),
            ("s4", "s7"),
            ("s7", "s8"),
            ("s2", "s3"),
            ("s7", "s6"),
            ("s4", "s3"),
            ("s6", "s8"),
            ("s4", "s5"),
            ("s3", "s5"),
            ("s5", "s6"),
            ("s5", "s7"),
        ]

        for s1, s2 in links:
            self.addLink(switches[s1], switches[s2])


if __name__ == "__main__":
    setLogLevel("info")

    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    topo = CustomMeshTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    net.start()
    CLI(net)
    net.stop()
