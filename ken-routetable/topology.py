#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class CustomTopo(Topo):
    def build(self):
        h1 = self.addHost("h1", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", mac="00:00:00:00:00:04")

        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")
        s5 = self.addSwitch("s5")

        self.addLink(h1, s1)
        self.addLink(h2, s1)

        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)

        self.addLink(s2, s5)
        self.addLink(s3, s5)
        self.addLink(s4, s5)

        self.addLink(h3, s5)
        self.addLink(h4, s5)


if __name__ == "__main__":
    setLogLevel("info")

    # Подключаем внешний контроллер OSKen, запущенный на 127.0.0.1:6653
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    topo = CustomTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    # net.addController(controller)

    net.start()
    CLI(net)
    net.stop()
