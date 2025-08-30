#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time
import os


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd("sysctl net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        super(LinuxRouter, self).terminate()


class NetworkTopo(Topo):
    def build(self, **_opts):

        r1 = self.addNode("r1", cls=LinuxRouter)
        r2 = self.addNode("r2", cls=LinuxRouter)
        r3 = self.addNode("r3", cls=LinuxRouter)

        h1 = self.addHost("h1", ip="10.0.1.100/24", defaultRoute="via 10.0.1.10")
        h2 = self.addHost("h2", ip="10.0.2.100/24", defaultRoute="via 10.0.2.20")

        # r1-r3 link
        self.addLink(
            r1,
            r3,
            intfName1="r1-eth1",
            params1={"ip": "10.0.3.1/24"},
            intfName2="r3-eth1",
            params2={"ip": "10.0.3.3/24"},
        )

        # r2-r3 link
        self.addLink(
            r2,
            r3,
            intfName1="r2-eth1",
            params1={"ip": "10.0.4.2/24"},
            intfName2="r3-eth2",
            params2={"ip": "10.0.4.3/24"},
        )

        # hosts to routers
        self.addLink(h1, r1, intfName2="r1-eth2", params2={"ip": "10.0.1.10/24"})
        self.addLink(h2, r2, intfName2="r2-eth2", params2={"ip": "10.0.2.20/24"})


def create_frr_configs():
    configs = {
        "r1zebra.conf": """
hostname r1
interface r1-eth1
 ip address 10.0.3.1/24
interface r1-eth2
 ip address 10.0.1.10/24
""",
        "r2zebra.conf": """
hostname r2
interface r2-eth1
 ip address 10.0.4.2/24
interface r2-eth2
 ip address 10.0.2.20/24
""",
        "r3zebra.conf": """
hostname r3
interface r3-eth1
 ip address 10.0.3.3/24
interface r3-eth2
 ip address 10.0.4.3/24
""",
        "r1ospfd.conf": """
router ospf
 ospf router-id 1.1.1.1
 network 10.0.1.0/24 area 0
 network 10.0.3.0/24 area 0
""",
        "r2ospfd.conf": """
router ospf
 ospf router-id 2.2.2.2
 network 10.0.2.0/24 area 0
 network 10.0.4.0/24 area 0
""",
        "r3ospfd.conf": """
router ospf
 ospf router-id 3.3.3.3
 network 10.0.3.0/24 area 0
 network 10.0.4.0/24 area 0
""",
    }

    for filename, content in configs.items():
        with open(f"/tmp/cfg/{filename}", "w") as f:
            f.write(content)


def run():
    create_frr_configs()
    topo = NetworkTopo()
    net = Mininet(controller=None, topo=topo)
    net.start()

    r1, r2, r3 = net.get("r1", "r2", "r3")

    # запуск zebra
    for r in [r1, r2, r3]:
        r.cmd(
            f"zebra -f /tmp/cfg/{r.name}zebra.conf -d -z /tmp/{r.name}zebra.api -i /tmp/{r.name}zebra.pid"
        )

    time.sleep(1)

    # запуск ospfd
    for r in [r1, r2, r3]:
        r.cmd(
            f"ospfd -f /tmp/cfg/{r.name}ospfd.conf -d -z /tmp/{r.name}zebra.api -i /tmp/{r.name}ospfd.pid"
        )

    info("*** Waiting for OSPF convergence\n")
    time.sleep(3)

    info("*** Routing Table on r1:\n")
    info(r1.cmd("route -n"))
    info("*** Routing Table on r2:\n")
    info(r2.cmd("route -n"))
    info("*** Routing Table on r3:\n")
    info(r3.cmd("route -n"))

    CLI(net)
    net.stop()

    os.system("killall -9 ospfd zebra")
    os.system("rm -f /tmp/*.api /tmp/*.pid")


if __name__ == "__main__":
    setLogLevel("info")
    run()
