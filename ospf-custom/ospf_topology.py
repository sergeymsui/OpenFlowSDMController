#!/usr/bin/python

import os
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super(LinuxRouter, self).terminate()


class OSPFTopo(Topo):
    def build(self):
        h1 = self.addHost("h1", ip="10.0.1.2/24", defaultRoute="via 10.0.1.1")
        h2 = self.addHost("h2", ip="10.0.2.2/24", defaultRoute="via 10.0.2.1")
        h3 = self.addHost("h3", ip="10.0.3.2/24", defaultRoute="via 10.0.3.1")
        h4 = self.addHost("h4", ip="10.0.4.2/24", defaultRoute="via 10.0.4.1")

        switches = {}
        for i in range(1, 10):
            defip = (i + 1) * 10
            switches[f"s{i}"] = self.addNode(
                f"s{i}", cls=LinuxRouter, ip=f"10.0.3.{defip}/24"
            )

        self.addLink(h1, switches["s1"])
        self.addLink(h2, switches["s2"])
        self.addLink(h3, switches["s9"])
        self.addLink(h4, switches["s8"])

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


def generate_config(router_name, interfaces):
    zebra_conf = f"""
hostname {router_name}
password zebra
log file /tmp/{router_name}_zebra.log
"""
    ospfd_conf = f"""
hostname {router_name}
password zebra
log file /tmp/{router_name}_ospfd.log
router ospf
"""

    for intf, ip in interfaces:
        ospfd_conf += f" network {ip}/24 area 0\n"

    dev_num = str(router_name).replace("s", "")
    ospfd_conf += f" ospf router-id {dev_num}.{dev_num}.{dev_num}.{dev_num}"

    zebra_path = f"/tmp/{router_name}_zebra.conf"
    ospfd_path = f"/tmp/{router_name}_ospfd.conf"

    with open(zebra_path, "w") as f:
        f.write(zebra_conf.strip() + "\n")

    with open(ospfd_path, "w") as f:
        f.write(ospfd_conf.strip() + "\n")

    return zebra_path, ospfd_path


def run():
    topo = OSPFTopo()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    net.start()

    for i in range(1, 10):
        rname = f"s{i}"
        router = net.getNodeByName(rname)

        interfaces = []
        for intf in router.intfList():
            if "lo" not in intf.name:
                ip = f"10.0.{i}{intf.name[-1]}.1"
                router.setIP(ip, intf=intf)
                interfaces.append((intf.name, ip))

        zebra_conf, ospfd_conf = generate_config(rname, interfaces)

        router.cmd(
            f"zebra -f {zebra_conf} -d -z /tmp/{rname}.zebra.api -i /tmp/{rname}.zebra.pid"
        )
        router.cmd(
            f"ospfd -f {ospfd_conf} -d -z /tmp/{rname}.zebra.api -i /tmp/{rname}.ospfd.pid"
        )

    info("*** Запуск CLI\n")
    CLI(net)

    net.stop()
    os.system("killall -9 zebra ospfd")
    os.system(
        "rm -f /tmp/*.zebra* /tmp/*.ospfd* /tmp/*.log /tmp/s*zebra.conf /tmp/s*ospfd.conf"
    )


if __name__ == "__main__":
    setLogLevel("info")
    run()
