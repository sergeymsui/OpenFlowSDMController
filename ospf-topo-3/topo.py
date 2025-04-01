#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import os, time


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd("sysctl net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        super(LinuxRouter, self).terminate()


class CustomTopo(Topo):
    def build(self):
        # Routers
        routers = {}
        for i in range(1, 10):
            routers[f"s{i}"] = self.addNode(f"s{i}", cls=LinuxRouter)

        # Hosts
        h1 = self.addHost("h1", ip="10.0.1.10/24", defaultRoute="via 10.0.1.1")
        h2 = self.addHost("h2", ip="10.0.2.10/24", defaultRoute="via 10.0.2.1")
        h3 = self.addHost("h3", ip="10.0.3.10/24", defaultRoute="via 10.0.3.1")
        h4 = self.addHost("h4", ip="10.0.4.10/24", defaultRoute="via 10.0.4.1")

        # Host links

        self.addLink(h1, routers["s1"], params2={"ip": "10.0.1.1/24"})
        self.addLink(h2, routers["s2"], params2={"ip": "10.0.2.1/24"})

        sw1 = self.addSwitch("sw1", failMode="standalone")
        sw2 = self.addSwitch("sw2", failMode="standalone")

        self.addLink(sw1, h3)
        self.addLink(sw2, h4)

        self.addLink(sw1, routers["s9"], params2={"ip": "10.0.3.1/24"})
        self.addLink(sw2, routers["s8"], params2={"ip": "10.0.4.1/24"})

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

        subnet = 10
        for link in links:
            self.addLink(
                routers[link[0]],
                routers[link[1]],
                intfName1=f"{link[0]}-{link[1]}",
                params1={"ip": f"10.0.{subnet}.1/24"},
                intfName2=f"{link[1]}-{link[0]}",
                params2={"ip": f"10.0.{subnet}.2/24"},
            )
            subnet += 1


def create_frr_configs():
    ospf_configs = {}
    zebra_configs = {}

    routers_interfaces = {f"s{i}": [] for i in range(1, 10)}

    # Интерфейсы для хостов
    routers_interfaces["s1"].append(("s1-eth0", "10.0.1.1/24"))
    routers_interfaces["s2"].append(("s2-eth0", "10.0.2.1/24"))
    routers_interfaces["s8"].append(("s8-eth0", "10.0.4.1/24"))
    routers_interfaces["s9"].append(("s9-eth0", "10.0.3.1/24"))

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

    subnet = 10
    for link in links:
        r1, r2 = link
        ip1 = f"10.0.{subnet}.1/24"
        ip2 = f"10.0.{subnet}.2/24"
        routers_interfaces[r1].append((f"{r1}-{r2}", ip1))
        routers_interfaces[r2].append((f"{r2}-{r1}", ip2))
        subnet += 1

    for router, interfaces in routers_interfaces.items():
        zebra_cfg = f"hostname {router}\n"
        ospf_cfg = f"router ospf\n ospf router-id 1.1.1.{router[1:]}\n"

        for intf_name, ip in interfaces:
            zebra_cfg += f"interface {intf_name}\n ip address {ip}\n"

            network = ip.rsplit(".", 1)[0] + ".0/24"
            ospf_cfg += f" network {network} area 0\n"

        zebra_configs[f"{router}zebra.conf"] = zebra_cfg
        ospf_configs[f"{router}ospfd.conf"] = ospf_cfg

    for filename, content in {**zebra_configs, **ospf_configs}.items():
        with open(f"/tmp/{filename}", "w") as f:
            f.write(content)


def run():
    create_frr_configs()
    topo = CustomTopo()
    net = Mininet(controller=None, topo=topo)
    net.start()

    routers = [net.get(f"s{i}") for i in range(1, 10)]
    for r in routers:
        r.cmd(
            f"zebra -f /tmp/{r.name}zebra.conf -d -z /tmp/{r.name}zebra.api -i /tmp/{r.name}zebra.pid"
        )
        time.sleep(1)

    for r in routers:
        r.cmd(
            f"ospfd -f /tmp/{r.name}ospfd.conf -d -z /tmp/{r.name}zebra.api -i /tmp/{r.name}ospfd.pid"
        )

    info("*** Waiting for OSPF convergence\n")
    time.sleep(5)

    CLI(net)
    net.stop()

    os.system("killall -9 ospfd zebra")
    os.system("rm -f /tmp/*.api /tmp/*.pid")


if __name__ == "__main__":
    setLogLevel("info")
    run()
