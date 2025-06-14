#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import os, time


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        self.cmd("sysctl -w net.ipv4.conf.all.proxy_arp=1")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super(LinuxRouter, self).terminate()


class VL2OSPFTopo(Topo):
    def build(self, num_pods=6, num_hosts_per_tor=4):
        self.routers = {}
        switch_counter = 1

        for i in range(1, num_pods + 1):
            name = f"s{switch_counter}"
            self.routers[name] = self.addNode(name, cls=LinuxRouter)
            switch_counter += 1
            for j in range(1, num_hosts_per_tor + 1):
                host = self.addHost(
                    f"h{i}_{j}",
                    ip=f"10.{i}.{j}.10/24",
                    defaultRoute=f"via 10.{i}.{j}.1",
                )
                self.addLink(
                    host, self.routers[name], params2={"ip": f"10.{i}.{j}.1/24"}
                )

        tor_switches = list(self.routers.values())

        agg_switches = []
        for i in range(1, num_pods + 1):
            name = f"s{switch_counter}"
            agg = self.addNode(name, cls=LinuxRouter)
            self.routers[name] = agg
            agg_switches.append(agg)
            switch_counter += 1
            for tor in tor_switches:
                self.addLink(tor, agg)

        for i in range(1, num_pods):
            name = f"s{switch_counter}"
            core = self.addNode(name, cls=LinuxRouter)
            self.routers[name] = core
            switch_counter += 1
            for agg in agg_switches:
                self.addLink(agg, core)


def generate_frr_configs(topo, net):
    info("Generating FRR configs...\n")
    for name in topo.routers.keys():
        router = net.get(name)
        interfaces = router.intfList()

        zebra_cfg = f"hostname {name}\n"
        ospf_cfg = (
            f"router ospf\n ospf router-id 1.1.1.{name[1:]}\n  redistribute connected\n"
        )

        for intf in interfaces:
            ip_output = router.cmd(f"ip -4 addr show {intf}")
            try:
                ip_mask = ip_output.split("inet ")[1].split()[0]
                zebra_cfg += f"interface {intf}\n ip address {ip_mask}\n"
                network = ip_mask.rsplit(".", 1)[0] + ".0"
                ospf_cfg += f" network {network}/24 area 0\n"
            except IndexError:
                continue

        with open(f"/tmp/{name}_zebra.conf", "w") as f:
            f.write(zebra_cfg)
        with open(f"/tmp/{name}_ospfd.conf", "w") as f:
            f.write(ospf_cfg)


def run():
    setLogLevel("info")

    topo = VL2OSPFTopo(num_pods=6, num_hosts_per_tor=4)
    net = Mininet(topo=topo, controller=None, waitConnected=True)
    net.start()

    generate_frr_configs(topo, net)

    for name in topo.routers.keys():
        router = net.get(name)
        zebra_conf = f"/tmp/{name}_zebra.conf"
        ospf_conf = f"/tmp/{name}_ospfd.conf"
        router.cmd(f"zebra -f {zebra_conf} -d -z /tmp/{name}.api -i /tmp/{name}.pid")
        time.sleep(0.5)
        router.cmd(
            f"ospfd -f {ospf_conf} -d -z /tmp/{name}.api -i /tmp/{name}_ospfd.pid"
        )
        for intf in router.intfList():
            router.cmd(f"sysctl -w net.ipv4.conf.{intf}.proxy_arp=1")

    info("*** Waiting for OSPF convergence...\n")
    time.sleep(30)  # Подождать дольше для конвергенции OSPF

    info("\n#### STARTING PINGALL ####\n")
    net.pingAll()

    CLI(net)
    net.stop()

    os.system("killall -9 ospfd zebra")
    os.system("rm -f /tmp/*.api /tmp/*.pid /tmp/*zebra.conf /tmp/*ospfd.conf")


if __name__ == "__main__":
    run()
