#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from time import sleep


class VL2Topology(Topo):
    def build(self, num_pods=4, num_hosts_per_tor=2):
        """
        VL2 Topology Generator
        :param num_pods: число ToR и Aggregation коммутаторов
        :param num_hosts_per_tor: сколько серверов подключено к одному ToR
        """

        tor_switches = []
        agg_switches = []
        core_switches = []

        # ToR (Top of Rack) switches
        for i in range(1, num_pods + 1):
            tor = self.addSwitch(f"tor{i}")
            tor_switches.append(tor)
            # Подключаем хосты к каждому ToR
            for j in range(1, num_hosts_per_tor + 1):
                host = self.addHost(f"h{i}_{j}", mac=f"00:00:00:00:{i:02x}:{j:02x}")
                self.addLink(host, tor)

        # Aggregation switches
        for i in range(1, num_pods + 1):
            agg = self.addSwitch(f"agg{i}")
            agg_switches.append(agg)
            # Подключаем каждый ToR к Aggregation
            for tor in tor_switches:
                self.addLink(tor, agg, bw=1000, delay="5ms")

        # Core switches (для полноты картины)
        for i in range(1, num_pods):
            core = self.addSwitch(f"core{i}")
            core_switches.append(core)
            for agg in agg_switches:
                self.addLink(agg, core, bw=1000, delay="5ms")


if __name__ == "__main__":
    setLogLevel("info")
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    topo = VL2Topology(num_pods=4, num_hosts_per_tor=3)
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    net.start()

    sleep(3)
    print("Topology started. You can now attach your controller.")

    CLI(net)
    net.stop()
