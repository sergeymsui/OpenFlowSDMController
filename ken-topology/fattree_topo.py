#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class FatTreeK4(Topo):
    def build(self):
        k = 4
        pods = k
        core_switches = []
        agg_switches = []
        tor_switches = []
        hosts = []

        # Core layer
        core_per_pod = k // 2
        num_core = (k // 2) ** 2
        core_index = 1
        for i in range(num_core):
            sw = self.addSwitch(f"core{core_index}")
            core_switches.append(sw)
            core_index += 1

        # Pods
        for pod in range(pods):
            agg_in_pod = []
            tor_in_pod = []

            # Aggregation
            for i in range(core_per_pod):
                agg_sw = self.addSwitch(f"agg{pod}_{i}")
                agg_in_pod.append(agg_sw)
                agg_switches.append(agg_sw)

            # ToR
            for i in range(core_per_pod):
                tor_sw = self.addSwitch(f"tor{pod}_{i}")
                tor_in_pod.append(tor_sw)
                tor_switches.append(tor_sw)

                # Хосты к ToR
                for j in range(core_per_pod):
                    host = self.addHost(f"h{pod}_{i}_{j}")
                    hosts.append(host)
                    self.addLink(host, tor_sw, cls=TCLink, bw=1000)

            # ToR ↔ Agg
            for tor in tor_in_pod:
                for agg in agg_in_pod:
                    self.addLink(tor, agg, cls=TCLink, bw=1000)

            # Agg ↔ Core
            for i, agg in enumerate(agg_in_pod):
                for j in range(core_per_pod):
                    core_sw = core_switches[i * core_per_pod + j]
                    self.addLink(agg, core_sw, cls=TCLink, bw=1000)


if __name__ == "__main__":
    setLogLevel("info")
    topo = FatTreeK4()
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)
    net = Mininet(
        topo=topo,
        controller=controller,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
    )
    net.start()

    print("\n=== Fat-tree k=4 started ===\n")
    print("Available hosts:", " ".join(h.name for h in net.hosts))

    CLI(net)
    net.stop()

    # добавить iperf
