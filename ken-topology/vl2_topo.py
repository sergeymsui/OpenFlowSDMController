#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from time import sleep


class VL2Topology(Topo):
    def build(self, num_pods=6, num_hosts_per_tor=4):
        """
        VL2 Topology Generator для 24 хостов с неймингом s1, s2, s3...
        """

        tor_switches = []
        agg_switches = []
        core_switches = []

        switch_counter = 1

        # ToR (Top of Rack) switches
        for i in range(1, num_pods + 1):
            tor_name = f"s{switch_counter}"
            tor = self.addSwitch(tor_name)
            tor_switches.append(tor)
            switch_counter += 1

            # Подключаем хосты к каждому ToR
            for j in range(1, num_hosts_per_tor + 1):
                host = self.addHost(f"h{i}_{j}", mac=f"00:00:00:00:{i:02x}:{j:02x}")
                self.addLink(host, tor)

        # Aggregation switches
        for i in range(1, num_pods + 1):
            agg_name = f"s{switch_counter}"
            agg = self.addSwitch(agg_name)
            agg_switches.append(agg)
            switch_counter += 1

            # Подключаем каждый ToR к Aggregation
            for tor in tor_switches:
                self.addLink(tor, agg, bw=100, delay="5ms")

        # Core switches
        for i in range(1, num_pods):
            core_name = f"s{switch_counter}"
            core = self.addSwitch(core_name)
            core_switches.append(core)
            switch_counter += 1

            for agg in agg_switches:
                self.addLink(agg, core, bw=100, delay="5ms")


if __name__ == "__main__":
    setLogLevel("info")
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    topo = VL2Topology(num_pods=6, num_hosts_per_tor=4)
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    net.start()

    sleep(5)

    demands = [
        ("h1_1", "h6_1", 100),
        ("h1_2", "h6_2", 100),
        ("h1_3", "h6_3", 100),
        ("h1_4", "h6_4", 100),
        ("h2_1", "h5_1", 100),
        ("h2_2", "h5_2", 100),
        ("h2_3", "h5_3", 100),
        ("h2_4", "h5_4", 100),
        ("h3_1", "h4_1", 100),
        ("h3_2", "h4_2", 100),
        ("h3_3", "h4_3", 100),
        ("h3_4", "h4_4", 100),
    ]

    for _, dst, _ in demands:
        dst_host = net.get(dst)
        dst_host.cmd(f"iperf -s -i 1 > /tmp/iperf_server_{dst}.log &")

    i = 20
    while i > 0:
        print(f"i: {i}")
        sleep(1)
        i -= 1

    for src, dst, bw in demands:
        src_host = net.get(src)
        dst_host = net.get(dst)
        dst_ip = dst_host.IP()
        cmd = f"iperf -c {dst_ip} -b {bw}M -t 500 -i 1 > /tmp/iperf_client_{src}_to_{dst}.log &"
        src_host.cmd(cmd)

    sleep(3)
    print("Topology started. You can now attach your controller.")

    CLI(net)
    net.stop()
