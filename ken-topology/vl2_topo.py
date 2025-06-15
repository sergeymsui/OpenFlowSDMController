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
                self.addLink(tor, agg, bw=50, delay="1ms")

        # Core switches
        for i in range(1, num_pods):
            core_name = f"s{switch_counter}"
            core = self.addSwitch(core_name)
            core_switches.append(core)
            switch_counter += 1

            for agg in agg_switches:
                self.addLink(agg, core, bw=50, delay="1ms")


if __name__ == "__main__":
    setLogLevel("info")
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    pods = 6
    hosts_per_pod = 4
    topo = VL2Topology(num_pods=6, num_hosts_per_tor=4)
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    net.start()

    sleep(5)

    demands = list()
    for i in range(1, pods + 1):
        for j in range(1, hosts_per_pod + 1):
            src = f"h{i}_{j}"
            for ii in range(1, pods + 1):
                for jj in range(1, hosts_per_pod + 1):
                    dst = f"h{ii}_{jj}"
                    if src != dst:
                        demands.append((src, dst, 100))

    for _, dst, _ in demands:
        dst_host = net.get(dst)
        dst_host.cmd(f"iperf -s -i 1 > /tmp/iperf_server_{dst}.log &")

    i = 10
    while i > 0:
        print(f"i: {i}")
        sleep(1)
        i -= 1

    for src, dst, bw in demands:
        src_host = net.get(src)
        dst_host = net.get(dst)
        dst_ip = dst_host.IP()
        cmd = f"iperf -c {dst_ip} -b {bw}M -t 1500 -i 1 > /tmp/iperf_client_{src}_to_{dst}.log &"
        src_host.cmd(cmd)

    sleep(3)
    print("Topology started. You can now attach your controller.")

    CLI(net)
    net.stop()
