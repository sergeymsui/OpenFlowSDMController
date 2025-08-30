#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

from time import sleep

class B4GeoTopology(Topo):
    def build(self):
        # Узлы (коммутаторы)
        nodes = {}
        for i in range(1, 20):  # L1 to L19
            sw_name = f"s{i}"
            nodes[sw_name] = self.addSwitch(sw_name)

        # Хосты (по одному на каждый узел)
        for i in range(1, 13):
            host = self.addHost(f"h{i}", mac=f"00:00:00:00:00:{i:02x}")
            print(f" \"00:00:00:00:00:{i:02x}\" : \"h{i}\", ")
            self.addLink(host, nodes[f"s{i}"])

        # Связи (как на карте)
        links = [
            ("s1", "s2"),
            ("s2", "s6"),
            ("s1", "s3"),
            ("s3", "s4"),
            ("s3", "s7"),
            ("s4", "s6"),
            ("s6", "s7"),
            ("s4", "s5"),
            ("s4", "s8"),
            ("s7", "s5"),
            ("s7", "s8"),
            ("s5", "s8"),
            ("s5", "s12"),
            ("s8", "s10"),
            ("s9", "s10"),
            ("s9", "s12"),
            ("s10", "s12"),
            ("s10", "s11"),
            ("s11", "s12"),
        ]

        for n1, n2 in links:
            self.addLink(nodes[n1], nodes[n2], bw=100, delay="30ms")


if __name__ == "__main__":
    setLogLevel("info")
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    topo = B4GeoTopology()
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    net.start()
    
    sleep(5)

    demands = [
        ("h1", "h10", 100),
        ("h2", "h9", 100),
        ("h3", "h11", 100),
        ("h4", "h12", 100),
        ("h5", "h7", 100),
        ("h6", "h8", 100),
        ("h7", "h2", 100),
        ("h8", "h4", 100),
        ("h9", "h5", 100),
        ("h10", "h1", 100),
    ]

    for _, dst, _ in demands:
        dst_host = net.get(dst)
        dst_host.cmd(f"iperf -s -u -i 1 > /tmp/iperf_server_{dst}.log &")

    i = 20
    while i > 0:
        print(f"i: {i}")
        sleep(1)
        i -= 1
        

    for src, dst, bw in demands:
        src_host = net.get(src)
        dst_host = net.get(dst)
        dst_ip = dst_host.IP()
        cmd = f"iperf -u -c {dst_ip} -b {bw}M -t 500 -i 1 > /tmp/iperf_client_{src}_to_{dst}.log &"
        src_host.cmd(cmd)

    CLI(net)
    net.stop()
