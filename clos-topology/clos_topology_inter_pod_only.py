# -*- coding: utf-8 -*-
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from time import sleep

# ---------- Утилиты ----------

def mac_for(pod, edge, host):
    # MAC вида 00:00:pp:ee:hh (pp/ee/hh в hex, 2 символа)
    return f"00:00:{pod:02x}:{edge:02x}:{host:02x}"

# ---------- Топология Clos / fat-tree ----------

class ClosTopology(Topo):
    """
    Параметризуемая Clos (fat-tree).
      - pods = k (k чётное)
      - в каждом поде: k/2 edge и k/2 agg
      - core-коммутаторов: (k/2)^2, разбиты на (k/2) групп по (k/2)
      - каждый agg в поде подключается к ровно одному core в каждой группе,
        причём берётся «столбец» = индекс agg внутри пода (каноническая разводка)
    """

    def build(self, k=6, hosts_per_edge=2, agg_bw=1000, core_bw=500, host_bw=1000):
        if k % 2 != 0:
            raise ValueError("k must be even for a fat-tree topology")

        pods = k
        edge_per_pod = k // 2
        agg_per_pod  = k // 2

        edge_switches = []  # все edge
        agg_switches  = []  # все agg
        core_switches = []  # все core

        # для удобства: списки по подам
        pod_edges = []  # [ [edge s1..], [edge s..], ...]
        pod_aggs  = []

        sw_id = 1

        # --- Строим поды: edge + hosts, затем agg, и линки edge<->agg ---
        for pod in range(pods):
            cur_edges = []
            for e_idx in range(edge_per_pod):
                sname = f"s{sw_id}"; sw_id += 1
                s = self.addSwitch(sname)
                cur_edges.append(s)
                edge_switches.append(s)

                # хосты на каждом edge
                for h_idx in range(hosts_per_edge):
                    hname = f"h{pod}_{e_idx}_{h_idx}"
                    mac = mac_for(pod, e_idx, h_idx)
                    h = self.addHost(hname, mac=mac)  # IP пусть выдаёт Mininet
                    self.addLink(h, s, bw=host_bw)

            pod_edges.append(cur_edges)

            cur_aggs = []
            for a_idx in range(agg_per_pod):
                sname = f"s{sw_id}"; sw_id += 1
                s = self.addSwitch(sname)
                cur_aggs.append(s)
                agg_switches.append(s)

                # полносвязно edge внутри пода → agg
                for e_sw in cur_edges:
                    self.addLink(e_sw, s, bw=agg_bw)

            pod_aggs.append(cur_aggs)

        # --- Core-коммутаторы ---
        num_groups = k // 2
        group_size = k // 2
        total_core = (k // 2) ** 2

        # создаём core и разбиваем на группы
        for _ in range(total_core):
            sname = f"s{sw_id}"; sw_id += 1
            core_switches.append(self.addSwitch(sname))

        # core-группы: список списков размером [num_groups][group_size]
        core_groups = [
            core_switches[g*group_size:(g+1)*group_size]
            for g in range(num_groups)
        ]

        # --- Подключаем agg к core «по столбцам» ---
        for pod in range(pods):
            for a_idx, agg_sw in enumerate(pod_aggs[pod]):  # a_idx ∈ [0..k/2-1]
                for g in range(num_groups):                 # по одному core из каждой группы
                    core_sw = core_groups[g][a_idx]
                    self.addLink(agg_sw, core_sw, bw=core_bw)

# ---------- Запуск сценария Inter-pod only ----------

def run_test():
    """
    Inter-pod only: источники — поды [0..(k/2-1)], приёмники — поды [(k/2)..(k-1)].
    k=6 => источники: 0,1,2; приёмники: 3,4,5
    """
    setLogLevel("info")

    # Параметры топологии
    k = 6                   # чётное
    hosts_per_edge = 2
    host_bw = 1000          # Мбит/с host↔edge
    agg_bw  = 1000          # Мбит/с edge↔agg
    core_bw = 500           # Мбит/с agg↔core (узкое место)

    topo = ClosTopology(
        k=k,
        hosts_per_edge=hosts_per_edge,
        agg_bw=agg_bw,
        core_bw=core_bw,
        host_bw=host_bw,
    )

    # Контроллер (убедитесь, что ваш SDN-контроллер слушает этот адрес/порт)
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Mininet
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    net.start()

    # (опционально) принудительно включим OpenFlow13 на свитчах
    for s in net.switches:
        s.cmd(f"ovs-vsctl set Bridge {s.name} protocols=OpenFlow13")

    # Дадим свитчам сконнектиться с контроллером
    sleep(5)

    # Разобьём хосты по подам по имени h{pod}_{edge}_{host}
    hosts_by_pod = {}
    for h in net.hosts:
        pod_idx = int(h.name.split('_')[0][1:])  # 'h3_1_0' -> '3'
        hosts_by_pod.setdefault(pod_idx, []).append(h)

    # Поднимем iperf-серверы
    for h in net.hosts:
        # используйте iperf3 если iperf отсутствует: "iperf3 -s -D"
        h.cmd(f"iperf -s -i 1 > /tmp/iperf_server_{h.name}.log &")

    sleep(3)

    # Inter-pod only: источники из pod ∈ [0..k/2-1], приёмники из pod ∈ [k/2..k-1]
    demands = []
    for src_pod in range(k // 2):          # 0,1,2
        for dst_pod in range(k // 2, k):   # 3,4,5
            for src_h in hosts_by_pod.get(src_pod, []):
                for dst_h in hosts_by_pod.get(dst_pod, []):
                    demands.append((src_h, dst_h))

    # Запустим iperf-клиентов (100 Мбит/с на поток, 60 секунд)
    for src_h, dst_h in demands:
        dst_ip = dst_h.IP()
        cmd = (
            f"iperf -c {dst_ip} -b 100M -t 60 -i 1 "
            f"> /tmp/iperf_client_{src_h.name}_to_{dst_h.name}.log &"
        )
        src_h.cmd(cmd)

    print("Запущено: k=6, Inter-pod only (pods 0–2 -> pods 3–5). Откройте CLI для проверки.")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    run_test()
