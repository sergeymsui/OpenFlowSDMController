#!/usr/bin/python

"""
clos_topology.py
=================

Этот скрипт создает простую Clos‑подобную (fat‑tree) топологию в Mininet и запускает
нагрузочные тесты с помощью `iperf`. Топология параметризуется числом
``k``, которое определяет количество подов, количество edge‑ и
aggregation‑коммутаторов в каждом поде, а также количеством хостов
подключенных к каждому edge‑коммутатору. Для демонстрации работы
маршрутизирующих алгоритмов можно установить различную пропускную
способность на разных уровнях сети (например, ограничить канал
агрегация‑core), чтобы создать узкие места и увидеть, как выбор
маршрутов влияет на пропускную способность.

Для запуска топологии достаточно выполнить команду:

```
sudo python clos_topology.py
```

Скрипт предполагает наличие удаленного контроллера по адресу 127.0.0.1:6633,
который управляет OpenFlow‑коммутаторами (например, контроллер OS‑Ken из
предыдущего примера). После старта все хосты поднимают iperf‑серверы, а
далее автоматически создаются клиенты iperf для выбранных пар источников
и получателей. В конце можно открыть CLI Mininet для интерактивной
работы и наблюдения за состоянием сети.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from time import sleep

hosts = {
    "h0_0_0": "00:00:00:00:00:02",
    "h0_0_1": "00:00:00:00:00:01",
    "h0_1_0": "00:00:00:00:01:00",
    "h0_1_1": "00:00:00:00:01:01",
    "h1_0_0": "00:00:00:01:00:00",
    "h1_0_1": "00:00:00:01:00:01",
    "h1_1_0": "00:00:00:01:01:00",
    "h1_1_1": "00:00:00:01:01:01",
    "h2_0_0": "00:00:00:02:00:00",
    "h2_0_1": "00:00:00:02:00:01",
    "h2_1_0": "00:00:00:02:01:00",
    "h2_1_1": "00:00:00:02:01:01",
    "h3_0_0": "00:00:00:03:00:00",
    "h3_0_1": "00:00:00:03:00:01",
    "h3_1_0": "00:00:00:03:01:00",
    "h3_1_1": "00:00:00:03:01:01",
}


class ClosTopology(Topo):
    def build(self, k=4, hosts_per_edge=2, agg_bw=1000, core_bw=500, host_bw=1000):
        if k % 2 != 0:
            raise ValueError("k must be even for a fat‑tree topology")

        pods = k
        edge_switches = []  # список всех edge‑коммутаторов
        agg_switches = []  # список всех aggregation‑коммутаторов
        core_switches = []  # список всех core‑коммутаторов

        # Счетчик для уникальных имен коммутаторов
        switch_counter = 1

        # Построение подов: в каждом поде k/2 edge и k/2 aggregation коммутаторов
        # и hosts_per_edge хостов на каждый edge
        for pod in range(pods):
            # Edge‑коммутаторы в текущем поде
            pod_edges = []
            for edge_idx in range(k // 2):
                sw_name = f"s{switch_counter}"
                sw = self.addSwitch(sw_name)
                switch_counter += 1
                pod_edges.append(sw)
                edge_switches.append(sw)

                # Подключаем хосты к edge‑коммутатору
                for host_idx in range(hosts_per_edge):
                    host_name = f"h{pod}_{edge_idx}_{host_idx}"
                    mac = hosts[host_name]
                    host = self.addHost(host_name, mac=mac)
                    print(mac, host)
                    # Хост‑edge link
                    self.addLink(host, sw, bw=host_bw)

            # Aggregation‑коммутаторы в текущем поде
            pod_aggs = []
            for agg_idx in range(k // 2):
                sw_name = f"s{switch_counter}"
                sw = self.addSwitch(sw_name)
                switch_counter += 1
                pod_aggs.append(sw)
                agg_switches.append(sw)

                # Подключаем каждый edge‑коммутатор из этого пода к текущему aggregation‑коммутатору
                for edge_sw in pod_edges:
                    # Указываем пропускную способность на линке edge‑→‑aggregation
                    self.addLink(edge_sw, sw, bw=agg_bw)

        # Core‑коммутаторы: их число (k/2)^2
        num_core = (k // 2) ** 2
        for core_idx in range(num_core):
            sw_name = f"s{switch_counter}"
            sw = self.addSwitch(sw_name)
            switch_counter += 1
            core_switches.append(sw)

        # Подключаем каждый aggregation‑коммутатор ко всем core‑коммутаторам.
        # Можно уменьшить количество связей для создания менее избыточной топологии.
        for agg_sw in agg_switches:
            for core_sw in core_switches:
                # Указываем пропускную способность на линке aggregation‑→‑core
                self.addLink(agg_sw, core_sw, bw=core_bw)


def run_test():
    """Запускает Clos‑топологию и выполняет iperf‑тесты.

    Трафик генерируется только между группами подов, чтобы насытить
    восходящие каналы core‑уровня. Для демонстрации создаются потоки
    от хостов в первых половинах подов к хостам во второй половине.
    """
    setLogLevel("info")

    # Параметры топологии
    k = 4  # должно быть четным
    hosts_per_edge = 2
    agg_bw = 1000  # Мбит/с между edge и аггрегатором
    core_bw = 500  # Мбит/с между аггрегатором и core
    host_bw = 1000  # Мбит/с между хостом и edge

    topo = ClosTopology(
        k=k,
        hosts_per_edge=hosts_per_edge,
        agg_bw=agg_bw,
        core_bw=core_bw,
        host_bw=host_bw,
    )

    # Используем удаленный контроллер. Ожидается, что он запущен и знает о топологии.
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Запускаем Mininet. autoSetMacs=True назначит MAC‑адреса в зависимости от имени узла,
    # но мы уже передали MAC‑адреса хостам, поэтому оставляем значение по умолчанию False.
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink)
    net.start()

    # Небольшая пауза, чтобы коммутаторы установили соединение с контроллером
    sleep(5)

    # Получаем список хостов, сгруппировав их по подам
    hosts_by_pod = {}
    for host in net.hosts:
        # Имя вида h{pod}_{edge}_{host}
        parts = host.name[1:].split("_")
        pod_idx = int(parts[0])
        hosts_by_pod.setdefault(pod_idx, []).append(host)

    # Запускаем iperf‑сервер на каждом хосте
    for host in net.hosts:
        host.cmd(f"iperf -s -i 1 > /tmp/iperf_server_{host.name}.log &")

    # Дадим серверам подняться
    sleep(20)

    # Формируем список demand‑ов: источники из первой половины подов (0..(k/2 - 1)),
    # назначения из второй половины (k/2 .. k-1). Такие потоки будут
    # обязательно проходить через core‑коммутаторы и создадут нагрузку.
    demands = []
    for src_pod in range(k // 2):
        for src_host in hosts_by_pod.get(src_pod, []):
            for dst_pod in range(k // 2, k):
                for dst_host in hosts_by_pod.get(dst_pod, []):
                    demands.append((src_host, dst_host))
                    print(src_host.name, dst_host.name)

    # Запускаем iperf‑клиенты для каждого demand. Ограничиваем скорость в 100 Мбит/с,
    # чтобы при достаточном количестве потоков перегрузить core‑уровень.
    for src_host, dst_host in demands:
        dst_ip = dst_host.IP()
        cmd = f"iperf -c {dst_ip} -b 100M -t 60 -i 1 > /tmp/iperf_client_{src_host.name}_to_{dst_host.name}.log &"
        src_host.cmd(cmd)

    print("Топология запущена, iperf‑трафик генерируется. Можно подключиться к CLI.")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    run_test()
