#!/usr/bin/python

"""
clos_topology_visualization.py
==============================

В этом скрипте создаётся и визуализируется Clos (fat‑tree) топология,
аналогичная определённой в clos_topology.py. Для визуализации
используется библиотека NetworkX совместно с Matplotlib. Узлы
располагаются слоями: хосты внизу, выше — edge‑коммутаторы, ещё
выше — aggregation‑коммутаторы, и на самом верху — core‑коммутаторы.
Различные типы узлов выделяются цветом.

Запустить скрипт можно так:

```
python clos_topology_visualization.py
```

При запуске будет создан файл PNG с изображением (clos_topology.png) в
текущей директории.
"""

import networkx as nx
import matplotlib

matplotlib.use("Agg")  # используем бэкенд, не требующий дисплея
import matplotlib.pyplot as plt


def build_clos_graph(k=4, hosts_per_edge=2):
    """Создаёт граф Clos‑топологии и возвращает его вместе с позициями узлов,
    метками и цветами для визуализации.

    :param int k: параметр fat‑tree (должен быть чётным). Число подов равно k.
    :param int hosts_per_edge: число хостов на каждый edge‑коммутатор.
    :return: (G, pos, labels, colors)
    """
    G = nx.Graph()
    pos = {}  # словарь позиций для узлов
    labels = {}  # словарь меток для узлов
    colors = []  # список цветов для узлов

    # Слои по оси Y: hosts=0, edge=1, aggregation=2, core=3
    layer_y = {"host": 0, "edge": 1, "agg": 2, "core": 3}

    # Определяем количество core‑коммутаторов
    num_core = (k // 2) ** 2

    # Нумераторы для имён коммутаторов
    switch_counter = 1
    core_nodes = []
    agg_nodes_per_pod = [[] for _ in range(k)]
    edge_nodes_per_pod = [[] for _ in range(k)]
    host_nodes_per_pod = [[] for _ in range(k)]

    # Построение подов
    for pod in range(k):
        # edge коммутаторы в поде
        for edge_idx in range(k // 2):
            sw_name = f"s{switch_counter}"
            switch_counter += 1
            G.add_node(sw_name, type="edge")
            edge_nodes_per_pod[pod].append(sw_name)

            # Позиция: X рассчитывается из пода и edge_idx, Y = 1
            x = pod * (k // 2) + edge_idx
            y = layer_y["edge"]
            pos[sw_name] = (x, y)
            labels[sw_name] = sw_name
            colors.append("orange")

            # Хосты для edge
            for host_idx in range(hosts_per_edge):
                host_name = f"h{pod}_{edge_idx}_{host_idx}"
                G.add_node(host_name, type="host")
                # Позиция: X чуть смещается от edge, Y=0
                hx = x + (host_idx - (hosts_per_edge - 1) / 2) * 0.3
                hy = layer_y["host"]
                pos[host_name] = (hx, hy)
                labels[host_name] = host_name
                colors.append("red")
                host_nodes_per_pod[pod].append(host_name)
                # Добавляем ребро host↔edge
                G.add_edge(host_name, sw_name)

        # aggregation коммутаторы в поде
        for agg_idx in range(k // 2):
            sw_name = f"s{switch_counter}"
            switch_counter += 1
            G.add_node(sw_name, type="agg")
            agg_nodes_per_pod[pod].append(sw_name)
            # Позиция: X рассчитывается из пода и agg_idx, Y = 2
            x = pod * (k // 2) + agg_idx
            y = layer_y["agg"]
            pos[sw_name] = (x, y)
            labels[sw_name] = sw_name
            colors.append("purple")

            # Подключаем aggregation к edge внутри пода
            for edge_sw in edge_nodes_per_pod[pod]:
                G.add_edge(sw_name, edge_sw)

    # Core коммутаторы
    for core_idx in range(num_core):
        sw_name = f"s{switch_counter}"
        switch_counter += 1
        G.add_node(sw_name, type="core")
        core_nodes.append(sw_name)
        # Размещаем core узлы равномерно по оси X
        x = core_idx
        y = layer_y["core"]
        pos[sw_name] = (x, y)
        labels[sw_name] = sw_name
        colors.append("skyblue")

    # Подключаем каждую aggregation к каждому core
    for pod in range(k):
        for agg_sw in agg_nodes_per_pod[pod]:
            for core_sw in core_nodes:
                G.add_edge(agg_sw, core_sw)

    return G, pos, labels, colors


def visualize_clos(k=4, hosts_per_edge=2, outfile="clos_topology.png"):
    """Строит граф Clos‑топологии и сохраняет изображение в файл.

    :param int k: параметр fat‑tree (должен быть чётным)
    :param int hosts_per_edge: число хостов на каждый edge
    :param str outfile: имя выходного файла PNG
    """
    G, pos, labels, colors = build_clos_graph(k, hosts_per_edge)
    plt.figure(figsize=(12, 8))
    nx.draw(
        G,
        pos,
        labels=labels,
        node_color=colors,
        node_size=500,
        font_size=7,
        width=1,
        edge_color="gray",
    )
    plt.title(f"Clos topology (k={k}, hosts_per_edge={hosts_per_edge})")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(outfile)
    print(f"Топология сохранена в файл {outfile}")


if __name__ == "__main__":
    # По умолчанию визуализируем топологию 4‑pod с двумя хостами на каждый edge
    visualize_clos(k=4, hosts_per_edge=2)
