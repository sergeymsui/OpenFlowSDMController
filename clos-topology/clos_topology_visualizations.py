# -*- coding: utf-8 -*-
"""
visualize_clos_layers.py — 2D/3D визуализация Clos-топологии из pickle
с автоопределением уровней (host/access/aggregation/core).

"""

import argparse
import pickle
from collections import defaultdict

import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.collections import LineCollection
from mpl_toolkits.mplot3d.art3d import Line3DCollection


# -----------------------------
# Загрузка и нормализация графа
# -----------------------------
def load_graph(path: str):
    G = pickle.load(open(path, "rb"))
    if not isinstance(G, (nx.Graph, nx.DiGraph, nx.MultiGraph, nx.MultiDiGraph)):
        raise TypeError("Pickle не содержит граф NetworkX.")
    return G


def to_simple_undirected_with_labels(G_in):
    """Склеиваем направленные рёбра в одно неориентированное, собираем подписи портов."""
    if isinstance(G_in, (nx.Graph, nx.DiGraph)):
        MG = nx.MultiDiGraph(G_in)
    else:
        MG = G_in.copy()

    UG = nx.Graph()
    UG.add_nodes_from(MG.nodes(data=True))

    port_labels = defaultdict(list)

    for u, v, key, data in MG.edges(keys=True, data=True):
        sp = data.get("src_port")
        dp = data.get("dst_port")
        a, b = sorted([u, v])
        if u == a:
            left = f"{u}:{sp}" if sp is not None else f"{u}"
            right = f"{v}:{dp}" if dp is not None else f"{v}"
        else:
            left = f"{a}:{dp}" if dp is not None else f"{a}"
            right = f"{b}:{sp}" if sp is not None else f"{b}"
        port_labels[(a, b)].append(f"{left} \u2194 {right}")

    for (a, b), labels in port_labels.items():
        UG.add_edge(a, b, label="\n".join(sorted(set(labels))))

    return UG


# -----------------------------
# Определение уровней
# -----------------------------
def infer_levels(Gu: nx.Graph):
    """
    Возвращает:
      level_of[node] = 0..3  (0=host, 1=access, 2=aggregation, 3=core)
      level_names = {0:'host', 1:'access', 2:'aggregation', 3:'core'}
    Логика:
      - host: узлы с type=='host' или у которых имя похоже на hX_... (запасной вариант)
      - access: switch, который имеет хотя бы одного соседа-хоста
      - aggregation: switch без соседей-хостов, но с соседями-access
      - core: оставшиеся switch
    """
    # 1) классификация хостов
    hosts = set(n for n, d in Gu.nodes(data=True) if d.get("type") == "host")
    if not hosts:
        # запасной эвристический вариант по имени
        hosts = set(n for n in Gu.nodes if isinstance(n, str) and n.startswith("h"))

    level_of = {}
    for n in Gu.nodes:
        if n in hosts:
            level_of[n] = 0  # host

    # 2) access: switch с хотя бы одним хост-соседом
    for n, d in Gu.nodes(data=True):
        if n in level_of:
            continue
        if d.get("type") == "switch" or (isinstance(n, str) and n.startswith("s")):
            if any(nei in hosts for nei in Gu.neighbors(n)):
                level_of[n] = 1  # access

    # 3) aggregation: без хостов, но с соседями-access
    for n, d in Gu.nodes(data=True):
        if n in level_of:
            continue
        if d.get("type") == "switch" or (isinstance(n, str) and n.startswith("s")):
            neis = list(Gu.neighbors(n))
            if all(nei not in hosts for nei in neis) and any(
                level_of.get(nei) == 1 for nei in neis
            ):
                level_of[n] = 2  # aggregation

    # 4) core: оставшиеся сваичи
    for n, d in Gu.nodes(data=True):
        if n in level_of:
            continue
        if d.get("type") == "switch" or (isinstance(n, str) and n.startswith("s")):
            level_of[n] = 3  # core

    # На случай «прочих» типов узлов
    for n in Gu.nodes:
        if n not in level_of:
            level_of[n] = 1  # отнесём к access по умолчанию

    level_names = {0: "host", 1: "access", 2: "aggregation", 3: "core"}
    return level_of, level_names


# -----------------------------
# 2D раскладка (уровни по Y)
# -----------------------------
def layered_2d_positions(G: nx.Graph, level_of: dict, x_gap=1.8, y_gap=2.4):
    """Кладём узлы рядами по уровням: 0..3. Возвращает pos {node:(x,y)}."""
    buckets = defaultdict(list)
    for n in G.nodes:
        buckets[level_of[n]].append(n)

    pos = {}
    for lvl in sorted(buckets.keys()):
        nodes = sorted(buckets[lvl], key=str)
        count = len(nodes)
        xs = [i * x_gap for i in range(count)]
        # центрируем вокруг 0
        shift = (count - 1) * x_gap / 2 if count else 0
        for i, n in enumerate(nodes):
            pos[n] = (xs[i] - shift, -lvl * y_gap)  # ниже — больший lvl
    return pos


def draw_2d(
    G: nx.Graph, level_of: dict, level_names: dict, out_png: str | None, show: bool
):
    pos = layered_2d_positions(G, level_of)

    # палитра уровней (четыре контрастных цвета)
    colors = {
        0: "#1f77b4",  # host
        1: "#2ca02c",  # access
        2: "#ff7f0e",  # aggregation
        3: "#9467bd",  # core
    }

    plt.figure(figsize=(14, 10))
    # узлы по уровням
    for lvl, name in level_names.items():
        nodes = [n for n in G.nodes if level_of[n] == lvl]
        if nodes:
            nx.draw_networkx_nodes(
                G,
                pos,
                nodelist=nodes,
                node_size=700,
                node_color=colors.get(lvl, "#7f7f7f"),
                label=f"{lvl}: {name}",
                node_shape="o" if lvl == 0 else "s",
            )
    # рёбра
    nx.draw_networkx_edges(G, pos, width=1.6, alpha=0.85)
    nx.draw_networkx_labels(G, pos, font_size=9)

    # легенда
    plt.legend(scatterpoints=1, frameon=False, loc="upper right")
    plt.axis("off")
    plt.tight_layout()
    if out_png:
        plt.savefig(out_png, dpi=200, bbox_inches="tight")
        print(f"[OK] 2D PNG сохранён: {out_png}")
    if show:
        plt.show()
    plt.close()


# -----------------------------
# 3D раскладка (уровни по Z)
# -----------------------------
def layered_3d_positions(G: nx.Graph, level_of: dict, x_gap=1.8, y_gap=1.2, z_gap=1.8):
    """Каждый уровень на своей высоте z=lvl*z_gap, узлы раскладываем сеткой по x,y."""
    buckets = defaultdict(list)
    for n in G.nodes:
        buckets[level_of[n]].append(n)

    pos3 = {}
    for lvl in sorted(buckets.keys()):
        nodes = sorted(buckets[lvl], key=str)
        count = len(nodes)
        # простая прямоугольная сетка
        cols = max(1, int(round(count**0.5)))
        rows = (count + cols - 1) // cols
        # центрируем
        x_shift = (cols - 1) * x_gap / 2
        y_shift = (rows - 1) * y_gap / 2
        for idx, n in enumerate(nodes):
            r = idx // cols
            c = idx % cols
            x = c * x_gap - x_shift
            y = r * y_gap - y_shift
            z = lvl * z_gap
            pos3[n] = (x, y, z)
    return pos3


def draw_3d(
    G: nx.Graph, level_of: dict, level_names: dict, out_png: str | None, show: bool
):
    pos3 = layered_3d_positions(G, level_of)

    colors = {
        0: "#1f77b4",
        1: "#2ca02c",
        2: "#ff7f0e",
        3: "#9467bd",
    }

    fig = plt.figure(figsize=(14, 10))
    ax = fig.add_subplot(111, projection="3d")

    # узлы по уровням (разные слои Z)
    for lvl, name in level_names.items():
        xs, ys, zs, labels = [], [], [], []
        for n in G.nodes:
            if level_of[n] == lvl:
                x, y, z = pos3[n]
                xs.append(x)
                ys.append(y)
                zs.append(z)
                labels.append(n)
        if xs:
            ax.scatter(
                xs,
                ys,
                zs,
                s=60 if lvl == 0 else 40,
                depthshade=True,
                label=f"{lvl}: {name}",
                c=[colors.get(lvl, "#7f7f7f")] * len(xs),
            )

            # подписи узлов (не перебарщиваем для больших графов)
            if len(xs) <= 120:
                for x, y, z, lab in zip(xs, ys, zs, labels):
                    ax.text(x, y, z + 0.06, lab, fontsize=8, ha="center", va="bottom")

    # рёбра
    segs = []
    for u, v in G.edges():
        x1, y1, z1 = pos3[u]
        x2, y2, z2 = pos3[v]
        segs.append([(x1, y1, z1), (x2, y2, z2)])
    lc = Line3DCollection(segs, linewidths=1.2, alpha=0.85)
    ax.add_collection3d(lc)

    # косметика
    ax.set_axis_off()
    ax.legend(loc="upper left")
    # авто-границы
    all_x = [p[0] for p in pos3.values()] or [0]
    all_y = [p[1] for p in pos3.values()] or [0]
    all_z = [p[2] for p in pos3.values()] or [0]
    span = max(max(all_x) - min(all_x), max(all_y) - min(all_y), 1.0)
    cx = (max(all_x) + min(all_x)) / 2
    cy = (max(all_y) + min(all_y)) / 2
    cz = (max(all_z) + min(all_z)) / 2
    ax.set_xlim(cx - span / 1.2, cx + span / 1.2)
    ax.set_ylim(cy - span / 1.2, cy + span / 1.2)
    ax.set_zlim(min(all_z) - 0.5, max(all_z) + 0.5)

    plt.tight_layout()
    if out_png:
        plt.savefig(out_png, dpi=200, bbox_inches="tight")
        print(f"[OK] 3D PNG сохранён: {out_png}")
    if show:
        plt.show()
    plt.close()


# -----------------------------
# main
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--pickle", default="clos_topograph_k4.pickle", help="Путь к pickle с графом"
    )
    ap.add_argument("--png2d", default=None, help="PNG для 2D-визуализации")
    ap.add_argument("--png3d", default=None, help="PNG для 3D-визуализации")
    ap.add_argument("--show", action="store_true", help="Показать окна plt.show()")
    args = ap.parse_args()

    G_raw = load_graph(args.pickle)
    G = to_simple_undirected_with_labels(G_raw)

    level_of, level_names = infer_levels(G)

    draw_2d(G, level_of, level_names, out_png=args.png2d, show=args.show)
    draw_3d(G, level_of, level_names, out_png=args.png3d, show=args.show)


if __name__ == "__main__":
    main()
