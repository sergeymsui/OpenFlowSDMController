#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clos Experiment (current): Avg Throughput & Avg MLU (no sorting)
– столбцы: Avg Throughput (левая ось)
– столбцы: Avg MLU (правая ось)
– без соединяющих линий/пиков; контрастные цвета и штриховки для печати IEEE
"""

import matplotlib.pyplot as plt
import pandas as pd
from textwrap import wrap

# ---- Данные ровно в том порядке, как в отчёте ----
# (алгоритм, avg_throughput_mbps, avg_mlu_percent)
data = [
    ("Adaptive Shortest Paths (ASP)", 96.5, 97.99),
    ("ILP", 59.30, 59.30),
    ("Greedy (GRD)", 87.50, 88.60),
    ("MSA", 39.90, 40.50),
    ("Frank–Wolfe (FWA)", 69.80, 70.79),
    ("USTM", 69.91, 70.45),
    ("OSPF", 44.5, 45.21),
    ("Load Aware Paths (LAP)", 70.4, 71.37),
]

df = pd.DataFrame(data, columns=["algorithm", "avg_mbps", "avg_mlu"])

x = range(len(df))
labels = ["\n".join(wrap(a, 22)) for a in df["algorithm"]]

plt.figure(figsize=(12, 6))
ax1 = plt.gca()

bar_w = 0.42
x_left = [i - bar_w / 2 for i in x]  # позиции для Throughput
x_right = [i + bar_w / 2 for i in x]  # позиции для MLU

# Цвета/штриховки (контрастные и читаемые в ч/б)
color_thr = "#00429d"  # тёмно-синий
color_mlu = "#42deb2"  # карминово-красный
hatch_thr = ""
hatch_mlu = ""

# Столбцы: средняя пропускная способность (левая ось)
bars_thr = ax1.bar(
    x_left,
    df["avg_mbps"],
    width=bar_w,
    label="Avg Throughput (Mbps)",
    color=color_thr,
    edgecolor="black",
    linewidth=0.6,
    hatch=hatch_thr,
)
ax1.set_ylabel("Throughput (Mbps)", fontsize=10)
ax1.set_xticks(list(x))
ax1.set_xticklabels(labels, fontsize=9)
ax1.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.8)

# Столбцы: средний MLU (%) — правая ось
ax2 = ax1.twinx()
bars_mlu = ax2.bar(
    x_right,
    df["avg_mlu"],
    width=bar_w,
    label="Avg MLU (%)",
    color=color_mlu,
    edgecolor="black",
    linewidth=0.6,
    hatch=hatch_mlu,
)
ax2.set_ylabel("Avg MLU (%)", fontsize=10)
ax2.set_ylim(0, max(110, int(df["avg_mlu"].max() * 1.1)))  # небольшой запас сверху

plt.title(
    "Clos Experiment (Current): Avg Throughput & Avg MLU by Algorithm", fontsize=11
)

# Легенда (из обеих осей)
h1, l1 = ax1.get_legend_handles_labels()
h2, l2 = ax2.get_legend_handles_labels()
ax1.legend(h1 + h2, l1 + l2, loc="upper right", frameon=False, fontsize=9)

plt.tight_layout()
plt.savefig("clos_metrics_avg_ieee.png", dpi=300)
plt.show()
