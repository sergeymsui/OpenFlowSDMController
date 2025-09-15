#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clos Experiment (current): one figure
– столбцы: Average Throughput (Mbps)
– точки:  Peak Throughput (Mbps)
– точки:  Avg MLU (%) на правой оси (без соединяющей линии)
"""

import matplotlib.pyplot as plt
import pandas as pd
from textwrap import wrap

# ---- Данные из текущего эксперимента ----
# ASP = Adaptive Shortest Paths, GRD = Greedy, FWA = Frank–Wolfe,
# USTM, OSPF, LAP = Load Aware Paths, ILP, MSA
data = [
    ("USTM", 100.30, 593.87, 100.30),
    ("ASP",   76.57, 329.21,  76.57),
    ("LAP",   74.75, 331.43,  74.75),
    ("FWA",   74.03, 386.25,  74.03),
    ("GRD",   72.11, 409.55,  72.11),
    ("ILP",   65.91, 313.53,  65.91),
    ("OSPF",  44.25, 379.62,  44.25),
    ("MSA",   35.71, 377.25,  35.71),
]

df = pd.DataFrame(data, columns=["algorithm", "avg", "peak", "mlu_avg"])
df = df.sort_values(by="avg", ascending=False).reset_index(drop=True)

x = range(len(df))
labels = ["\n".join(wrap(a, 20)) for a in df["algorithm"]]

plt.figure(figsize=(12, 6))
ax1 = plt.gca()

# Столбцы: средняя пропускная способность
bar_width = 0.55
bars = ax1.bar(list(x), df["avg"], width=bar_width, label="Avg Throughput (Mbps)")

ax1.set_ylabel("Throughput (Mbps)", fontsize=10)
ax1.set_xticks(list(x))
ax1.set_xticklabels(labels, fontsize=9)
ax1.grid(axis="y", linestyle=":", linewidth=0.5)

# Точки: пиковая пропускная способность (левая ось)
ax1.scatter(list(x), df["peak"], marker="o", s=50, label="Peak Throughput (Mbps)", zorder=3)

# Точки: Avg MLU (%) на правой оси (без линии)
ax2 = ax1.twinx()
ax2.scatter(list(x), df["mlu_avg"], marker="D", s=45, label="Avg MLU (%)", zorder=3)
ax2.set_ylabel("Avg MLU (%)", fontsize=10)
ax2.set_ylim(0, max(110, int(df["mlu_avg"].max() * 1.1)))  # небольшой запас сверху

plt.title("Clos Experiment (Current): Throughput and Avg MLU by Algorithm", fontsize=11)

# Совмещённая легенда
h1, l1 = ax1.get_legend_handles_labels()
h2, l2 = ax2.get_legend_handles_labels()
ax1.legend(h1 + h2, l1 + l2, loc="upper right", frameon=False, fontsize=9)

plt.tight_layout()
plt.savefig("clos_metrics_current_points.png", dpi=300)
plt.show()
