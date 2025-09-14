#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Построение одной диаграммы:
– два столбца (Average/Peak Throughput)
– линия MLU (%) на правой оси
"""

import matplotlib.pyplot as plt
import pandas as pd
from textwrap import wrap

# ---- Данные из эксперимента ----
data = [
    ("ASP", 271.68, 320.34, 18.98),
    ("ILP", 334.58, 405.36, 26.50),
    ("GRD", 339.34, 397.32, 32.74),
    ("MSA", 217.91, 224.30, 52.18),
    ("FWA", 257.71, 278.18, 44.79),
    ("USTM", 254.63, 303.26, 43.54),
    ("OSPF", 233.03, 241.94, 44.78),
    ("LAP", 192.67, 212.45, 29.74),
]

df = pd.DataFrame(data, columns=["algorithm", "avg", "peak", "mlu"])
df = df.sort_values(by="avg", ascending=False).reset_index(drop=True)

x = range(len(df))
labels = ["\n".join(wrap(a, 20)) for a in df["algorithm"]]

plt.figure(figsize=(12, 6))
ax1 = plt.gca()

bar_width = 0.38
bars1 = ax1.bar(
    [i - bar_width / 2 for i in x],
    df["avg"],
    width=bar_width,
    color="#1f77b4",
    label="Avg Throughput (Mbps)",
)
bars2 = ax1.bar(
    [i + bar_width / 2 for i in x],
    df["peak"],
    width=bar_width,
    color="#7f7f7f",
    label="Peak Throughput (Mbps)",
)

ax1.set_ylabel("Throughput (Mbps)", fontsize=10)
ax1.set_xticks(x)
ax1.set_xticklabels(labels, fontsize=9)
ax1.grid(axis="y", color="lightgray", linestyle=":", linewidth=0.5)

# Линия MLU
ax2 = ax1.twinx()
ax2.plot(x, df["mlu"], marker="o", linewidth=2, color="#d62728", label="MLU (%)")
ax2.set_ylabel("MLU (%)", fontsize=10)

plt.title("Clos Experiment: Throughput and MLU by Algorithm", fontsize=11)

handles1, labels1 = ax1.get_legend_handles_labels()
handles2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(
    handles1 + handles2, labels1 + labels2, loc="upper right", frameon=False, fontsize=9
)

plt.tight_layout()
plt.savefig("clos_one_figure_metrics_ieee.png", dpi=300)
plt.show()
