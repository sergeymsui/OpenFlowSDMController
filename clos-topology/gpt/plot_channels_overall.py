#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# ---------- ДАННЫЕ (capacity = 100) ----------
labels = ["GRD", "FWA", "LAP", "UMST", "ILP", "MSA", "OSPF"]

# CHANNELS OVERALL
avg_thr_mbps = [88.60, 70.79, 72.65, 70.22, 81.24, 38.13, 45.21]
peak_thr_mbps = [358.18, 398.79, 282.50, 371.02, 291.09, 396.20, 384.80]

# При capacity=100, Avg MLU (%) == avg_thr_mbps
avg_mlu_pct = avg_thr_mbps[:]

C_TURQUOISE = "#17becf"
C_GRAY = "#6c757d"
C_LINE = "#2c3e50"

# ---------- ФИГУРА ----------
fig_w, fig_h = 12, 6
fig, ax1 = plt.subplots(figsize=(fig_w, fig_h))

x = np.arange(len(labels))
w = 0.38

# Столбцы по левой оси
bars_avg = ax1.bar(
    x - w / 2,
    avg_thr_mbps,
    width=w,
    label="Avg throughput",
    color=C_TURQUOISE,
    edgecolor="black",
    linewidth=0.4,
)
bars_peak = ax1.bar(
    x + w / 2,
    peak_thr_mbps,
    width=w,
    label="Peak throughput",
    color=C_GRAY,
    edgecolor="black",
    linewidth=0.4,
)

ax1.set_ylabel("Throughput [Mbps]")
ax1.set_xticks(x, labels)
ax1.set_xlabel("Algorithm")
ax1.grid(axis="y", linestyle="--", linewidth=0.6, alpha=0.5)
ax1.spines["top"].set_visible(False)
ax1.spines["right"].set_visible(False)


# Подписи над столбцами
def annotate_bars(ax, bars):
    for b in bars:
        v = b.get_height()
        ax.annotate(
            f"{v:.0f}",
            xy=(b.get_x() + b.get_width() / 2, v),
            xytext=(0, 2.0),
            textcoords="offset points",
            ha="center",
            va="bottom",
        )


annotate_bars(ax1, bars_avg)
annotate_bars(ax1, bars_peak)

# ЛЕГЕНДА
h1, l1 = ax1.get_legend_handles_labels()
ax1.legend(h1, l1, loc="upper left", frameon=False)

plt.tight_layout(pad=0.6)
plt.savefig("CHANNELS_OVERALL.png", dpi=500)
# plt.show()
