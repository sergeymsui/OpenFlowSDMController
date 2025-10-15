#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# ---------- ДАННЫЕ (capacity = 100) ----------
labels = ["GRD", "FWA", "LAP", "UMST", "ILP", "MSA", "OSPF"]

# Throughput (Mbps)
tput_bw_mean = [
    17.091,
    16.659,
    15.026,
    14.226,
    14.095,
    10.834,
    10.764,
]  # byte-weighted mean
tput_avg = [
    5.344,
    4.294,
    4.309,
    3.819,
    4.696,
    2.220,
    2.739,
]  # avg per-flow (mean)

# Median TCP RTT (ms)
rtt_median = [48.569, 62.549, 191.508, 68.870, 63.484, 53.763, 41.755]

# ---------- СТИЛЬ «IEEE-like» ----------
# Шрифты и размеры (приближенно под колонку IEEE)
# mpl.rcParams.update(
#     {
#         "font.family": "serif",
#         "font.serif": ["DejaVu Serif"],
#         "font.size": 9,  # базовый размер
#         "axes.titlesize": 9,
#         "axes.labelsize": 9,
#         "xtick.labelsize": 8,
#         "ytick.labelsize": 8,
#         "legend.fontsize": 8,
#         "axes.linewidth": 0.8,
#         "xtick.major.width": 0.8,
#         "ytick.major.width": 0.8,
#         "savefig.dpi": 300,
#     }
# )

# Цвета (первый — бирюзовый, как просили; остальное — сдержанная гамма)
C_TURQUOISE = "#17becf"  # бирюзовый
C_GRAY = "#6c757d"
C_LINE = "#2c3e50"  # тёмно-графитовый для линии RTT

# ---------- ФИГУРА ----------
# Одноколоночный формат IEEE ~3.5" по ширине (в дюймах)
fig_w, fig_h = 12, 6
fig, ax1 = plt.subplots(figsize=(fig_w, fig_h))

x = np.arange(len(labels))
w = 0.38  # ширина столбца

# Левая ось: два набора столбцов
bars_bw = ax1.bar(
    x - w / 2,
    tput_bw_mean,
    width=w,
    label="Throughput (bw-mean)",
    color=C_TURQUOISE,
    edgecolor="black",
    linewidth=0.4,
)
bars_av = ax1.bar(
    x + w / 2,
    tput_avg,
    width=w,
    label="Throughput (avg per-flow)",
    color=C_GRAY,
    edgecolor="black",
    linewidth=0.4,
)

ax1.set_ylabel("Throughput [Mbps]")
ax1.set_xticks(x, labels, rotation=0)
ax1.set_xlabel("Algorithm")

# Тонкий горизонтальный грид
ax1.grid(axis="y", linestyle="--", linewidth=0.6, alpha=0.5)
for spine in ["top", "right"]:
    ax1.spines[spine].set_visible(False)


# Подписи над столбцами (компактно)
def annotate_bars(ax, bars):
    for b in bars:
        v = b.get_height()
        ax.annotate(
            f"{v:.2f}",
            xy=(b.get_x() + b.get_width() / 2, v),
            xytext=(0, 2.0),
            textcoords="offset points",
            ha="center",
            va="bottom",
        )


annotate_bars(ax1, bars_bw)
annotate_bars(ax1, bars_av)

# Правая ось: медиана RTT (линия с маркерами)
ax2 = ax1.twinx()
ax2.plot(
    x,
    rtt_median,
    marker="o",
    markersize=3.5,
    linewidth=1.4,
    color=C_LINE,
    label="Median TCP RTT",
)
ax2.set_ylabel("TCP RTT [ms]")
for spine in ["top"]:
    ax2.spines[spine].set_visible(False)

# Подписи точек RTT (ненавязчиво)
for xi, val in zip(x, rtt_median):
    ax2.annotate(
        f"{val:.0f}",
        xy=(xi, val),
        xytext=(0, 4),
        textcoords="offset points",
        ha="center",
        va="bottom",
    )

# Легенда: объединяем обе оси
h1, l1 = ax1.get_legend_handles_labels()
h2, l2 = ax2.get_legend_handles_labels()
leg = ax1.legend(h1 + h2, l1 + l2, loc="upper right", frameon=False)

# Заголовок для внутреннего пользования (в статью обычно не печатают)
# plt.title("Throughput (bw-mean & avg) vs Median TCP RTT (capacity=100)")

plt.tight_layout(pad=0.6)
plt.savefig("FLOWS_OVERALL.png", dpi=500)
# plt.show()
