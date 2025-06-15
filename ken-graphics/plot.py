import csv
from collections import defaultdict
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.ticker as ticker
import statistics
from scipy.signal import savgol_filter


def load_bandwidth_relative(csv_file, interval="second"):
    time_buckets = defaultdict(int)
    start_time = None

    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                length = int(row["length"])

                if start_time is None:
                    start_time = ts

                delta = ts - start_time

                if interval == "second":
                    total_seconds = int(delta.total_seconds())
                elif interval == "minute":
                    total_seconds = int(delta.total_seconds() // 60)
                else:
                    raise ValueError("Unsupported interval")

                time_buckets[total_seconds] += length
            except Exception:
                continue

    return dict(sorted(time_buckets.items()))


def seconds_to_time(x, pos):
    """Формат для оси X как в Wireshark — MM:SS"""

    if int(x) % 10 > 0:
        return ""
    return int(x)


def compact_bytes(x, pos):
    """Формат компактных единиц для оси Y"""
    for unit in ["Bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"]:
        if x < 1000:
            return f"{x:.0f} {unit}"
        x /= 1000

    return f"{x:.0f} P"


def plot_multiple_bandwidth_series(
    file_list, interval="second", start_time=100, end_time=300
):
    multiplicit = 1.3
    plt.figure(figsize=(12 * multiplicit, 5 * multiplicit))
    ax = plt.gca()

    label_padding = 5
    label_box_height = 22
    used_y_positions = list()

    def find_non_overlapping_y(y_center, step=label_box_height, max_attempts=20):
        for i in range(max_attempts):
            direction = (-1) ** i
            offset = (i + 1) // 2 * step * direction
            y_try = y_center + offset
            if all(abs(y_try - y_used) >= step for y_used in used_y_positions):
                used_y_positions.append(y_try)
                return y_try
        return y_center

    label_anchor = 10
    m_val = 0
    for csv_file, name in file_list.items():
        bandwidth = load_bandwidth_relative(csv_file, interval=interval)
        bandwidth = {t: v for t, v in bandwidth.items() if start_time <= t <= end_time}

        times = list(range(start_time, end_time + 1))
        values = [bandwidth.get(t, 0) for t in times]

        if len(values) < 7:
            continue  # Пропускаем если данных слишком мало для сглаживания

        # Dynamic window size (не больше длины массива и нечетное)
        window = min(len(values) // 2 * 2 + 1, 17)
        smoothed = savgol_filter(values, window, min(7, window - 1))

        avg = statistics.mean(values) if values else 0
        label = name

        line = ax.plot(
            times,
            smoothed,
            label=f"{label} (Avg. {int(avg // 1_000_000):,} Мбит/с)",
            linewidth=2,
        )[0]
        m_val = max(m_val, max(smoothed))
        color = line.get_color()

        ax.axhline(avg, linestyle="--", linewidth=1.5, color=color, alpha=0.8)

        y_pos = find_non_overlapping_y(avg)
        ax.text(
            start_time + 5 + label_anchor,
            y_pos + 5,
            label,
            ha="left",
            va="bottom",
            fontsize=9,
            color="white",
            bbox=dict(
                boxstyle="round,pad=0.3", facecolor=color, edgecolor="none", alpha=1.0
            ),
            zorder=10,
        )
        label_anchor += 10

    ax.set_xlabel("Time (s)", fontsize=12)
    ax.set_ylabel("Throughput", fontsize=12)
    ax.grid(True, linestyle="--", alpha=0.5)

    ax.set_xlim(start_time, end_time)
    ax.set_ylim(0, 1.2 * m_val)

    ax.xaxis.set_major_formatter(ticker.FuncFormatter(seconds_to_time))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(compact_bytes))

    ax.legend()
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    switch = "s12-eth6"
    files = {
        f"./vl2/lwr/{switch}.csv": "BMcW",
        f"./vl2/ospf/{switch}.csv": "OSPF",
        f"./vl2/ilp/{switch}.csv": "ILP",
        f"./vl2/grd/{switch}.csv": "GRD",
        f"./vl2/msa/{switch}.csv": "MSA",
        f"./vl2/fwa/{switch}.csv": "FWA",
        f"./vl2/sdm/{switch}.csv": "USTM",
    }
    plot_multiple_bandwidth_series(files, interval="second")
