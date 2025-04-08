import csv
from collections import defaultdict
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.ticker as ticker
import statistics
import os

def load_bandwidth_relative(csv_file, interval='second'):
    time_buckets = defaultdict(int)
    start_time = None

    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = datetime.fromisoformat(row['timestamp'].replace("Z", "+00:00"))
                length = int(row["length"])

                if start_time is None:
                    start_time = ts

                delta = ts - start_time

                if interval == 'second':
                    total_seconds = int(delta.total_seconds())
                elif interval == 'minute':
                    total_seconds = int(delta.total_seconds() // 60)
                else:
                    raise ValueError("Unsupported interval")

                time_buckets[total_seconds] += length
            except Exception:
                continue

    return dict(sorted(time_buckets.items()))

def plot_multiple_bandwidth_series(file_list, interval='second', duration_limit=300):
    plt.figure(figsize=(14, 6))

    ax = plt.gca()
    label_padding = 5  # отступ от средней линии
    label_box_height = 22  # высота плашки в пикселях

    used_y_positions = []

    def find_non_overlapping_y(y_center, step=label_box_height, max_attempts=20):
        """
        Пытается найти свободное вертикальное положение, начиная с y_center,
        чередуя вверх и вниз.
        """
        for i in range(max_attempts):
            direction = (-1) ** i  # вверх/вниз чередование
            offset = (i + 1) // 2 * step * direction
            y_try = y_center + offset
            if all(abs(y_try - y_used) >= step for y_used in used_y_positions):
                used_y_positions.append(y_try)
                return y_try
        # если не нашли — ставим как есть (может пересечься)
        return y_center

    label_anchor = 10
    for csv_file in file_list:
        bandwidth = load_bandwidth_relative(csv_file, interval=interval)
        bandwidth = {t: v for t, v in bandwidth.items() if t <= duration_limit}

        times = list(bandwidth.keys())
        values = list(bandwidth.values())
        avg = statistics.mean(values) if values else 0
        label = os.path.splitext(os.path.basename(csv_file))[0]

        line = ax.plot(times, values, label=f"{label} (ср. {int(avg):,} Б/с)", linewidth=2)[0]
        color = line.get_color()

        ax.fill_between(times, values, color=color, alpha=0.1)
        ax.axhline(avg, linestyle='--', linewidth=1.5, color=color, alpha=0.8)

        # Поиск свободного места
        y_pos = find_non_overlapping_y(avg)

        ax.text(
            label_anchor, y_pos + label_padding,
            label,
            ha='left', va='bottom',
            fontsize=9, color='white',
            bbox=dict(
                boxstyle="round,pad=0.3",
                facecolor=color,
                edgecolor='none',
                alpha=1.0
            ),
            zorder=10
        )
        label_anchor += 10

    # Оформление
    ax.set_title("Сравнение пропускной способности по времени (нормализованное начало)", fontsize=16)
    ax.set_xlabel("Время (секунды от начала захвата)", fontsize=12)
    ax.set_ylabel("Объём трафика (байты/секунда)", fontsize=12)
    ax.grid(True, linestyle='--', alpha=0.5)

    ax.set_ylim(0)
    ax.set_xlim(0, duration_limit)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f'{int(x):,}'.replace(',', ' ')))

    ax.legend()
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    switch = "s8"
    files = [
        f"ospf-{switch}-eth1_tcp_stats.csv",
        f"ilp-{switch}-eth1_tcp_stats.csv",
        f"grd-{switch}-eth1_tcp_stats.csv",
        f"msa-{switch}-eth1_tcp_stats.csv",
        f"fwa-{switch}-eth1_tcp_stats.csv",
        f"ustm-{switch}-eth1_tcp_stats.csv",
    ]
    plot_multiple_bandwidth_series(files, interval='second')  # можно 'minute'
