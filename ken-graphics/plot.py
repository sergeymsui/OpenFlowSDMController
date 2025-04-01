import csv
from collections import defaultdict
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.dates as mdates
import matplotlib.ticker as ticker
import statistics

def load_bandwidth_by_time(csv_file, interval='second'):
    time_buckets = defaultdict(int)

    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = datetime.fromisoformat(row['timestamp'].replace("Z", "+00:00"))
                length = int(row["length"])

                if interval == 'second':
                    time_key = ts.replace(microsecond=0)
                elif interval == 'minute':
                    time_key = ts.replace(second=0, microsecond=0)
                else:
                    raise ValueError("Unsupported interval")

                time_buckets[time_key] += length
            except Exception:
                continue

    return dict(sorted(time_buckets.items()))

def plot_bandwidth_timeline(bandwidth_by_time):
    times = list(bandwidth_by_time.keys())
    bytes_transferred = list(bandwidth_by_time.values())
    avg_bandwidth = statistics.mean(bytes_transferred)

    plt.figure(figsize=(14, 6))
    plt.plot(times, bytes_transferred, label="Пропускная способность", color="royalblue", marker="", linewidth=2)
    plt.fill_between(times, bytes_transferred, color="royalblue", alpha=0.2)

    # Горизонтальная линия среднего значения
    plt.axhline(avg_bandwidth, color='red', linestyle='--', linewidth=2, label=f"Среднее: {int(avg_bandwidth):,} байт/сек")

    # Оформление
    plt.title("Пропускная способность по времени", fontsize=16)
    plt.xlabel("Время", fontsize=12)
    plt.ylabel("Объём трафика (байты/секунда)", fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.5)

    # Форматирование времени на оси X
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.xticks(rotation=45)

    # Форматирование оси Y
    plt.gca().yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f'{int(x):,}'.replace(',', ' ')))

    plt.tight_layout()
    plt.legend()
    plt.show()

if __name__ == "__main__":
    csv_file = "grd-s9-eth1_tcp_stats.csv"
    bandwidth_by_time = load_bandwidth_by_time(csv_file, interval='second')  # можно поменять на 'minute'
    plot_bandwidth_timeline(bandwidth_by_time)
