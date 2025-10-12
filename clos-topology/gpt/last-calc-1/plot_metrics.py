#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import math
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


def ci95_from_mean_std_count(mean: float, std: float, n: int):
    """95% ДИ для среднего по mean/std/n; возвращает (lo, hi) или (nan, nan) при n<=1."""
    if n is None or n <= 1 or not np.isfinite(std):
        return (np.nan, np.nan)
    # t-критическое (прибл.): для n>30 ~1.96; иначе берём типичные значения
    if n > 30:
        t = 1.96
    elif n >= 10:
        t = 2.262
    elif n >= 6:
        t = 2.776
    else:
        t = 4.303
    half = t * std / math.sqrt(n)
    return (mean - half, mean + half)


def read_and_prepare(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    # приводим числовые поля
    num_cols = [
        "throughput_mbps",
        "avg_tcp_rtt_ms",
        "duration_sec",
        "bytes",
        "pkts",
        "rtt_samples",
    ]
    for col in num_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    # фильтры валидности
    if "duration_sec" in df.columns:
        df = df[df["duration_sec"] > 0]
    if "throughput_mbps" in df.columns:
        df = df[df["throughput_mbps"].notna()]
    # algo_dir как строка
    if "algo_dir" in df.columns:
        df["algo_dir"] = df["algo_dir"].astype(str)
    else:
        df["algo_dir"] = "unknown"
    return df


def aggregate_metrics(df: pd.DataFrame) -> pd.DataFrame:
    rows = []

    # --- Throughput ---
    if "throughput_mbps" in df.columns:
        g = (
            df.groupby("algo_dir", dropna=False)["throughput_mbps"]
            .agg(mean="mean", std="std", count="count")
            .reset_index()
        )
        for _, r in g.iterrows():
            lo, hi = ci95_from_mean_std_count(r["mean"], r["std"], int(r["count"]))
            rows.append(
                {
                    "algo_dir": r["algo_dir"],
                    "metric": "throughput_mbps",
                    "mean": r["mean"],
                    "ci95_lo": lo,
                    "ci95_hi": hi,
                    "count": int(r["count"]),
                }
            )

    # --- TCP RTT ---
    if "avg_tcp_rtt_ms" in df.columns and "rtt_samples" in df.columns:
        mask = df["avg_tcp_rtt_ms"].notna() & (df["rtt_samples"].fillna(0) > 0)
        g = (
            df[mask]
            .groupby("algo_dir", dropna=False)["avg_tcp_rtt_ms"]
            .agg(mean="mean", std="std", count="count")
            .reset_index()
        )
        for _, r in g.iterrows():
            lo, hi = ci95_from_mean_std_count(r["mean"], r["std"], int(r["count"]))
            rows.append(
                {
                    "algo_dir": r["algo_dir"],
                    "metric": "avg_tcp_rtt_ms",
                    "mean": r["mean"],
                    "ci95_lo": lo,
                    "ci95_hi": hi,
                    "count": int(r["count"]),
                }
            )

    out = pd.DataFrame(
        rows, columns=["algo_dir", "metric", "mean", "ci95_lo", "ci95_hi", "count"]
    )
    return out


def plot_bar_with_ci(ax, xlabels, means, ci_los, ci_his, title, ylabel):
    x = np.arange(len(xlabels))
    ax.bar(x, means)
    yerr = np.vstack(
        [np.array(means) - np.array(ci_los), np.array(ci_his) - np.array(means)]
    )
    yerr = np.nan_to_num(yerr, nan=0.0)
    ax.errorbar(x, means, yerr=yerr, fmt="none", capsize=4, linewidth=1)
    ax.set_xticks(x)
    ax.set_xticklabels(xlabels, rotation=30, ha="right")
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Путь к входному CSV (flows.csv)")
    ap.add_argument(
        "--outdir", default="./plots", help="Каталог для сохранения графиков/агрегаций"
    )
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    df = read_and_prepare(args.csv)
    if df.empty:
        raise SystemExit("Входной CSV пуст или не содержит валидных строк.")

    agg = aggregate_metrics(df)
    if agg.empty:
        raise SystemExit(
            "После агрегации нет данных. Проверьте столбцы 'throughput_mbps' и 'avg_tcp_rtt_ms'."
        )

    agg_out = os.path.join(args.outdir, "aggregated_metrics.csv")
    agg.to_csv(agg_out, index=False)

    # --- График Throughput ---
    tput = agg[agg["metric"] == "throughput_mbps"].copy()
    if not tput.empty:
        tput = tput.sort_values("mean", ascending=False)
        fig1, ax1 = plt.subplots(figsize=(10, 5))
        plot_bar_with_ci(
            ax1,
            xlabels=tput["algo_dir"].tolist(),
            means=tput["mean"].tolist(),
            ci_los=tput["ci95_lo"].tolist(),
            ci_his=tput["ci95_hi"].tolist(),
            title="Средний Throughput по алгоритмам (±95% ДИ)",
            ylabel="Мбит/с",
        )
        tput_png = os.path.join(args.outdir, "throughput_mbps_by_algo.png")
        fig1.tight_layout()
        fig1.savefig(tput_png, dpi=150)
        print(f"- график Throughput: {tput_png}")
    else:
        print("Предупреждение: нет данных для Throughput-графика.")

    # --- График RTT ---
    rtt = agg[agg["metric"] == "avg_tcp_rtt_ms"].copy()
    if not rtt.empty:
        rtt = rtt.sort_values("mean", ascending=True)
        fig2, ax2 = plt.subplots(figsize=(10, 5))
        plot_bar_with_ci(
            ax2,
            xlabels=rtt["algo_dir"].tolist(),
            means=rtt["mean"].tolist(),
            ci_los=rtt["ci95_lo"].tolist(),
            ci_his=rtt["ci95_hi"].tolist(),
            title="Средний TCP RTT по алгоритмам (±95% ДИ)",
            ylabel="мс",
        )
        rtt_png = os.path.join(args.outdir, "rtt_ms_by_algo.png")
        fig2.tight_layout()
        fig2.savefig(rtt_png, dpi=150)
        print(f"- график RTT:        {rtt_png}")
    else:
        print(
            "Предупреждение: нет данных RTT (колонка avg_tcp_rtt_ms пустая или нет TCP-образцов)."
        )

    print(f"- агрегированные метрики: {agg_out}")
    print("Готово.")


if __name__ == "__main__":
    main()
