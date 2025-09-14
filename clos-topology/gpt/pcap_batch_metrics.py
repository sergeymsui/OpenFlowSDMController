#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, subprocess, sys, re, statistics
from pathlib import Path
from glob import glob


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        print(f"[ERROR] {' '.join(cmd)}\n{p.stderr}", file=sys.stderr)
        sys.exit(1)
    return p.stdout


def parse_io_stat(text, bin_sec):
    """
    Разбор `tshark -q -z io,stat,<bin>`.
    У вас формат с колонками "Frames | Bytes".
    Возвращает список bits/s по каждому тайм-бину.
    """
    bits = []
    for line in text.splitlines():
        # строки вида "  0 <>  1 |   958 | 30464012 |"
        if "<>" in line and "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3 and parts[2].isdigit():
                bytes_val = int(parts[2])
                bps = (bytes_val * 8) / bin_sec
                bits.append(bps)
    return bits


def parse_conv_tcp(text):
    flows = []
    for line in text.splitlines():
        m = re.match(
            r"\s*([0-9a-fA-F\.:]+):(\d+)\s+<->\s+([0-9a-fA-F\.:]+):(\d+)\s+(\d+)\s+(\d+)\s+([\d\.]+)",
            line,
        )
        if m:
            src, sp, dst, dp, pkts, byts, dur = m.groups()
            flows.append(
                {
                    "src": src,
                    "sp": int(sp),
                    "dst": dst,
                    "dp": int(dp),
                    "packets": int(pkts),
                    "bytes": int(byts),
                    "duration": float(dur),
                }
            )
    return flows


def human_bps(bps):
    units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]
    v = float(bps)
    i = 0
    while v >= 1000 and i < len(units) - 1:
        v /= 1000.0
        i += 1
    return f"{v:.2f} {units[i]}"


def file_metrics(pcap, cap_mbps, bin_sec):
    io = run(["tshark", "-r", pcap, "-q", "-z", f"io,stat,{bin_sec:g}"])
    series = parse_io_stat(io, bin_sec)
    cap_bps = cap_mbps * 1_000_000.0
    if series:
        avg_bps = sum(series) / len(series)
        peak_bps = max(series)
        mlu = (peak_bps / cap_bps) if cap_bps > 0 else 0.0
    else:
        avg_bps = peak_bps = mlu = 0.0
    return avg_bps, peak_bps, mlu, len(series)


def flows_from_files(files, tcp_port=None):
    all_flows = []
    for f in files:
        cmd = ["tshark", "-r", f, "-q", "-z", "conv,tcp"]
        if tcp_port:
            cmd = [
                "tshark",
                "-r",
                f,
                "-Y",
                f"tcp.port=={tcp_port}",
                "-q",
                "-z",
                "conv,tcp",
            ]
        out = run(cmd)
        flows = parse_conv_tcp(out)
        # добавим имя файла, чтобы отладить дубликаты при необходимости
        for fl in flows:
            fl["_file"] = f
        all_flows.extend(flows)
    return all_flows


def jain(values):
    if not values:
        return 0.0
    s = sum(values)
    s2 = sum(v * v for v in values)
    n = len(values)
    if s2 == 0:
        return 0.0
    return (s * s) / (n * s2)


def main():
    ap = argparse.ArgumentParser(
        description="Batch metrics from many PCAPs: MLU, Throughput, FCT, Fairness"
    )
    ap.add_argument(
        "--glob", required=True, help="Glob for PCAPs to aggregate (e.g. '/tmp/*.pcap')"
    )
    ap.add_argument(
        "--capacity-mbps",
        type=float,
        required=True,
        help="Link capacity (Mbps) for MLU on each pcap",
    )
    ap.add_argument(
        "--bin",
        type=float,
        default=1.0,
        help="io,stat bin size in seconds (default 1.0)",
    )
    ap.add_argument(
        "--flows-glob",
        default=None,
        help="Glob for PCAPs to compute per-flow FCT/Fairness (e.g. only receiver host pcaps)",
    )
    ap.add_argument(
        "--tcp-port",
        type=int,
        default=None,
        help="Optional TCP port filter for flow stats (e.g., 5201 for iperf3)",
    )
    ap.add_argument(
        "--out-csv",
        type=Path,
        default=Path("./pcap_summary.csv"),
        help="CSV with per-file metrics",
    )
    ap.add_argument(
        "--out-flows",
        type=Path,
        default=Path("./flows_summary.csv"),
        help="CSV with per-flow stats (if flows-glob set)",
    )
    args = ap.parse_args()

    files = sorted(glob(args.glob))
    if not files:
        print(f"[ERROR] no files matched: {args.glob}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] matched {len(files)} files for interface metrics")

    # per-file + network summary
    rows = []
    total_avg_sum = 0.0
    total_peak_sum = 0.0
    network_mlu = 0.0

    for f in files:
        avg_bps, peak_bps, mlu, n_bins = file_metrics(f, args.capacity_mbps, args.bin)
        rows.append((f, avg_bps, peak_bps, mlu, n_bins))
        total_avg_sum += avg_bps
        total_peak_sum += peak_bps
        network_mlu = max(network_mlu, mlu)

    # write per-file CSV
    with args.out_csv.open("w", encoding="utf-8") as out:
        out.write("file,avg_bps,peak_bps,MLU,time_bins\n")
        for f, avg, peak, mlu, bins in rows:
            out.write(f"{f},{avg:.3f},{peak:.3f},{mlu:.6f},{bins}\n")

    print("\n=== NETWORK SUMMARY (from interface pcaps) ===")
    print(f"Files:                {len(files)}")
    print(f"Total avg throughput: {human_bps(total_avg_sum)}")
    print(f"Total peak throughput:{human_bps(total_peak_sum)}")
    print(f"Network MLU (max):    {network_mlu*100:.2f}%")
    print(f"Per-file CSV:         {args.out_csv}")

    # optional: flows (FCT & fairness) from a subset (e.g., receiver pcaps)
    if args.flows_glob:
        ffiles = sorted(glob(args.flows_glob))
        if not ffiles:
            print(f"[WARN] flows-glob matched 0 files: {args.flows_glob}")
        else:
            print(f"\n[INFO] computing flows from {len(ffiles)} files (flows-glob)")
            flows = flows_from_files(ffiles, tcp_port=args.tcp_port)

            # чтобы не удваивать потоки, дедуплим по (src,sp,dst,dp) — берём запись с макс. bytes
            dedup = {}
            for fl in flows:
                key = (fl["src"], fl["sp"], fl["dst"], fl["dp"])
                if key not in dedup or fl["bytes"] > dedup[key]["bytes"]:
                    dedup[key] = fl
            flows_u = list(dedup.values())

            durations = [f["duration"] for f in flows_u if f["duration"] > 0]
            per_flow_thr = [
                (f["bytes"] * 8.0) / f["duration"] for f in flows_u if f["duration"] > 0
            ]
            fairness = jain(per_flow_thr)
            if durations:
                fct_median = statistics.median(durations)
                fct_p95 = (
                    statistics.quantiles(durations, n=100)[94]
                    if len(durations) >= 2
                    else fct_median
                )
            else:
                fct_median = fct_p95 = 0.0

            print("\n=== FLOW SUMMARY (from flows-glob) ===")
            print(f"Flows (uniq):         {len(flows_u)}")
            print(f"FCT median:           {fct_median:.3f} s")
            print(f"FCT p95:              {fct_p95:.3f} s")
            print(f"Fairness (Jain):      {fairness:.4f}")

            # write per-flow CSV
            with args.out_flows.open("w", encoding="utf-8") as out:
                out.write("src,sp,dst,dp,packets,bytes,duration_s,throughput_bps\n")
                for fl in flows_u:
                    thr = (
                        (fl["bytes"] * 8.0) / fl["duration"]
                        if fl["duration"] > 0
                        else 0.0
                    )
                    out.write(
                        f'{fl["src"]},{fl["sp"]},{fl["dst"]},{fl["dp"]},{fl["packets"]},{fl["bytes"]},{fl["duration"]:.6f},{thr:.3f}\n'
                    )
            print(f"Per-flow CSV:         {args.out_flows}")
    else:
        print(
            "\n[NOTE] Flows/FCT/Fairness не считались (не задан --flows-glob). "
            "Чтобы избежать двойного учёта, указывайте glob только для pcap приёмников, "
            "например '--flows-glob \"/tmp/hosts_rx/*.pcap\"'."
        )


if __name__ == "__main__":
    main()
