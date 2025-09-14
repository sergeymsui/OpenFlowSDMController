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


def parse_conv_tcp(text):
    # строки вида: "10.0.0.1:1234 <-> 10.0.0.2:5001   100  123456  1.234"
    flows = []
    line_re = re.compile(
        r"\s*([0-9a-fA-F\.:]+):(\d+)\s+<->\s+([0-9a-fA-F\.:]+):(\d+)\s+(\d+)\s+(\d+)\s+([\d\.]+)"
    )
    for line in text.splitlines():
        m = line_re.match(line)
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


def normalize_key(f):
    a = (f["src"], f["sp"])
    b = (f["dst"], f["dp"])
    return tuple(sorted((a, b)))


def jain(values):
    if not values:
        return 0.0
    s = sum(values)
    s2 = sum(v * v for v in values)
    n = len(values)
    return 0.0 if s2 == 0 else (s * s) / (n * s2)


def main():
    ap = argparse.ArgumentParser(
        description="Compute Flows/FCT/Fairness from many PCAPs (core/agg captures)."
    )
    ap.add_argument("--glob", required=True, help='PCAP glob, e.g. "/tmp/pcaps/*.pcap"')
    ap.add_argument(
        "--tcp-port",
        type=int,
        default=5001,
        help="Traffic port (iperf=5001, iperf3=5201)",
    )
    ap.add_argument(
        "--src-subnet",
        default=None,
        help='Optional src subnet filter, e.g. "10.0.0.0/8"',
    )
    ap.add_argument(
        "--dst-subnet",
        default=None,
        help='Optional dst subnet filter, e.g. "10.0.0.0/8"',
    )
    ap.add_argument(
        "--out-flows",
        type=Path,
        default=Path("./flows_summary.csv"),
        help="Per-flow CSV output",
    )
    args = ap.parse_args()

    files = sorted(glob(args.glob))
    if not files:
        print(f"[ERROR] no files matched: {args.glob}", file=sys.stderr)
        sys.exit(1)

    # Display-filter на уровне IP/TCP (без MAC, чтобы работало на core/agg)
    filt = f"ip && tcp && tcp.port=={args.tcp_port}"
    # опциональные подсети можно довесить, если нужно:
    # (tshark не поддерживает удобной ip.addr in subnet в display-фильтрах,
    # поэтому этот пункт оставим опциональным и без усложнений)
    print(f"[INFO] matched {len(files)} files")
    print(f"[INFO] display filter:\n{filt}\n")

    dedup = {}
    total_seen = 0

    for f in files:
        cmd = ["tshark", "-r", f, "-Y", filt, "-q", "-z", "conv,tcp"]
        out = run(cmd)
        flows = parse_conv_tcp(out)
        total_seen += len(flows)
        for fl in flows:
            key = normalize_key(fl)
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

    print("=== FLOW SUMMARY ===")
    print(f"Files parsed:     {len(files)}")
    print(f"Flows seen (raw): {total_seen}")
    print(f"Flows unique:     {len(flows_u)}")
    print(f"FCT median:       {fct_median:.3f} s")
    print(f"FCT p95:          {fct_p95:.3f} s")
    print(f"Fairness (Jain):  {fairness:.4f}")

    with args.out_flows.open("w", encoding="utf-8") as out:
        out.write("src,sp,dst,dp,packets,bytes,duration_s,throughput_bps\n")
        for fl in flows_u:
            thr = (fl["bytes"] * 8.0) / fl["duration"] if fl["duration"] > 0 else 0.0
            out.write(
                f'{fl["src"]},{fl["sp"]},{fl["dst"]},{fl["dp"]},{fl["packets"]},{fl["bytes"]},{fl["duration"]:.6f},{thr:.3f}\n'
            )
    print(f"Per-flow CSV:     {args.out_flows}")


if __name__ == "__main__":
    main()
