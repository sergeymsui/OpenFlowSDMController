#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
import sys
import re
import statistics
from pathlib import Path

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        print(f"[ERROR] command failed: {' '.join(cmd)}\n{p.stderr}", file=sys.stderr)
        sys.exit(1)
    return p.stdout

def parse_io_stat(text):
    """
    Разбор вывода `tshark -q -z io,stat,<bin>`.
    Возвращает список значений bits/s (float) по каждому тайм-бинy.
    """
    bits = []
    # строки вида: "  0.000-1.000     12345   987654  7.90 Mbits/s ..."
    line_re = re.compile(r"^\s*\d+\.\d+\-\d+\.\d+.*?([\d\.]+)\s+K?M?G?bits/s\s*$", re.IGNORECASE)
    # Но формат бывает разный; возьмём последнюю числовую колонку как bits/s:
    fallback_re = re.compile(r"^\s*\d+\.\d+\-\d+\.\d+\s+.*?\s+([\d\.]+)$")

    for line in text.splitlines():
        if re.search(r"^\s*\d+\.\d+\-\d+\.\d+", line):
            parts = line.split()
            try:
                # Последний столбец обычно "Bits/s"
                val = float(parts[-1])
                bits.append(val)
            except Exception:
                m = fallback_re.match(line)
                if m:
                    bits.append(float(m.group(1)))
    return bits

def human_bps(bps):
    units = ["bps","Kbps","Mbps","Gbps","Tbps"]
    v = float(bps)
    i = 0
    while v >= 1000 and i < len(units)-1:
        v /= 1000.0
        i += 1
    return f"{v:.2f} {units[i]}"

def parse_conv_tcp(text):
    """
    Разбор `tshark -q -z conv,tcp`:
    Возвращает список словарей flows = [{src,dst,sp,dp,packets,bytes,duration_sec}, ...]
    """
    flows = []
    in_table = False
    header_seen = False
    for line in text.splitlines():
        if "TCP Conversations" in line:
            in_table = True
            header_seen = False
            continue
        if not in_table:
            continue
        if not header_seen and re.search(r"Address", line) and re.search(r"Packets", line):
            header_seen = True
            continue
        if header_seen:
            # Конец таблицы
            if line.strip().startswith("=") or line.strip().startswith("|==="):
                continue
            if line.strip() == "" or "Total:" in line:
                continue
            # Ожидаем строки вида:
            #   10.0.0.1:1234 <-> 10.0.0.2:5201      100    123456    1.234
            # Разрежем по пробелам аккуратно: сначала заберём левую и правую части адресов
            m = re.match(r"\s*([0-9a-fA-F\.:]+):(\d+)\s+<->\s+([0-9a-fA-F\.:]+):(\d+)\s+(\d+)\s+(\d+)\s+([\d\.]+)", line)
            if m:
                src, sp, dst, dp, pkts, byts, dur = m.groups()
                flows.append({
                    "src": src, "sp": int(sp),
                    "dst": dst, "dp": int(dp),
                    "packets": int(pkts),
                    "bytes": int(byts),
                    "duration": float(dur)
                })
    return flows

def jain_index(values):
    if not values:
        return 0.0
    s1 = sum(values)
    s2 = sum(v*v for v in values)
    n = len(values)
    if s2 == 0:
        return 0.0
    return (s1*s1) / (n * s2)

def main():
    ap = argparse.ArgumentParser(description="Compute MLU, Throughput, FCT, Fairness from a PCAP using tshark.")
    ap.add_argument("pcap", help="Path to pcap file")
    ap.add_argument("--capacity-mbps", type=float, required=True,
                    help="Link capacity for MLU (in Mbps), e.g., 500")
    ap.add_argument("--bin", type=float, default=1.0,
                    help="Time bin for io,stat in seconds (default: 1.0)")
    ap.add_argument("--tcp-port", type=int, default=None,
                    help="Optional TCP port filter (e.g., 5201 for iperf3) for conv stats")
    ap.add_argument("--out-csv", type=Path, default=None,
                    help="Optional CSV path to dump per-flow stats")
    args = ap.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        print(f"[ERROR] file not found: {pcap}", file=sys.stderr); sys.exit(1)

    # ---- 1) io,stat ----
    io_cmd = ["tshark", "-r", str(pcap), "-q", "-z", f"io,stat,{args.bin:g}"]
    io_out = run(io_cmd)
    bits_series = parse_io_stat(io_out)
    if not bits_series:
        print("[WARN] no traffic detected in io,stat (bits/s series empty)")
    cap_bps = args.capacity_mbps * 1_000_000.0

    total_time_bins = len(bits_series)
    avg_bps = sum(bits_series)/total_time_bins if total_time_bins else 0.0
    peak_bps = max(bits_series) if bits_series else 0.0
    mlu = (peak_bps / cap_bps) if cap_bps > 0 else 0.0

    # ---- 2) conv,tcp ----
    conv_cmd = ["tshark", "-r", str(pcap), "-q", "-z", "conv,tcp"]
    if args.tcp_port:
        conv_cmd = ["tshark", "-r", str(pcap), "-Y", f"tcp.port=={args.tcp_port}", "-q", "-z", "conv,tcp"]
    conv_out = run(conv_cmd)
    flows = parse_conv_tcp(conv_out)

    # Вычислим FCT и пер-флоу throughput
    durations = [f["duration"] for f in flows if f["duration"] > 0]
    per_flow_thr = [(f["bytes"] * 8.0) / f["duration"] for f in flows if f["duration"] > 0]  # bps
    fairness = jain_index(per_flow_thr)

    # Агрегаты FCT
    fct_median = statistics.median(durations) if durations else 0.0
    fct_p95 = (statistics.quantiles(durations, n=100)[94] if len(durations) >= 2 else fct_median) if durations else 0.0

    # Итоговый Throughput (агрегированный) можно брать как средний по io,stat
    # или как сумму per-flow throughput. Возьмём оба для информации:
    sum_per_flow_bps = sum(per_flow_thr)

    # ---- Вывод ----
    print("=== PCAP METRICS ===")
    print(f"File:            {pcap}")
    print(f"Time bin:        {args.bin:.3f} s")
    print(f"Capacity:        {args.capacity_mbps:.2f} Mbps")
    print("")
    print(f"Throughput(avg): {human_bps(avg_bps)}   (io,stat)")
    print(f"Throughput(peak):{human_bps(peak_bps)}  (io,stat)")
    print(f"Throughput(sum): {human_bps(sum_per_flow_bps)} (sum of per-flow)")
    print(f"MLU (peak/cap):  {mlu*100:.2f}%")
    print("")
    print(f"Flows counted:   {len(flows)}")
    print(f"FCT median:      {fct_median:.3f} s")
    print(f"FCT p95:         {fct_p95:.3f} s")
    print(f"Fairness (Jain): {fairness:.4f}")

    # ---- CSV (пер-флоу) ----
    if args.out_csv:
        with args.out_csv.open("w", encoding="utf-8") as f:
            f.write("src,sp,dst,dp,packets,bytes,duration_s,throughput_bps\n")
            for fl in flows:
                thr = (fl["bytes"]*8.0)/fl["duration"] if fl["duration"]>0 else 0.0
                f.write(f'{fl["src"]},{fl["sp"]},{fl["dst"]},{fl["dp"]},{fl["packets"]},{fl["bytes"]},{fl["duration"]:.6f},{thr:.3f}\n')
        print(f"\nPer-flow CSV saved to: {args.out_csv}")

if __name__ == "__main__":
    main()
