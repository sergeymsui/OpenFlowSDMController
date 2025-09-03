# -*- coding: utf-8 -*-
"""
plot_bw_metrics_enhanced.py — анализ CSV (расширенный формат) и расчёт метрик:
Throughput, MLU, FCT, Jain fairness. Строит графики, печатает и/или сохраняет отчёт.

Примеры:
  python plot_bw_metrics_enhanced.py --capacity "10 Gbps" --proto TCP --fairness-by flow \
      ./csv/exp1.csv:OSPF ./csv/exp2.csv:BMcW

  python plot_bw_metrics_enhanced.py --iface 1 --capacity "1 Gbps" --metrics-out metrics.csv \
      ./csv/ospf.csv:OSPF

Поля CSV (из Go-скрипта):
  source_file,timestamp_rfc3339,timestamp_unix_ns,iface_index,eth_type,ip_version,
  src_ip,dst_ip,proto,src_port,dst_port,length_bytes,tcp_syn,tcp_fin,tcp_rst,tcp_ack,tcp_psh,
  flow_id_5tuple,pair_id_dir,pair_id_undir
"""

import argparse
import csv
import statistics
from collections import defaultdict, namedtuple
from datetime import datetime, timezone

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

try:
    from scipy.signal import savgol_filter
    _HAS_SG = True
except Exception:
    _HAS_SG = False

# -------------------------
# Парсинг единиц/ёмкости
# -------------------------
_UNITS = {
    "bps": 1,
    "kbps": 1_000,
    "mbps": 1_000_000,
    "gbps": 1_000_000_000,
    "tbps": 1_000_000_000_000,
}

def parse_capacity(text):
    """'10 Gbps' -> bps (float) или чистое число."""
    if text is None:
        return None
    s = str(text).strip().lower()
    # чистое число
    try:
        return float(s)
    except ValueError:
        pass
    # число + префикс
    import re
    m = re.match(r"^\s*([0-9]*\.?[0-9]+)\s*([kmgte]?)\s*b?p?s?\s*$", s)
    if not m:
        raise ValueError(f"Не удалось распарсить ёмкость: {text}")
    val = float(m.group(1))
    p = m.group(2)
    scale = 1
    if p == "k": scale = _UNITS["kbps"]
    elif p == "m": scale = _UNITS["mbps"]
    elif p == "g": scale = _UNITS["gbps"]
    elif p == "t": scale = _UNITS["tbps"]
    return val * scale

# -------------------------
# Форматтеры осей
# -------------------------
def seconds_to_mmss(x, pos):
    try:
        x = int(x)
    except Exception:
        return ""
    if x < 0 or (x % 10) != 0:
        return ""
    m, s = divmod(x, 60)
    return f"{m:02d}:{s:02d}"

def compact_bps(x, pos):
    units = ["бит/с", "Кбит/с", "Мбит/с", "Гбит/с", "Тбит/с", "Пбит/с"]
    x = float(x)
    for u in units:
        if abs(x) < 1000.0:
            return f"{x:.0f} {u}"
        x /= 1000.0
    return f"{x:.0f} Эбит/с"

# -------------------------
# Загрузка CSV
# -------------------------
Row = namedtuple("Row",
                 "t_unix_ns iface ipver proto src dst sport dport lenb syn fin rst ack psh flow_id pair_dir pair_undir")

def _to_int(s, default=0):
    try:
        return int(s)
    except Exception:
        return default

def _to_boolflag(s):
    return s == "1"

def _pass_filters(row: Row, flt_iface, flt_proto, flt_ipver):
    if flt_iface is not None and row.iface != flt_iface:
        return False
    if flt_proto and row.proto.upper() != flt_proto:
        return False
    if flt_ipver and row.ipver != flt_ipver:
        return False
    return True

def load_csv(path, iface_filter=None, proto_filter=None, ipver_filter=None):
    """
    Возвращает:
      rows: list[Row]
      t0_ns: минимальный unix_ns (начало эксперимента в этом файле)
    """
    rows = []
    t0 = None
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for d in r:
            try:
                t_ns = int(d.get("timestamp_unix_ns", ""))
            except Exception:
                # пробуем rfc3339
                try:
                    ts = datetime.fromisoformat(d["timestamp_rfc3339"].replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    t_ns = int(ts.timestamp() * 1e9)
                except Exception:
                    continue

            iface = _to_int(d.get("iface_index", ""), default=-1)
            ipver = _to_int(d.get("ip_version", ""), default=0)
            proto = (d.get("proto") or "").upper()
            src = d.get("src_ip") or ""
            dst = d.get("dst_ip") or ""
            sport = _to_int(d.get("src_port", ""), default=0)
            dport = _to_int(d.get("dst_port", ""), default=0)
            length = _to_int(d.get("length_bytes", ""), default=0)

            syn = _to_boolflag(d.get("tcp_syn", "0"))
            fin = _to_boolflag(d.get("tcp_fin", "0"))
            rst = _to_boolflag(d.get("tcp_rst", "0"))
            ack = _to_boolflag(d.get("tcp_ack", "0"))
            psh = _to_boolflag(d.get("tcp_psh", "0"))

            flow_id = d.get("flow_id_5tuple") or ""
            pair_dir = d.get("pair_id_dir") or ""
            pair_undir = d.get("pair_id_undir") or ""

            row = Row(t_ns, iface, ipver, proto, src, dst, sport, dport, length,
                      syn, fin, rst, ack, psh, flow_id, pair_dir, pair_undir)
            if not _pass_filters(row, iface_filter, proto_filter, ipver_filter):
                continue

            rows.append(row)
            if t0 is None or t_ns < t0:
                t0 = t_ns
    return rows, (t0 or 0)

# -------------------------
# Агрегация по времени
# -------------------------
def aggregate_throughput(rows, t0_ns, interval="second", raw=True):
    """
    Возвращает:
      times: [0..N] секунды/минуты от начала
      bits_per_second: [..] bps на интервал
    """
    bucket = defaultdict(int)  # bytes
    for r in rows:
        dt_ns = r.t_unix_ns - t0_ns
        if dt_ns < 0:
            continue
        if interval == "second":
            b = dt_ns // 1_000_000_000
        elif interval == "minute":
            b = dt_ns // 60_000_000_000
        else:
            raise ValueError("Unsupported interval")
        bucket[int(b)] += r.lenb  # bytes

    if not bucket:
        return [], []

    tmin, tmax = min(bucket.keys()), max(bucket.keys())
    times = list(range(tmin, tmax + 1))
    if interval == "second":
        scale = 8.0
    else:
        scale = 8.0 / 60.0

    vals = [bucket.get(t, 0) * scale for t in times]  # bps
    if raw:
        return times, vals

    # сглаживание
    if _HAS_SG and len(vals) >= 7:
        n = len(vals)
        win = min(n if n % 2 == 1 else n - 1, 17)
        if win < 7: win = 7
        if win > n: win = n if n % 2 == 1 else n - 1
        poly = min(3, win - 1)
        vals_sm = savgol_filter(vals, win, poly)
        return times, list(vals_sm)
    else:
        return times, vals

# -------------------------
# Метрики: avg, peak, MLU
# -------------------------
def series_metrics(times, bps, capacity_bps=None):
    if not bps:
        return 0.0, 0.0, None, None
    avg = statistics.mean(bps)
    peak = max(bps)
    if capacity_bps:
        utiliz = [v / capacity_bps for v in bps]
        mlu = max(utiliz)
        t_mlu = times[utiliz.index(mlu)]
        return avg, peak, mlu, t_mlu
    return avg, peak, None, None

# -------------------------
# FCT и Fairness
# -------------------------
def compute_flows(rows):
    """
    Собираем info по направленным потокам (flow_id_5tuple).
    Для TCP: начало — первый SYN без ACK; конец — первый FIN/RST (по времени).
    Фоллбек: первый пакет -> последний пакет.
    Возвращает список dict: {flow_id, bytes, t_first, t_last, fct_s, rate_bps}
    """
    by_flow = defaultdict(lambda: {"t_first": None, "t_last": None, "bytes": 0,
                                   "syn0": None, "finrst": None})
    for r in rows:
        fid = r.flow_id
        if not fid:
            # если нет flow_id — собирать нечего
            continue

        ent = by_flow[fid]
        # временные границы
        if ent["t_first"] is None or r.t_unix_ns < ent["t_first"]:
            ent["t_first"] = r.t_unix_ns
        if ent["t_last"] is None or r.t_unix_ns > ent["t_last"]:
            ent["t_last"] = r.t_unix_ns

        ent["bytes"] += r.lenb

        if r.proto == "TCP":
            # начало: первый SYN без ACK
            if r.syn and not r.ack:
                if ent["syn0"] is None or r.t_unix_ns < ent["syn0"]:
                    ent["syn0"] = r.t_unix_ns
            # конец: первый FIN или RST
            if r.fin or r.rst:
                if ent["finrst"] is None or r.t_unix_ns < ent["finrst"]:
                    ent["finrst"] = r.t_unix_ns

    out = []
    for fid, ent in by_flow.items():
        start_ns = ent["syn0"] if ent["syn0"] is not None else ent["t_first"]
        end_ns = ent["finrst"] if ent["finrst"] is not None else ent["t_last"]
        if start_ns is None or end_ns is None:
            continue
        dur = max((end_ns - start_ns) / 1e9, 1e-6)
        rate = (ent["bytes"] * 8.0) / dur
        out.append({
            "flow_id": fid,
            "bytes": ent["bytes"],
            "t_first_ns": ent["t_first"],
            "t_last_ns": ent["t_last"],
            "t_start_ns": int(start_ns),
            "t_end_ns": int(end_ns),
            "fct_s": dur,
            "rate_bps": rate,
        })
    return out

def compute_pairs(rows, directed=True):
    key_name = "pair_dir" if directed else "pair_undir"
    by_pair = defaultdict(lambda: {"t_first": None, "t_last": None, "bytes": 0})
    for r in rows:
        key = getattr(r, key_name)
        if not key:
            continue
        ent = by_pair[key]
        if ent["t_first"] is None or r.t_unix_ns < ent["t_first"]:
            ent["t_first"] = r.t_unix_ns
        if ent["t_last"] is None or r.t_unix_ns > ent["t_last"]:
            ent["t_last"] = r.t_unix_ns
        ent["bytes"] += r.lenb

    out = []
    for key, ent in by_pair.items():
        dur = max((ent["t_last"] - ent["t_first"]) / 1e9, 1e-6)
        rate = (ent["bytes"] * 8.0) / dur
        out.append({
            "pair": key,
            "bytes": ent["bytes"],
            "fct_s": dur,
            "rate_bps": rate,
        })
    return out

def jain_index(values):
    if not values:
        return None
    s1 = sum(values)
    s2 = sum(v*v for v in values)
    n = len(values)
    if s2 == 0:
        return 1.0
    return (s1*s1)/(n*s2)

# -------------------------
# Визуализация
# -------------------------
def plot_series(series_list, interval="second", title=None, show_avg=True, smooth=True):
    """
    series_list: list of dict {
      'label': str,
      'times': [...],
      'bps': [...]
    }
    """
    if not series_list:
        print("[WARN] Нет данных для графика.")
        return

    plt.figure(figsize=(12, 6))
    ax = plt.gca()

    ymax = 0.0
    for s in series_list:
        times = s["times"]
        vals = s["bps"]
        if smooth and _HAS_SG and len(vals) >= 7:
            n = len(vals)
            win = min(n if n % 2 == 1 else n - 1, 17)
            if win < 7: win = 7
            if win > n: win = n if n % 2 == 1 else n - 1
            poly = min(3, win - 1)
            vals_plot = savgol_filter(vals, win, poly)
        else:
            vals_plot = vals
        line = ax.plot(times, vals_plot, linewidth=2, label=s["label"])[0]
        ymax = max(ymax, max(vals_plot))
        if show_avg and vals:
            avg = statistics.mean(vals)
            ax.axhline(avg, linestyle="--", linewidth=1.0, color=line.get_color(), alpha=0.8)

    ax.set_xlabel("Время (MM:SS)" if interval == "second" else "Время, мин", fontsize=12)
    ax.set_ylabel("Пропускная способность, бит/с", fontsize=12)
    ax.grid(True, linestyle="--", alpha=0.5)

    # по всем сериям общий диапазон по X
    all_t = [t for s in series_list for t in s["times"]]
    if all_t:
        ax.set_xlim(min(all_t), max(all_t))
    ax.set_ylim(0, 1.2*ymax if ymax > 0 else 1)

    if interval == "second":
        ax.xaxis.set_major_formatter(ticker.FuncFormatter(seconds_to_mmss))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(compact_bps))
    if title:
        ax.set_title(title)
    ax.legend()
    plt.tight_layout()
    plt.show()

# -------------------------
# Отчёт в CSV
# -------------------------
def export_metrics_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)
    print(f"[OK] Метрики сохранены: {path}")

# -------------------------
# main
# -------------------------
def main():
    ap = argparse.ArgumentParser(description="Throughput/MLU/FCT/Fairness по расширенному CSV")
    ap.add_argument("inputs", nargs="+",
                    help="Список файлов вида path.csv[:LABEL]. Пример: ./csv/ospf.csv:OSPF")
    ap.add_argument("--interval", choices=["second", "minute"], default="second")
    ap.add_argument("--capacity", default=None, help='Ёмкость линка (bps или строки типа "10 Gbps") для MLU')
    ap.add_argument("--iface", type=int, default=None, help="Фильтр iface_index (если указать — берём только этот интерфейс)")
    ap.add_argument("--proto", default=None, help="Фильтр по протоколу (TCP/UDP/ICMPv4/ICMPv6)")
    ap.add_argument("--ipver", type=int, choices=[4, 6], default=None, help="Фильтр IP версии")
    ap.add_argument("--fairness-by", choices=["flow", "pair_dir", "pair_undir"], default="flow",
                    help="Для Jain: по потокам (flow_id) или по парам (dir/undir)")
    ap.add_argument("--no-smooth", action="store_true", help="Не сглаживать линии на графике")
    ap.add_argument("--metrics-out", default=None, help="Путь для CSV с агрегированными метриками")
    args = ap.parse_args()

    capacity_bps = parse_capacity(args.capacity) if args.capacity else None
    series_for_plot = []
    report_rows = []

    # Дополнительно копим per-iface MLU (если iface_index присутствует и не фильтруем)
    per_iface_data = defaultdict(list)  # iface_index -> list of (times, bps) across inputs

    total_avg_sum = 0.0

    for spec in args.inputs:
        if ":" in spec:
            path, label = spec.split(":", 1)
        else:
            path, label = spec, spec

        rows, t0_ns = load_csv(path, iface_filter=args.iface, proto_filter=(args.proto or None),
                               ipver_filter=args.ipver)
        if not rows:
            print(f"[WARN] Пустые данные после фильтров: {path}")
            continue

        # Серия throughput (RAW для метрик, SMOOTH для отрисовки отдельно)
        times_raw, bps_raw = aggregate_throughput(rows, t0_ns, args.interval, raw=True)
        if not bps_raw:
            print(f"[WARN] Нет throughput после агрегации: {path}")
            continue

        # Метрики по серии
        avg_bps, max_bps, mlu, mlu_t = series_metrics(times_raw, bps_raw, capacity_bps)
        total_avg_sum += avg_bps

        # Добавим в список для графика
        times_plot, bps_plot = aggregate_throughput(rows, t0_ns, args.interval, raw=args.no_smooth)
        series_for_plot.append({"label": label, "times": times_plot, "bps": bps_plot})

        # FCT/Fairness
        jain_val = None
        flows_list = []
        pairs_list = []
        if args.fairness_by == "flow":
            flows_list = compute_flows(rows)
            jain_val = jain_index([f["rate_bps"] for f in flows_list])
        elif args.fairness_by == "pair_dir":
            pairs_list = compute_pairs(rows, directed=True)
            jain_val = jain_index([p["rate_bps"] for p in pairs_list])
        else:
            pairs_list = compute_pairs(rows, directed=False)
            jain_val = jain_index([p["rate_bps"] for p in pairs_list])

        # Печать кратко
        mlu_str = f"{mlu*100:.1f}% @ t={int(mlu_t)}" if mlu is not None else "—"
        print(f"- {label}: avg={compact_bps(avg_bps, None)}, peak={compact_bps(max_bps, None)}, MLU={mlu_str}, "
              f"Jain={jain_val:.4f}" if jain_val is not None else f"Jain=—")

        report_rows.append([
            label,
            f"{avg_bps:.3f}",
            f"{max_bps:.3f}",
            f"{mlu:.6f}" if mlu is not None else "",
            str(int(mlu_t)) if mlu is not None else "",
            f"{jain_val:.6f}" if jain_val is not None else "",
            len(flows_list) if flows_list else "",
            len(pairs_list) if pairs_list else "",
        ])

        # Пер-IFACE агрегация (если в данных встречаются iface_index)
        if args.iface is None:
            # сгруппируем исходные ряды по iface и посчитаем их throughput отдельно
            by_iface_rows = defaultdict(list)
            for r in rows:
                by_iface_rows[r.iface].append(r)
            for iface_idx, rlist in by_iface_rows.items():
                t_i, v_i = aggregate_throughput(rlist, t0_ns, args.interval, raw=True)
                if v_i:
                    per_iface_data[iface_idx].append((t_i, v_i))

    # Общий график
    plot_series(series_for_plot, interval=args.interval,
                title=f"Throughput ({args.proto or 'ALL'})",
                show_avg=True, smooth=not args.no_smooth)

    # Дополнительный отчёт по MLU per iface_index
    if per_iface_data:
        print("\n=== Per-IFACE MLU ===")
        for iface_idx, tv_list in sorted(per_iface_data.items(), key=lambda x: (x[0] is None, x[0])):
            # объединим ряды по времени: суммируем bps в один ряд
            bucket = defaultdict(float)
            for times, vals in tv_list:
                for t, v in zip(times, vals):
                    bucket[t] += v
            if not bucket:
                continue
            times = sorted(bucket.keys())
            vals = [bucket[t] for t in times]
            avg_i, max_i, mlu_i, mlu_t = series_metrics(times, vals, capacity_bps)
            print(f"iface={iface_idx}: avg={compact_bps(avg_i, None)}, "
                  f"peak={compact_bps(max_i, None)}, "
                  f"MLU={'—' if mlu_i is None else f'{mlu_i*100:.1f}% @ t={int(mlu_t)}'}")

    # Суммарный throughput (как сумма средних across inputs)
    print("\n=== Total throughput (sum of series averages) ===")
    print(compact_bps(total_avg_sum, None))

    # Экспорт агрегированного отчёта
    if args.metrics_out:
        export_metrics_csv(
            args.metrics_out,
            header=["label", "avg_bps", "peak_bps", "mlu", "mlu_time", "jain", "flows_count", "pairs_count"],
            rows=report_rows,
        )

if __name__ == "__main__":
    main()
