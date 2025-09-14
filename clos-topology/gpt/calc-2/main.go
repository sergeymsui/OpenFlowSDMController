// pcap_summary_fast.go
// go 1.21+
// Многопоточный парсер PCAP/PCAPNG без tshark: считает MLU, bps, и (опционально) TCP-потоки.
// Поддерживает Ethernet (Mininet/OVS стандартный случай).

package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ---- CLI flags ----

type argsT struct {
	Glob         string
	CapacityMbps float64
	BinSec       float64
	FlowsGlob    string
	TCPPort      int
	OutCSV       string
	OutFlows     string
	Jobs         int
}

func parseFlags() argsT {
	var a argsT
	flag.StringVar(&a.Glob, "glob", "", "Glob для PCAP (например '/tmp/*.pcap') [required]")
	flag.Float64Var(&a.CapacityMbps, "capacity-mbps", 0, "Линк (Mbps) для MLU [required]")
	flag.Float64Var(&a.BinSec, "bin", 1.0, "Размер тайм-окна, сек (default 1.0)")
	flag.StringVar(&a.FlowsGlob, "flows-glob", "", "Glob PCAP для расчёта потоков/FCT/Fairness (обычно pcaps приёмников)")
	flag.IntVar(&a.TCPPort, "tcp-port", 0, "Фильтр tcp.port (0=выкл)")
	flag.StringVar(&a.OutCSV, "out-csv", "./pcap_summary.csv", "CSV по файлам")
	flag.StringVar(&a.OutFlows, "out-flows", "./flows_summary.csv", "CSV по потокам")
	flag.IntVar(&a.Jobs, "jobs", runtime.NumCPU(), "Кол-во параллельных файлов")
	flag.Parse()
	if a.Glob == "" || a.CapacityMbps <= 0 {
		flag.Usage()
		os.Exit(2)
	}
	if a.BinSec <= 0 {
		a.BinSec = 1.0
	}
	if a.Jobs < 1 {
		a.Jobs = 1
	}
	return a
}

// ---- Metrics structures ----

type metricResult struct {
	File                 string
	AvgBps, PeakBps      float64
	MLUAvg, MLUPeak      float64
	TimeBins             int
}

type flowKey struct {
	Src, Dst string
	Sp, Dp   uint16
}

type flowAgg struct {
	Packets int64
	Bytes   int64
	First   time.Time
	Last    time.Time
}

type flowRow struct {
	Src, Dst string
	Sp, Dp   uint16
	Packets  int64
	Bytes    int64
	Duration float64 // seconds
	ThrBps   float64
}

// ---- Utilities ----

func humanBps(bps float64) string {
	u := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	i := 0
	for bps >= 1000 && i < len(u)-1 {
		bps /= 1000
		i++
	}
	return fmt.Sprintf("%.2f %s", bps, u[i])
}

func jain(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s, s2 float64
	for _, v := range xs {
		s += v
		s2 += v * v
	}
	if s2 == 0 {
		return 0
	}
	n := float64(len(xs))
	return (s * s) / (n * s2)
}

func p95(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	idx := int(math.Ceil(0.95*float64(len(s)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

// ---- Core: single-file scan ----

type scanOpts struct {
	BinSec       float64
	CapBps       float64
	CollectFlows bool
	TCPPort      int // 0 = all
}

type scanOut struct {
	M metricResult
	// Flows заполняется только если CollectFlows=true
	Flows map[flowKey]flowAgg
	Err   error
}

func openPcap(path string) (gopacket.PacketDataSource, layers.LinkType, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, err
	}
	// pcapng сначала
	if ngr, e := pcapgo.NewNgReader(bufio.NewReader(f), pcapgo.DefaultNgReaderOptions); e == nil {
		lt := layers.LinkTypeEthernet // предположим Ethernet (Mininet)
		closeFn := func() error { return f.Close() }
		return ngr, lt, closeFn, nil
	}
	// классический pcap
	if r, e := pcapgo.NewReader(f); e == nil {
		lt := r.LinkType()
		closeFn := func() error { return f.Close() }
		return r, lt, closeFn, nil
	}
	_ = f.Close()
	return nil, 0, nil, fmt.Errorf("unsupported/failed pcap reader for %s", path)
}

func scanFile(path string, o scanOpts) scanOut {
	src, lt, closeFn, err := openPcap(path)
	if err != nil {
		return scanOut{Err: err}
	}
	defer closeFn()

	ps := gopacket.NewPacketSource(src, lt)
	ps.Lazy = true  // не декодируй всё
	ps.NoCopy = true

	bin := o.BinSec
	capBps := o.CapBps

	var start time.Time
	var bins map[int64]int64 = make(map[int64]int64) // binIdx -> bytes
	var totalBytes int64
	var lastBin int64 = -1

	var flows map[flowKey]flowAgg
	if o.CollectFlows {
		flows = make(map[flowKey]flowAgg, 1024)
	}

	for pkt := range ps.Packets() {
		ci := pkt.Metadata().CaptureInfo
		if start.IsZero() {
			start = ci.Timestamp
		}
		// байты «на проводе»
		wire := int64(ci.Length)
		// учёт бинов
		dt := ci.Timestamp.Sub(start).Seconds()
		if dt < 0 {
			// редкий случай — просто скипаем «в прошлое»
			continue
		}
		idx := int64(dt / bin)
		bins[idx] += wire
		if idx > lastBin {
			lastBin = idx
		}
		totalBytes += wire

		// Потоки (минимальный парс IPv4/IPv6+TCP)
		if o.CollectFlows {
			netL := pkt.NetworkLayer()
			if netL == nil {
				continue
			}
			var srcIP, dstIP net.IP
			switch ly := netL.(type) {
			case *layers.IPv4:
				srcIP, dstIP = ly.SrcIP, ly.DstIP
			case *layers.IPv6:
				srcIP, dstIP = ly.SrcIP, ly.DstIP
			default:
				continue
			}
			trL := pkt.TransportLayer()
			if trL == nil {
				continue
			}
			tcp, ok := trL.(*layers.TCP)
			if !ok {
				continue
			}
			if o.TCPPort > 0 && !(int(tcp.SrcPort) == o.TCPPort || int(tcp.DstPort) == o.TCPPort) {
				continue
			}
			key := flowKey{
				Src: srcIP.String(), Dst: dstIP.String(),
				Sp: uint16(tcp.SrcPort), Dp: uint16(tcp.DstPort),
			}
			agg := flows[key]
			agg.Packets++
			agg.Bytes += wire
			if agg.First.IsZero() || ci.Timestamp.Before(agg.First) {
				agg.First = ci.Timestamp
			}
			if ci.Timestamp.After(agg.Last) {
				agg.Last = ci.Timestamp
			}
			flows[key] = agg
		}
	}

	// собрать метрики
	nbins := 0
	var sumBps float64
	var peakBps float64
	for i := int64(0); i <= lastBin; i++ {
		bytes := float64(bins[i])
		bps := (bytes * 8.0) / bin
		sumBps += bps
		if bps > peakBps {
			peakBps = bps
		}
		nbins++
	}
	var avgBps float64
	if nbins > 0 {
		avgBps = sumBps / float64(nbins)
	}
	m := metricResult{
		File:    path,
		AvgBps:  avgBps,
		PeakBps: peakBps,
		MLUAvg:  safeDiv(avgBps, capBps),
		MLUPeak: safeDiv(peakBps, capBps),
		TimeBins: nbins,
	}

	return scanOut{M: m, Flows: flows, Err: nil}
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// ---- Workers over multiple files ----

func uniqStrings(ss []string) []string {
	m := map[string]struct{}{}
	for _, s := range ss {
		m[s] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func main() {
	a := parseFlags()

	files, err := filepath.Glob(a.Glob)
	if err != nil {
		log.Fatalf("[ERROR] glob: %v", err)
	}
	if len(files) == 0 {
		log.Fatalf("[ERROR] no files matched: %s", a.Glob)
	}
	sort.Strings(files)
	fmt.Printf("[INFO] matched %d files for interface metrics\n", len(files))

	var flowsWant = map[string]bool{}
	if a.FlowsGlob != "" {
		ff, err := filepath.Glob(a.FlowsGlob)
		if err != nil {
			log.Fatalf("[ERROR] flows-glob: %v", err)
		}
		for _, f := range ff {
			flowsWant[f] = true
		}
		if len(flowsWant) == 0 {
			fmt.Printf("[WARN] flows-glob matched 0 files: %s\n", a.FlowsGlob)
		} else {
			fmt.Printf("[INFO] will collect flows from %d files\n", len(flowsWant))
		}
	}

	// pipeline
	type job struct{ path string }
	type res struct{ out scanOut }

	in := make(chan job)
	out := make(chan res)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		opts := scanOpts{
			BinSec: a.BinSec,
			CapBps: a.CapacityMbps * 1_000_000.0,
			// Включаем потоки только там, где это нужно — чтобы не тормозить лишний раз
			CollectFlows: false,
			TCPPort:      a.TCPPort,
		}
		for j := range in {
			opts.CollectFlows = flowsWant[j.path]
			out <- res{out: scanFile(j.path, opts)}
		}
	}

	nw := a.Jobs
	if nw > len(files) {
		nw = len(files)
	}
	if nw < 1 {
		nw = 1
	}
	for i := 0; i < nw; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for _, f := range files {
			in <- job{path: f}
		}
		close(in)
		wg.Wait()
		close(out)
	}()

	// aggregate
	var rows []metricResult
	var sumAvg, sumPeak float64
	var netMLUAvg float64
	var netMLUPeak float64
	var flowsAll = make(map[flowKey]flowAgg)

	for r := range out {
		if r.out.Err != nil {
			log.Fatalf("[ERROR] %v", r.out.Err)
		}
		m := r.out.M
		rows = append(rows, m)
		sumAvg += m.AvgBps
		sumPeak += m.PeakBps
		netMLUAvg += m.MLUAvg
		if m.MLUPeak > netMLUPeak {
			netMLUPeak = m.MLUPeak
		}
		// merge flows
		for k, v := range r.out.Flows {
			if ex, ok := flowsAll[k]; !ok || v.Bytes > ex.Bytes {
				flowsAll[k] = v
			}
		}
	}

	// финальные сетевые MLU
	if len(rows) > 0 {
		netMLUAvg /= float64(len(rows))
	}

	// write per-file CSV
	if err := writePerFileCSV(a.OutCSV, rows); err != nil {
		log.Fatalf("[ERROR] write %s: %v", a.OutCSV, err)
	}

	fmt.Println("\n=== NETWORK SUMMARY (from interface pcaps) ===")
	fmt.Printf("Files:                 %d\n", len(rows))
	fmt.Printf("Total avg throughput:  %s\n", humanBps(sumAvg))
	fmt.Printf("Total peak throughput: %s\n", humanBps(sumPeak))
	fmt.Printf("Network MLU avg:       %.2f%%\n", netMLUAvg*100.0)
	fmt.Printf("Network MLU peak:      %.2f%%\n", netMLUPeak*100.0)
	fmt.Printf("Per-file CSV:          %s\n", a.OutCSV)

	// flows summary (if any collected)
	if len(flowsAll) > 0 {
		var fr []flowRow
		fr = fr[:0]
		var durs []float64
		var thrs []float64
		for k, v := range flowsAll {
			d := v.Last.Sub(v.First).Seconds()
			if d <= 0 {
				continue
			}
			thr := (float64(v.Bytes) * 8.0) / d
			fr = append(fr, flowRow{
				Src:     k.Src, Dst: k.Dst, Sp: k.Sp, Dp: k.Dp,
				Packets: v.Packets, Bytes: v.Bytes, Duration: d, ThrBps: thr,
			})
			durs = append(durs, d)
			thrs = append(thrs, thr)
		}
		// write CSV
		if err := writePerFlowCSV(a.OutFlows, fr); err != nil {
			log.Fatalf("[ERROR] write %s: %v", a.OutFlows, err)
		}
		// summary
		fmt.Println("\n=== FLOW SUMMARY (from flows-glob) ===")
		fmt.Printf("Flows (uniq):          %d\n", len(fr))
		fmt.Printf("FCT median:            %.3f s\n", median(durs))
		fmt.Printf("FCT p95:               %.3f s\n", p95(durs))
		fmt.Printf("Fairness (Jain):       %.4f\n", jain(thrs))
		fmt.Printf("Per-flow CSV:          %s\n", a.OutFlows)
	} else if a.FlowsGlob != "" {
		fmt.Println("\n[WARN] flows-glob задан, но подходящих пакетов TCP не найдено или длительность = 0.")
	}
}

// --- CSV helpers & small stats ---

func writePerFileCSV(path string, rows []metricResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"file", "avg_bps", "peak_bps", "MLU_avg", "MLU_peak", "time_bins"})
	for _, r := range rows {
		rec := []string{
			r.File,
			fmt.Sprintf("%.3f", r.AvgBps),
			fmt.Sprintf("%.3f", r.PeakBps),
			fmt.Sprintf("%.6f", r.MLUAvg),
			fmt.Sprintf("%.6f", r.MLUPeak),
			strconv.Itoa(r.TimeBins),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

func writePerFlowCSV(path string, flows []flowRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"src", "sp", "dst", "dp", "packets", "bytes", "duration_s", "throughput_bps"})
	for _, fl := range flows {
		rec := []string{
			fl.Src, fmt.Sprintf("%d", fl.Sp), fl.Dst, fmt.Sprintf("%d", fl.Dp),
			fmt.Sprintf("%d", fl.Packets),
			fmt.Sprintf("%d", fl.Bytes),
			fmt.Sprintf("%.6f", fl.Duration),
			fmt.Sprintf("%.3f", fl.ThrBps),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return 0.5 * (s[n/2-1] + s[n/2])
}
