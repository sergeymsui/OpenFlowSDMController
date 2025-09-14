// pcap_summary_fast.go (robust)
// go: 1.21+
// deps: github.com/google/gopacket v1
//
// Пример:
//   go mod init pcapfast
//   go get github.com/google/gopacket@latest
//   go build -o pcap_summary_fast pcap_summary_fast.go
//   ./pcap_summary_fast \
//     --glob "/home/user/pcaps/*.pcap" \
//     --capacity-mbps 500 \
//     --bin 1 \
//     --jobs 6 \
//     --flows-glob "/home/user/pcaps/hosts_rx/*.pcap" \
//     --tcp-port 5201 \
//     --skip-bad

package main

import (
	"bufio"
	"compress/gzip"
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
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type argsT struct {
	Glob         string
	CapacityMbps float64
	BinSec       float64
	FlowsGlob    string
	TCPPort      int
	OutCSV       string
	OutFlows     string
	Jobs         int
	SkipBad      bool
}

func parseFlags() argsT {
	var a argsT
	flag.StringVar(&a.Glob, "glob", "", "Glob для PCAP (напр. '/tmp/*.pcap') [required]")
	flag.Float64Var(&a.CapacityMbps, "capacity-mbps", 0, "Линк (Mbps) для MLU [required]")
	flag.Float64Var(&a.BinSec, "bin", 1.0, "Размер тайм-окна, сек (default 1.0)")
	flag.StringVar(&a.FlowsGlob, "flows-glob", "", "Glob PCAP для потоков/FCT/Fairness (обычно pcap приёмников)")
	flag.IntVar(&a.TCPPort, "tcp-port", 0, "Фильтр tcp.port (0=выкл)")
	flag.StringVar(&a.OutCSV, "out-csv", "./pcap_summary.csv", "CSV по файлам")
	flag.StringVar(&a.OutFlows, "out-flows", "./flows_summary.csv", "CSV по потокам")
	flag.IntVar(&a.Jobs, "jobs", runtime.NumCPU(), "Кол-во параллельных файлов")
	flag.BoolVar(&a.SkipBad, "skip-bad", true, "Пропускать битые/нечитабельные pcap вместо выхода с ошибкой")
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

// ---------- Метрики / потоки ----------

type metricResult struct {
	File            string
	AvgBps, PeakBps float64
	MLUAvg, MLUPeak float64
	TimeBins        int
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
	Duration float64
	ThrBps   float64
}

// ---------- Утилиты ----------

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
func p95(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(math.Ceil(0.95*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}
func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// ---------- Открытие PCAP/PCAPNG (+.gz) ----------

type opener struct {
	path   string
	file   *os.File
	reader gopacket.PacketDataSource
	lt     layers.LinkType         // для pcap/pcap fallback
	ng     *pcapgo.NgReader        // для pcapng
	ifLT   map[int]layers.LinkType // pcapng: ifaceIndex -> LT
	close  func() error
}

func (o *opener) Close() {
	if o.close != nil {
		_ = o.close()
	}
}

func openAny(path string) (*opener, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// поддержка .gz
	var rd *bufio.Reader
	var closer func() error
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gr, e := gzip.NewReader(f)
		if e != nil {
			_ = f.Close()
			return nil, fmt.Errorf("gzip open failed: %w", e)
		}
		rd = bufio.NewReader(gr)
		closer = func() error { _ = gr.Close(); return f.Close() }
	} else {
		rd = bufio.NewReader(f)
		closer = f.Close
	}

	// 1) PCAPNG (pure Go)
	if ng, e := pcapgo.NewNgReader(rd, pcapgo.DefaultNgReaderOptions); e == nil {
		ifLT := map[int]layers.LinkType{}
		for i, ifc := range ng.Interfaces() {
			ifLT[i] = ifc.LinkType
		}
		return &opener{path: path, file: f, reader: ng, ng: ng, ifLT: ifLT, close: closer}, nil
	}
	// 2) PCAP (pure Go)
	if pr, e := pcapgo.NewReader(rd); e == nil {
		lt := pr.LinkType()
		return &opener{path: path, file: f, reader: pr, lt: lt, close: closer}, nil
	}

	// 3) Фолбэк на libpcap (понимает SLL/SLL2 и многие экзотики)
	_ = f.Close() // откроем заново обычным способом
	h, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("unsupported/failed pcap reader for %s", path)
	}
	return &opener{
		path:   path,
		reader: h,
		lt:     layers.LinkType(h.LinkType()),
		close:  h.Close,
	}, nil
}

// ---------- Сканирование файла ----------

type scanOpts struct {
	BinSec       float64
	CapBps       float64
	CollectFlows bool
	TCPPort      int // 0=выкл
	SkipBad      bool
}
type scanOut struct {
	M     metricResult
	Flows map[flowKey]flowAgg
	Err   error
}

func scanFile(path string, o scanOpts) scanOut {
	op, err := openAny(path)
	if err != nil {
		if o.SkipBad {
			log.Printf("[WARN] skip %s: %v", path, err)
			return scanOut{M: metricResult{File: path}}
		}
		return scanOut{Err: err}
	}
	defer op.Close()

	bin := o.BinSec
	capBps := o.CapBps

	var start time.Time
	bins := map[int64]int64{}
	var lastBin int64 = -1

	var flows map[flowKey]flowAgg
	if o.CollectFlows {
		flows = make(map[flowKey]flowAgg, 1024)
	}

	switch r := op.reader.(type) {
	case *pcapgo.NgReader:
		for {
			data, ci, e := r.ReadPacketData()
			if e != nil {
				break
			}
			if start.IsZero() {
				start = ci.Timestamp
			}
			wire := int64(ci.Length) // on-the-wire length
			dt := ci.Timestamp.Sub(start).Seconds()
			if dt < 0 {
				continue
			}
			idx := int64(dt / bin)
			bins[idx] += wire
			if idx > lastBin {
				lastBin = idx
			}
			if o.CollectFlows {
				lt := op.ifLT[ci.InterfaceIndex]
				parseFlow(data, lt, ci.Timestamp, int(ci.Length), flows, o.TCPPort)
			}
		}
	case *pcapgo.Reader:
		ps := gopacket.NewPacketSource(r, op.lt)
		ps.Lazy, ps.NoCopy = true, true
		for pkt := range ps.Packets() {
			ci := pkt.Metadata().CaptureInfo
			if start.IsZero() {
				start = ci.Timestamp
			}
			wire := int64(ci.Length)
			dt := ci.Timestamp.Sub(start).Seconds()
			if dt < 0 {
				continue
			}
			idx := int64(dt / bin)
			bins[idx] += wire
			if idx > lastBin {
				lastBin = idx
			}
			if o.CollectFlows {
				extractFlow(pkt, flows, o.TCPPort)
			}
		}
	case *pcap.Handle:
		for {
			data, ci, e := r.ReadPacketData()
			if e != nil {
				break
			}
			if start.IsZero() {
				start = ci.Timestamp
			}
			wire := int64(ci.Length)
			dt := ci.Timestamp.Sub(start).Seconds()
			if dt < 0 {
				continue
			}
			idx := int64(dt / bin)
			bins[idx] += wire
			if idx > lastBin {
				lastBin = idx
			}
			if o.CollectFlows {
				parseFlow(data, layers.LinkType(r.LinkType()), ci.Timestamp, int(ci.Length), flows, o.TCPPort)
			}
		}
	default:
		return scanOut{Err: fmt.Errorf("unknown reader type")}
	}

	// агрегаты
	nbins := 0
	var sumBps, peakBps float64
	for i := int64(0); i <= lastBin; i++ {
		b := float64(bins[i])
		bps := (b * 8.0) / bin
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
		File:     path,
		AvgBps:   avgBps,
		PeakBps:  peakBps,
		MLUAvg:   safeDiv(avgBps, capBps),
		MLUPeak:  safeDiv(peakBps, capBps),
		TimeBins: nbins,
	}
	return scanOut{M: m, Flows: flows}
}

// parseFlow: быстрый парс сырых данных (по linktype), учитывает wireLen
func parseFlow(data []byte, lt layers.LinkType, ts time.Time, wireLen int, flows map[flowKey]flowAgg, tcpPort int) {
	pkt := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	netL := pkt.NetworkLayer()
	trL := pkt.TransportLayer()
	if netL == nil || trL == nil {
		return
	}

	var srcIP, dstIP net.IP
	switch ly := netL.(type) {
	case *layers.IPv4:
		srcIP, dstIP = ly.SrcIP, ly.DstIP
	case *layers.IPv6:
		srcIP, dstIP = ly.SrcIP, ly.DstIP
	default:
		return
	}
	tcp, ok := trL.(*layers.TCP)
	if !ok {
		return
	}
	if tcpPort > 0 && !(int(tcp.SrcPort) == tcpPort || int(tcp.DstPort) == tcpPort) {
		return
	}
	key := flowKey{Src: srcIP.String(), Dst: dstIP.String(), Sp: uint16(tcp.SrcPort), Dp: uint16(tcp.DstPort)}
	agg := flows[key]
	agg.Packets++
	agg.Bytes += int64(wireLen)
	if agg.First.IsZero() || ts.Before(agg.First) {
		agg.First = ts
	}
	if ts.After(agg.Last) {
		agg.Last = ts
	}
	flows[key] = agg
}

// extractFlow: если уже собран Packet
func extractFlow(pkt gopacket.Packet, flows map[flowKey]flowAgg, tcpPort int) {
	netL := pkt.NetworkLayer()
	trL := pkt.TransportLayer()
	if netL == nil || trL == nil {
		return
	}

	var srcIP, dstIP net.IP
	switch ly := netL.(type) {
	case *layers.IPv4:
		srcIP, dstIP = ly.SrcIP, ly.DstIP
	case *layers.IPv6:
		srcIP, dstIP = ly.SrcIP, ly.DstIP
	default:
		return
	}
	tcp, ok := trL.(*layers.TCP)
	if !ok {
		return
	}
	if tcpPort > 0 && !(int(tcp.SrcPort) == tcpPort || int(tcp.DstPort) == tcpPort) {
		return
	}
	ci := pkt.Metadata().CaptureInfo
	key := flowKey{Src: srcIP.String(), Dst: dstIP.String(), Sp: uint16(tcp.SrcPort), Dp: uint16(tcp.DstPort)}
	agg := flows[key]
	agg.Packets++
	agg.Bytes += int64(ci.Length) // on-the-wire length
	if agg.First.IsZero() || ci.Timestamp.Before(agg.First) {
		agg.First = ci.Timestamp
	}
	if ci.Timestamp.After(agg.Last) {
		agg.Last = ci.Timestamp
	}
	flows[key] = agg
}

// ---------- Конвейер по файлам ----------

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

	flowsWant := map[string]bool{}
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

	type job struct{ path string }
	type res struct{ out scanOut }

	in := make(chan job)
	out := make(chan res)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		opts := scanOpts{
			BinSec:       a.BinSec,
			CapBps:       a.CapacityMbps * 1_000_000.0,
			CollectFlows: false,
			TCPPort:      a.TCPPort,
			SkipBad:      a.SkipBad,
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

	var rows []metricResult
	var sumAvg, sumPeak float64
	var netMLUAvg, netMLUPeak float64
	flowsAll := make(map[flowKey]flowAgg)

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
		for k, v := range r.out.Flows {
			if ex, ok := flowsAll[k]; !ok || v.Bytes > ex.Bytes {
				flowsAll[k] = v
			}
		}
	}
	if len(rows) > 0 {
		netMLUAvg /= float64(len(rows))
	}

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

	// Потоки (если собирали)
	if len(flowsAll) > 0 {
		var fr []flowRow
		var durs, thrs []float64
		for k, v := range flowsAll {
			d := v.Last.Sub(v.First).Seconds()
			if d <= 0 {
				continue
			}
			thr := (float64(v.Bytes) * 8.0) / d
			fr = append(fr, flowRow{
				Src: k.Src, Dst: k.Dst, Sp: k.Sp, Dp: k.Dp,
				Packets: v.Packets, Bytes: v.Bytes, Duration: d, ThrBps: thr,
			})
			durs = append(durs, d)
			thrs = append(thrs, thr)
		}
		if err := writePerFlowCSV(a.OutFlows, fr); err != nil {
			log.Fatalf("[ERROR] write %s: %v", a.OutFlows, err)
		}
		fmt.Println("\n=== FLOW SUMMARY (from flows-glob) ===")
		fmt.Printf("Flows (uniq):          %d\n", len(fr))
		fmt.Printf("FCT median:            %.3f s\n", median(durs))
		fmt.Printf("FCT p95:               %.3f s\n", p95(durs))
		fmt.Printf("Fairness (Jain):       %.4f\n", jain(thrs))
		fmt.Printf("Per-flow CSV:          %s\n", a.OutFlows)
	} else if a.FlowsGlob != "" {
		fmt.Println("\n[WARN] flows-glob задан, но подходящих TCP пакетов не найдено/некорректны длительности.")
	}
}
