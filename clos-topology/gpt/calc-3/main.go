// pcap_summary_flows_channels.go
// go 1.21+
// deps: github.com/google/gopacket v1  (и системный libpcap)
//
// Что считает:
//   1) MLU по каналам (per-file): avg/peak по бинам -> MLU_avg/MLU_peak на базе ёмкости канала
//   2) Пропускную способность по потокам: TCP/UDP 5-tuple -> bytes, duration, throughput_bps
//
// Примеры:
//   go mod init pcapfc && go get github.com/google/gopacket@latest
//   sudo apt-get install -y libpcap-dev
//   go build -o pcap_fc pcap_summary_flows_channels.go
//
//   # Один дефолтный лимит 100 Мбит/с для всех каналов, бины 1с, TCP flows с приёмников
//   ./pcap_fc \
//     --glob "/home/vda/tmp/ospf-2/*.pcap" \
//     --capacity-mbps 100 \
//     --bin 1 \
//     --flows-glob "/home/vda/tmp/ospf-2/hosts_rx/*.pcap" \
//     --proto tcp \
//     --jobs 6
//
//   # Разные ёмкости по файлам (channels.csv: file,capacity_mbps)
//   ./pcap_fc \
//     --glob "/pcaps/core/*.pcap" \
//     --caps-csv ./channels.csv \
//     --bin 0.5 \
//     --flows-glob "/pcaps/hosts/*.pcap" \
//     --proto any

package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"log"
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
)

/* ========================= FLAGS ========================= */

type argsT struct {
	Glob         string // pcap’ы для каналов (MLU per channel)
	CapsCSV      string // переопределение capacity per file: CSV "file,capacity_mbps"
	CapacityMbps float64
	BinSec       float64
	OutChannels  string

	FlowsGlob string // pcap’ы, по которым вытаскиваем потоки (обычно у приёмников)
	Proto     string // tcp|udp|any
	TCPPort   int    // 0 = любой
	UDPPort   int    // 0 = любой
	OutFlows  string

	Jobs    int
	SkipBad bool
}

func parseFlags() argsT {
	var a argsT
	flag.StringVar(&a.Glob, "glob", "", "Glob PCAP для расчёта MLU по каналам (напр. '/tmp/*.pcap') [required]")
	flag.StringVar(&a.CapsCSV, "caps-csv", "", "CSV c ёмкостью каналов: file,capacity_mbps (перекрывает --capacity-mbps)")
	flag.Float64Var(&a.CapacityMbps, "capacity-mbps", 0, "Ёмкость канала по умолчанию (Mbps) для всех файлов без явного значения")
	flag.Float64Var(&a.BinSec, "bin", 1.0, "Размер бина по времени для MLU (сек)")
	flag.StringVar(&a.OutChannels, "out-channels", "./channels_summary.csv", "CSV-вывод для каналов")

	flag.StringVar(&a.FlowsGlob, "flows-glob", "", "Glob PCAP для извлечения потоков (обычно pcap приёмников)")
	flag.StringVar(&a.Proto, "proto", "tcp", "Протоколы для flows: tcp|udp|any")
	flag.IntVar(&a.TCPPort, "tcp-port", 0, "Фильтр tcp.port (0 = любой)")
	flag.IntVar(&a.UDPPort, "udp-port", 0, "Фильтр udp.port (0 = любой)")
	flag.StringVar(&a.OutFlows, "out-flows", "./flows_summary.csv", "CSV-вывод для потоков")

	flag.IntVar(&a.Jobs, "jobs", runtime.NumCPU(), "Параллельные файлы")
	flag.BoolVar(&a.SkipBad, "skip-bad", true, "Пропускать битые pcap (иначе завершаемся)")
	flag.Parse()

	if a.Glob == "" {
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

/* ========================= TYPES ========================= */

type chanRow struct {
	File            string
	CapacityMbps    float64
	AvgBps, PeakBps float64
	MLUAvg, MLUPeak float64
	TimeBins        int
}

type flowKey struct {
	Src, Dst string
	Sp, Dp   uint16
	Proto    string // "tcp"|"udp"
}
type flowAgg struct {
	Packets int64
	Bytes   int64
	First   time.Time
	Last    time.Time
}

/* ========================= UTIL ========================= */

func humanBps(bps float64) string {
	u := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	i := 0
	for bps >= 1000 && i < len(u)-1 {
		bps /= 1000
		i++
	}
	return fmt.Sprintf("%.2f %s", bps, u[i])
}
func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func readCapsCSV(path string) (map[string]float64, error) {
	m := map[string]float64{}
	if path == "" {
		return m, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	// optional header
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	for i, row := range rows {
		if len(row) < 2 {
			continue
		}
		if i == 0 && strings.Contains(strings.ToLower(row[0]), "file") {
			continue // header
		}
		c, err := strconv.ParseFloat(strings.TrimSpace(row[1]), 64)
		if err != nil {
			return nil, fmt.Errorf("caps-csv parse: %v", err)
		}
		m[strings.TrimSpace(row[0])] = c
	}
	return m, nil
}

func matchCapacity(file string, caps map[string]float64, def float64) float64 {
	// Сначала прямое совпадение по полному пути
	if v, ok := caps[file]; ok {
		return v
	}
	// Потом — по базовому имени
	base := filepath.Base(file)
	if v, ok := caps[base]; ok {
		return v
	}
	return def
}

/* ========================= PCAP READER ========================= */

type opener struct {
	handle *pcap.Handle
	lt     layers.LinkType
}

func openAny(path string) (*opener, error) {
	h, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, err
	}
	return &opener{handle: h, lt: layers.LinkType(h.LinkType())}, nil
}

func (o *opener) Close() {
	if o.handle != nil {
		o.handle.Close()
	}
}

/* ========================= CHANNEL SCAN ========================= */

type chanScanOpts struct {
	BinSec  float64
	CapBps  float64
	SkipBad bool
}

func scanChannel(file string, o chanScanOpts) (chanRow, error) {
	op, err := openAny(file)
	if err != nil {
		if o.SkipBad {
			log.Printf("[WARN] skip channel %s: %v", file, err)
			return chanRow{File: file, CapacityMbps: o.CapBps / 1e6}, nil
		}
		return chanRow{}, err
	}
	defer op.Close()

	bins := map[int64]int64{}
	var lastBin int64 = -1
	var start time.Time

	for {
		data, ci, e := op.handle.ReadPacketData()
		_ = data
		if e != nil {
			break
		}
		if start.IsZero() {
			start = ci.Timestamp
		}
		dt := ci.Timestamp.Sub(start).Seconds()
		if dt < 0 {
			continue
		}
		idx := int64(dt / o.BinSec)
		bins[idx] += int64(ci.Length) // on-the-wire bytes
		if idx > lastBin {
			lastBin = idx
		}
	}

	// агрегаты
	nbins := 0
	var sumBps, peakBps float64
	for i := int64(0); i <= lastBin; i++ {
		b := float64(bins[i])
		bps := (b * 8.0) / o.BinSec
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
	return chanRow{
		File:         file,
		CapacityMbps: o.CapBps / 1e6,
		AvgBps:       avgBps,
		PeakBps:      peakBps,
		MLUAvg:       safeDiv(avgBps, o.CapBps),
		MLUPeak:      safeDiv(peakBps, o.CapBps),
		TimeBins:     nbins,
	}, nil
}

/* ========================= FLOWS SCAN ========================= */

type flowScanOpts struct {
	Proto   string // tcp|udp|any
	TCPPort int
	UDPPort int
	SkipBad bool
}

func parseFlowPkt(data []byte, lt layers.LinkType, ci gopacket.CaptureInfo, agg map[flowKey]flowAgg, o flowScanOpts) {
	pkt := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	netL := pkt.NetworkLayer()
	if netL == nil {
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

	trL := pkt.TransportLayer()
	if trL == nil {
		return
	}

	switch tl := trL.(type) {
	case *layers.TCP:
		if o.Proto == "udp" {
			return
		}
		if o.TCPPort > 0 && !(int(tl.SrcPort) == o.TCPPort || int(tl.DstPort) == o.TCPPort) {
			return
		}
		key := flowKey{Src: srcIP.String(), Dst: dstIP.String(), Sp: uint16(tl.SrcPort), Dp: uint16(tl.DstPort), Proto: "tcp"}
		f := agg[key]
		f.Packets++
		f.Bytes += int64(ci.Length)
		if f.First.IsZero() || ci.Timestamp.Before(f.First) {
			f.First = ci.Timestamp
		}
		if ci.Timestamp.After(f.Last) {
			f.Last = ci.Timestamp
		}
		agg[key] = f
	case *layers.UDP:
		if o.Proto == "tcp" {
			return
		}
		if o.UDPPort > 0 && !(int(tl.SrcPort) == o.UDPPort || int(tl.DstPort) == o.UDPPort) {
			return
		}
		key := flowKey{Src: srcIP.String(), Dst: dstIP.String(), Sp: uint16(tl.SrcPort), Dp: uint16(tl.DstPort), Proto: "udp"}
		f := agg[key]
		f.Packets++
		f.Bytes += int64(ci.Length)
		if f.First.IsZero() || ci.Timestamp.Before(f.First) {
			f.First = ci.Timestamp
		}
		if ci.Timestamp.After(f.Last) {
			f.Last = ci.Timestamp
		}
		agg[key] = f
	default:
		return
	}
}

func scanFlows(file string, o flowScanOpts) (map[flowKey]flowAgg, error) {
	op, err := openAny(file)
	if err != nil {
		if o.SkipBad {
			log.Printf("[WARN] skip flows %s: %v", file, err)
			return map[flowKey]flowAgg{}, nil
		}
		return nil, err
	}
	defer op.Close()

	agg := make(map[flowKey]flowAgg, 4096)
	for {
		data, ci, e := op.handle.ReadPacketData()
		if e != nil {
			break
		}
		parseFlowPkt(data, op.lt, ci, agg, o)
	}
	return agg, nil
}

/* ========================= CSV OUT ========================= */

func writeChannelsCSV(path string, rows []chanRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"file", "capacity_mbps", "avg_bps", "peak_bps", "MLU_avg", "MLU_peak", "time_bins"})
	for _, r := range rows {
		rec := []string{
			r.File,
			fmt.Sprintf("%.6f", r.CapacityMbps),
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

func writeFlowsCSV(path string, agg map[flowKey]flowAgg) error {
	type flowRow struct {
		flowKey
		Packets  int64
		Bytes    int64
		Duration float64
		ThrBps   float64
	}
	rows := make([]flowRow, 0, len(agg))
	for k, v := range agg {
		d := v.Last.Sub(v.First).Seconds()
		if d <= 0 {
			continue
		}
		rows = append(rows, flowRow{
			flowKey:  k,
			Packets:  v.Packets,
			Bytes:    v.Bytes,
			Duration: d,
			ThrBps:   (float64(v.Bytes) * 8.0) / d,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ThrBps > rows[j].ThrBps })

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"proto", "src", "sp", "dst", "dp", "packets", "bytes", "duration_s", "throughput_bps"})
	for _, r := range rows {
		rec := []string{
			r.Proto, r.Src, strconv.Itoa(int(r.Sp)), r.Dst, strconv.Itoa(int(r.Dp)),
			strconv.FormatInt(r.Packets, 10),
			strconv.FormatInt(r.Bytes, 10),
			fmt.Sprintf("%.6f", r.Duration),
			fmt.Sprintf("%.3f", r.ThrBps),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

/* ========================= MAIN ========================= */

func main() {
	a := parseFlags()

	// Список файлов каналов
	files, err := filepath.Glob(a.Glob)
	if err != nil {
		log.Fatalf("[ERROR] glob: %v", err)
	}
	if len(files) == 0 {
		log.Fatalf("[ERROR] no files matched: %s", a.Glob)
	}
	sort.Strings(files)
	fmt.Printf("[INFO] channels: %d files\n", len(files))

	// Карта ёмкостей per file
	caps, err := readCapsCSV(a.CapsCSV)
	if err != nil {
		log.Fatalf("[ERROR] caps-csv: %v", err)
	}
	if len(caps) == 0 && a.CapacityMbps <= 0 {
		log.Fatalf("[ERROR] neither --caps-csv nor --capacity-mbps given")
	}

	/* ---------- CHANNELS (MLU per channel) ---------- */

	type jobC struct{ file string }
	type resC struct {
		row chanRow
		err error
	}

	inC := make(chan jobC)
	outC := make(chan resC)

	var wgC sync.WaitGroup
	workerC := func() {
		defer wgC.Done()
		for j := range inC {
			capMbps := matchCapacity(j.file, caps, a.CapacityMbps)
			row, e := scanChannel(j.file, chanScanOpts{
				BinSec:  a.BinSec,
				CapBps:  capMbps * 1_000_000.0,
				SkipBad: a.SkipBad,
			})
			row.CapacityMbps = capMbps
			outC <- resC{row: row, err: e}
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
		wgC.Add(1)
		go workerC()
	}
	go func() {
		for _, f := range files {
			inC <- jobC{file: f}
		}
		close(inC)
		wgC.Wait()
		close(outC)
	}()

	var channels []chanRow
	for r := range outC {
		if r.err != nil {
			log.Fatalf("[ERROR] channel: %v", r.err)
		}
		channels = append(channels, r.row)
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].File < channels[j].File })

	if err := writeChannelsCSV(a.OutChannels, channels); err != nil {
		log.Fatalf("[ERROR] write channels: %v", err)
	}
	fmt.Printf("Channels CSV: %s\n", a.OutChannels)

	/* ---------- FLOWS (throughput per flow) ---------- */

	var ff []string
	if a.FlowsGlob == "" {
		fmt.Println("[INFO] --flows-glob не задан: берём те же файлы, что и для каналов.")
		ff = append(ff, files...) // files — это список из --glob
	} else {
		var err error
		ff, err = filepath.Glob(a.FlowsGlob)
		if err != nil {
			log.Fatalf("[ERROR] flows-glob: %v", err)
		}
		if len(ff) == 0 {
			log.Fatalf("[ERROR] flows-glob matched 0 files: %s", a.FlowsGlob)
		}
	}
	sort.Strings(ff)
	fmt.Printf("[INFO] flows: %d files\n", len(ff))
	if err != nil {
		log.Fatalf("[ERROR] flows-glob: %v", err)
	}
	if len(ff) == 0 {
		log.Fatalf("[ERROR] flows-glob matched 0 files: %s", a.FlowsGlob)
	}
	sort.Strings(ff)
	fmt.Printf("[INFO] flows: %d files\n", len(ff))

	type jobF struct{ file string }
	type resF struct {
		m   map[flowKey]flowAgg
		err error
	}
	inF := make(chan jobF)
	outF := make(chan resF)

	var wgF sync.WaitGroup
	workerF := func() {
		defer wgF.Done()
		opts := flowScanOpts{
			Proto:   strings.ToLower(a.Proto),
			TCPPort: a.TCPPort,
			UDPPort: a.UDPPort,
			SkipBad: a.SkipBad,
		}
		for j := range inF {
			m, e := scanFlows(j.file, opts)
			outF <- resF{m: m, err: e}
		}
	}

	nwf := a.Jobs
	if nwf > len(ff) {
		nwf = len(ff)
	}
	if nwf < 1 {
		nwf = 1
	}
	for i := 0; i < nwf; i++ {
		wgF.Add(1)
		go workerF()
	}
	go func() {
		for _, f := range ff {
			inF <- jobF{file: f}
		}
		close(inF)
		wgF.Wait()
		close(outF)
	}()

	// Объединяем потоки из разных файлов:
	// чтобы не дублировать, берём для 5-tuple: Bytes = max(Bytes), First=min, Last=max.
	flows := map[flowKey]flowAgg{}
	for r := range outF {
		if r.err != nil {
			log.Fatalf("[ERROR] flows: %v", r.err)
		}
		for k, v := range r.m {
			if ex, ok := flows[k]; !ok {
				flows[k] = v
			} else {
				if v.Bytes > ex.Bytes {
					ex.Bytes = v.Bytes
					// packets не суммируем, оставим как proxy
					ex.Packets = v.Packets
				}
				if !v.First.IsZero() && (ex.First.IsZero() || v.First.Before(ex.First)) {
					ex.First = v.First
				}
				if v.Last.After(ex.Last) {
					ex.Last = v.Last
				}
				flows[k] = ex
			}
		}
	}

	if len(flows) == 0 {
		log.Fatal(errors.New("no flows found"))
	}
	if err := writeFlowsCSV(a.OutFlows, flows); err != nil {
		log.Fatalf("[ERROR] write flows: %v", err)
	}
	fmt.Printf("Flows CSV:    %s\n", a.OutFlows)

	// Краткий summary по потокам
	type pair struct {
		k flowKey
		v flowAgg
	}
	var list []pair
	for k, v := range flows {
		list = append(list, pair{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		di := list[i].v.Last.Sub(list[i].v.First).Seconds()
		dj := list[j].v.Last.Sub(list[j].v.First).Seconds()
		ti := 0.0
		if di > 0 {
			ti = (float64(list[i].v.Bytes) * 8) / di
		}
		tj := 0.0
		if dj > 0 {
			tj = (float64(list[j].v.Bytes) * 8) / dj
		}
		return ti > tj
	})
	top := 5
	if len(list) < top {
		top = len(list)
	}
	fmt.Println("\nTop flows by throughput:")
	for i := 0; i < top; i++ {
		v := list[i].v
		d := v.Last.Sub(v.First).Seconds()
		thr := 0.0
		if d > 0 {
			thr = (float64(v.Bytes) * 8) / d
		}
		fmt.Printf("  %s %s:%d -> %s:%d  thr=%s  bytes=%d  dur=%.3fs\n",
			list[i].k.Proto, list[i].k.Src, list[i].k.Sp, list[i].k.Dst, list[i].k.Dp,
			humanBps(thr), v.Bytes, d)
	}
}
