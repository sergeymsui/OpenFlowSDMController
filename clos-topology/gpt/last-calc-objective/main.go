// pcap_objective.go
// go 1.21+
// deps: github.com/google/gopacket (и системный libpcap)
// Цели: корректное сравнение алгоритмов без методических перекосов.
// - Уровень байтов настраиваем: L2 / L3 payload / Line-rate (L2 + 20B per frame).
// - Потоки из разных файлов НЕ растягиваем по времени: merge=best (или none).
// - Сводки: mean/median/p95 + byte-weighted mean. RTT — диагностически (TCP ACK).

package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
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

/************** FLAGS **************/
type argsT struct {
	Glob         string
	CapsCSV      string
	CapacityMbps float64
	BinSec       float64
	IgnoreEmpty  bool
	OutChannels  string

	FlowsGlob string
	Proto     string // tcp|udp|any
	Port      int    // 0=any (TCP or UDP)
	BytesMode string // l2|l3payload|linerate
	Merge     string // best|none
	BestOf    string // bytes|packets|throughput (для merge=best)
	OutFlows  string

	Jobs    int
	SkipBad bool
	Quiet   bool
}

func parseFlags() argsT {
	var a argsT
	flag.StringVar(&a.Glob, "glob", "", "Glob PCAP для расчёта MLU по каналам (напр. '.../grd/*.pcap') [required]")
	flag.StringVar(&a.CapsCSV, "caps-csv", "", "CSV file,capacity_mbps (перекрывает --capacity-mbps)")
	flag.Float64Var(&a.CapacityMbps, "capacity-mbps", 0, "Ёмкость канала по умолчанию, если не указана в caps CSV")
	flag.Float64Var(&a.BinSec, "bin", 1.0, "Размер временного бина, сек (MLU)")
	flag.BoolVar(&a.IgnoreEmpty, "ignore-empty-bins", false, "Среднее по MLU считать только по бинам с трафиком")
	flag.StringVar(&a.OutChannels, "out-channels", "./channels_summary.csv", "Вывод CSV по каналам")

	flag.StringVar(&a.FlowsGlob, "flows-glob", "", "Glob PCAP для извлечения потоков (рекомендуется одна точка наблюдения)")
	flag.StringVar(&a.Proto, "proto", "any", "Фильтр протокола: tcp|udp|any")
	flag.IntVar(&a.Port, "port", 0, "Фильтр по TCP/UDP порту (0 = любой)")
	flag.StringVar(&a.BytesMode, "bytes-mode", "l3payload", "Счёт байтов: l2|l3payload|linerate")
	flag.StringVar(&a.Merge, "merge", "best", "Слияние потоков из разных файлов: best|none")
	flag.StringVar(&a.BestOf, "best-of", "bytes", "Критерий best (bytes|packets|throughput)")
	flag.StringVar(&a.OutFlows, "out-flows", "./flows_summary.csv", "Вывод CSV по потокам")

	flag.IntVar(&a.Jobs, "jobs", runtime.NumCPU(), "Параллельные файлы")
	flag.BoolVar(&a.SkipBad, "skip-bad", true, "Пропускать битые PCAP")
	flag.BoolVar(&a.Quiet, "quiet", false, "Тише лог")
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
	a.BytesMode = strings.ToLower(a.BytesMode)
	a.Merge = strings.ToLower(a.Merge)
	a.BestOf = strings.ToLower(a.BestOf)
	a.Proto = strings.ToLower(a.Proto)
	return a
}

/************** TYPES **************/
type chanRow struct {
	File            string
	CapacityMbps    float64
	AvgBps, PeakBps float64
	MLUAvg, MLUPeak float64
	TimeBins        int
	ActiveBins      int
}

type flowKey struct {
	File     string // чтобы при merge=none различать одинаковые 5-tuple в разных файлах
	Src, Dst string
	Sp, Dp   uint16
	Proto    string // "tcp"|"udp"
}

func (k flowKey) same5tuple() flowKey {
	return flowKey{File: "", Src: k.Src, Dst: k.Dst, Sp: k.Sp, Dp: k.Dp, Proto: k.Proto}
}
func (k flowKey) reverse() flowKey {
	return flowKey{File: k.File, Src: k.Dst, Dst: k.Src, Sp: k.Dp, Dp: k.Sp, Proto: k.Proto}
}

type flowAgg struct {
	File    string
	Packets int64
	Frames  int64
	Bytes   int64 // по выбранному bytes-mode
	L2Bytes int64 // для сведений (исходный L2)
	First   time.Time
	Last    time.Time

	RTTSum      time.Duration
	RTTSamples  int64
	Outstanding map[uint32]time.Time // seqEnd -> tSent
}

/************** UTIL **************/
func humanBps(bps float64) string {
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	i := 0
	for bps >= 1000 && i < len(units)-1 {
		bps /= 1000
		i++
	}
	return fmt.Sprintf("%.2f %s", bps, units[i])
}
func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	pos := (p / 100.0) * float64(len(sorted)-1)
	l := int(math.Floor(pos))
	u := int(math.Ceil(pos))
	if l == u {
		return sorted[l]
	}
	w := pos - float64(l)
	return sorted[l]*(1-w) + sorted[u]*w
}

/************** CAPACITY MAP **************/
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
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	for i, row := range rows {
		if len(row) < 2 {
			continue
		}
		if i == 0 && strings.Contains(strings.ToLower(row[0]), "file") {
			continue
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
	if v, ok := caps[file]; ok {
		return v
	}
	base := filepath.Base(file)
	if v, ok := caps[base]; ok {
		return v
	}
	return def
}

/************** PCAP READER (pcap | pcapng) **************/
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

/************** CHANNEL SCAN (MLU) **************/
type chanScanOpts struct {
	BinSec      float64
	CapBps      float64
	SkipBad     bool
	IgnoreEmpty bool
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

	// Считаем только L2 длину пакета (pcap length). Line-rate тут не нужен.
	bins := map[int64]struct {
		bytes int64
		cnt   int64
	}{}
	var start time.Time
	var maxIdx int64 = -1

	for {
		_, ci, e := op.handle.ReadPacketData()
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
		rec := bins[idx]
		rec.bytes += int64(ci.Length) // L2 bytes
		rec.cnt++
		bins[idx] = rec
		if idx > maxIdx {
			maxIdx = idx
		}
	}

	nbins := 0
	active := 0
	var sumBps, peakBps float64
	if maxIdx >= 0 {
		for i := int64(0); i <= maxIdx; i++ {
			rec, ok := bins[i]
			var bps float64
			if ok {
				active++
				bps = (float64(rec.bytes) * 8.0) / o.BinSec
			} else {
				if o.IgnoreEmpty {
					continue
				}
				bps = 0
			}
			sumBps += bps
			if bps > peakBps {
				peakBps = bps
			}
			nbins++
		}
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
		ActiveBins:   active,
	}, nil
}

/************** FLOWS SCAN **************/
type flowScanOpts struct {
	Proto     string // tcp|udp|any
	Port      int
	SkipBad   bool
	BytesMode string // l2|l3payload|linerate
}

func addBytes(bytesMode string, ciLen int, ipPayload int, frames *int64) int64 {
	switch bytesMode {
	case "l3payload":
		if ipPayload < 0 {
			ipPayload = 0
		}
		return int64(ipPayload)
	case "linerate":
		// аппроксимация: L2 + 20 байт на кадр (переамбула 8 + IFG 12)
		*frames++
		return int64(ciLen) + 20
	default: // "l2"
		return int64(ciLen)
	}
}

func parseFile(path string, o flowScanOpts) (map[flowKey]flowAgg, error) {
	op, err := openAny(path)
	if err != nil {
		if o.SkipBad {
			log.Printf("[WARN] skip flows %s: %v", path, err)
			return map[flowKey]flowAgg{}, nil
		}
		return nil, err
	}
	defer op.Close()

	flows := make(map[flowKey]flowAgg, 4096)

	for {
		data, ci, e := op.handle.ReadPacketData()
		if e != nil {
			break
		}

		p := gopacket.NewPacket(data, op.lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

		var ipSrc, ipDst string
		var ipPayloadLen int
		var l4proto string

		if l4 := p.Layer(layers.LayerTypeIPv4); l4 != nil {
			ip := l4.(*layers.IPv4)
			ipSrc, ipDst = ip.SrcIP.String(), ip.DstIP.String()
			l4proto = ip.Protocol.String()
			ihl := int(ip.IHL) * 4
			total := int(ip.Length)
			if total >= ihl {
				ipPayloadLen = total - ihl
			} else {
				ipPayloadLen = 0
			}
		} else if l6 := p.Layer(layers.LayerTypeIPv6); l6 != nil {
			ip := l6.(*layers.IPv6)
			ipSrc, ipDst = ip.SrcIP.String(), ip.DstIP.String()
			l4proto = ip.NextHeader.String()
			ipPayloadLen = int(ip.Length) // IPv6 Length = payload
		} else {
			continue
		}

		tr := p.TransportLayer()
		if tr == nil {
			continue
		}

		ts := ci.Timestamp
		var key flowKey
		isTCP := false
		var seqEnd, ackNum uint32
		var hasACK bool
		var sport, dport uint16

		switch tl := tr.(type) {
		case *layers.TCP:
			isTCP = true
			l4proto = "tcp"
			sport, dport = uint16(tl.SrcPort), uint16(tl.DstPort)
			seqEnd = uint32(tl.Seq) + uint32(len(tl.Payload))
			ackNum = uint32(tl.Ack)
			hasACK = tl.ACK
		case *layers.UDP:
			l4proto = "udp"
			sport, dport = uint16(tr.(*layers.UDP).SrcPort), uint16(tr.(*layers.UDP).DstPort)
		default:
			continue
		}

		// Фильтры
		switch o.Proto {
		case "tcp":
			if !isTCP {
				continue
			}
		case "udp":
			if isTCP {
				continue
			}
		}
		if o.Port > 0 && int(sport) != o.Port && int(dport) != o.Port {
			continue
		}

		key = flowKey{
			File: filepath.Base(path),
			Src:  ipSrc, Dst: ipDst,
			Sp: sport, Dp: dport,
			Proto: l4proto,
		}
		f := flows[key]
		f.File = filepath.Base(path)
		f.Packets++
		f.L2Bytes += int64(ci.Length)
		f.Bytes += addBytes(o.BytesMode, ci.Length, ipPayloadLen, &f.Frames)
		if f.First.IsZero() || ts.Before(f.First) {
			f.First = ts
		}
		if ts.After(f.Last) {
			f.Last = ts
		}
		if isTCP {
			if f.Outstanding == nil {
				f.Outstanding = make(map[uint32]time.Time)
			}
			if seqEnd > 0 && len(p.ApplicationLayer().Payload()) > 0 {
				// если нет AL — fallback к TCP payload длине
				f.Outstanding[seqEnd] = ts
			}
			if hasACK {
				rev := key.reverse()
				if peer, ok := flows[rev]; ok && len(peer.Outstanding) > 0 {
					var chosen uint32
					var sent time.Time
					for sEnd, tSent := range peer.Outstanding {
						if sEnd <= ackNum && (chosen == 0 || sEnd < chosen) {
							chosen, sent = sEnd, tSent
						}
					}
					if chosen != 0 && !sent.IsZero() {
						rtt := ts.Sub(sent)
						if rtt > 0 && rtt < 10*time.Second {
							peer.RTTSum += rtt
							peer.RTTSamples++
						}
						for sEnd := range peer.Outstanding {
							if sEnd <= ackNum {
								delete(peer.Outstanding, sEnd)
							}
						}
						flows[rev] = peer
					}
				}
			}
		}
		flows[key] = f
	}
	return flows, nil
}

/************** MERGE POLICY **************/
func chooseBetter(a, b flowAgg, bestOf string) flowAgg {
	switch bestOf {
	case "packets":
		if b.Packets > a.Packets {
			return b
		}
	case "throughput":
		da := a.Last.Sub(a.First).Seconds()
		db := b.Last.Sub(b.First).Seconds()
		ta := 0.0
		tb := 0.0
		if da > 0 {
			ta = (float64(a.Bytes) * 8) / da
		}
		if db > 0 {
			tb = (float64(b.Bytes) * 8) / db
		}
		if tb > ta {
			return b
		}
	default: // "bytes"
		if b.Bytes > a.Bytes {
			return b
		}
	}
	return a
}

func mergeBest(all map[flowKey]flowAgg, m map[flowKey]flowAgg, bestOf string) {
	for k, v := range m {
		k5 := k.same5tuple() // сливаем по 5-tuple, без file
		if v.First.IsZero() || v.Last.Sub(v.First) <= 0 {
			continue
		}
		if ex, ok := all[k5]; !ok {
			all[k5] = v
		} else {
			all[k5] = chooseBetter(ex, v, bestOf)
		}
	}
}

/************** CSV **************/
func writeChannelsCSV(path string, rows []chanRow) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"file", "capacity_mbps", "avg_bps", "peak_bps", "MLU_avg", "MLU_peak", "time_bins", "active_bins"})
	for _, r := range rows {
		rec := []string{
			r.File,
			fmt.Sprintf("%.6f", r.CapacityMbps),
			fmt.Sprintf("%.3f", r.AvgBps),
			fmt.Sprintf("%.3f", r.PeakBps),
			fmt.Sprintf("%.6f", r.MLUAvg),
			fmt.Sprintf("%.6f", r.MLUPeak),
			strconv.Itoa(r.TimeBins),
			strconv.Itoa(r.ActiveBins),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeFlowsCSV(path string, rows []map[string]string) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"file", "proto", "src", "sp", "dst", "dp", "packets", "frames", "bytes", "bytes_l2", "duration_s", "throughput_bps", "avg_tcp_rtt_ms", "rtt_samples"}
	_ = w.Write(header)
	for _, r := range rows {
		row := make([]string, 0, len(header))
		for _, h := range header {
			row = append(row, r[h])
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return w.Error()
}

/************** MAIN **************/
func main() {
	a := parseFlags()

	// --- CHANNELS ---
	files, err := filepath.Glob(a.Glob)
	if err != nil || len(files) == 0 {
		log.Fatalf("[ERROR] no files matched: %s", a.Glob)
	}
	sort.Strings(files)
	if !a.Quiet {
		fmt.Printf("[INFO] channels: %d files\n", len(files))
	}

	caps, err := readCapsCSV(a.CapsCSV)
	if err != nil {
		log.Fatalf("[ERROR] caps-csv: %v", err)
	}
	if len(caps) == 0 && a.CapacityMbps <= 0 {
		log.Fatalf("[ERROR] need --caps-csv or --capacity-mbps")
	}

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
				BinSec: a.BinSec, CapBps: capMbps * 1_000_000.0, SkipBad: a.SkipBad, IgnoreEmpty: a.IgnoreEmpty,
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
	wgC.Add(nw)
	for i := 0; i < nw; i++ {
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
	if !a.Quiet {
		fmt.Printf("Channels CSV: %s\n", a.OutChannels)
	}

	// сводка MLU
	var chAvgThrMean, chMaxThr, chMLUAvgMean, chMLUPeakMax float64
	var nCh int
	for _, r := range channels {
		chAvgThrMean += r.AvgBps
		if r.PeakBps > chMaxThr {
			chMaxThr = r.PeakBps
		}
		chMLUAvgMean += r.MLUAvg
		if r.MLUPeak > chMLUPeakMax {
			chMLUPeakMax = r.MLUPeak
		}
		nCh++
	}
	if nCh > 0 {
		chAvgThrMean /= float64(nCh)
		chMLUAvgMean /= float64(nCh)
	}
	fmt.Println("\n=== CHANNELS OVERALL ===")
	fmt.Printf("Avg throughput (mean of per-channel avg): %s\n", humanBps(chAvgThrMean))
	fmt.Printf("Max throughput (max per-channel peak):   %s\n", humanBps(chMaxThr))
	fmt.Printf("Avg MLU (mean of MLU_avg):               %.2f%%\n", chMLUAvgMean*100.0)
	fmt.Printf("Max MLU (max of MLU_peak):               %.2f%%\n", chMLUPeakMax*100.0)

	// --- FLOWS ---
	var ff []string
	if a.FlowsGlob == "" {
		if !a.Quiet {
			fmt.Println("[INFO] --flows-glob не задан: берём те же файлы, что и для каналов.")
		}
		ff = append(ff, files...)
	} else {
		ff, err = filepath.Glob(a.FlowsGlob)
		if err != nil || len(ff) == 0 {
			log.Fatalf("[ERROR] flows-glob matched 0: %s", a.FlowsGlob)
		}
	}
	sort.Strings(ff)
	if !a.Quiet {
		fmt.Printf("[INFO] flows: %d files\n", len(ff))
	}

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
		opts := flowScanOpts{Proto: a.Proto, Port: a.Port, SkipBad: a.SkipBad, BytesMode: a.BytesMode}
		for j := range inF {
			m, e := parseFile(j.file, opts)
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
	wgF.Add(nwf)
	for i := 0; i < nwf; i++ {
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

	var flowsMerged map[flowKey]flowAgg
	var flowsPerFile []map[flowKey]flowAgg
	if a.Merge == "none" {
		flowsPerFile = make([]map[flowKey]flowAgg, 0, len(ff))
	}
	flowsMerged = make(map[flowKey]flowAgg)

	for r := range outF {
		if r.err != nil {
			log.Fatalf("[ERROR] flows: %v", r.err)
		}
		if a.Merge == "none" {
			flowsPerFile = append(flowsPerFile, r.m)
		} else {
			mergeBest(flowsMerged, r.m, a.BestOf)
		}
	}

	// Подготовка строк CSV
	rows := make([]map[string]string, 0, 4096)
	addRow := func(k flowKey, v flowAgg) {
		d := v.Last.Sub(v.First).Seconds()
		if d <= 0 {
			return
		}
		thr := (float64(v.Bytes) * 8.0) / d
		avgRTT := ""
		if k.Proto == "tcp" && v.RTTSamples > 0 {
			avgRTT = fmt.Sprintf("%.3f", float64(v.RTTSum.Microseconds())/1000.0/float64(v.RTTSamples))
		}
		rows = append(rows, map[string]string{
			"file": v.File, "proto": k.Proto, "src": k.Src, "sp": strconv.Itoa(int(k.Sp)),
			"dst": k.Dst, "dp": strconv.Itoa(int(k.Dp)),
			"packets":        strconv.FormatInt(v.Packets, 10),
			"frames":         strconv.FormatInt(v.Frames, 10),
			"bytes":          strconv.FormatInt(v.Bytes, 10),
			"bytes_l2":       strconv.FormatInt(v.L2Bytes, 10),
			"duration_s":     fmt.Sprintf("%.6f", d),
			"throughput_bps": fmt.Sprintf("%.3f", thr),
			"avg_tcp_rtt_ms": avgRTT,
			"rtt_samples":    strconv.FormatInt(v.RTTSamples, 10),
		})
	}

	if a.Merge == "none" {
		for _, m := range flowsPerFile {
			for k, v := range m {
				addRow(k, v)
			}
		}
	} else {
		for k, v := range flowsMerged {
			addRow(k, v)
		}
	}

	if len(rows) == 0 {
		log.Fatal(errors.New("no flows found"))
	}
	if err := writeFlowsCSV(a.OutFlows, rows); err != nil {
		log.Fatalf("[ERROR] write flows: %v", err)
	}
	if !a.Quiet {
		fmt.Printf("Flows CSV: %s\n", a.OutFlows)
	}

	// Сводки (без искажений)
	var tputs []float64 // per-flow throughput (bps)
	var rtts []float64  // per-flow avg RTT (ms) где есть сэмплы
	var bytesAll float64
	var wsumTput float64

	for _, r := range rows {
		thrBps, _ := strconv.ParseFloat(r["throughput_bps"], 64)
		if thrBps > 0 {
			tputs = append(tputs, thrBps/1e6) // в Мбит/с для вывода
		}
		b, _ := strconv.ParseFloat(r["bytes"], 64)
		bytesAll += b
		wsumTput += (thrBps * b)

		if r["avg_tcp_rtt_ms"] != "" {
			v, _ := strconv.ParseFloat(r["avg_tcp_rtt_ms"], 64)
			if v > 0 {
				rtts = append(rtts, v)
			}
		}
	}
	sort.Float64s(tputs)
	sort.Float64s(rtts)

	var meanT, medT, p95T float64
	if len(tputs) > 0 {
		sum := 0.0
		for _, x := range tputs {
			sum += x
		}
		meanT = sum / float64(len(tputs))
		medT = percentile(tputs, 50)
		p95T = percentile(tputs, 95)
	}
	var bwMeanT float64
	if bytesAll > 0 {
		bwMeanT = (wsumTput / bytesAll) / 1e6
	} // байтово-взвешенное среднее, Мбит/с

	var meanR, medR, p95R float64
	if len(rtts) > 0 {
		sum := 0.0
		for _, x := range rtts {
			sum += x
		}
		meanR = sum / float64(len(rtts))
		medR = percentile(rtts, 50)
		p95R = percentile(rtts, 95)
	}

	fmt.Println("\n=== FLOWS OVERALL (objective) ===")
	if len(tputs) > 0 {
		fmt.Printf("Throughput (per-flow, Mbps): mean=%.3f  median=%.3f  p95=%.3f  n=%d\n", meanT, medT, p95T, len(tputs))
		fmt.Printf("Throughput (byte-weighted mean):         %.3f Mbps\n", bwMeanT)
	} else {
		fmt.Println("Throughput: NA")
	}
	if len(rtts) > 0 {
		fmt.Printf("TCP RTT (per-flow, ms):      mean=%.3f  median=%.3f  p95=%.3f  n=%d\n", meanR, medR, p95R, len(rtts))
	} else {
		fmt.Println("TCP RTT: NA (нет двунаправленных наблюдений)")
	}
}
