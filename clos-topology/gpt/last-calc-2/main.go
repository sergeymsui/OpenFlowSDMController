package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

/************** Flags **************/
var (
	globPattern  = flag.String("glob", "", "Glob-шаблон pcap/pcapng файлов одной папки алгоритма (напр. inter_pod_only/grd/*.pcap)")
	workers      = flag.Int("workers", runtime.NumCPU(), "Количество параллельных воркеров")
	outFlowsCSV  = flag.String("out-flows", "flows.csv", "Выходной CSV со сводкой по потокам")
	protoFilter  = flag.String("proto", "any", "Фильтр протокола: tcp|udp|any")
	portFilter   = flag.Int("port", 0, "Фильтр по TCP/UDP порту (0 = любой)")
	minFlowBytes = flag.Int64("min-flow-bytes", 0, "Порог отсечения потоков по объёму IP-payload байт")
	quiet        = flag.Bool("quiet", false, "Тише логирование")
)

/************** Types **************/
type flowKey struct {
	Src, Dst     string
	Sport, Dport uint16
	Proto        string // TCP|UDP
}

func (k flowKey) Reverse() flowKey {
	return flowKey{Src: k.Dst, Dst: k.Src, Sport: k.Dport, Dport: k.Sport, Proto: k.Proto}
}

type flowStats struct {
	BytesPayload int64 // только IP-payload (без L2/L3 заголовков)
	Pkts         int64
	First, Last  time.Time

	// RTT (для TCP, по кумулятивным ACK)
	RTTSum      time.Duration
	RTTSamples  int64
	Outstanding map[uint32]time.Time // seqEnd -> tSent (для исходящего направления)
}

type flowRow struct {
	flowKey
	Packets     int64
	Bytes       int64
	DurationSec float64
	TputMbps    float64
	AvgRTTms    string // пусто для не-TCP или без сэмплов
	RTTSamples  int64
}

/************** PCAP Reader **************/
type reader interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
}

func openAny(path string) (reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Авто-детект pcapng по магии 0a0d0d0a
	br := bufio.NewReader(f)
	magic, _ := br.Peek(4)
	if len(magic) == 4 && magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &wrappedReader{closer: f, ng: ng}, nil
	}
	pr, err := pcapgo.NewReader(br)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &wrappedReader{closer: f, pr: pr}, nil
}

type wrappedReader struct {
	closer *os.File
	pr     *pcapgo.Reader
	ng     *pcapgo.NgReader
}

func (w *wrappedReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if w.ng != nil {
		return w.ng.ReadPacketData()
	}
	return w.pr.ReadPacketData()
}
func (w *wrappedReader) Close() error {
	if w.closer != nil {
		return w.closer.Close()
	}
	return nil
}

/************** Per-file parsing **************/
type parseOpts struct {
	Proto string // tcp|udp|any
	Port  int    // фильтр по src/dst порту
}

func parseFile(path string, opts parseOpts) (map[flowKey]*flowStats, error) {
	r, err := openAny(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if c, ok := r.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}()

	flows := make(map[flowKey]*flowStats, 4096)

	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

		// IPv4/IPv6
		var ipSrc, ipDst string
		var ipPayloadLen int // длина полезной нагрузки IP (без заголовка IP)
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
			ipPayloadLen = int(ip.Length) // у IPv6 Length уже payload
		} else {
			continue
		}

		// L4
		isTCP := false
		var sport, dport uint16
		var seqEnd, ackNum uint32
		var hasACK bool

		if tl := p.Layer(layers.LayerTypeTCP); tl != nil {
			t := tl.(*layers.TCP)
			isTCP = true
			l4proto = "TCP"
			sport, dport = uint16(t.SrcPort), uint16(t.DstPort)
			seqEnd = uint32(t.Seq) + uint32(len(t.Payload))
			ackNum = uint32(t.Ack)
			hasACK = t.ACK
		} else if ul := p.Layer(layers.LayerTypeUDP); ul != nil {
			u := ul.(*layers.UDP)
			l4proto = "UDP"
			sport, dport = uint16(u.SrcPort), uint16(u.DstPort)
		} else {
			continue
		}

		// Протокольный/портовый фильтр
		switch strings.ToLower(opts.Proto) {
		case "tcp":
			if !isTCP {
				continue
			}
		case "udp":
			if isTCP {
				continue
			}
		}
		if opts.Port > 0 {
			if int(sport) != opts.Port && int(dport) != opts.Port {
				continue
			}
		}

		k := flowKey{Src: ipSrc, Dst: ipDst, Sport: sport, Dport: dport, Proto: l4proto}
		fs := flows[k]
		if fs == nil {
			fs = &flowStats{Outstanding: make(map[uint32]time.Time)}
			flows[k] = fs
		}

		// учёт по пакету
		fs.BytesPayload += int64(ipPayloadLen)
		fs.Pkts++
		ts := ci.Timestamp
		if fs.First.IsZero() || ts.Before(fs.First) {
			fs.First = ts
		}
		if ts.After(fs.Last) {
			fs.Last = ts
		}

		// RTT только для TCP: «отправили сегмент» -> ждём ACK в обратном key
		if isTCP {
			if seqEnd > 0 && ipPayloadLen > 0 {
				fs.Outstanding[seqEnd] = ts
			}
			if hasACK {
				rev := k.Reverse()
				if peer := flows[rev]; peer != nil && len(peer.Outstanding) > 0 {
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
						// удаляем все подтверждённые (кумулятивный ACK)
						for sEnd := range peer.Outstanding {
							if sEnd <= ackNum {
								delete(peer.Outstanding, sEnd)
							}
						}
					}
				}
			}
		}
	}
	return flows, nil
}

/************** Merge policy (best observation per flow) **************/
func mergeBest(dst map[flowKey]flowStats, src map[flowKey]*flowStats) {
	for k, v := range src {
		// игнорируем нулевую длительность
		if v.First.IsZero() || v.Last.Sub(v.First) <= 0 {
			continue
		}
		if ex, ok := dst[k]; !ok {
			dst[k] = *v
		} else {
			// Берём наблюдение с наибольшим объёмом IP-полезной нагрузки;
			// при равенстве — с большим числом пакетов.
			if v.BytesPayload > ex.BytesPayload || (v.BytesPayload == ex.BytesPayload && v.Pkts > ex.Pkts) {
				dst[k] = *v
			}
		}
	}
}

/************** CSV **************/
func writeFlowsCSV(path string, rows []flowRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{
		"proto", "src", "sport", "dst", "dport",
		"packets", "bytes_ip_payload", "duration_sec", "throughput_mbps",
		"avg_tcp_rtt_ms", "rtt_samples",
	})
	for _, r := range rows {
		rec := []string{
			r.Proto, r.Src, fmt.Sprintf("%d", r.Sport), r.Dst, fmt.Sprintf("%d", r.Dport),
			fmt.Sprintf("%d", r.Packets),
			fmt.Sprintf("%d", r.Bytes),
			fmt.Sprintf("%.6f", r.DurationSec),
			fmt.Sprintf("%.6f", r.TputMbps),
			r.AvgRTTms,
			fmt.Sprintf("%d", r.RTTSamples),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

/************** Helpers **************/
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
	return sorted[l]*(1.0-w) + sorted[u]*w
}

/************** Main **************/
func main() {
	flag.Parse()
	if *globPattern == "" {
		fmt.Fprintln(os.Stderr, "Укажите --glob, например: inter_pod_only/grd/*.pcap")
		os.Exit(2)
	}
	if *workers < 1 {
		*workers = 1
	}

	files, err := filepath.Glob(*globPattern)
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "Файлы не найдены по шаблону: %s\n", *globPattern)
		os.Exit(2)
	}
	sort.Strings(files)
	if !*quiet {
		fmt.Printf("[INFO] files: %d, workers: %d\n", len(files), *workers)
	}

	type job struct{ path string }
	type res struct {
		m   map[flowKey]*flowStats
		err error
	}

	in := make(chan job)
	out := make(chan res)
	var wg sync.WaitGroup

	// воркеры
	wg.Add(*workers)
	for i := 0; i < *workers; i++ {
		go func() {
			defer wg.Done()
			opts := parseOpts{Proto: strings.ToLower(*protoFilter), Port: *portFilter}
			for j := range in {
				m, e := parseFile(j.path, opts)
				out <- res{m: m, err: e}
			}
		}()
	}
	go func() {
		for _, p := range files {
			in <- job{path: p}
		}
		close(in)
		wg.Wait()
		close(out)
	}()

	// сбор и merge
	flows := make(map[flowKey]flowStats)
	errCount := 0
	for r := range out {
		if r.err != nil {
			errCount++
			if !*quiet {
				fmt.Fprintf(os.Stderr, "[WARN] %v\n", r.err)
			}
			continue
		}
		mergeBest(flows, r.m)
	}
	if !*quiet && errCount > 0 {
		fmt.Printf("[INFO] файлов с ошибками: %d\n", errCount)
	}

	// в строки
	rows := make([]flowRow, 0, len(flows))
	for k, v := range flows {
		dur := v.Last.Sub(v.First).Seconds()
		if dur <= 0 {
			continue
		}
		tput := (float64(v.BytesPayload) * 8.0) / dur / 1e6 // Mbps
		avgRTT := ""
		if strings.EqualFold(k.Proto, "TCP") && v.RTTSamples > 0 {
			avgRTT = fmt.Sprintf("%.3f", float64(v.RTTSum.Microseconds())/1000.0/float64(v.RTTSamples))
		}
		rows = append(rows, flowRow{
			flowKey:     k,
			Packets:     v.Pkts,
			Bytes:       v.BytesPayload,
			DurationSec: dur,
			TputMbps:    tput,
			AvgRTTms:    avgRTT,
			RTTSamples:  v.RTTSamples,
		})
	}
	// фильтр по min bytes
	if *minFlowBytes > 0 {
		filt := rows[:0]
		for _, r := range rows {
			if r.Bytes >= *minFlowBytes {
				filt = append(filt, r)
			}
		}
		rows = filt
	}

	// сортировка для удобства
	sort.Slice(rows, func(i, j int) bool { return rows[i].TputMbps > rows[j].TputMbps })

	// CSV
	if err := writeFlowsCSV(*outFlowsCSV, rows); err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка записи CSV: %v\n", err)
		os.Exit(1)
	}
	if !*quiet {
		fmt.Printf("Flows CSV: %s  (потоков: %d)\n", *outFlowsCSV, len(rows))
	}

	// агрегаты по throughput и RTT
	var tputs []float64
	var rtts []float64
	for _, r := range rows {
		if r.TputMbps > 0 && math.IsFinite(r.TputMbps) {
			tputs = append(tputs, r.TputMbps)
		}
		if r.AvgRTTms != "" {
			var v float64
			fmt.Sscanf(r.AvgRTTms, "%f", &v)
			if v > 0 && math.IsFinite(v) {
				rtts = append(rtts, v)
			}
		}
	}
	sort.Float64s(tputs)
	sort.Float64s(rtts)

	tMean, tMed, tP95 := math.NaN(), math.NaN(), math.NaN()
	if len(tputs) > 0 {
		sum := 0.0
		for _, x := range tputs {
			sum += x
		}
		tMean = sum / float64(len(tputs))
		tMed = percentile(tputs, 50)
		tP95 = percentile(tputs, 95)
	}
	rttMean := math.NaN()
	if len(rtts) > 0 {
		sum := 0.0
		for _, x := range rtts {
			sum += x
		}
		rttMean = sum / float64(len(rtts))
	}

	fmt.Println("\n=== SUMMARY (per-flow) ===")
	if len(tputs) > 0 {
		fmt.Printf("Throughput Mbps: mean=%.3f  median=%.3f  p95=%.3f  (n=%d)\n", tMean, tMed, tP95, len(tputs))
	} else {
		fmt.Println("Throughput: нет данных")
	}
	if len(rtts) > 0 {
		fmt.Printf("TCP RTT ms:     mean=%.3f  (n=%d flows with RTT)\n", rttMean, len(rtts))
	} else {
		fmt.Println("TCP RTT: нет данных")
	}
}
