// pcap_summary_fast.go (robust)
// go: 1.21+
// deps: github.com/google/gopacket v1
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

// ---------------- CLI ----------------

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

// --------------- Metrics & flow structs ---------------

type metricResult struct {
	File                 string
	AvgBps, PeakBps      float64
	MLUAvg, MLUPeak      float64
	TimeBins             int
}

type flowKey struct{ Src, Dst string; Sp, Dp uint16 }
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

// ---------------- Utils ----------------

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
	for _, v := range xs { s += v; s2 += v*v }
	if s2 == 0 { return 0 }
	n := float64(len(xs))
	return (s*s)/(n*s2)
}

func median(xs []float64) float64 {
	if len(xs) == 0 { return 0 }
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 { return s[n/2] }
	return 0.5 * (s[n/2-1] + s[n/2])
}
func p95(xs []float64) float64 {
	if len(xs) == 0 { return 0 }
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(math.Ceil(0.95*float64(len(s))))-1
	if i < 0 { i = 0 }
	if i >= len(s) { i = len(s)-1 }
	return s[i]
}
func safeDiv(a, b float64) float64 { if b == 0 { return 0 }; return a/b }

// ---------------- Robust open & scan ----------------

// формат файла
type fileFmt int
const (
	fmtUnknown fileFmt = iota
	fmtPCAP
	fmtPCAPNG
)

type opener struct {
	path   string
	file   *os.File
	reader gopacket.PacketDataSource
	lt     layers.LinkType           // для pcap
	ng     *pcapgo.NgReader         // для pcapng
	ifLT   map[int]layers.LinkType  // pcapng: ifaceIndex -> LT
	close  func() error
}

func (o *opener) Close() { if o.close != nil { _ = o.close() } }

func detectFmt(f *os.File) (fileFmt, []byte, error) {
	// читаем первые 4 байта (без сдвига)
	if _, err := f.Seek(0, 0); err != nil { return fmtUnknown, nil, err }
	h := make([]byte, 4)
	n, err := f.Read(h); if err != nil || n < 4 { return fmtUnknown, h, err }
	_, _ = f.Seek(0, 0)
	switch {
	case h[0] == 0x0A && h[1] == 0x0D && h[2] == 0x0D && h[3] == 0x0A:
		return fmtPCAPNG, h, nil
	case (h[0] == 0xA1 && h[1] == 0xB2 && h[2] == 0xC3 && h[3] == 0xD4) ||
		(h[0] == 0xD4 && h[1] == 0xC3 && h[2] == 0xB2 && h[3] == 0xA1) ||
		(h[0] == 0xA1 && h[1] == 0xB2 && h[2] == 0x3C && h[3] == 0x4D) ||
		(h[0] == 0x4D && h[1] == 0x3C && h[2] == 0xB2 && h[3] == 0xA1):
		return fmtPCAP, h, nil
	default:
		return fmtUnknown, h, nil
	}
}

func openAny(path string) (*opener, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }

	// поддержим .gz на всякий (tcpdump -z)
	var rd *bufio.Reader
	var closer func() error
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gr, e := gzip.NewReader(f)
		if e != nil { _ = f.Close(); return nil, fmt.Errorf("gzip open failed: %w", e) }
		rd = bufio.NewReader(gr)
		closer = func() error { _ = gr.Close(); return f.Close() }
	} else {
		rd = bufio.NewReader(f)
		closer = f.Close
	}

	// сначала пробуем pcapng/pcap (pure Go)
	// pcapng
	if ng, e := pcapgo.NewNgReader(rd, pcapgo.DefaultNgReaderOptions); e == nil {
		// соберём карту link-type по интерфейсам
		ifLT := map[int]layers.LinkType{}
		for i, ifc := range ng.Interfaces() {
			ifLT[i] = ifc.LinkType
		}
		return &opener{path: path, file: f, reader: ng, ng: ng, ifLT: ifLT, close: closer}, nil
	}
	// pcap
	if pr, e := pcapgo.NewReader(rd); e == nil {
		lt := pr.LinkType()
		return &opener{path: path, file: f, reader: pr, lt: lt, close: closer}, nil
	}

	// фолбэк на libpcap (понимает почти всё, в т.ч. SLL2)
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

	// читаем пакеты унифицированно
	switch r := op.reader.(type) {
	case *pcapgo.NgReader:
		for {
			data, ci, e := r.ReadPacketData()
			if e != nil { break }
			if start.IsZero() { start = ci.Timestamp }
			wire := int64(ci.CaptureLength) // pcapng уже даёт wirelen в CaptureLength
			dt := ci.Timestamp.Sub(start).Seconds()
			if dt < 0 { continue }
			idx := int64(dt / bin)
			bins[idx] += wire
			if idx > lastBin { lastBin = idx }

			if o.CollectFlows {
				lt := op.ifLT[ci.InterfaceIndex]
				parseFlow(data, lt, ci.Timestamp, flows, o.TCPPort)
			}
		}
	case *pcapgo.Reader:
		ps := gopacket.NewPacketSource(r, op.lt)
		ps.Lazy, ps.NoCopy = true, true
		for pkt := range ps.Packets() {
			ci := pkt.Metadata().CaptureInfo
			if start.IsZero() { start = ci.Timestamp }
			wire := int64(ci.Length)
			dt := ci.Timestamp.Sub(start).Seconds()
			if dt < 0 { continue }
			idx := int64(dt / bin)
			bins[idx] += wire
			if idx > lastBin { lastBin = idx }

			if o.CollectFlows {
				extractFlow(pkt, flows, o.TCPPort)
			}
		}
	case *pcap.Handle:
		for {
			data, ci, e := r.ReadPacketData()
			if e != nil { break }
			if start.IsZero() { start = ci.Timestamp }
			wire := int64(ci.CaptureLength)
			dt := ci.Timestamp.Sub(start).Seconds()
			if dt < 0 { continue }
			idx := int64(dt / bin)
			bins[idx] += wire
			if idx > lastBin { lastBin = idx }

			if o.CollectFlows {
				parseFlow(data, layers.LinkType(r.LinkType()), ci.Timestamp, flows, o.TCPPort)
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
		if bps > peakBps { peakBps = bps }
		nbins++
	}
	var avgBps float64
	if nbins > 0 { avgBps = sumBps / float64(nbins) }

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

// parseFlow: дешёвый парс из сырого data + linktype
func parseFlow(data []byte, lt layers.LinkType, ts time.Time, flows map[flowKey]flowAgg, tcpPort int) {
	pkt := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if pkt.NetworkLayer() == nil || pkt.TransportLayer() == nil { return }
	// поддержим IPv4/IPv6 + TCP
	var srcIP, dstIP net.IP
	switch ly := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		srcIP, dstIP = ly.SrcIP, ly.DstIP
	case *layers.IPv6:
		srcIP, dstIP = ly.SrcIP, ly.DstIP
	default:
		return
	}
	tcp, ok := pkt.TransportLayer().(*layers.TCP)
	if !ok { return }
	if tcpPort > 0 && !(int(tcp.SrcPort) == tcpPort || int(tcp.DstPort) == tcpPort) {
		return
	}
	key := flowKey{Src: srcIP.String(), Dst: dstIP.String(), Sp: uint16(tcp.SrcPort), Dp: uint16(tcp.DstPort)}
	agg := flows[key]
	agg.Packets++
	agg.Bytes += int64(len(data))
	if agg.First.IsZero() || ts.Before(agg.First) { agg.First = ts }
	if ts.After(agg.Last) { agg.Last = ts }
	flows[key] = agg
}

// extractFlow: быстрый путь, если уже есть Packet
func extractFlow(pkt gopacket.Packet, flows map[flowKey]flowAgg, tcpPort int) {
	netL := pkt.NetworkLayer()
	trL := pkt.TransportLayer()
	if netL == nil || trL == nil { return }
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
	if !ok { return }
	if tcpPort > 0 && !(int(tcp.SrcPort) == tcpPort || int(tcp.DstPort) == tcpPort) { return }
	key := flowKey{Src: srcIP.String(), Dst: dstIP.String(), Sp: uint16(tcp.SrcPort), Dp: uint16(tcp.DstPort)}
	ci := pkt.Metadata().CaptureInfo
	agg := flows[key]
	agg.Packets++
	agg.Bytes += int
