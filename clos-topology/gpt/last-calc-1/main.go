package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type FlowKey struct {
	Src, Dst   string
	Sport, Dport uint16
	Proto      string
}

// направление «туда» и «обратно» для удобства поиска ACK’ов
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{Src: k.Dst, Dst: k.Src, Sport: k.Dport, Dport: k.Sport, Proto: k.Proto}
}

type FlowStats struct {
	Bytes        int64
	Pkts         int64
	FirstTS      time.Time
	LastTS       time.Time
	// RTT измеряется только для TCP (по ack’ам)
	RTTSum       time.Duration
	RTTSamples   int64
	// для TCP храним «висящие» сегменты: seqEnd -> ts
	Outstanding  map[uint32]time.Time
	LastAckedSeq uint32
}

type Row struct {
	AlgoOrDir string
	File      string
	Flow      FlowKey
	Bytes     int64
	Pkts      int64
	Duration  float64 // сек
	ThroughMb float64 // Мбит/с
	AvgRTTms  string  // пусто для не-TCP
	RTTSamples int64
}

var (
	rootPath     = flag.String("path", ".", "root directory with pcap files")
	outCSV       = flag.String("out", "flows.csv", "output CSV file")
	minFlowBytes = flag.Int64("minflowbytes", 0, "filter: minimal bytes per flow")
)

func main() {
	flag.Parse()

	var rows []Row
	err := filepath.WalkDir(*rootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil { return err }
		if d.IsDir() { return nil }
		low := strings.ToLower(d.Name())
		if !(strings.HasSuffix(low, ".pcap") || strings.HasSuffix(low, ".pcapng")) {
			return nil
		}
		algo := relTopDir(*rootPath, path) // имя подкаталога-алгоритма
		fileRows, err := processPCAP(path, algo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: %s: %v\n", path, err)
			return nil
		}
		rows = append(rows, fileRows...)
		return nil
	})
	if err != nil {
		panic(err)
	}

	// фильтр и сортировка
	filtered := rows[:0]
	for _, r := range rows {
		if r.Bytes >= *minFlowBytes {
			filtered = append(filtered, r)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].AlgoOrDir != filtered[j].AlgoOrDir {
			return filtered[i].AlgoOrDir < filtered[j].AlgoOrDir
		}
		if filtered[i].File != filtered[j].File {
			return filtered[i].File < filtered[j].File
		}
		// по throughput убыв.
		return filtered[i].ThroughMb > filtered[j].ThroughMb
	})

	if err := writeCSV(*outCSV, filtered); err != nil {
		panic(err)
	}
	fmt.Printf("OK: %d flow-строк записано в %s\n", len(filtered), *outCSV)
}

func relTopDir(root, full string) string {
	rel, err := filepath.Rel(root, full)
	if err != nil { return "" }
	parts := strings.Split(rel, string(os.PathSeparator))
	if len(parts) > 1 {
		return parts[0] // например: "grd", "ilp", "ospf-1"
	}
	return ""
}

func processPCAP(path, algo string) ([]Row, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()

	// поддержка pcap и pcapng
	var r gopacket.PacketDataSource
	br := bufio.NewReader(f)
	peek, _ := br.Peek(4)
	if len(peek) == 4 && string(peek[:4]) == "\x0a\x0d\x0d\x0a" {
		// pcapng
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil { return nil, err }
		r = ng
	} else {
		pr, err := pcapgo.NewReader(br)
		if err != nil { return nil, err }
		r = pr
	}

	flows := make(map[FlowKey]*FlowStats)

	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF { break }
		if err != nil { return nil, err }

		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		})
		// IPv4/IPv6
		var (
			ipSrc, ipDst string
			proto string
			payloadLen int
			srcPort, dstPort uint16
			isTCP bool
			seqEnd uint32
			ackNum uint32
			ack bool
		)

		if l4 := pkt.Layer(layers.LayerTypeIPv4); l4 != nil {
			ip := l4.(*layers.IPv4)
			ipSrc = ip.SrcIP.String()
			ipDst = ip.DstIP.String()
			proto = ip.Protocol.String()
			payloadLen = int(ip.Length) - int(ip.IHL)*4
		} else if l6 := pkt.Layer(layers.LayerTypeIPv6); l6 != nil {
			ip := l6.(*layers.IPv6)
			ipSrc = ip.SrcIP.String()
			ipDst = ip.DstIP.String()
			proto = ip.NextHeader.String()
			// нет простого поля «length всего IP» — возьмём payload
			payloadLen = int(ip.Length)
		} else {
			continue // не IP
		}

		// TCP/UDP
		if tl := pkt.Layer(layers.LayerTypeTCP); tl != nil {
			t := tl.(*layers.TCP)
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
			isTCP = true
			ack = t.ACK
			// seqEnd = seq + payloadLen (без опций/заголовка)
			seqEnd = uint32(t.Seq) + uint32(len(t.Payload))
			ackNum = uint32(t.Ack)
			proto = "TCP"
		} else if ul := pkt.Layer(layers.LayerTypeUDP); ul != nil {
			u := ul.(*layers.UDP)
			srcPort = uint16(u.SrcPort)
			dstPort = uint16(u.DstPort)
			proto = "UDP"
		} else {
			// другие L4 проигнорируем
			continue
		}

		k := FlowKey{Src: ipSrc, Dst: ipDst, Sport: srcPort, Dport: dstPort, Proto: proto}
		fs := flows[k]
		if fs == nil {
			fs = &FlowStats{Outstanding: make(map[uint32]time.Time)}
			flows[k] = fs
		}

		// Складываем байты/пакеты/TS
		fs.Bytes += int64(payloadLen)
		fs.Pkts++
		ts := ci.Timestamp
		if fs.FirstTS.IsZero() || ts.Before(fs.FirstTS) {
			fs.FirstTS = ts
		}
		if ts.After(fs.LastTS) {
			fs.LastTS = ts
		}

		// RTT только для TCP: фиксация исходящих сегментов и обработка ACK’ов
		if isTCP {
			// регистрируем отправку сегмента (payload > 0)
			if seqEnd > 0 && payloadLen > 0 {
				fs.Outstanding[seqEnd] = ts
			}
			// если пришёл ACK в обратном направлении — посчитаем RTT
			if ack {
				rev := k.Reverse()
				revStats := flows[rev]
				if revStats != nil && len(revStats.Outstanding) > 0 {
					// найдём минимальный seqEnd, который <= ackNum
					var minSeq uint32 = 0
					var sendTS time.Time
					for sEnd, tSent := range revStats.Outstanding {
						if sEnd <= ackNum {
							if minSeq == 0 || sEnd < minSeq {
                                minSeq = sEnd
								sendTS = tSent
							}
						}
					}
					if minSeq != 0 && !sendTS.IsZero() {
						rtt := ts.Sub(sendTS)
						if rtt > 0 && rtt < time.Second*10 { // отсечь мусор
							revStats.RTTSum += rtt
							revStats.RTTSamples++
						}
						// удалить все подтверждённые сегменты (кумулятивный ACK)
						for sEnd := range revStats.Outstanding {
							if sEnd <= ackNum {
								delete(revStats.Outstanding, sEnd)
							}
						}
						revStats.LastAckedSeq = ackNum
					}
				}
			}
		}
	}

	// формируем строки
	var rows []Row
	for k, s := range flows {
		if s.FirstTS.IsZero() || s.LastTS.Sub(s.FirstTS) <= 0 {
			continue
		}
		dur := s.LastTS.Sub(s.FirstTS).Seconds()
		through := (float64(s.Bytes) * 8.0) / dur / 1e6 // Mbps
		avgRTT := ""
		if k.Proto == "TCP" && s.RTTSamples > 0 {
			avgRTT = fmt.Sprintf("%.3f", float64(s.RTTSum.Microseconds())/1000.0/float64(s.RTTSamples))
		}
		rows = append(rows, Row{
			AlgoOrDir: algo,
			File:      filepath.Base(path),
			Flow:      k,
			Bytes:     s.Bytes,
			Pkts:      s.Pkts,
			Duration:  dur,
			ThroughMb: through,
			AvgRTTms:  avgRTT,
			RTTSamples: s.RTTSamples,
		})
	}
	return rows, nil
}

func writeCSV(path string, rows []Row) error {
	f, err := os.Create(path)
	if err != nil { return err }
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"algo_dir", "file",
		"proto", "src", "sport", "dst", "dport",
		"pkts", "bytes", "duration_sec", "throughput_mbps",
		"avg_tcp_rtt_ms", "rtt_samples",
	}
	if err := w.Write(header); err != nil { return err }

	for _, r := range rows {
		rec := []string{
			r.AlgoOrDir, r.File,
			r.Flow.Proto, r.Flow.Src, fmt.Sprintf("%d", r.Flow.Sport),
			r.Flow.Dst, fmt.Sprintf("%d", r.Flow.Dport),
			fmt.Sprintf("%d", r.Pkts),
			fmt.Sprintf("%d", r.Bytes),
			fmt.Sprintf("%.6f", r.Duration),
			fmt.Sprintf("%.6f", r.ThroughMb),
			r.AvgRTTms,
			fmt.Sprintf("%d", r.RTTSamples),
		}
		if err := w.Write(rec); err != nil { return err }
	}
	return nil
}
