// pcap_summary.go
// Пересбор Python-скрипта на Go.
// Требуются: tshark в PATH.
// go build -o pcap_summary && ./pcap_summary --glob "/tmp/*.pcap" --capacity-mbps 500

package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Flow struct {
	Src      string
	Sp       int
	Dst      string
	Dp       int
	Packets  int64
	Bytes    int64
	Duration float64
	File     string
}

func runCmd(cmd []string) string {
	c := exec.Command(cmd[0], cmd[1:]...)
	out, err := c.CombinedOutput()
	if err != nil {
		log.Fatalf("[ERROR] %s\n%s", strings.Join(cmd, " "), string(out))
	}
	return string(out)
}

// Разбор "tshark -q -z io,stat,<bin>" для колонок Frames | Bytes
// Возвращает срез bits/s по каждому тайм-бину.
func parseIoStat(text string, binSec float64) []float64 {
	var bits []float64
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "<>") && strings.Contains(line, "|") {
			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				p := strings.TrimSpace(parts[2])
				// иногда в таблицах бывают пробелы, запятые — чистим
				p = strings.ReplaceAll(p, ",", "")
				if _, err := strconv.Atoi(p); err == nil {
					bytesVal, _ := strconv.ParseInt(p, 10, 64)
					bps := (float64(bytesVal) * 8.0) / binSec
					bits = append(bits, bps)
				}
			}
		}
	}
	return bits
}

// Разбор "tshark -q -z conv,tcp" (с возможным -Y "tcp.port==X")
func parseConvTCP(text string) []Flow {
	re := regexp.MustCompile(`\s*([0-9a-fA-F\.:]+):(\d+)\s+<->\s+([0-9a-fA-F\.:]+):(\d+)\s+(\d+)\s+(\d+)\s+([\d\.]+)`)
	var flows []Flow
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		m := re.FindStringSubmatch(line)
		if len(m) == 8 {
			sp, _ := strconv.Atoi(m[2])
			dp, _ := strconv.Atoi(m[4])
			pkts, _ := strconv.ParseInt(m[5], 10, 64)
			byts, _ := strconv.ParseInt(m[6], 10, 64)
			dur, _ := strconv.ParseFloat(m[7], 64)
			flows = append(flows, Flow{
				Src:      m[1],
				Sp:       sp,
				Dst:      m[3],
				Dp:       dp,
				Packets:  pkts,
				Bytes:    byts,
				Duration: dur,
			})
		}
	}
	return flows
}

func humanBps(bps float64) string {
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	v := bps
	i := 0
	for v >= 1000.0 && i < len(units)-1 {
		v /= 1000.0
		i++
	}
	return fmt.Sprintf("%.2f %s", v, units[i])
}

func fileMetrics(pcap string, capMbps float64, binSec float64) (avgBps, peakBps, mlu float64, nBins int) {
	// tshark -r <pcap> -q -z io,stat,<bin>
	binStr := fmt.Sprintf("%.6g", binSec)
	out := runCmd([]string{"tshark", "-r", pcap, "-q", "-z", "io,stat," + binStr})
	series := parseIoStat(out, binSec)
	capBps := capMbps * 1_000_000.0
	if len(series) > 0 {
		var sum float64
		peak := series[0]
		for _, v := range series {
			sum += v
			if v > peak {
				peak = v
			}
		}
		avg := sum / float64(len(series))
		var m float64
		if capBps > 0 {
			m = peak / capBps
		}
		return avg, peak, m, len(series)
	}
	return 0, 0, 0, 0
}

func flowsFromFiles(files []string, tcpPort int) []Flow {
	var all []Flow
	for _, f := range files {
		cmd := []string{"tshark", "-r", f, "-q", "-z", "conv,tcp"}
		if tcpPort > 0 {
			cmd = []string{"tshark", "-r", f, "-Y", fmt.Sprintf("tcp.port==%d", tcpPort), "-q", "-z", "conv,tcp"}
		}
		out := runCmd(cmd)
		flows := parseConvTCP(out)
		for i := range flows {
			flows[i].File = f
		}
		all = append(all, flows...)
	}
	return all
}

func jain(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}
	var s, s2 float64
	for _, v := range values {
		s += v
		s2 += v * v
	}
	if s2 == 0 {
		return 0.0
	}
	n := float64(len(values))
	return (s * s) / (n * s2)
}

func median(xs []float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	s := make([]float64, n)
	copy(s, xs)
	sort.Float64s(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return 0.5 * (s[n/2-1] + s[n/2])
}

func pPercentile(xs []float64, p float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return xs[0]
	}
	s := make([]float64, n)
	copy(s, xs)
	sort.Float64s(s)
	// nearest-rank
	rank := int(math.Ceil(p * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return s[rank-1]
}

func writePerFileCSV(path string, rows [][5]interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"file", "avg_bps", "peak_bps", "MLU", "time_bins"})
	for _, r := range rows {
		rec := []string{
			fmt.Sprintf("%v", r[0]),
			fmt.Sprintf("%.3f", r[1]),
			fmt.Sprintf("%.3f", r[2]),
			fmt.Sprintf("%.6f", r[3]),
			fmt.Sprintf("%v", r[4]),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

func writePerFlowCSV(path string, flows []Flow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"src", "sp", "dst", "dp", "packets", "bytes", "duration_s", "throughput_bps"})
	for _, fl := range flows {
		thr := 0.0
		if fl.Duration > 0 {
			thr = (float64(fl.Bytes) * 8.0) / fl.Duration
		}
		rec := []string{
			fl.Src,
			fmt.Sprintf("%d", fl.Sp),
			fl.Dst,
			fmt.Sprintf("%d", fl.Dp),
			fmt.Sprintf("%d", fl.Packets),
			fmt.Sprintf("%d", fl.Bytes),
			fmt.Sprintf("%.6f", fl.Duration),
			fmt.Sprintf("%.3f", thr),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

func main() {
	var (
		globPat      string
		capacityMbps float64
		binSec       float64
		flowsGlob    string
		tcpPort      int
		outCSV       string
		outFlows     string
	)
	flag.StringVar(&globPat, "glob", "", "Glob для PCAP (напр. '/tmp/*.pcap') [required]")
	flag.Float64Var(&capacityMbps, "capacity-mbps", 0, "Пропускная способность линка (Mbps) для MLU [required]")
	flag.Float64Var(&binSec, "bin", 1.0, "io,stat размер бина в секундах (default 1.0)")
	flag.StringVar(&flowsGlob, "flows-glob", "", "Glob для PCAP, по которым считать потоки/FCT/Fairness (обычно pcap приёмников)")
	flag.IntVar(&tcpPort, "tcp-port", 0, "Необязательный фильтр tcp.port (например, 5201 для iperf3)")
	flag.StringVar(&outCSV, "out-csv", "./pcap_summary.csv", "CSV c метриками по файлам")
	flag.StringVar(&outFlows, "out-flows", "./flows_summary.csv", "CSV c метриками по потокам (если задан --flows-glob)")
	flag.Parse()

	if globPat == "" || capacityMbps <= 0 {
		flag.Usage()
		os.Exit(2)
	}

	files, err := filepath.Glob(globPat)
	if err != nil {
		log.Fatalf("[ERROR] glob failed: %v", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		log.Fatalf("[ERROR] no files matched: %s", globPat)
	}
	fmt.Printf("[INFO] matched %d files for interface metrics\n", len(files))

	var rows [][5]interface{}
	var totalAvg, totalPeak, networkMLU float64
	for _, f := range files {
		avg, peak, mlu, nBins := fileMetrics(f, capacityMbps, binSec)
		rows = append(rows, [5]interface{}{f, avg, peak, mlu, nBins})
		totalAvg += avg
		totalPeak += peak
		if mlu > networkMLU {
			networkMLU = mlu
		}
	}

	if err := writePerFileCSV(outCSV, rows); err != nil {
		log.Fatalf("[ERROR] write CSV: %v", err)
	}

	fmt.Println("\n=== NETWORK SUMMARY (from interface pcaps) ===")
	fmt.Printf("Files:                %d\n", len(files))
	fmt.Printf("Total avg throughput: %s\n", humanBps(totalAvg))
	fmt.Printf("Total peak throughput:%s\n", humanBps(totalPeak))
	fmt.Printf("Network MLU (max):    %.2f%%\n", networkMLU*100.0)
	fmt.Printf("Per-file CSV:         %s\n", outCSV)

	if flowsGlob != "" {
		ffiles, err := filepath.Glob(flowsGlob)
		if err != nil {
			log.Fatalf("[ERROR] flows-glob glob failed: %v", err)
		}
		sort.Strings(ffiles)
		if len(ffiles) == 0 {
			fmt.Printf("\n[WARN] flows-glob matched 0 files: %s\n", flowsGlob)
		} else {
			fmt.Printf("\n[INFO] computing flows from %d files (flows-glob)\n", len(ffiles))
			all := flowsFromFiles(ffiles, tcpPort)

			// Дедуп по (src,sp,dst,dp) — берём запись с макс bytes
			type key struct {
				src, dst string
				sp, dp   int
			}
			dedup := make(map[key]Flow)
			for _, fl := range all {
				k := key{fl.Src, fl.Dst, fl.Sp, fl.Dp}
				if ex, ok := dedup[k]; !ok || fl.Bytes > ex.Bytes {
					dedup[k] = fl
				}
			}
			uniq := make([]Flow, 0, len(dedup))
			for _, v := range dedup {
				uniq = append(uniq, v)
			}

			var durations []float64
			var perFlowThr []float64
			for _, f := range uniq {
				if f.Duration > 0 {
					durations = append(durations, f.Duration)
					perFlowThr = append(perFlowThr, (float64(f.Bytes)*8.0)/f.Duration)
				}
			}
			fctMedian := median(durations)
			fctP95 := pPercentile(durations, 0.95)
			fair := jain(perFlowThr)

			fmt.Println("\n=== FLOW SUMMARY (from flows-glob) ===")
			fmt.Printf("Flows (uniq):         %d\n", len(uniq))
			fmt.Printf("FCT median:           %.3f s\n", fctMedian)
			fmt.Printf("FCT p95:              %.3f s\n", fctP95)
			fmt.Printf("Fairness (Jain):      %.4f\n", fair)

			if err := writePerFlowCSV(outFlows, uniq); err != nil {
				log.Fatalf("[ERROR] write flow CSV: %v", err)
			}
			fmt.Printf("Per-flow CSV:         %s\n", outFlows)
		}
	} else {
		fmt.Println("\n[NOTE] Flows/FCT/Fairness не считались (не задан --flows-glob). " +
			"Чтобы избежать двойного учёта, указывайте glob только для pcap приёмников, " +
			"например --flows-glob \"/tmp/hosts_rx/*.pcap\".")
	}
}
