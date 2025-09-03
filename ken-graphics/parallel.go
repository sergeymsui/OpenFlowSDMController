package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	// Базовая директория — рядом с бинарником
	exe, err := os.Executable()
	if err != nil {
		log.Fatal("Не удалось получить путь к бинарнику:", err)
	}
	baseDir := filepath.Dir(exe)
	inDir := filepath.Join(baseDir, "pcaps")
	outDir := filepath.Join(baseDir, "csv")

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatal("Не удалось создать выходную папку:", err)
	}

	files, err := listPcapFiles(inDir)
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatalf("В папке %s не найдено .pcap/.pcapng", inDir)
	}

	workers := runtime.NumCPU()
	jobs := make(chan string, len(files))
	var wg sync.WaitGroup

	fmt.Printf("Найдено файлов: %d, запускаю %d воркеров\n", len(files), workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for f := range jobs {
				if err := processFile(f, outDir); err != nil {
					log.Printf("[worker %d] ошибка в %s: %v", id, f, err)
				}
			}
		}(i + 1)
	}

	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	wg.Wait()

	fmt.Println("Готово. CSV лежат в:", outDir)
}

func listPcapFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать директорию %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext == ".pcap" || ext == ".pcapng" {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out, nil
}

func processFile(inPath, outDir string) error {
	format, err := detectFormat(inPath)
	if err != nil {
		return fmt.Errorf("не удалось определить формат %s: %w", inPath, err)
	}

	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("ошибка открытия %s: %w", inPath, err)
	}
	defer inFile.Close()

	var packetSource *gopacket.PacketSource
	switch format {
	case "pcapng":
		ng, err := pcapgo.NewNgReader(inFile, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return fmt.Errorf("ошибка pcapng ридера: %w", err)
		}
		packetSource = gopacket.NewPacketSource(ng, ng.LinkType())
	case "pcap":
		r, err := pcapgo.NewReader(inFile)
		if err != nil {
			return fmt.Errorf("ошибка pcap ридера: %w", err)
		}
		packetSource = gopacket.NewPacketSource(r, r.LinkType())
	default:
		return fmt.Errorf("неизвестный формат файла: %s", format)
	}

	packetSource.Lazy = true
	packetSource.NoCopy = true

	outName := strings.TrimSuffix(filepath.Base(inPath), filepath.Ext(inPath)) + ".csv"
	outPath := filepath.Join(outDir, outName)

	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("не удалось создать CSV %s: %w", outPath, err)
	}
	defer outFile.Close()

	writer := csv.NewWriter(outFile)
	defer writer.Flush()

	// Расширенный заголовок
	header := []string{
		"source_file",
		"timestamp_rfc3339",
		"timestamp_unix_ns",
		"iface_index",      // для pcapng, если есть
		"eth_type",         // 0x0800, 0x86DD и т.п.
		"ip_version",       // 4/6 или пусто
		"src_ip",
		"dst_ip",
		"proto",            // TCP/UDP/ICMP/…
		"src_port",
		"dst_port",
		"length_bytes",     // on-the-wire
		"tcp_syn",
		"tcp_fin",
		"tcp_rst",
		"tcp_ack",
		"tcp_psh",
		"flow_id_5tuple",   // FNV-1a64 направленный
		"pair_id_dir",      // src→dst
		"pair_id_undir",    // src↔dst (без направления)
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("не удалось записать заголовок: %w", err)
	}

	var n int
	srcFile := filepath.Base(inPath)

	for packet := range packetSource.Packets() {
		ci := packet.Metadata().CaptureInfo
		ts := ci.Timestamp
		timestampStr := ts.Format(time.RFC3339Nano)
		unixNs := ts.UnixNano()
		length := ci.Length // on-the-wire bytes

		var ifaceIdxStr string
		if ci.InterfaceIndex > 0 {
			ifaceIdxStr = strconv.Itoa(ci.InterfaceIndex)
		}

		// Ethernet / EtherType
		var ethType string
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			if eth, ok := ethLayer.(*layers.Ethernet); ok {
				ethType = fmt.Sprintf("0x%04x", uint16(eth.EthernetType))
			}
		}

		// IP
		var (
			ipVer         string
			srcIP, dstIP  string
			proto         string
			srcPort, dstPort string
			tcpSYN, tcpFIN, tcpRST, tcpACK, tcpPSH string
		)

		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ip4 := ipv4Layer.(*layers.IPv4)
			ipVer = "4"
			srcIP = ip4.SrcIP.String()
			dstIP = ip4.DstIP.String()
			proto = ip4.Protocol.String()
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ip6 := ipv6Layer.(*layers.IPv6)
			ipVer = "6"
			srcIP = ip6.SrcIP.String()
			dstIP = ip6.DstIP.String()
			proto = ip6.NextHeader.String()
		}

		// TCP/UDP порты и флаги
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			srcPort = strconv.Itoa(int(tcp.SrcPort))
			dstPort = strconv.Itoa(int(tcp.DstPort))
			proto = "TCP"
			if tcp.SYN {
				tcpSYN = "1"
			}
			if tcp.FIN {
				tcpFIN = "1"
			}
			if tcp.RST {
				tcpRST = "1"
			}
			if tcp.ACK {
				tcpACK = "1"
			}
			if tcp.PSH {
				tcpPSH = "1"
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPort = strconv.Itoa(int(udp.SrcPort))
			dstPort = strconv.Itoa(int(udp.DstPort))
			proto = "UDP"
		} else if icmp4 := packet.Layer(layers.LayerTypeICMPv4); icmp4 != nil {
			_ = icmp4.(*layers.ICMPv4)
			proto = "ICMPv4"
		} else if icmp6 := packet.Layer(layers.LayerTypeICMPv6); icmp6 != nil {
			_ = icmp6.(*layers.ICMPv6)
			proto = "ICMPv6"
		}

		// Формируем идентификаторы потока/пары
		flowID := flowID5Tuple(srcIP, dstIP, proto, srcPort, dstPort)
		pairDir := pairID(srcIP, dstIP)
		pairUndir := pairIDUndir(srcIP, dstIP)

		row := []string{
			srcFile,
			timestampStr,
			strconv.FormatInt(unixNs, 10),
			ifaceIdxStr,
			ethType,
			ipVer,
			srcIP,
			dstIP,
			proto,
			srcPort,
			dstPort,
			strconv.Itoa(length),
			tcpSYN, tcpFIN, tcpRST, tcpACK, tcpPSH,
			flowID,
			pairDir,
			pairUndir,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("ошибка записи строки: %w", err)
		}

		n++
		if n%100000 == 0 {
			fmt.Printf("[%s] обработано пакетов: %d\n", filepath.Base(inPath), n)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("ошибка при записи CSV: %w", err)
	}

	fmt.Printf("[%s] готово, пакетов: %d, CSV: %s\n", filepath.Base(inPath), n, outPath)
	return nil
}

// flow_id как FNV-1a64 от направленного 5-кортежа (если чего-то нет — используем "-")
func flowID5Tuple(src, dst, proto, sport, dport string) string {
	if src == "" && dst == "" && proto == "" {
		return ""
	}
	key := strings.Join([]string{
		normIP(src), ">", normIP(dst), "|", strings.ToUpper(proto), "|", sport, ":", dport,
	}, "")
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return fmt.Sprintf("%016x", h.Sum64())
}

func pairID(src, dst string) string {
	if src == "" && dst == "" {
		return ""
	}
	return normIP(src) + "->" + normIP(dst)
}

func pairIDUndir(src, dst string) string {
	a := normIP(src)
	b := normIP(dst)
	if a == "" && b == "" {
		return ""
	}
	if a <= b {
		return a + "<>" + b
	}
	return b + "<>" + a
}

func normIP(s string) string {
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}

// Определение формата файла по сигнатуре
func detectFormat(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return "", err
	}

	// pcapng: 0x0A0D0D0A
	if bytes.Equal(magic, []byte{0x0A, 0x0D, 0x0D, 0x0A}) {
		return "pcapng", nil
	}

	// pcap (включая ns-variant)
	switch {
	case bytes.Equal(magic, []byte{0xA1, 0xB2, 0xC3, 0xD4}), // big endian
		bytes.Equal(magic, []byte{0xD4, 0xC3, 0xB2, 0xA1}), // little endian
		bytes.Equal(magic, []byte{0xA1, 0xB2, 0x3C, 0x4D}), // ns big endian
		bytes.Equal(magic, []byte{0x4D, 0x3C, 0xB2, 0xA1}): // ns little endian
		return "pcap", nil
	}

	return "", errors.New("неизвестная сигнатура файла")
}
