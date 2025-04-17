package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	inputFile := "D:/ustm-s8-eth1.pcap"
	outputFile := "./ustm-s8-eth1_tcp_stats.csv"

	// Открытие pcapng файла
	handle, err := os.Open(inputFile)
	if err != nil {
		log.Fatal("Ошибка при открытии файла:", err)
	}
	defer handle.Close()

	reader, err := pcapgo.NewReader(handle)
	if err != nil {
		log.Fatal("Ошибка чтения pcapng:", err)
	}

	// Создание CSV
	outFile, err := os.Create(outputFile)
	if err != nil {
		log.Fatal("Не удалось создать CSV файл:", err)
	}
	defer outFile.Close()
	writer := csv.NewWriter(outFile)
	defer writer.Flush()

	// Запись заголовков
	writer.Write([]string{"timestamp", "src_port", "dst_port", "length"})

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	n := 0
	for packet := range packetSource.Packets() {
		// Получение TCP слоя
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Фильтрация портов
			if inPortRange(tcp.SrcPort, 9080, 9090) || inPortRange(tcp.DstPort, 9080, 9090) {
				ts := packet.Metadata().Timestamp
				timestampStr := ts.Format(time.RFC3339Nano)
				unixNs := ts.UnixNano()
				length := packet.Metadata().Length

				// Запись строки
				writer.Write([]string{
					timestampStr,
					strconv.FormatInt(unixNs, 10),
					strconv.Itoa(int(tcp.SrcPort)),
					strconv.Itoa(int(tcp.DstPort)),
					strconv.Itoa(length),
				})

                fmt.Printf("n: %d, SrcPort: %d, DstPort: %d, length: %d\n", n, tcp.SrcPort, tcp.DstPort, length)
                n++
			}
		}
	}
	fmt.Println("Готово! Результаты записаны в:", outputFile)
}

// Проверка, входит ли порт в указанный диапазон
func inPortRange(port layers.TCPPort, min, max int) bool {
	return int(port) >= min && int(port) <= max
}
