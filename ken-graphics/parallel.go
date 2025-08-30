package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	rootDir := "/home/vda/Test"

	var wg sync.WaitGroup

	// Поиск всех pcap файлов
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Println("Ошибка при обходе:", err)
			return nil
		}

		// Проверяем расширение файла
		if !info.IsDir() && (filepath.Ext(path) == ".pcap" || filepath.Ext(path) == ".pcapng") {
			wg.Add(1)
			go func(pcapPath string) {
				defer wg.Done()
				processPcap(pcapPath)
			}(path)
		}
		return nil
	})

	if err != nil {
		log.Fatal("Ошибка обхода папок:", err)
	}

	// Ждем завершения всех горутин
	wg.Wait()

	fmt.Println("Обработка завершена!")
}

func processPcap(inputFile string) {
	fmt.Printf("Обрабатываю файл: %s\n", inputFile)

	outputFile := inputFile[:len(inputFile)-len(filepath.Ext(inputFile))] + ".csv"

	handle, err := os.Open(inputFile)
	if err != nil {
		log.Printf("Ошибка при открытии файла %s: %v\n", inputFile, err)
		return
	}
	defer handle.Close()

	reader, err := pcapgo.NewReader(handle)
	if err != nil {
		log.Printf("Ошибка чтения pcapng %s: %v\n", inputFile, err)
		return
	}

	outFile, err := os.Create(outputFile)
	if err != nil {
		log.Printf("Не удалось создать CSV файл %s: %v\n", outputFile, err)
		return
	}
	defer outFile.Close()

	bufWriter := bufio.NewWriter(outFile)
	defer bufWriter.Flush()

	writer := csv.NewWriter(bufWriter)
	defer writer.Flush()

	// Запись заголовка
	err = writer.Write([]string{"timestamp", "timestamp_unix_ns", "src_port", "dst_port", "length"})
	if err != nil {
		log.Printf("Ошибка записи заголовка: %v\n", err)
		return
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	n := 0
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			if inPortRange(tcp.SrcPort, 0, 65535) || inPortRange(tcp.DstPort, 0, 65535) {
				ts := packet.Metadata().Timestamp
				timestampStr := ts.Format(time.RFC3339Nano)
				unixNs := ts.UnixNano()
				length := packet.Metadata().Length

				err = writer.Write([]string{
					timestampStr,
					strconv.FormatInt(unixNs, 10),
					strconv.Itoa(int(tcp.SrcPort)),
					strconv.Itoa(int(tcp.DstPort)),
					strconv.Itoa(length),
				})
				if err != nil {
					log.Printf("Ошибка записи строки: %v\n", err)
				}
				n++
			}
		}
	}
	fmt.Printf("Файл %s обработан: %d записей\n", inputFile, n)
}

func inPortRange(port layers.TCPPort, min, max int) bool {
	return int(port) >= min && int(port) <= max
}
