from scapy.all import rdpcap, TCP
from collections import defaultdict
import matplotlib.pyplot as plt

def calculate_bandwidth_scapy(pcap_file, port_range=(9080, 9090)):
    port_bandwidth = defaultdict(int)

    print("Чтение pcap-файла...")
    packets = rdpcap(pcap_file)  # Быстрое чтение всех пакетов
    print(f"Загружено пакетов: {len(packets)}")

    for pkt in packets:
        if TCP in pkt and hasattr(pkt, 'time'):
            try:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                length = len(pkt)
                timestamp = pkt.time  # UNIX-время (float)

                if port_range[0] <= sport <= port_range[1]:
                    port_bandwidth[sport] += length
                    print(f"[{timestamp:.3f}] Пакет: {length} байт | src={sport}")
                if port_range[0] <= dport <= port_range[1]:
                    port_bandwidth[dport] += length
                    print(f"[{timestamp:.3f}] Пакет: {length} байт | dst={dport}")
            except Exception:
                continue

    return port_bandwidth


def plot_bandwidth(port_bandwidth):
    ports = sorted(port_bandwidth.keys())
    bandwidths = [port_bandwidth[p] for p in ports]

    plt.figure(figsize=(10, 6))
    plt.bar(ports, bandwidths)
    plt.xlabel('Порты')
    plt.ylabel('Пропускная способность (байты)')
    plt.title('Пропускная способность по портам 9080-9090')
    plt.xticks(ports)
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    pcap_file = 'D:/ospf-h2-h4.pcapng'
    port_bandwidth = calculate_bandwidth_scapy(pcap_file)
    plot_bandwidth(port_bandwidth)
