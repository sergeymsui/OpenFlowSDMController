#!/bin/bash
#
# capture_core.sh — захват трафика на core-свитчах Clos k=4
# сохраняет pcap в /tmp/core_sX_ethY.pcap
#

# Список core-свитчей
CORES="s17 s18 s19 s20"

# Папка для логов
OUTDIR="/tmp"
mkdir -p "$OUTDIR"

# Время захвата (секунд)
DURATION=60

# Узнаем список интерфейсов у каждого core-свитча
for sw in $CORES; do
    echo "[INFO] Интерфейсы $sw:"
    ovs-vsctl list-ports $sw
done

echo
echo "[INFO] Запуск tcpdump на uplink-интерфейсах..."
echo

# Запуск tcpdump на каждом порту core-свитчей
for sw in $CORES; do
    for iface in $(ovs-vsctl list-ports $sw); do
        # Игнорируем интерфейсы без "eth" (служебные могут быть)
        if [[ "$iface" == *"eth"* ]]; then
            outfile="$OUTDIR/${sw}_${iface}.pcap"
            echo "  -> $sw / $iface -> $outfile"
            # Захватим только заголовки (-s 128), без резолвинга имен (-n)
            # Ограничение по времени через timeout
            sudo timeout $DURATION tcpdump -i $iface -n -s 128 -w $outfile &
        fi
    done
done

echo
echo "[INFO] Захват запущен на $DURATION секунд..."
wait
echo "[INFO] Захват завершён. Файлы pcap в $OUTDIR"
