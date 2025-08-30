#!/bin/bash

# Проверка, передан ли аргумент SERVER_IP
if [ $# -ne 1 ]; then
    echo "Ошибка: Укажите IP-адрес сервера как аргумент."
    echo "Пример: ./client.sh 192.168.1.100"
    exit 1
fi

SERVER_IP=$1

# Запуск клиентов iperf для портов 9080–9089
for port in {9080..9089}; do
    iperf -c "$SERVER_IP" -p $port -t 500 -i 1 &
    echo "Started iperf client for $SERVER_IP on port $port"
done