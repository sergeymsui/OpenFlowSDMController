#!/bin/bash

# Завершение всех процессов iperf, запущенных на клиентах для портов 9080–9089
for port in {9080..9089}; do
    # Ищем PID процессов iperf с указанным портом
    pid=$(ps aux | grep "[i]perf -c .* -p $port" | awk '{print $2}')
    if [ -n "$pid" ]; then
        kill -9 $pid
        echo "Stopped iperf client on port $port (PID: $pid)"
    else
        echo "No iperf client found on port $port"
    fi
done

echo "All iperf clients stopped."