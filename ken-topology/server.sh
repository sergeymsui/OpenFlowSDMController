#!/bin/bash
for port in {9080..9089}; do
    iperf -s -p $port &
    echo "Started iperf server on port $port"
done