#!/bin/bash
gcc -g -I/usr/include/pcap sniffer/uniqtcpdump.c -lpcap -o sniffer/uniqtcpdump
