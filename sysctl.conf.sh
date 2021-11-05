#!/bin/bash

echo "prevent smurf attack."
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "Drop source routed packets"
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route

echo "prevent SYN Flood and TCP Starvation"
sysctl -w net/ipv4/tcp_syncookies=1
sysctl -w net/ipv4/tcp_timestamps=1
echo 2048 > /proc/sys/net/ipv4/tcp_max_syn_backlog
echo 3 > /proc/sys/net/ipv4/tcp_synack_retries

echo "Address Spoofing Protection"
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter

echo "Disable SYN Packet tracking"
sysctl -w net/netfilter/nf_conntrack_tcp_loose=0
