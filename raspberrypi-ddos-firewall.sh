#!/bin/bash

# VARIABLES - Change these to match your environment.

# Define Loopback Interface
lo="lo"

# Define External Network (haven't found a way to pickup dhcp addresses e.g. on an LTE connection)
#wan="eth0"
wan="wwan0"
#wanIP="x.x.x.x"
wanIP="ip route get 1.2.3.4 | awk '{print 7}'"

# Define External Servers
EXT_NTP1="clock3.redhat.com"
EXT_NTP2="ntp.public.otago.ac.nz"

# Define Internal Network
laniface="eth0"
lanIP="192.168.0.200"
lanrange="192.168.0.0/24"

# Define Internal Servers
#INT_SMTP="192.168.0.20"
#INT_DNS1="192.168.0.10"
#INT_DNS2="192.168.0.11"

# Set Kernel Parameters
#/sbin/sysctl -w net/ipv4/conf/all/accept_redirects="0"
#/sbin/sysctl -w net/ipv4/conf/all/accept_source_route="0"
#/sbin/sysctl -w net/ipv4/conf/all/log_martians="1"
#/sbin/sysctl -w net/ipv4/conf/all/rp_filter="1"
#/sbin/sysctl -w net/ipv4/icmp_echo_ignore_all="0"
#/sbin/sysctl -w net/ipv4/icmp_echo_ignore_broadcasts="1"
#/sbin/sysctl -w net/ipv4/icmp_ignore_bogus_error_responses="0"
#/sbin/sysctl -w net/ipv4/ip_forward="0"
#/sbin/sysctl -w net/ipv4/tcp_syncookies="1"

# Flush all Rules
/sbin/iptables -F

#Set Policies
/sbin/iptables -P INPUT DROP
/sbin/iptables -P OUTPUT DROP
/sbin/iptables -P FORWARD DROP

# Delete all User-created Chains
/sbin/iptables -X

# Allow access to the Loopback host
/sbin/iptables -A INPUT -i lo -j ACCEPT
/sbin/iptables -A OUTPUT -o lo -j ACCEPT


# DDoS, portscan and malformed packet blocks
echo "Setting up Basic DDos Protection"

echo "Creating inbound pkt filter:"
/sbin/iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL ALL -m comment --comment "xmas pkts (xmas portscanners)" -j DROP
/sbin/iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL NONE -m comment --comment "null pkts (null portscanners)" -j DROP
/sbin/iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
/sbin/iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
/sbin/iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
echo "Inbound malformed pkts are being dropped at line-rate."

echo "Creating outbound pkt filter:"
/sbin/iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL ALL -m comment --comment "xmas pkts (xmas portscanners)" -j DROP
/sbin/iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL NONE -m comment --comment "null pkts (null portscanners)" -j DROP
/sbin/iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
/sbin/iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
/sbin/iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
echo "Outbound malformed pkts are being dropped at line-rate"

echo "Creating IPv6 in/out pkt filter:"
ip6tables -t raw -A PREROUTING -j DROP
ip6tables -t raw -A OUTPUT -j DROP
echo "Dropping all IPv6 pkts."

echo "Creating drop rules for bogons"
/sbin/iptables -t raw -A PREROUTING -s 224.0.0.0/3 -i eth0 -m comment --comment "BOGONS" -j DROP
/sbin/iptables -t raw -A PREROUTING -s 169.254.0.0/16 -i eth0 -m comment --comment "BOGONS" -j DROP
/sbin/iptables -t raw -A PREROUTING -s 172.16.0.0/12 -i eth0 -m comment --comment "BOGONS" -j DROP
/sbin/iptables -t raw -A PREROUTING -s 192.0.2.0/24 -i eth0 -m comment --comment "BOGONS" -j DROP
/sbin/iptables -t raw -A PREROUTING -s 192.168.0.0/16 -i eth0 -m comment --comment "BOGONS" -j DROP
/sbin/iptables -t raw -A PREROUTING -s 10.0.0.0/8 -i eth0 -m comment --comment "BOGONS" -j DROP
/sbin/iptables -t raw -A PREROUTING -s 0.0.0.0/8 -i eth0 -m comment --comment "BOGONS" -j DROP
/sbin/iptables -t raw -A PREROUTING -s 240.0.0.0/5 -i eth0 -m comment --comment "BOGONS" -j DROP
/sbin/iptables -t raw -A PREROUTING -s 127.0.0.0/8 ! -i lo -m comment --comment "Only lo iface can have an addr-range of 127.0.0.x/8" -j DROP
echo "Bogons are now being dropped."
echo "RAW table has been created to drop bad pkts/traffic at line-rate (i.e. before conntrack and routing decisions)"

echo "Creating mangle table:"
echo "Populating PREROUTING, INPUT, FORWARD, OUTPUT and POSTROUTING rules:"
/sbin/iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

/sbin/iptables -t mangle -A INPUT -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -t mangle -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
/sbin/iptables -t mangle -A INPUT -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

/sbin/iptables -t mangle -A FORWARD -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -t mangle -A FORWARD -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
/sbin/iptables -t mangle -A FORWARD -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

/sbin/iptables -t mangle -A OUTPUT -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -t mangle -A OUTPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
/sbin/iptables -t mangle -A OUTPUT -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

/sbin/iptables -t mangle -A POSTROUTING -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -t mangle -A POSTROUTING -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
/sbin/iptables -t mangle -A POSTROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP
echo "Mangle/prerouting DDoS Rules added!"

# SYNPROXY start... Do not track new tcp packets
echo"Setting up Basic conntrack Protections"
/sbin/iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
echo "Not tracking new tcp connections that start with syn flag to save cpu and contrack slaughtering during DDoS!"

echo "Creating extra chains!"
/sbin/iptables -N IN_DPI_RULES
/sbin/iptables -N IN_CUSTOMRULES
/sbin/iptables -N FORWARDING_IN_CUSTOMRULES
/sbin/iptables -N SAFEZONE
echo "IN_DPI_RULES, IN_CUSTOMRULES, FORWARDING_IN_CUSTOMRULES and SAFEZONE created!"

echo "Setting up Basic firewall structure"
echo ...
echo "Starting with INPUT..."
/sbin/iptables -A INPUT -i lo -m comment --comment "Allow loopback connections" -j ACCEPT
/sbin/iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "ESTABLISHED, RELATED Quick Accept" -j ACCEPT
/sbin/iptables -A INPUT -m comment --comment "Pkt-checks" -j IN_DPI_RULES
/sbin/iptables -A INPUT -m -conntrack --ctstate NEW -s 0/0 -m comment --comment "Allowed Ports and Services for New conns to host" -j IN_CUSTOMRULES
#/sbin/iptables -A INPUT -m comment --comment "LOG all dropped traffic" -j LOG --log-prefix "[/sbin/iptables-BLOCKED]: " --log-level 7
/sbin/iptables -A INPUT -m comment --comment "Default Policy" -j DROP
echo "Done"
echo ......
#
#Few FORWARD chain rules purely for counters and stopping bogus traffic
#
echo "Starting with FORWARD..."
/sbin/iptables -A FORWARD -i lo -m comment --comment "Allow loopback connections" -j ACCEPT
/sbin/iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "RELATED,ESTABLISHED Quick Accept" -j ACCEPT
/sbin/iptables -A FORWARD -m comment --comment "Pkt-checks" -j IN_DPI_RULES
# Uncomment the following line if device is a router:
#/sbin/iptables -A FORWARD -m -conntrack --ctstate NEW -s 0/0 -m comment --comment "Allowed Ports and Services for New conns to LAN" -j FORWARDING_IN_CUSTOMRULES
/sbin/iptables -A FORWARD -m comment --comment "Default Policy" -j DROP
echo "Done"
echo ...
#
#Few OUTPUT chain rules for counters
#
echo "Starting with OUTPUT"
/sbin/iptables -A OUTPUT -i lo -m comment --comment "Allow loopback connections" -j ACCEPT
/sbin/iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "RELATED,ESTABLISHED Quick Accept" -j ACCEPT
/sbin/iptables -A OUTPUT -m comment --comment "Pkt-checks" -j IN_DPI_RULES
/sbin/iptables -A OUTPUT -m conntrack --ctstate NEW -m comment --comment "Egress - NEW counters" -j ACCEPT
# Uncomment the following rule to debug Egress connections:
#/sbin/iptables -A OUTPUT -m comment --comment "Egress - LOG DROPPED PACKETS counters" -j LOG --log-prefix "[OUT-BLOCKED]: " --log-level 7
/sbin/iptables -A OUTPUT -m comment --comment "Default Policy" -j DROP
echo "Done"
echo ...
#
#Boilerplate rules to ensure only legit traffic reaches the server and bogus traffic is silently discarded
#
echo "Populating DPI, Allowed ports and Safe IPs"
/sbin/iptables -A IN_DPI_RULES -m conntrack --ctstate INVALID -m comment --comment "Drop INVALID state connections" -j DROP
/sbin/iptables -A IN_DPI_RULES -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
/sbin/iptables -A IN_DPI_RULES -p ICMP --icmp-type echo-request -m comment --comment "ICMP ping" -j ACCEPT
/sbin/iptables -A IN_DPI_RULES -p ICMP --icmp-type echo-reply -m comment --comment "ICMP ping" -j ACCEPT
/sbin/iptables -A IN_DPI_RULES -p ICMP --icmp-type 11 -m comment --comment "ICMP traceroute" -j ACCEPT
/sbin/iptables -A IN_DPI_RULES -p ICMP --icmp-type PTMD -m comment --comment "PTMD" -j ACCEPT
#/sbin/iptables -A IN_DPI_RULES -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460  ## not working correctly /sbin/iptables error with --scack-perm parameter
/sbin/iptables -A IN_DPI_RULES -m comment --comment "Jump back to main filter rules" -j RETURN
#
#This chain is where you open your tcp/udp ports and will be 1 of only 2 places that users' should modify
#Since we're already allowing related and established traffic all that's left is to allow new connections to specific ports.
#If you wan't to restrict port access to a specific IP/ip-range then I'd suggest following the SSH example which jumps to the safezone list of IP's/IP-ranges
#
/sbin/iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 22 -m comment --comment "Allow SSH" -j SAFEZONE
/sbin/iptables -A IN_CUSTOMRULES -p udp -m udp --dport 67 -m comment --comment "Allow dhcp" -j ACCEPT
/sbin/iptables -A IN_CUSTOMRULES -p udp -m udp --dport 68 -m comment --comment "Allow dhcp" -j ACCEPT
/sbin/iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 501 -i eth0 -m comment --comment "Allow modbus TCP" -j SAFEZONE
/sbin/iptables -A IN_CUSTOMRULES -p udp -m udp --dport 123 -m comment --comment "Allow NTP" -j ACCEPT
/sbin/iptables -A IN_CUSTOMRULES -m comment --comment "Jump back to main filter rules" -j RETURN
/sbin/iptables -A IN_CUSTOMRULES -m comment --comment "Explicit drop rule */paranoid*/" -j DROP
#
#This chain is where you open your tcp/udp ports to your LAN and will be 1 of only 2 places that users' should modify
#Since we're already allowing related and established traffic all that's left is to allow new connections to specific ports.
#If you wan't to restrict port access to a specific IP/ip-range then I'd suggest following the SSH example which jumps to the safezone list of IP's/IP-ranges
#Uncomment the following rules if the device is a RTR and comment out the corresponding rules in the IN_CUSTOMRULES chain to avoid unecessary pkt traversal through the firewall rules.
#
#/sbin/iptables -A FORWARDING_IN_CUSTOMRULES -p tcp -m tcp --dport 22 -m comment --comment "Allow SSH" -j SAFEZONE
#/sbin/iptables -A FORWARDING_IN_CUSTOMRULES -p udp -m udp --dport 67 -m comment --comment "Allow dhcp" -j ACCEPT
#/sbin/iptables -A FORWARDING_IN_CUSTOMRULES -p udp -m udp --dport 68 -m comment --comment "Allow dhcp" -j ACCEPT
#/sbin/iptables -A FORWARDING_IN_CUSTOMRULES -p tcp -m tcp --dport 501 -i eth0 -m comment --comment "Allow modbus TCP" -j SAFEZONE
#/sbin/iptables -A FORWARDING_IN_CUSTOMRULES -p udp -m udp --dport 123 -m comment --comment "Allow NTP" -j ACCEPT
#/sbin/iptables -A FORWARDING_IN_CUSTOMRULES -m comment --comment "Jump back to main filter rules" -j RETURN
#/sbin/iptables -A FORWARDING_IN_CUSTOMRULES -m comment --comment "Explicit drop rule */paranoid*/" -j DROP
#
#
#SAFEZONE or permitted IP/IP-ranges in a dedicated chain for neatness and readibility, Since /sbin/iptables doesn't have the ability (as far as i'm aware) to have iplists by default. 
#
/sbin/iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-secure-IP" -j ACCEPT
/sbin/iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-secure-IP" -j ACCEPT
/sbin/iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-hq" -j ACCEPT
/sbin/iptables -A SAFEZONE -s 10.8.0.0/24 -j ACCEPT
/sbin/iptables -A SAFEZONE -s 192.168.0.0/16 -j ACCEPT
/sbin/iptables -A SAFEZONE -j RETURN
echo "Done!"
echo
echo "setting up kernel DDoS params"
### add kernel params when one of the pi's come back online
echo "Configuring CongestionControlAlgorithm, Swap & LowLevel Kernel messages to console"
cat << EOF >> /etc/sysctl.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
vm.swappiness = 1
vm.vfs_cache_pressure = 50
kernel.printk = 3 4 1 3
EOF


echo "Firewall DDoS configuration is complete!!!"
echo ...
echo "To view all added rules/table structure:"
echo "/sbin/iptables -t raw -nvL --line-numbers && /sbin/iptables -t mangle -nvL --line-numbers && /sbin/iptables -t filter -nvL --line-numbers && /sbin/iptables -t nat -nvL --line-numbers"
