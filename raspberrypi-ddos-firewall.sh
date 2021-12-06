#!/bin/bash

# VARIABLES - Change these to match your environment.
# Location of the binaries
iptables="/sbin/iptables"
sysctl="/sbin/sysctl"

# Define Loopback Interface
lo="lo"

# Define External Network (haven't found a way to pickup dhcp addresses e.g. on an LTE connection)
#wan="eth0"
wan="wwan0"
#wanIP="x.x.x.x"
wanIP="ip route get 1.2.3.4 | awk '{print $7}'"

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
$SYSCTL -w net/ipv4/conf/all/accept_redirects="0"
$SYSCTL -w net/ipv4/conf/all/accept_source_route="0"
$SYSCTL -w net/ipv4/conf/all/log_martians="1"
$SYSCTL -w net/ipv4/conf/all/rp_filter="1"
$SYSCTL -w net/ipv4/icmp_echo_ignore_all="0"
$SYSCTL -w net/ipv4/icmp_echo_ignore_broadcasts="1"
$SYSCTL -w net/ipv4/icmp_ignore_bogus_error_responses="0"
$SYSCTL -w net/ipv4/ip_forward="0"
$SYSCTL -w net/ipv4/tcp_syncookies="1"

# Flush all Rules
$IPT -F

#Set Policies
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# Delete all User-created Chains
$IPT -X

# Allow access to the Loopback host
$IPT -A INPUT -i $LOOPBACK -j ACCEPT
$IPT -A OUTPUT -o $LOOPBACK -j ACCEPT


# DDoS, portscan and malformed packet blocks
echo "Setting up Basic DDos Protection"
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t raw -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -t raw -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL ALL -m comment --comment "xmas pkts (xmas portscanners)" -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL NONE -m comment --comment "null pkts (null portscanners)" -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -t raw -A PREROUTING -s 224.0.0.0/3 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 169.254.0.0/16 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 172.16.0.0/12 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 192.0.2.0/24 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 10.0.0.0/8 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 0.0.0.0/8 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 240.0.0.0/5 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 127.0.0.0/8 ! -i lo -m comment --comment "Only lo iface can have an addr-range of 127.0.0.x/8" -j DROP

iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
echo "mangle/prerouting DDoS Rules added!"
# SYNPROXY start... Do not track new tcp packets
echo"Setting up Basic conntrack Protections"
iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
echo "Not tracking new tcp connections that start with syn flag to save cpu and contrack slaughtering during DDoS!"

echo "Creating extra chains!"
iptables -N IN_DPI_RULES
iptables -N IN_CUSTOMRULES
iptables -N FORWARDING_IN_CUSTOMRULES
iptables -N SAFEZONE
echo "IN_DPI_RULES, IN_CUSTOMRULES, FORWARDING_IN_CUSTOMRULES and SAFEZONE created!"

echo "Setting up Basic firewall structure"
echo ...
echo "Starting with INPUT..."
iptables -A INPUT -i lo -m comment --comment "Allow loopback connections" -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "ESTABLISHED, RELATED QUICK ACCEPT" -j ACCEPT
iptables -A INPUT -m comment --comment "Security Rules" -j IN_DPI_RULES
iptables -A INPUT -m comment --comment "Allowed Ports and Services" -j IN_CUSTOMRULES
iptables -A INPUT -m comment --comment "LOG all dropped traffic" -j LOG --log-prefix "[IPTABLES-BLOCKED]: " --log-level 7
iptables -A INPUT -m comment --comment "Explicitly DROP other connections" -j DROP
echo "Done"
echo ......
#
#Few FORWARD chain rules purely for counters and stopping bogus traffic
#
echo "Starting with FORWARD..."
iptables -A FORWARD -i lo -m comment --comment "Allow loopback connections" -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m comment --comment "Security Rules" -j IN_DPI_RULES
iptables -A FORWARD -m comment --comment "Allowed services" -j FORWARDING_IN_CUSTOMRULES
iptables -A FORWARD -m conntrack --ctstate INVALID -m comment --comment "Drop INVALID state connections" -j DROP
echo "Done"
echo ...
#
#Few OUTPUT chain rules for counters
#
echo "starting with OUTPUT"
iptables -A OUTPUT -i lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "RELATED,ESTABLISHED QUICK ACCEPT" -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate INVALID -m comment --comment "Drop INVALID state connections" -j DROP
iptables -A OUTPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "All TCP sessions should begin with SYN" -j DROP
iptables -A OUTPUT -m conntrack --ctstate NEW -m comment --comment "Egress - NEW counters" -j ACCEPT
iptables -A OUTPUT -m comment --comment "Egress - LOG DROPPED PACKETS counters" -j LOG --log-prefix "[OUT-BLOCKED]: " --log-level 7
iptables -A OUTPUT -m comment --comment "Egress - DROPPED PACKETS counters" -j DROP
echo "Done"
echo ...
#
#Boilerplate rules to ensure only legit traffic reaches the server and bogus traffic is silently discarded
#
echo "Populating DPI, Allowed ports and Safe IPs"
 iptables -A IN_DPI_RULES -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "All TCP sessions should begin with SYN" -j DROP
 #iptables -A IN_DPI_RULES -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460  ## not working correctly iptables error with --scack-perm parameter
 iptables -A IN_DPI_RULES -m conntrack --ctstate INVALID -m comment --comment "Drop INVALID state connections" -j DROP
 iptables -A IN_DPI_RULES -m comment --comment "Jump back to main filter rules" -j RETURN
#
#This chain is where you open your tcp/udp ports and will be 1 of only 2 places that users' should modify
#Since we're already allowing related and established traffic all that's left is to allow new connections to specific ports.
#If you wan't to restrict port access to a specific IP/ip-range then I'd suggest following the SSH example which jumps to the safezone list of IP's/IP-ranges
#
 iptables -A IN_CUSTOMRULES -p ICMP --icmp-type echo-reply -s 0.0.0.0/0 -m comment --comment "ICMP ping replies to our pings" -j ACCEPT
 iptables -A IN_CUSTOMRULES -p ICMP --icmp-type echo-request -s 0.0.0.0/0 -m comment --comment "ICMP ping this device" -j ACCEPT
 iptables -A IN_CUSTOMRULES -p ICMP --icmp-type 11 -s 0.0.0.0/0 -m comment --comment "ICMP exceeded" -j ACCEPT
 iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow SSH" -j SAFEZONE
 #iptables -A IN_CUSTOMRULES -p udp -m udp --dport 67 --sport 68 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow dhcp" -j ACCEPT
 iptables -A IN_CUSTOMRULES -m comment --comment "Jump back to main filter rules" -j RETURN
 iptables -A IN_CUSTOMRULES -m comment --comment "Explicit drop rule */paranoid*/" -j DROP
#
#
 #iptables -A FORWARDING_IN_CUSTOMRULES -p ICMP --icmp-type echo-reply -s 0.0.0.0/0 -m comment --comment "ICMP ping" -j ACCEPT
 #iptables -A FORWARDING_IN_CUSTOMRULES -p ICMP --icmp-type 8 -s 0.0.0.0/0 -m comment --comment "ICMP traceroute" -j ACCEPT
 #iptables -A FORWARDING_IN_CUSTOMRULES -p ICMP --icmp-type 11 -s 0.0.0.0/0 -m comment --comment "ICMP traceroute" -j ACCEPT
 #iptables -A FORWARDING_IN_CUSTOMRULES -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow SSH" -j SAFEZONE
 #iptables -A FORWARDING_IN_CUSTOMRULES -p udp -m udp --dport 53 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow DNS to LAN" -j ACCEPT
 #iptables -A FORWARDING_IN_CUSTOMRULES -p udp -m udp --dport 67 --sport 68 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow dhcp" -j ACCEPT
 #iptables -A FORWARDING_IN_CUSTOMRULES -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow http" -j ACCEPT
 #iptables -A FORWARDING_IN_CUSTOMRULES -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow https" -j ACCEPT
 #iptables -A FORWARDING_IN_CUSTOMRULES -p udp -m udp --dport 123 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow NTP" -j ACCEPT
 iptables -A FORWARDING_IN_CUSTOMRULES -p udp -m udp --dport 1194 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow OpenVPN" -j ACCEPT
 iptables -A FORWARDING_IN_CUSTOMRULES -m comment --comment "Jump back to main filter rules" -j RETURN
 iptables -A FORWARDING_IN_CUSTOMRULES -m comment --comment "Explicit drop rule */paranoid*/" -j DROP
#
#SAFEZONE or permitted IP/IP-ranges in a dedicated chain for neatness and readibility, Since iptables doesn't have the ability (as far as i'm aware) to have iplists by default. 
#
 iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-secure-IP" -j ACCEPT
 iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-secure-IP" -j ACCEPT
 iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-hq" -j ACCEPT
 iptables -A SAFEZONE -s 10.8.0.0/24 -j ACCEPT
 iptables -A SAFEZONE -s 192.168.0.0/16 -j ACCEPT
 iptables -A SAFEZONE -j RETURN
 echo "Done!"
 echo
 echo "setting up kernel DDoS params"
 ### add kernel params when one of the pi's come back online
 
 echo "Firewall DDoS configuration is complete!!!"
 echo ...
 echo "To view all added rules/table structure:"
 echo "type iptables -t mangle -nvL --line-numbers && iptables -t raw -nvL --line-numbers && iptables -nvL --line-numbers"
 
 #! /bin/bash

echo creating inbound pkt filter:

iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL ALL -m comment --comment "xmas pkts (xmas portscanners)" -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL NONE -m comment --comment "null pkts (null portscanners)" -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

echo inbound malformed pkts are being dropped at line-rate
echo 
echo 
echo creating outbound pkt filter:

iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL ALL -m comment --comment "xmas pkts (xmas portscanners)" -j DROP
iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL NONE -m comment --comment "null pkts (null portscanners)" -j DROP
iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t raw -A OUTPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

echo 
echo
echo outbound malformed pkts are being dropped at line-rate
echo 
echo 
echo creating IPv6 in/out pkt filter:

ip6tables -t raw -A PREROUTING -j DROP

ip6tables -t raw -A OUTPUT -j DROP

echo
echo
echo dropping all IPv6 pkts.
echo
echo
echo creating drop rules for bogons
echo ...
echo 

iptables -t raw -A PREROUTING -s 224.0.0.0/3 -i eth0 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 169.254.0.0/16 -i eth0 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 172.16.0.0/12 -i eth0 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 192.0.2.0/24 -i eth0 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 192.168.0.0/16 -i eth0 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 10.0.0.0/8 -i eth0 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 0.0.0.0/8 -i eth0 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 240.0.0.0/5 -i eth0 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 127.0.0.0/8 ! -i lo -m comment --comment "Only lo iface can have an addr-range of 127.0.0.x/8" -j DROP

echo bogons are now being dropped.
echo
echo
echo RAW table has been created to drop bad pkts/traffic at line-rate (i.e. before conntrack and routing decisions)
echo
echo
echo creating mangle table:
echo ...
echo populating PREROUTING, INPUT, FORWARD, OUTPUT and POSTROUTING rules:
echo ...
echo 
echo



iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

iptables -t mangle -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
iptables -t mangle -A INPUT -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

iptables -t mangle -A FORWARD -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A FORWARD -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
iptables -t mangle -A FORWARD -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

iptables -t mangle -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A OUTPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
iptables -t mangle -A OUTPUT -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

iptables -t mangle -A POSTROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A POSTROUTING -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
iptables -t mangle -A POSTROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP

echo completed mangle table
echo
echo
echo creating filter table
echo ...
echo populating INPUT FORWARD and OUTPUT rules:
echo ...
echo 
echo




iptables -A INPUT -i lo -m comment --comment "allow lo iface traffic"  -j ACCEPT
iptables -A INPUT -m comment --comment "Pkt-checks" -j IN_DPI_RULES
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "ESTABLISHED,RELATED conns quick accept" -j ACCEPT
iptables -A INPUT -conntrack --ctstate NEW -s 0/0 -m comment --comment "Allowed Ports and Services for New conns" -j IN_CUSTOMRULES
iptables -A INPUT -m comment --comment "Explicitly DROP other connections" -j DROP

iptables -A FORWARD -i lo -j ACCEPT
iptables -A FORWARD -m comment --comment "Pkt-checks" -j IN_DPI_RULES
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "RELATED,ESTABLISHED conns quick accept" -j ACCEPT
iptables -A FORWARD -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP


iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m comment --comment "Pkt-checks" -j IN_DPI_RULES
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "RELATED,ESTABLISHED conns quick accept" -j ACCEPT
iptables -A OUTPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
iptables -A OUTPUT -m conntrack --ctstate NEW -m comment --comment "Egress - NEW counters" -j ACCEPT
iptables -A OUTPUT -m comment --comment "Egress - DROPPED PACKETS counters" -j DROP


iptables -A IN_DPI_RULES -m conntrack --ctstate INVALID -m comment --comment "Drop INVALID state connections" -j DROP
iptables -A IN_DPI_RULES -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
iptables -A IN_DPI_RULES -p ICMP --icmp-type echo-request -m comment --comment "ICMP ping" -j ACCEPT
iptables -A IN_DPI_RULES -p ICMP --icmp-type echo-reply -m comment --comment "ICMP ping" -j ACCEPT
iptables -A IN_DPI_RULES -p ICMP --icmp-type 11 -m comment --comment "ICMP traceroute" -j ACCEPT
iptables -A IN_DPI_RULES -p ICMP --icmp-type PTMD -m comment --comment "PTMD" -j ACCEPT
iptables -A IN_DPI_RULES -m comment --comment "Jump back to main filter rules" -j RETURN

iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 22 -m comment --comment "Allow SSH" -j SAFEZONE
iptables -A IN_CUSTOMRULES -p udp -m udp --dport 67 -m comment --comment "Allow dhcp" -j ACCEPT
iptables -A IN_CUSTOMRULES -p udp -m udp --dport 68 -m comment --comment "Allow dhcp" -j ACCEPT
iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 501 -i eth0 -m comment --comment "Allow modbus TCP" -j SAFEZONE
iptables -A IN_CUSTOMRULES -p udp -m udp --dport 123 -m comment --comment "Allow NTP" -j ACCEPT
iptables -A IN_CUSTOMRULES -m comment --comment "Jump back to main filter rules" -j RETURN
iptables -A IN_CUSTOMRULES -m comment --comment "Explicit drop rule */paranoid*/" -j DROP

iptables -A SAFEZONE -s 37.48.118.94/32 -m comment --comment allow-ingress-from-TIM-secure-IP -j ACCEPT
iptables -A SAFEZONE -s 188.34.190.74/32 -m comment --comment allow-ingress-from-TIM-secure-IP -j ACCEPT
iptables -A SAFEZONE -s 105.23.225.106/32 -m comment --comment allow-ingress-from-EDS-hq -j ACCEPT
iptables -A SAFEZONE -s 34.90.83.14/32 -m comment --comment allow-ingress-from-EDS-hq -j ACCEPT
iptables -A SAFEZONE -s 165.255.239.57/32 -m comment --comment allow-ingress-from-EDS-hq -j ACCEPT
iptables -A SAFEZONE -s 35.246.178.53/32 -m comment --comment allow-ingress-from-EDS-hq -j ACCEPT
iptables -A SAFEZONE -s 35.235.240.0/20 -m comment --comment allow-ingress-from-google-iap -j ACCEPT
iptables -A SAFEZONE -s 10.8.0.0/24 -i tun0 -m comment --comment "Allow src 10.8.0.0/24 from tun0 iface" -j ACCEPT
iptables -A SAFEZONE -s 192.168.0.0/16 -j ACCEPT
iptables -A SAFEZONE -m comment --comment "JUMP back to IN_CUSTOMRULES chain" -j RETURN

echo firewall configuration is complete.
echo
echo
echo to view all the rules run the following script:
echo RAW rules:
echo "iptables -t raw -nvL --line-numbers"
echo
echo MANGLE rules:
echo "iptables -t mangle -nvL --line-numbers"
echo
echo FILTER rules: 
echo "iptables -t filter -nvL --line-numbers"
echo 
echo View all tables:
echo
echo "iptables -t raw -nvL --line-numbers && iptables -t mangle -nvL --line-numbers && iptables -t filter -nvL --line-numbers && iptables -t nat -nvL --line-numbers"
