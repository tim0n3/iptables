#!/bin/bash
iptables -N IN_CUSTOMRULES_TCP
iptables -N IN_CUSTOMRULES_UDP
iptables -N IN_CUSTOMRULES_ICMP
iptables -N IN_CUSTOMRULES_SAFEZONE
#iptables -N FORWARDING_IN_CUSTOMRULES uncomment if the device is a router/firewall/proxy.
#iptables -N OUT_CUSTOMRULES uncomment if you require a more complicated ruleset for egress traffic

# INPUT - Houstbound pkts from the net
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "accept established, related pkts" -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate INVALID,UNTRACKED -m comment --comment "reject invalid pkts" -j REJECT --reject-with icmp-protocol-unreachable
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m comment --comment "Jump to pre-safezone chain" -j IN_CUSTOMRULES_TCP
iptables -A INPUT -p udp -m conntrack --ctstate NEW -m comment --comment "Jump to pre-safezone chain" -j IN_CUSTOMRULES_UDP
iptables -A INPUT -p icmp -m comment --comment "Jump to pre-safezone chain" -j IN_CUSTOMRULES_ICMP
iptables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
iptables -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A INPUT -j REJECT --reject-with icmp-protocol-unreachable

# FORWARD - LANbound pkts from the net
# FORWARD - Netbound pkts from the LAN
iptables -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "accept established, related pkts" -j ACCEPT
iptables -A FORWARD -p tcp -m conntrack --ctstate INVALID -m comment --comment "reject invalid pkts" -j REJECT --reject-with icmp-protocol-unreachable
iptables -A FORWARD -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j REJECT --reject-with tcp-reset
iptables -A FORWARD -s 192.168.0.0/16 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -p tcp -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A FORWARD -j REJECT --reject-with icmp-protocol-unreachable

# OUTPUT - Netbound pkts from the host
iptables -A OUTPUT -i lo -j ACCEPT
iptables -A OUTPUT -p tcp -m conntrack -ctstate ESTABLISHED,RELATED -m comment --comment "accept established, related pkts" -j ACCEPT
iptables -A OUTPUT -p tcp -m conntrack --ctstate INVALID -m comment --comment "reject invalid pkts" -j REJECT --reject-with icmp-protocol-unreachable
iptables -A OUTPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j REJECT --reject-with tcp-reset
iptables -A OUTPUT -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j REJECT --reject-with tcp-reset
iptables -A OUTPUT -m conntrack -ctstate new -m comment --comment "accept new egress pkts" -j ACCEPT
iptables -A OUTPUT -m comment --comment "Default Policy" -j REJECT --reject-with --icmp-protocol-unreachable

# Part of INPUT rules
iptables -A IN_CUSTOMRULES_TCP -p tcp -m tcp --dport 22  -m comment --comment "Allow SSH for safezone IPs" -j IN_CUSTOMRULES_SAFEZONE
#iptables -A IN_CUSTOMRULES_TCP -p tcp -m tcp --dport 1194  -m comment --comment "Allow OpenVPN-TCP" -j ACCEPT
iptables -A IN_CUSTOMRULES_TCP -m comment --comment "back to  INPUT" -j RETURN

# Part of INPUT rules
iptables -A IN_CUSTOMRULES_UDP --sport 67 --dport 68 -m comment --comment "Allow dhcp" -j ACCEPT
#iptables -A IN_CUSTOMRULES_UDP --dport 1194 -m comment --comment "accept OpenVPN-UDP" -j ACCEPT
#iptables -A IN_CUSTOMRULES_UDP --dport 51820 -m comment --comment "accept WireGuard-UDP" -j ACCEPT
iptables -A IN_CUSTOMRULES_UDP -m comment --comment "back to  INPUT" -j RETURN

# Part of INPUT rules
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type destination-unreachable -m comment --comment " ICMP_DST_UNREACHABLE" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type source-quench -m comment --comment "ICMP_SOURCE_QUENCH" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type time-exceeded -m comment --comment "ICMP_TIME_EXCEEDED" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type parameter-problem -m comment --comment "ICMP_PARAMETER_PROBLEM" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type echo-request -m comment --comment "ICMP_ECHO_REQUEST" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type echo-reply -m comment --comment "ICMP_ECHO_REPLY" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -m comment --comment "back to  INPUT" -j RETURN
iptables -A IN_CUSTOMRULES_ICMP -m comment --comment "paranoid drop rule" -j REJECT --reject-with icmp-protocol-unreachable

iptables -A IN_CUSTOMRULES_SAFEZONE -s x.x.x.x/x -m comment --comment "EDS IP" -j ACCEPT
iptables -A IN_CUSTOMRULES_SAFEZONE -s x.x.x.x/x -m comment --comment "Tim IP" -j ACCEPT
iptables -A IN_CUSTOMRULES_SAFEZONE -s x.x.x.x/x -m comment --comment "EDS RMM IP" -j ACCEPT
iptables -A IN_CUSTOMRULES_SAFEZONE -s 192.168.88.0/24 -m comment --comment "LAN CONNECTIONS" -j ACCEPT
iptables -A IN_CUSTOMRULES_SAFEZONE -m comment --comment "Jump back to Customrules chain" -j RETURN

# RAW - prerouting - Houstbound pkts from the net
iptables -t raw -A PREROUTING -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "TCP invalid combination of flags attack (7 rules)" -DROP
iptables -t raw -A PREROUTING -p tcp -m tcp ! --tcp-flags ALL ALL -m comment --comment "XMAS port scan" -DROP
iptables -t raw -A PREROUTING -p tcp -m tcp ! --tcp-flags ALL NONE -m comment --comment "NULL port scan" -DROP
iptables -t raw -A PREROUTING -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -m comment --comment "DROP EXCESSIVE TCP RST PACKETS" -j ACCEPT
iptables -t raw -A PREROUTING -p tcp -m tcp --dport 0 -m comment --comment "TCP Port 0 attack (2 rules)" -j DROP
iptables -t raw -A PREROUTING -p tcp -m tcp --sport 0 -m comment --comment "TCP Port 0 attack" -j DROP
iptables -t raw -A PREROUTING -p udp -m udp --dport 0 -m comment --comment "UDP Port 0 attack (2 rules)" -j DROP
iptables -t raw -A PREROUTING -p udp -m udp --sport 0 -m comment --comment "UDP Port 0 attack" -j DROP
iptables -t raw -A PREROUTING -p icmp -m comment --comment "Accept used protocols and drop all others" -j ACCEPT
iptables -t raw -A PREROUTING -p igmp -m comment --comment "Accept used protocols and drop all others" -j ACCEPT
iptables -t raw -A PREROUTING -p tcp -m comment --comment "Accept used protocols and drop all others" -j ACCEPT
iptables -t raw -A PREROUTING -p udp -m comment --comment "Accept used protocols and drop all others" -j ACCEPT
#iptables -t raw -A PREROUTING -p l2tp -m comment --comment "Accept used protocols and drop all others" -j ACCEPT
#iptables -t raw -A PREROUTING -p gre -m comment --comment "Accept used protocols and drop all others" -j ACCEPT
#iptables -t raw -A PREROUTING -p etherip -m comment --comment "Accept used protocols and drop all others" -j ACCEPT
#iptables -t raw -A PREROUTING -p ospf -m comment --comment "Accept used protocols and drop all others" -j ACCEPT
iptables -t raw -A PREROUTING -m comment --comment "Drop unused protocols" -j DROP

# MANGLE - ALL - ALL pkts to and from the net
#iptables -t mangle -A PREROUTING -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -m comment --comment "All TCP sessions should begin with SYN" -j DROP
#iptables -t mangle -A INPUT -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -m comment --comment "All TCP sessions should begin with SYN" -j DROP
#iptables -t mangle -A FORWARD -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -m comment --comment "All TCP sessions should begin with SYN" -j DROP
#iptables -t mangle -A OUTPUT -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -m comment --comment "All TCP sessions should begin with SYN" -j DROP

netfilter-persistent save
netfilter-persistent reload

cat << EOF >> /etc/sysctl.conf
# Turn on Source Address Verification in all interfaces to prevent some
# spoofing attacks
net/ipv4/conf/default/rp_filter=1
net/ipv4/conf/all/rp_filter=1

# Do not accept IP source route packets (we are not a router)
net/ipv4/conf/default/accept_source_route=0
net/ipv4/conf/all/accept_source_route=0
net/ipv6/conf/default/accept_source_route=0
net/ipv6/conf/all/accept_source_route=0

# Disable ICMP redirects. ICMP redirects are rarely used but can be used in
# MITM (man-in-the-middle) attacks. Disabling ICMP may disrupt legitimate
# traffic to those sites.
net/ipv4/conf/default/accept_redirects=0
net/ipv4/conf/all/accept_redirects=0
net/ipv6/conf/default/accept_redirects=0
net/ipv6/conf/all/accept_redirects=0

# Ignore bogus ICMP errors
net/ipv4/icmp_echo_ignore_broadcasts=1
net/ipv4/icmp_ignore_bogus_error_responses=1
net/ipv4/icmp_echo_ignore_all=0

# Don't log Martian Packets (impossible packets)
net/ipv4/conf/default/log_martians=0
net/ipv4/conf/all/log_martians=0

# Change to '1' to enable TCP/IP SYN cookies This disables TCP Window Scaling
# (http://lkml.org/lkml/2008/2/5/167)
net/ipv4/tcp_syncookies=0

#net/ipv4/tcp_fin_timeout=30
#net/ipv4/tcp_keepalive_intvl=1800

# normally allowing tcp_sack is ok, but if going through OpenBSD 3.8 RELEASE or
# earlier pf firewall, should set this to 0
net/ipv4/tcp_sack=1
EOF

sysctl -p