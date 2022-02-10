#!/bin/bash
iptables -N IN_CUSTOMRULES_TCP
iptables -N IN_CUSTOMRULES_UDP
iptables -N IN_CUSTOMRULES_ICMP
iptables -N IN_CUSTOMRULES_SAFEZONE
#iptables -N FORWARDING_IN_CUSTOMRULES uncomment if the device is a router/firewall/proxy.
#iptables -N OUT_CUSTOMRULES uncomment if you require a more complicated ruleset for egress traffic

# INPUT - Houstbound pkts from the net
iptables -A INPUT -p tcp -m conntrack --ctstate established,related -m comment --comment "accept established, related pkts" -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate invalid -m comment --comment "reject invalid pkts" -j DROP
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
iptables -A FORWARD -p tcp -m conntrack --ctstate established,related -m comment --comment "accept established, related pkts" -j ACCEPT
iptables -A FORWARD -p tcp -m conntrack --ctstate invalid -m comment --comment "reject invalid pkts" -j DROP
iptables -A FORWARD -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A FORWARD -j REJECT --reject-with icmp-protocol-unreachable

# OUTPUT - Netbound pkts from the host
iptables -A OUTPUT -p tcp -m conntrack -ctstate established,related -m comment --comment "accept established, related pkts" -j ACCEPT
iptables -A OUTPUT -p tcp -m conntrack --ctstate invalid -m comment --comment "reject invalid pkts" -j DROP
iptables -A OUTPUT -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j REJECT --reject-with tcp-reset
iptables -A OUTPUT -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j REJECT --reject-with tcp-reset
iptables -A OUTPUT -m conntrack -ctstate new -m comment --comment "accept new egress pkts" -j ACCEPT
iptables -A OUTPUT -m comment --comment "Default Policy" -j REJECT --reject-with --icmp-protocol-unreachable

# Part of INPUT rules
iptables -A IN_CUSTOMRULES_TCP -p tcp -m tcp --dport 22  -m comment --comment "Allow SSH for safezone IPs" -j IN_CUSTOMRULES_SAFEZONE
iptables -A IN_CUSTOMRULES_TCP -p tcp -m tcp --dport 1194  -m comment --comment "Allow OpenVPN-TCP" -j ACCEPT
iptables -A IN_CUSTOMRULES_TCP -m comment --comment "back to  INPUT" -j RETURN

# Part of INPUT rules
iptables -A IN_CUSTOMRULES_UDP --dport 1194 -m comment --comment "accept OpenVPN-UDP" -j ACCEPT
iptables -A IN_CUSTOMRULES_UDP --dport 51820 -m comment --comment "accept WireGuard-UDP" -j ACCEPT
iptables -A IN_CUSTOMRULES_UDP -m comment --comment "back to  INPUT" -j RETURN

# Part of INPUT rules
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type destination-unreachable -m comment --comment " ICMP_DST_UNREACHABLE" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type source-quench -m comment --comment "ICMP_SOURCE_QUENCH" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type time-exceeded -m comment --comment "ICMP_TIME_EXCEEDED" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type parameter-problem -m comment --comment "ICMP_PARAMETER_PROBLEM" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type echo-request -m comment --comment "ICMP_ECHO_REQUEST" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -p icmp --icmp-type echo-reply -m comment --comment "ICMP_ECHO_REPLY" -j ACCEPT
iptables -A IN_CUSTOMRULES_ICMP -m comment --comment "back to  INPUT" -j RETURN
iptables -A IN_CUSTOMRULES_ICMP -m comment --comment "paranoid drop rule" -j DROP

netfilter-persistent save
netfilter-persistent reload