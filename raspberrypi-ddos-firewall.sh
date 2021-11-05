#!/bin/bash


# DDoS, portscan and malformed packet blocks
echo "Setting up Basic DDos Protection"
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags RST RST -j DROP
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
iptables -t mangle -A PREROUTING -p tcp -m state --state NEW -m recent --set --name DEFAULT --rsource
iptables -t mangle -A PREROUTING -p tcp -m state --state NEW -m recent --update --seconds 10 --hitcount 25 --name DEFAULT --rsource -j DROP
iptables -t mangle -A PREROUTING -p icmp -m limit --limit 2/sec -j ACCEPT
iptables -t mangle -A PREROUTING -p icmp -j DROP
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
 #iptables -A IN_CUSTOMRULES -p udp -m udp --dport 67 --sport 68 -m conntrack --ctstate NEW -i 0.0.0.0/0 -m comment --comment "Allow dhcp" -j ACCEPT
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
 #iptables -A FORWARDING_IN_CUSTOMRULES -p udp -m udp --dport 1194 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow OpenVPN" -j ACCEPT
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
 
 
