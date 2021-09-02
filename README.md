# iptables
Firewall rules intended for but not limited to single hosts. (router/firewall)

Function:

Filter table:

Allow (quick) loopback iface traffic
Allow (quick) ESTABLISHED and RELATED traffic
Stateful Packet Inspection filters to drop bogus traffic to ensure only legitimate traffic reaches the host/network.
Opened ports/services
SAFEZONE for whitelisted IP's (requires changing rules in  IN_CUSTOMRULES chain to be more meaningful)

NAT table:

 NAT connections destined for VPN clients

