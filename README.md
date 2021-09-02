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


# Misc:

Logging functionality:

one of the INPUT chain rules logs packets before the default drop rule so in order to filter out the fluff we'll copy the records to a seperate logfile.

## Process:

Create the following file > /etc/rsyslog.d/iptables.conf
and use the following to log dropped packets in a seperate file from the syslog file.

  :msg, contains, "[IPTABLES-BLOCKED]" - /var/log/iptables.log
    & ~
    
then restart syslog process (assuming you're on ubuntu/debian) with the following command (as root):
### /etc/init.d/rsyslog restart
