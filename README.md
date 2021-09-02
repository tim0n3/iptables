# iptables
Firewall rules intended for but not limited to single hosts. (router/firewall)

Function:

Filter table:

Allow (quick) loopback iface traffic
Allow (quick) ESTABLISHED and RELATED traffic
Stateful Packet Inspection filters to drop bogus traffic to ensure only legitimate traffic reaches the host/network.
Opened ports/services
SAFEZONE for whitelisted IP's (requires changing rules in  IN_CUSTOMRULES chain to be more meaningful)


Chain INPUT (policy ACCEPT 0 packets, 0 bytes) 
num   pkts bytes target     prot opt in     out     source               destination
1     1008 88912 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
2    75832   54M ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate ESTABLISHED /* EST skip filter rules */
3        0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED /* REL skip filter rules */
4       23  1352 IN_DPI_RULES  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* Security Rules */
5       23  1352 IN_CUSTOMRULES  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* Allowed Ports and Services */
6       23  1352 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* LOG all dropped traffic */ LOG flags 0 level 4 prefix "[IPTABLES-BLOCKED]: "
7       23  1352 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* Explicitly DROP other connections */



NAT table:

 NAT connections destined for VPN clients


# Misc:

Logging functionality:

one of the INPUT chain rules logs packets before the default drop rule so in order to filter out the fluff we'll copy the records to a seperate logfile.

## Process:

Create the following file > `/etc/rsyslog.d/iptables.conf`
and use the following to log dropped packets in a seperate file from the syslog file.
`
  :msg, contains, "[IPTABLES-BLOCKED]" - /var/log/iptables.log
    & ~
 `
 
then restart syslog process (assuming you're on ubuntu/debian) with the following command (as root):
` /etc/init.d/rsyslog restart
`
