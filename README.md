# iptables
Firewall rules intended for single hosts (not routers/firewalls)

Function:

Filter table:

Rules 1-2 Allow Established and Related connections first.

Rules 3-4 Drop malicious tcp packets if the connection is NEW. New tcp connections should always have the syn-flag.

Rules 5-6 Log and then Drop Invalid and Untracked state connections.

Rule 7 is where you open up ports and allow tcp/udp

Rule 8 Allow's connections for the loopback iface (lo) to avoid issues with dns etc... especially if using a cloud server on GCP/AWS/DO etc...

Rule 9 is the default policy for the INPUT chain i.e. DROP all traffic that makes it to here.


NAT table:

Rule 1: NAT connections destined for VPN clients

Rule 2: ...
