# iptables
Firewall rules intended for but not limited to single hosts. (router/firewall)

Function:

Mangle table:
```
N/A
```
Raw table: 
```
1. Block bogus pkts.
2. Allow specified protocols
3. Block all else
```
Filter table:
```
Allow (quick) loopback iface traffic <br>
Allow (quick) ESTABLISHED and RELATED traffic <br>
Ports to be open in forward table if using port forwards. <br>
```

NAT table:
```
1. SNAT connections destined for WAN
2. No Open ports defined but dummy port forward rules to use as template. <br>
```

# Misc:

Logging functionality:
```
N/A
```
