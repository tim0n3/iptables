# feb/04/2022 15:15:41 by RouterOS 6.49.2
# model = RBLHGR
/interface bridge
add admin-mac=48:8F:5A:76:1A:C4 auto-mac=no comment=defconf name=bridge
/interface l2tp-server
add disabled=yes name=l2tp-in-energydrive user=tim
/interface pptp-server
add disabled=yes name=pptp-energydrive user=energydrive
add disabled=yes name=pptp-tim user=tim
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
/interface lte apn
add apn=axxess default-route-distance=1
add apn=myMTN authentication=chap user=mtn
/interface lte
set [ find ] allow-roaming=yes apn-profiles=axxess mtu=1480 name=lte1
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/ip ipsec profile
set [ find default=yes ] dh-group=modp1024 dpd-interval=disable-dpd enc-algorithm=aes-128
/ip ipsec proposal
set [ find default=yes ] auth-algorithms=sha256,sha1 enc-algorithms=aes-256-cbc,aes-128-cbc lifetime=0s
/ip pool
add name=dhcp ranges=192.168.88.10-192.168.88.254
add name=PPTP-Pool ranges=192.168.99.10-192.168.99.200
/ip dhcp-server
add address-pool=dhcp disabled=no interface=bridge name=defconf
/ppp profile
add bridge=bridge local-address=10.6.0.1 name=energydrive remote-address=dhcp use-compression=no
add change-tcp-mss=yes dns-server=8.8.8.8,8.8.4.4 local-address=PPTP-Pool name=PPTP-Profile only-one=yes remote-address=PPTP-Pool use-encryption=yes
/queue type
set 0 kind=sfq
add kind=red name=redCustom red-avg-packet=1514
/queue tree
add bucket-size=0.01 max-limit=1M name=DOWN parent=bridge queue=redCustom
add name="1. VOIP" packet-mark=VOIP parent=DOWN priority=1 queue=default
add name="2. DNS" packet-mark=DNS parent=DOWN priority=2 queue=default
add name="3. ACK" packet-mark=ACK parent=DOWN priority=3 queue=default
add name="4. UDP" packet-mark=UDP parent=DOWN priority=3 queue=default
add name="5. ICMP" packet-mark=ICMP parent=DOWN priority=4 queue=default
add name="6. HTTP" packet-mark=HTTP parent=DOWN priority=5 queue=default
add name="7. HTTP_BIG" packet-mark=HTTP_BIG parent=DOWN priority=6 queue=default
add name="8. QUIC" packet-mark=QUIC parent=DOWN priority=7 queue=default
add name="9. OTHER" packet-mark=OTHER parent=DOWN queue=redCustom
add bucket-size=0.01 max-limit=1M name=UP parent=lte1 queue=redCustom
add name="1. VOIP_" packet-mark=VOIP parent=UP priority=1 queue=default
add name="2. DNS_" packet-mark=DNS parent=UP priority=2 queue=default
add name="3. ACK_" packet-mark=ACK parent=UP priority=3 queue=default
add name="4. UDP_" packet-mark=UDP parent=UP priority=3 queue=default
add name="5. ICMP_" packet-mark=ICMP parent=UP priority=4 queue=default
add name="6. HTTP_" packet-mark=HTTP parent=UP priority=5 queue=default
add name="7. HTTP_BIG_" packet-mark=HTTP_BIG parent=UP priority=6 queue=default
add name="8. QUIC_" packet-mark=QUIC parent=UP priority=7 queue=default
add name="9. OTHER_" packet-mark=OTHER parent=UP queue=redCustom
add name="0. IOT_CORE_" packet-mark=Google_IoT_Core-Packet parent=UP priority=1 queue=default
add disabled=yes name="10. no-mark_" packet-mark=no-mark parent=UP queue=default
add disabled=yes name="10. no-mark" packet-mark=no-mark parent=DOWN queue=redCustom
add name=SSH packet-mark=SSH parent=DOWN priority=1 queue=default
/user group
set full policy=local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,dude,tikapp
/interface bridge port
add bridge=bridge comment=defconf interface=ether1
add bridge=bridge comment=defconf interface=*2
/ip neighbor discovery-settings
set discover-interface-list=LAN
/ip settings
set tcp-syncookies=yes
/interface l2tp-server server
set default-profile=energydrive enabled=yes ipsec-secret=KdeKveZJbc0YR19uYUWMH7rZlkP6TSPC6qOtZ2wXKk3 use-ipsec=yes
/interface list member
add comment=defconf interface=bridge list=LAN
add comment=defconf interface=lte1 list=WAN
/interface pptp-server server
set authentication=chap,mschap1,mschap2 default-profile=PPTP-Profile enabled=yes
/ip address
add address=192.168.88.1/24 comment=defconf interface=ether1 network=192.168.88.0
/ip cloud
set ddns-enabled=yes ddns-update-interval=1m
/ip dhcp-server network
add address=192.168.88.0/24 comment=defconf gateway=192.168.88.1
/ip dns
set allow-remote-requests=yes servers=1.1.1.1,1.0.0.1
/ip dns static
add address=192.168.88.1 comment=defconf name=router.lan
/ip firewall address-list
add address=192.168.88.200 comment="RPi 4" list=support
add address=192.168.88.201 comment="WAP (Wifi)" list=support
add address=192.168.88.202 comment="Site Users (202 - 210)" list=support
add address=165.255.239.93 comment="Permitted Public IP's" list=support_external
add address=37.48.118.94 list=support_external
add address=105.23.225.106 list=support_external
add address=192.168.88.203 list=support
add address=192.168.88.204 list=support
add address=192.168.88.205 list=support
add address=192.168.88.206 list=support
add address=192.168.88.207 list=support
add address=192.168.88.208 list=support
add address=192.168.88.209 list=support
add address=192.168.88.210 list=support
add address=192.168.99.0/24 comment="VPN users" list=support
add address=192.168.88.1 comment=Gwy_IP list=support
add address=41.78.247.35 list=support_external
add address=165.255.239.57 list=support_external
add address=0.0.0.0/8 comment="Self-Identification [RFC 3330]" list=bogons
add address=10.0.0.0/8 comment="Private[RFC 1918] - CLASS A # Check if you need this subnet before enable it" list=bogons
add address=127.0.0.0/8 comment="Loopback [RFC 3330]" list=bogons
add address=169.254.0.0/16 comment="Link Local [RFC 3330]" list=bogons
add address=172.16.0.0/12 comment="Private[RFC 1918] - CLASS B # Check if you need this subnet before enable it" list=bogons
add address=192.168.0.0/16 comment="Private[RFC 1918] - CLASS C # Check if you need this subnet before enable it" disabled=yes list=bogons
add address=192.0.2.0/24 comment="Reserved - IANA - TestNet1" list=bogons
add address=192.88.99.0/24 comment="6to4 Relay Anycast [RFC 3068]" list=bogons
add address=198.18.0.0/15 comment="NIDB Testing" list=bogons
add address=198.51.100.0/24 comment="Reserved - IANA - TestNet2" list=bogons
add address=203.0.113.0/24 comment="Reserved - IANA - TestNet3" list=bogons
add address=224.0.0.0/4 comment="MC, Class D, IANA # Check if you need this subnet before enable it" list=bogons
add address=192.0.0.0/24 comment="Reserved - IANA - TestNet1" list=bogons
add address=0.0.0.0/8 comment=RFC6890 list=NotPublic
add address=10.0.0.0/8 comment=RFC6890 list=NotPublic
add address=100.64.0.0/10 comment=RFC6890 list=NotPublic
add address=127.0.0.0/8 comment=RFC6890 list=NotPublic
add address=169.254.0.0/16 comment=RFC6890 list=NotPublic
add address=172.16.0.0/12 comment=RFC6890 list=NotPublic
add address=192.0.0.0/24 comment=RFC6890 list=NotPublic
add address=192.0.2.0/24 comment=RFC6890 list=NotPublic
add address=192.168.0.0/16 comment=RFC6890 list=NotPublic
add address=192.88.99.0/24 comment=RFC3068 list=NotPublic
add address=198.18.0.0/15 comment=RFC6890 list=NotPublic
add address=198.51.100.0/24 comment=RFC6890 list=NotPublic
add address=203.0.113.0/24 comment=RFC6890 list=NotPublic
add address=224.0.0.0/4 comment=RFC4601 list=NotPublic
add address=240.0.0.0/4 comment=RFC6890 list=NotPublic
add address=192.168.88.1-192.168.88.254 list=allowed_to_router
add address=37.48.118.94 list=allowed_to_router
add address=165.255.239.57 list=allowed_to_router
add address=105.23.225.106 list=allowed_to_router
add address=127.0.0.0/8 comment="defconf: RFC6890" list=bad_ipv4
add address=192.0.0.0/24 comment="defconf: RFC6890" list=bad_ipv4
add address=192.0.2.0/24 comment="defconf: RFC6890 documentation" list=bad_ipv4
add address=198.51.100.0/24 comment="defconf: RFC6890 documentation" list=bad_ipv4
add address=203.0.113.0/24 comment="defconf: RFC6890 documentation" list=bad_ipv4
add address=240.0.0.0/4 comment="defconf: RFC6890 reserved" list=bad_ipv4
add address=0.0.0.0/8 comment="defconf: RFC6890" list=not_global_ipv4
add address=10.0.0.0/8 comment="defconf: RFC6890" list=not_global_ipv4
add address=100.64.0.0/10 comment="defconf: RFC6890" list=not_global_ipv4
add address=169.254.0.0/16 comment="defconf: RFC6890" list=not_global_ipv4
add address=172.16.0.0/12 comment="defconf: RFC6890" list=not_global_ipv4
add address=192.0.0.0/29 comment="defconf: RFC6890" list=not_global_ipv4
add address=192.168.0.0/16 comment="defconf: RFC6890" list=not_global_ipv4
add address=198.18.0.0/15 comment="defconf: RFC6890 benchmark" list=not_global_ipv4
add address=255.255.255.255 comment="defconf: RFC6890" list=not_global_ipv4
add address=224.0.0.0/4 comment="defconf: multicast" list=bad_src_ipv4
add address=255.255.255.255 comment="defconf: RFC6890" list=bad_src_ipv4
add address=0.0.0.0/8 comment="defconf: RFC6890" list=bad_dst_ipv4
add address=224.0.0.0/4 comment="defconf: RFC6890" list=bad_dst_ipv4
add address=0.0.0.0/8 comment="defconf: RFC6890" list=no_forward_ipv4
add address=169.254.0.0/16 comment="defconf: RFC6890" list=no_forward_ipv4
add address=224.0.0.0/4 comment="defconf: multicast" list=no_forward_ipv4
add address=255.255.255.255 comment="defconf: RFC6890" list=no_forward_ipv4
add address=34.90.83.14 list=allowed_to_router
add address=169.1.1.2 comment="AXXESS upstream DNS servers" list=public_DNS
add address=169.1.1.4 comment="AXXESS upstream DNS servers" list=public_DNS
add address=1.1.1.1 comment="AXXESS upstream DNS servers" list=public_DNS
add address=1.0.0.3 comment="AXXESS upstream DNS servers" list=public_DNS
add address=172.217.170.78 list=youtube
add address=172.217.170.46 list=youtube
add address=102.132.100.35 list=facebook
add address=102.132.100.60 list=whatsapp
add address=149.154.167.99 list=telegram
add address=8.8.8.8 comment="AXXESS upstream DNS servers" list=public_DNS
add address=8.8.4.4 comment="AXXESS upstream DNS servers" list=public_DNS
add address=1.1.1.3 comment="AXXESS upstream DNS servers" list=public_DNS
add address=172.217.170.42 list=googleapis
add address=172.217.170.106 list=googleapis
add address=172.217.170.74 list=googleapis
add address=216.58.223.138 list=googleapis
/ip firewall filter
add action=passthrough chain=output comment="special dummy rule to show fasttrack counters"
add action=passthrough chain=input comment="special dummy rule to show fasttrack counters"
add action=drop chain=forward comment="This rule blocks access to facebook" disabled=yes dst-address-list=facebook log=yes log-prefix="[Block] facebook"
add action=accept chain=input comment="### DO NOT DISABLE-Address-list of IP's that are allowed to access the router" in-interface=lte1 src-address-list=allowed_to_router
add action=accept chain=input comment="### DO NOT DISABLE-Address-list of Permitted Public DNS resolvers " in-interface=lte1 log=yes log-prefix="[ACCEPT DNS] :: PERMITTED RESOLVER-LIST : " src-address-list=public_DNS
add action=accept chain=forward comment="### DEBUG forwarding DNS not required - Address-list of Permitted Public DNS resolvers " in-interface=lte1 src-address-list=public_DNS
add action=accept chain=input comment="### DO NOT DISABLE-Address-list of IP's that are allowed to access the router" in-interface=bridge src-address-list=allowed_to_router
add action=fasttrack-connection chain=input comment="Services -- Counters --  access to the winbox" dst-port=8291 protocol=tcp
add action=accept chain=input comment="Services -- Counters -- External access to the winbox " connection-state=new dst-port=8291 in-interface=lte1 protocol=tcp src-address-list=support_external
add action=accept chain=input comment="Services -- Counters -- Local access to the winbox " connection-state=new dst-port=8291 in-interface=bridge protocol=tcp
add action=accept chain=input comment="defconf: accept established,related,untracked after RAW" connection-state=established,related,untracked
add action=accept chain=input comment="Accept established and related packets" connection-state=established,related
add action=accept chain=input comment="Accept all connections from local network" in-interface=bridge
add action=accept chain=input comment="defconf: accept ICMP after RAW" protocol=icmp
add action=drop chain=input comment="Drop invalid packets" connection-state=invalid
add action=drop chain=input comment="Drop all packets which are not destined to routes IP address" dst-address-type=!local
add action=drop chain=input comment="Drop all packets which does not have unicast source IP address" src-address-type=!unicast
add action=drop chain=input comment="Drop all packets from public internet which should not exist in public network" in-interface=lte1 src-address-list=NotPublic
add action=jump chain=input comment="Jump for icmp input flow" jump-target=ICMP protocol=icmp
add action=drop chain=input comment="Block all access to the winbox - except to support list # DO NOT ENABLE THIS RULE BEFORE ADD YOUR SUBNET IN THE SUPPORT ADDRESS LIST" dst-port=8291 protocol=tcp src-address-list=!allowed_to_router
add action=drop chain=input comment="Block all access to the winbox - except to support list # DO NOT ENABLE THIS RULE BEFORE ADD YOUR SUBNET IN THE SUPPORT ADDRESS LIST" dst-port=8291 protocol=tcp src-address-list=!support_external
add action=add-src-to-address-list address-list=Syn_Flooder address-list-timeout=1w chain=input comment="Add Syn Flood IP to the list" connection-limit=30,32 protocol=tcp tcp-flags=syn
add action=drop chain=input comment="Drop to syn flood list" src-address-list=Syn_Flooder
add action=add-src-to-address-list address-list=Port_Scanner address-list-timeout=1w chain=input comment="Port Scanner Detect" protocol=tcp psd=21,3s,3,1
add action=drop chain=input comment="Drop to port scan list" src-address-list=Port_Scanner
add action=drop chain=input comment="Default Policy" log=yes log-prefix="[INPUT-BLOCKED] :: "
add action=add-dst-to-address-list address-list=Facebook address-list-timeout=4d chain=forward comment=Google_IoT_Core content=cloudiotdevice.googleapis.com
add action=add-dst-to-address-list address-list=Facebook address-list-timeout=4d chain=forward comment=Google_IoT_Core content=.googleapis.com
add action=fasttrack-connection chain=forward comment="This rule blocks access to googleapis" dst-address-list=googleapis
add action=accept chain=forward comment="This rule blocks access to googleapis" dst-address-list=googleapis
add action=fasttrack-connection chain=forward comment="defconf: fasttrack established and related packets" connection-state=established,related
add action=accept chain=forward comment="Accept established and related packets" connection-state=established,related,untracked
add action=drop chain=forward comment="Drop invalid packets" connection-state=invalid
add action=drop chain=forward comment="Drop new connections from internet which are not dst-natted" connection-nat-state=!dstnat connection-state=new in-interface=lte1
add action=drop chain=forward comment="Drop all packets from local network to internet which should not exist in public network" dst-address-list=NotPublic in-interface=bridge
add action=drop chain=forward comment="Drop new connections from internet which are not dst-natted" connection-nat-state=!dstnat connection-state=new in-interface=lte1
add action=accept chain=forward comment="Allow established, related connections from internet which are dst-natted" connection-nat-state=dstnat connection-state=established,related in-interface=lte1
add action=drop chain=forward comment="defconf: drop bad forward IPs" src-address-list=no_forward_ipv4
add action=drop chain=forward comment="defconf: drop bad forward IPs" dst-address-list=no_forward_ipv4
add action=jump chain=output comment="Jump for icmp output" jump-target=ICMP protocol=icmp
add action=accept chain=ICMP comment="Echo request - Avoiding Ping Flood, adjust the limit as needed" icmp-options=8:0 limit=2,5:packet protocol=icmp
add action=accept chain=ICMP comment="Echo reply" icmp-options=0:0 protocol=icmp
add action=accept chain=ICMP comment="Time Exceeded" icmp-options=11:0 protocol=icmp
add action=accept chain=ICMP comment="Destination unreachable" icmp-options=3:0-1 protocol=icmp
add action=accept chain=ICMP comment=PMTUD icmp-options=3:4 protocol=icmp
add action=drop chain=ICMP comment="Drop to the other ICMPs" disabled=yes protocol=icmp
/ip firewall mangle
add action=mark-connection chain=prerouting comment=Google_IoT_Core new-connection-mark=Google_IoT_Core-Conn passthrough=yes src-address-list=googleapis
add action=mark-packet chain=prerouting connection-mark=Google_IoT_Core-Conn new-packet-mark=Google_IoT_Core-Packet passthrough=no src-address-list=googleapis
add action=mark-connection chain=postrouting comment=Google_IoT_Core dst-address-list=googleapis new-connection-mark=Google_IoT_Core-Conn passthrough=yes
add action=mark-packet chain=postrouting connection-mark=Google_IoT_Core-Conn dst-address-list=googleapis new-packet-mark=Google_IoT_Core-Packet passthrough=no
add action=mark-connection chain=prerouting comment=ssh_connt_mark dst-port=22 new-connection-mark=SSH-conn passthrough=yes protocol=tcp
add action=mark-packet chain=prerouting comment=ssh_packet_mark connection-mark=SSH-conn dst-port=22 new-packet-mark=SSH passthrough=no protocol=tcp
add action=mark-connection chain=prerouting comment=winbox_connt_mark dst-port=8291 new-connection-mark=winbox_conn passthrough=yes protocol=tcp
add action=mark-packet chain=prerouting comment=winbox_packet_mark connection-mark=winbox_conn dst-port=8291 new-packet-mark=winbox passthrough=no protocol=tcp
add action=mark-connection chain=postrouting comment=winbox_connt_mark dst-port=8291 new-connection-mark=winbox_conn passthrough=yes protocol=tcp
add action=mark-packet chain=postrouting comment=winbox_packet_mark connection-mark=winbox_conn dst-port=8291 new-packet-mark=winbox passthrough=yes protocol=tcp
add action=mark-connection chain=prerouting comment=DNS connection-state=new log=yes log-prefix="[MARK-DNS-UDP] :: " new-connection-mark=DNS passthrough=yes port=53 protocol=udp
add action=mark-packet chain=prerouting connection-mark=DNS log=yes log-prefix="[MARK-DNS-UDP-PACKET] :: " new-packet-mark=DNS passthrough=no
add action=mark-connection chain=postrouting connection-state=new new-connection-mark=DNS passthrough=yes port=53 protocol=udp
add action=mark-packet chain=postrouting connection-mark=DNS new-packet-mark=DNS passthrough=no
add action=mark-connection chain=prerouting comment=VOIP new-connection-mark=VOIP passthrough=yes port=5060-5062,10000-10050 protocol=udp
add action=mark-packet chain=prerouting connection-mark=VOIP new-packet-mark=VOIP passthrough=no
add action=mark-connection chain=prerouting comment=QUIC connection-state=new new-connection-mark=QUIC passthrough=yes port=80,443 protocol=udp
add action=mark-packet chain=prerouting connection-mark=QUIC new-packet-mark=QUIC passthrough=no
add action=mark-connection chain=prerouting comment=UDP connection-state=new new-connection-mark=UDP passthrough=yes protocol=udp
add action=mark-packet chain=prerouting connection-mark=UDP new-packet-mark=UDP passthrough=no
add action=mark-connection chain=prerouting comment=ICMP connection-state=new new-connection-mark=ICMP passthrough=yes protocol=icmp
add action=mark-packet chain=prerouting connection-mark=ICMP new-packet-mark=ICMP passthrough=no
add action=mark-connection chain=postrouting connection-state=new new-connection-mark=ICMP passthrough=yes protocol=icmp
add action=mark-packet chain=postrouting connection-mark=ICMP new-packet-mark=ICMP passthrough=no
add action=mark-packet chain=postrouting comment=ACK new-packet-mark=ACK packet-size=0-123 passthrough=no protocol=tcp tcp-flags=ack
add action=mark-packet chain=prerouting new-packet-mark=ACK packet-size=0-123 passthrough=no protocol=tcp tcp-flags=ack
add action=fasttrack-connection chain=prerouting comment=FASTTRACK_HTTP_normal_mark connection-state=new log-prefix="[MANGLE-PASS-HTTP] :: " port=80,443 protocol=tcp
add action=mark-connection chain=prerouting comment=HTTP_normal_mark connection-state=new log=yes log-prefix="[MANGLE-PASS-HTTP] :: " new-connection-mark=HTTP passthrough=yes port=80,443 protocol=tcp
add action=mark-packet chain=prerouting comment=HTTP_normal_packet_mark connection-mark=HTTP log=yes log-prefix="[PACKET-MARK-80] :: " new-packet-mark=HTTP passthrough=no
add action=mark-connection chain=prerouting comment=HTTP_BIG_CONN_MARK connection-bytes=5000000-0 connection-mark=HTTP connection-rate=2M-100M log=yes log-prefix="[MANGLE-PASS-80-BIG] :: " new-connection-mark=HTTP_BIG passthrough=yes protocol=tcp
add action=mark-packet chain=prerouting comment=HTTP_BIG_PACKET_MARK connection-mark=HTTP_BIG log=yes log-prefix="[PACKET-MARK-80-BIG] ::" new-packet-mark=HTTP_BIG passthrough=no
add action=mark-connection chain=prerouting comment=OTHER connection-state=new new-connection-mark=POP3 passthrough=yes port=995,465,587 protocol=tcp
add action=mark-packet chain=prerouting connection-mark=POP3 new-packet-mark=OTHER passthrough=no
add action=mark-connection chain=prerouting new-connection-mark=OTHER passthrough=yes
add action=mark-packet chain=prerouting connection-mark=OTHER new-packet-mark=OTHER passthrough=no
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" ipsec-policy=out,none out-interface-list=WAN
add action=masquerade chain=srcnat comment="src-NAT for Allowed clients" disabled=yes log-prefix=egress_lan_NAT out-interface-list=WAN
add action=masquerade chain=srcnat comment="src-NAT for Allowed clients" disabled=yes log=yes log-prefix=egress_lan_NAT out-interface-list=WAN src-address-list=support
add action=dst-nat chain=dstnat comment="DNAT to RPi SSH" disabled=yes in-interface=lte1 log=yes log-prefix=SSH_to_RPi4 port=22 protocol=tcp src-address-list=support_external to-addresses=192.168.88.200 to-ports=22
add action=accept chain=dstnat comment="dst-nat for allowed Public_IP's" disabled=yes src-address-list=support_external
/ip firewall raw
add action=accept chain=prerouting comment="defconf: enable for transparent firewall ### Only enable when doing debug so that traffic bypasses all prerouting rules"
add action=accept chain=prerouting comment="### DO NOT DISABLE-Address-list of IP's that are allowed to access the router" in-interface=lte1 src-address-list=allowed_to_router
add action=accept chain=prerouting comment="### DO NOT DISABLE - MikroTik Cloud DDNS servers" in-interface=lte1 log=yes log-prefix="[DDNS-IP-REFRESH] ::" protocol=udp src-address=159.148.172.251 src-port=15252
add action=accept chain=prerouting comment="### DO NOT DISABLE - MikroTik Cloud DDNS servers" in-interface=lte1 log=yes log-prefix="[DDNS-IP-REFRESH] ::" protocol=udp src-address=159.148.147.229 src-port=15252
add action=accept chain=prerouting comment="### DO NOT DISABLE-Address-list of Permitted Public DNS resolvers " in-interface=lte1 src-address-list=public_DNS
add action=accept chain=prerouting comment="### DO NOT DISABLE-Address-list of IP's that are allowed to access the router" in-interface=bridge src-address-list=allowed_to_router
add action=drop chain=prerouting comment="defconf: drop bogon IP's" src-address-list=bad_ipv4
add action=drop chain=prerouting comment="defconf: drop bogon IP's" dst-address-list=bad_ipv4
add action=drop chain=prerouting comment="defconf: drop bogon IP's" src-address-list=bad_src_ipv4
add action=drop chain=prerouting comment="defconf: drop bogon IP's" dst-address-list=bad_dst_ipv4
add action=drop chain=prerouting comment="defconf: drop bad UDP" log=yes log-prefix="[BLOCKED-BY-RAW-RULES] :: UDP = 0 IS BANNED : " port=0 protocol=udp
add action=jump chain=prerouting comment="defconf: jump to ICMP chain" jump-target=icmp4 protocol=icmp
add action=jump chain=prerouting comment="defconf: jump to TCP chain" jump-target=bad_tcp protocol=tcp
add action=drop chain=prerouting comment="defconf: drop the rest" log=yes log-prefix="[BLOCKED-BY-RAW-RULES] : "
add action=drop chain=bad_tcp comment="defconf: TCP flag filter" protocol=tcp tcp-flags=!fin,!syn,!rst,!ack
add action=drop chain=bad_tcp comment="defconf: TCP flag filter" protocol=tcp tcp-flags=!psh,!ack
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=fin,syn
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=fin,rst
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=fin,!ack
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=fin,urg
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=syn,rst
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=rst,urg
add action=accept chain=bad_tcp comment="defconf: TCP flag filter" protocol=tcp tcp-flags=syn,ack
add action=accept chain=bad_tcp comment="defconf: TCP flag filter" protocol=tcp tcp-flags=ack
add action=accept chain=bad_tcp comment="defconf: TCP flag filter" protocol=tcp tcp-flags=psh,ack
add action=drop chain=bad_tcp comment="defconf: TCP port 0 drop" port=0 protocol=tcp
add action=accept chain=icmp4 comment="defconf: echo reply" icmp-options=0:0 limit=5,10:packet protocol=icmp
add action=accept chain=icmp4 comment="defconf: net unreachable" icmp-options=3:0 protocol=icmp
add action=accept chain=icmp4 comment="defconf: host unreachable" icmp-options=3:1 protocol=icmp
add action=accept chain=icmp4 comment="defconf: protocol unreachable" icmp-options=3:2 protocol=icmp
add action=accept chain=icmp4 comment="defconf: port unreachable" icmp-options=3:3 protocol=icmp
add action=accept chain=icmp4 comment="defconf: fragmentation needed" icmp-options=3:4 protocol=icmp
add action=accept chain=icmp4 comment="defconf: echo" icmp-options=8:0 limit=5,10:packet protocol=icmp
add action=accept chain=icmp4 comment="defconf: time exceeded " icmp-options=11:0-255 protocol=icmp
add action=drop chain=icmp4 comment="defconf: drop other icmp" protocol=icmp
/ip firewall service-port
set ftp disabled=yes
set tftp disabled=yes
set irc disabled=yes
set h323 disabled=yes
set sip disabled=yes
set pptp disabled=yes
set udplite disabled=yes
set dccp disabled=yes
set sctp disabled=yes
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www address=105.23.225.106/32,37.48.118.94/32,34.90.83.14/32
set ssh disabled=yes
set api disabled=yes
set winbox address=192.168.88.0/24,37.48.118.94/32,165.255.239.57/32,105.23.225.106/32,34.90.83.14/32,188.34.190.74/32
set api-ssl disabled=yes
/ppp secret
add name=tim password=fromtheotherside profile=PPTP-Profile
add name=energydrive password=vCRkVHj16m2RdF9j profile=PPTP-Profile
add disabled=yes name=energydrv password=fromtheotherside profile=PPTP-Profile service=pptp
/system clock
set time-zone-name=Africa/Johannesburg
/system clock manual
set time-zone=+02:00
/system identity
set name=AMS001-LADLE-FURNACE-BAGHOUSE-FANS-LTE
/system leds
# using RSRP, modem-signal-threshold ignored
set 0 leds=,,,, type=modem-signal
set 1 leds=user-led type=modem-technology
/system routerboard settings
set auto-upgrade=yes cpu-frequency=750MHz
/system scheduler
add disabled=yes interval=12h name=Reboot on-event="system reboot" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
add comment="Crontab for auto-block script" disabled=yes interval=1m name=auto-blockcrontab on-event="/system script run auto-block" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
add comment="Crontab for telegram-block-script" disabled=yes interval=1m name="telegram-block-script crontab" on-event="/system script run telegram-block-script" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=\
    jan/01/1970 start-time=00:00:01
add comment="Crontab for no-mark" disabled=yes interval=30m name="no-mark crontab" on-event="/system script run no-mark" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
add comment="Crontab for watchdog" disabled=yes interval=6h name="watchdog crontab" on-event="/system script run watchdog" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
add comment="Crontab for auto-block script" interval=10m name=googleapis.com on-event="/system script run googleapis.com" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
/system script
add dont-require-permissions=no name=watchdog owner=admin policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=":if ([/ping 8.8.8.8 interval=5 count=1800] =0) do={\r\
    \n/system reboot\r\
    \n}"
add dont-require-permissions=no name=googleapis.com owner=admin policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=" #Script to add IP addresses for specific domains to address lists\r\
    \n{\r\
    \n#Array of desired domain names\r\
    \n foreach iplist in=(\"googleapis\") do={\r\
    \n  {\r\
    \n#Old entries are deleted\r\
    \n  /ip firewall address-list remove [find where list=\$iplist]\r\
    \n#Dummy variable to not get into loop\r\
    \n  global counter true\r\
    \n#Check if IP addresses are not repeating themselves\r\
    \n   while (\$counter) do={\r\
    \n#Resolve domain\r\
    \n    local ip [/resolve (\"www.\".\$iplist.\".com\")]\r\
    \n#Add IP to address list under specific domain list if it does not already exist\r\
    \n    if ([len [/ip firewall address-list find where address=\$ip]] = 0) do={\r\
    \n     /ip firewall address-list add address=\$ip list=\$iplist } else={\r\
    \n#If IP already exist in list then stop resolving this domain\r\
    \n     set counter false\r\
    \n    }\r\
    \n   }\r\
    \n  }\r\
    \n#If there is no firewall filter rules which blocks this specific domain then add it\r\
    \n  if ([:len [/ip firewall filter find where chain=forward && dst-address-list=\$iplist]] = 0) do={\r\
    \n   /ip firewall filter add chain=forward action=accept dst-address-list=\$iplist place-before=0 \\ \r\
    \n    comment=(\"This rule blocks access to \" . \$iplist)\r\
    \n  }\r\
    \n }\r\
    \n}"
/tool graphing interface
add interface=bridge
add interface=lte1
/tool graphing queue
add
add
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
/tool netwatch
add down-script="log info \"Netwatch missed a ping to 8.8.8.8 - starting 5 minute timeout script\" ; /system script run watchdog\r\
    \n" host=8.8.8.8
[admin@AMS001-LADLE-FURNACE-BAGHOUSE-FANS-LTE] > 
