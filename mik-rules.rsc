/interface lte
set [ find ] allow-roaming=yes name=lte1
/interface ethernet
set [ find default-name=ether1 ] mac-address=2C:C8:1B:25:FB:3F
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
/interface lte apn
set [ find default=yes ] apn=axxess
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/ip pool
add name=dhcp ranges=192.168.88.10-192.168.88.254
add name=vpn ranges=192.168.89.2-192.168.89.255
/ip dhcp-server
add address-pool=dhcp disabled=no interface=ether1 name=defconf
/ppp profile
set *FFFFFFFE dns-server=192.168.88.1,1.1.1.1 local-address=192.168.89.1 remote-address=vpn
/user group
set full policy=local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,dude,tikapp
/ip firewall connection tracking
set enabled=yes
/ip neighbor discovery-settings
set discover-interface-list=LAN
/interface l2tp-server server
set enabled=yes ipsec-secret=fromtheotherside use-ipsec=yes
/interface list member
add comment=defconf interface=ether1 list=LAN
add comment=defconf interface=lte1 list=WAN
add list=LAN
/interface ovpn-server server
set auth=sha1 certificate=server cipher=aes256 enabled=yes require-client-certificate=yes
/interface pptp-server server
set enabled=yes
/interface sstp-server server
set default-profile=default-encryption enabled=yes
/ip address
add address=192.168.88.1/24 comment=defconf interface=ether1 network=192.168.88.0
/ip cloud
set ddns-enabled=yes
/ip dhcp-server network
add address=192.168.88.0/24 comment=defconf gateway=192.168.88.1
/ip dns
set allow-remote-requests=yes servers=1.1.1.1,8.8.8.8 verify-doh-cert=yes
/ip dns static
add address=192.168.88.1 comment=defconf name=router.lan
/ip firewall address-list
add address=192.168.88.0/24 list=IP_used_on_LAN
add address=37.48.118.94 comment=safezone list=safezone
add address=34.90.83.14 comment=safezone list=safezone
add address=105.23.225.106 comment=safezone list=safezone
/ip firewall filter
add action=accept chain=input comment="defconf: accept established,related,untracked" connection-state=established,related,untracked
add action=accept chain=input comment="defconf: accept new conns from safezone" connection-state=new src-address-list=safezone
add action=reject chain=input comment="defconf: drop invalid" connection-state=invalid reject-with=icmp-protocol-unreachable
add action=reject chain=input comment="TCP non SYN scan attack input" connection-state=new protocol=tcp reject-with=tcp-reset tcp-flags=!syn
add action=accept chain=input comment="defconf: accept ICMP" protocol=icmp
add action=accept chain=input comment="defconf: accept to local loopback (for CAPsMAN)" dst-address=127.0.0.1
add action=accept chain=input comment="defconf: accept to local VPN server" connection-state=new disabled=yes dst-port=1194 protocol=tcp
add action=reject chain=input comment="defconf: drop all not coming from LAN - TCP REJECT" in-interface-list=!LAN protocol=tcp reject-with=tcp-reset
add action=reject chain=input comment="defconf: drop all not coming from LAN - UDP REJECT" in-interface-list=!LAN protocol=udp reject-with=icmp-port-unreachable
add action=reject chain=input comment="defconf: drop all not coming from LAN" in-interface-list=!LAN reject-with=icmp-protocol-unreachable
add action=fasttrack-connection chain=forward comment="defconf: fasttrack" connection-state=established,related
add action=accept chain=forward comment="defconf: accept established,related, untracked" connection-state=established,related,untracked
add action=accept chain=forward comment="defconf: accept new conns from safezone" connection-state=new src-address-list=safezone
add action=reject chain=forward comment="defconf: drop invalid" connection-state=invalid reject-with=icmp-protocol-unreachable
add action=reject chain=forward comment="TCP non SYN scan attack forward" connection-state=new protocol=tcp reject-with=tcp-reset tcp-flags=!syn
add action=accept chain=forward comment="accept in ipsec policy" ipsec-policy=in,ipsec
add action=accept chain=forward comment="accept out ipsec policy" ipsec-policy=out,ipsec
add action=reject chain=forward comment="defconf: drop all from WAN not DSTNATed - TCP reset" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN protocol=tcp reject-with=tcp-reset
add action=reject chain=forward comment="defconf: drop all from WAN not DSTNATed - UDP reset" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN protocol=udp reject-with=icmp-port-unreachable
add action=reject chain=forward comment="defconf: drop all from WAN not DSTNATed" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN reject-with=icmp-protocol-unreachable
/ip firewall mangle
add action=mark-connection chain=prerouting comment="HiP conn mark for safezone RMM" dst-address=34.90.83.14 dst-port=443 new-connection-mark=conn-safezone-rmm passthrough=yes protocol=tcp src-address-list=IP_used_on_LAN
add action=fasttrack-connection chain=prerouting comment="HiP fasttrack rmm conns with HiP" connection-mark=conn-safezone-rmm
add action=set-priority chain=prerouting comment="HiP conn-safezone-rmm DCSP" connection-mark=conn-safezone-rmm new-priority=from-dscp-high-3-bits passthrough=yes
add action=mark-connection chain=prerouting comment="HiP conn mark for safezone SSH" dst-port=22 new-connection-mark=conn-safezone-ssh passthrough=yes protocol=tcp src-address-list=safezone
add action=fasttrack-connection chain=prerouting comment="HiP fasttrack ssh conns with HiP" connection-mark=conn-safezone-ssh src-address-list=safezone
add action=set-priority chain=prerouting comment="HiP conn-safezone-ssh DCSP" connection-mark=conn-safezone-ssh new-priority=from-dscp-high-3-bits passthrough=yes src-address-list=safezone
add action=mark-connection chain=prerouting comment="HiP conn mark for safezone WINBOX" dst-port=8291 new-connection-mark=conn-safezone-winbox passthrough=yes protocol=tcp src-address-list=safezone
add action=fasttrack-connection chain=prerouting comment="HiP fasttrack winbox conns with HiP" connection-mark=conn-safezone-winbox src-address-list=safezone
add action=set-priority chain=prerouting comment="HiP conn-safezone-winbox DCSP" connection-mark=conn-safezone-winbox new-priority=from-dscp-high-3-bits passthrough=yes src-address-list=safezone
add action=mark-connection chain=prerouting comment="HiP conn mark for safezone MQTT/TLS/SSL" dst-address-type=unicast dst-port=8883 new-connection-mark=conn-safezone-mqtt-secure passthrough=yes protocol=tcp src-address-type=local
add action=fasttrack-connection chain=prerouting comment="HiP fasttrack mqtt conns with HiP" connection-mark=conn-safezone-mqtt-secure
add action=set-priority chain=prerouting comment="HiP conn-safezone-mqtt-secure DCSP" connection-mark=conn-safezone-mqtt-secure new-priority=from-dscp-high-3-bits passthrough=yes
add action=mark-connection chain=prerouting comment="HiP conn mark for safezone icmp" new-connection-mark=conn-safezone-icmp passthrough=yes protocol=icmp src-address-list=safezone
add action=fasttrack-connection chain=prerouting comment="HiP fasttrack icmp conns with HiP" connection-mark=conn-safezone-icmp src-address-list=safezone
add action=set-priority chain=prerouting comment="HiP conn-safezone-icmp DCSP" connection-mark=conn-safezone-icmp new-priority=from-dscp-high-3-bits passthrough=yes src-address-list=safezone
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" ipsec-policy=out,none out-interface-list=WAN
add action=dst-nat chain=dstnat comment="SSH to Pi from safezone" dst-port=22 in-interface=lte1 protocol=tcp src-address-list=safezone to-addresses=192.168.88.200 to-ports=22
add action=dst-nat chain=dstnat comment="WINBOX to MikroTik from safezone" dst-port=8291 in-interface=lte1 protocol=tcp src-address-list=safezone to-addresses=192.168.88.1 to-ports=8291
add action=masquerade chain=srcnat comment="masq. vpn traffic" disabled=yes src-address=192.168.89.0/24
/ip firewall raw
add action=drop chain=prerouting comment="TCP invalid combination of flags attack (7 rules)" protocol=tcp tcp-flags=!fin,!syn,!rst,!ack
add action=drop chain=prerouting protocol=tcp tcp-flags=fin,syn
add action=drop chain=prerouting protocol=tcp tcp-flags=fin,rst
add action=drop chain=prerouting protocol=tcp tcp-flags=fin,!ack
add action=drop chain=prerouting protocol=tcp tcp-flags=fin,urg
add action=drop chain=prerouting protocol=tcp tcp-flags=syn,rst
add action=drop chain=prerouting protocol=tcp tcp-flags=rst,urg
add action=drop chain=prerouting comment="TCP Port 0 attack (2 rules)" protocol=tcp src-port=0
add action=drop chain=prerouting dst-port=0 protocol=tcp
add action=drop chain=prerouting comment="UDP Port 0 attack (2 rules)" protocol=udp src-port=0
add action=drop chain=prerouting dst-port=0 protocol=udp
add action=drop chain=prerouting comment="IP Spoofing protection from WAN" in-interface-list=WAN src-address-list=IP_used_on_LAN
add action=drop chain=prerouting comment="IP Spoofing protection from LAN" dst-address=!255.255.255.255 in-interface-list=LAN src-address=!0.0.0.0 src-address-list=!IP_used_on_LAN
add action=accept chain=prerouting comment="Accept used protocols and drop all others" protocol=icmp
add action=accept chain=prerouting protocol=igmp
add action=accept chain=prerouting protocol=tcp
add action=accept chain=prerouting protocol=udp
add action=accept chain=prerouting disabled=yes protocol=gre
add action=accept chain=prerouting disabled=yes protocol=l2tp
add action=log chain=prerouting log=yes log-prefix="Not TCP protocol" protocol=!tcp
add action=drop chain=prerouting comment="Unused protocol protection" protocol=!tcp
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
set www address=192.168.88.0/24
set ssh disabled=yes
set api disabled=yes
set api-ssl disabled=yes
/ppp secret
add local-address=192.168.88.1 name=vpn password=fromtheotherside remote-address=192.168.88.150 service=ovpn
/system clock
set time-zone-name=Africa/Johannesburg
/system identity
set name=AMS001-COOLING-PUMP-LTE-01
/system routerboard settings
set auto-upgrade=yes cpu-frequency=750MHz
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
[admin@AMS001-COOLING-PUMP-LTE-01] > 
