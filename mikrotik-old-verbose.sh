# feb/04/2022 15:13:24 by RouterOS 6.49.2
# model = RBLHGR
/interface bridge
add admin-mac=48:8F:5A:76:1A:C4 ageing-time=5m arp=enabled arp-timeout=auto auto-mac=no comment=defconf dhcp-snooping=no disabled=no fast-forward=yes forward-delay=15s igmp-snooping=no max-message-age=20s mtu=auto name=bridge priority=0x8000 \
    protocol-mode=rstp transmit-hold-count=6 vlan-filtering=no
/interface ethernet
set [ find default-name=ether1 ] advertise=10M-half,10M-full,100M-half,100M-full arp=enabled arp-timeout=auto auto-negotiation=yes bandwidth=unlimited/unlimited disabled=no full-duplex=yes l2mtu=1598 loop-protect=default loop-protect-disable-time=5m \
    loop-protect-send-interval=5s mac-address=08:55:31:18:B5:35 mtu=1500 name=ether1 orig-mac-address=08:55:31:18:B5:35 rx-flow-control=off speed=100Mbps tx-flow-control=off
/interface l2tp-server
add disabled=yes name=l2tp-in-energydrive user=tim
/interface pptp-server
add disabled=yes name=pptp-energydrive user=energydrive
add disabled=yes name=pptp-tim user=tim
/queue interface
set bridge queue=no-queue
set l2tp-in-energydrive queue=no-queue
set pptp-energydrive queue=no-queue
set pptp-tim queue=no-queue
/interface ethernet switch
set 0 cpu-flow-control=yes mirror-source=none mirror-target=none name=switch1
/interface ethernet switch port
set 0 default-vlan-id=0 vlan-header=leave-as-is vlan-mode=disabled
set 1 default-vlan-id=0 vlan-header=leave-as-is vlan-mode=disabled
/interface list
set [ find name=all ] comment="contains all interfaces" exclude="" include="" name=all
set [ find name=none ] comment="contains no interfaces" exclude="" include="" name=none
set [ find name=dynamic ] comment="contains dynamic interfaces" exclude="" include="" name=dynamic
set [ find name=static ] comment="contains static interfaces" exclude="" include="" name=static
add comment=defconf exclude="" include="" name=WAN
add comment=defconf exclude="" include="" name=LAN
/interface lte apn
set [ find default=yes ] add-default-route=yes apn=internet default-route-distance=2 name=default use-peer-dns=yes
add add-default-route=yes apn=axxess default-route-distance=1 use-peer-dns=yes
add add-default-route=yes apn=myMTN authentication=chap default-route-distance=2 use-peer-dns=yes user=mtn
/interface lte
set [ find ] allow-roaming=yes apn-profiles=axxess !band disabled=no mtu=1480 name=lte1 network-mode=gsm,3g,lte
/queue interface
set lte1 queue=no-queue
/interface wireless security-profiles
set [ find default=yes ] authentication-types="" disable-pmkid=no eap-methods=passthrough group-ciphers=aes-ccm group-key-update=5m interim-update=0s management-protection=disabled management-protection-key="" mode=none mschapv2-password="" \
    mschapv2-username="" name=default radius-called-format=mac:ssid radius-eap-accounting=no radius-mac-accounting=no radius-mac-authentication=no radius-mac-caching=disabled radius-mac-format=XX:XX:XX:XX:XX:XX radius-mac-mode=as-username \
    static-algo-0=none static-algo-1=none static-algo-2=none static-algo-3=none static-key-0="" static-key-1="" static-key-2="" static-key-3="" static-sta-private-algo=none static-sta-private-key="" static-transmit-key=key-0 supplicant-identity=\
    MikroTik tls-certificate=none tls-mode=no-certificates unicast-ciphers=aes-ccm wpa-pre-shared-key="" wpa2-pre-shared-key=""
/ip dhcp-client option
set clientid_duid code=61 name=clientid_duid value="0xff\$(CLIENT_DUID)"
set clientid code=61 name=clientid value="0x01\$(CLIENT_MAC)"
set hostname code=12 name=hostname value="\$(HOSTNAME)"
/ip hotspot profile
set [ find default=yes ] dns-name="" hotspot-address=0.0.0.0 html-directory=flash/hotspot html-directory-override="" http-cookie-lifetime=3d http-proxy=0.0.0.0:0 login-by=cookie,http-chap name=default rate-limit="" smtp-server=0.0.0.0 \
    split-user-domain=no use-radius=no
/ip hotspot user profile
set [ find default=yes ] add-mac-cookie=yes address-list="" idle-timeout=none !insert-queue-before keepalive-timeout=2m mac-cookie-timeout=3d name=default !parent-queue !queue-type shared-users=1 status-autorefresh=1m transparent-proxy=no
/ip ipsec mode-config
set [ find default=yes ] name=request-only responder=no use-responder-dns=exclusively
/ip ipsec policy group
set [ find default=yes ] name=default
/ip ipsec profile
set [ find default=yes ] dh-group=modp1024 dpd-interval=disable-dpd enc-algorithm=aes-128 hash-algorithm=sha1 lifetime=1d name=default nat-traversal=yes proposal-check=obey
/ip ipsec proposal
set [ find default=yes ] auth-algorithms=sha256,sha1 disabled=no enc-algorithms=aes-256-cbc,aes-128-cbc lifetime=0s name=default pfs-group=modp1024
/ip pool
add name=dhcp ranges=192.168.88.10-192.168.88.254
add name=PPTP-Pool ranges=192.168.99.10-192.168.99.200
/ip dhcp-server
add address-pool=dhcp authoritative=yes disabled=no interface=bridge lease-script="" lease-time=10m name=defconf use-radius=no
/ppp profile
set *0 address-list="" !bridge !bridge-horizon bridge-learning=default !bridge-path-cost !bridge-port-priority change-tcp-mss=yes !dns-server !idle-timeout !incoming-filter !insert-queue-before !interface-list !local-address name=default on-down="" \
    on-up="" only-one=default !outgoing-filter !parent-queue !queue-type !rate-limit !remote-address !session-timeout use-compression=default use-encryption=default use-mpls=default use-upnp=default !wins-server
add address-list="" bridge=bridge !bridge-horizon bridge-learning=default !bridge-path-cost !bridge-port-priority change-tcp-mss=default !dns-server !idle-timeout !incoming-filter !insert-queue-before !interface-list local-address=10.6.0.1 name=\
    energydrive on-down="" on-up="" only-one=default !outgoing-filter !parent-queue !queue-type !rate-limit remote-address=dhcp !session-timeout use-compression=no use-encryption=default use-mpls=default use-upnp=default !wins-server
add address-list="" !bridge !bridge-horizon bridge-learning=default !bridge-path-cost !bridge-port-priority change-tcp-mss=yes dns-server=8.8.8.8,8.8.4.4 !idle-timeout !incoming-filter !insert-queue-before !interface-list local-address=PPTP-Pool \
    name=PPTP-Profile on-down="" on-up="" only-one=yes !outgoing-filter !parent-queue !queue-type !rate-limit remote-address=PPTP-Pool !session-timeout use-compression=default use-encryption=yes use-mpls=default use-upnp=default !wins-server
set *FFFFFFFE address-list="" !bridge !bridge-horizon bridge-learning=default !bridge-path-cost !bridge-port-priority change-tcp-mss=yes !dns-server !idle-timeout !incoming-filter !insert-queue-before !interface-list !local-address name=\
    default-encryption on-down="" on-up="" only-one=default !outgoing-filter !parent-queue !queue-type !rate-limit !remote-address !session-timeout use-compression=default use-encryption=yes use-mpls=default use-upnp=default !wins-server
/queue type
set 0 kind=sfq name=default sfq-allot=1514 sfq-perturb=5
set 1 kind=pfifo name=ethernet-default pfifo-limit=50
set 2 kind=sfq name=wireless-default sfq-allot=1514 sfq-perturb=5
set 3 kind=red name=synchronous-default red-avg-packet=1000 red-burst=20 red-limit=60 red-max-threshold=50 red-min-threshold=10
set 4 kind=sfq name=hotspot-default sfq-allot=1514 sfq-perturb=5
add kind=red name=redCustom red-avg-packet=1514 red-burst=20 red-limit=60 red-max-threshold=50 red-min-threshold=10
set 6 kind=pcq name=pcq-upload-default pcq-burst-rate=0 pcq-burst-threshold=0 pcq-burst-time=10s pcq-classifier=src-address pcq-dst-address-mask=32 pcq-dst-address6-mask=128 pcq-limit=50KiB pcq-rate=0 pcq-src-address-mask=32 pcq-src-address6-mask=\
    128 pcq-total-limit=2000KiB
set 7 kind=pcq name=pcq-download-default pcq-burst-rate=0 pcq-burst-threshold=0 pcq-burst-time=10s pcq-classifier=dst-address pcq-dst-address-mask=32 pcq-dst-address6-mask=128 pcq-limit=50KiB pcq-rate=0 pcq-src-address-mask=32 pcq-src-address6-mask=\
    128 pcq-total-limit=2000KiB
set 8 kind=none name=only-hardware-queue
set 9 kind=mq-pfifo mq-pfifo-limit=50 name=multi-queue-ethernet-default
set 10 kind=pfifo name=default-small pfifo-limit=10
/queue interface
set ether1 queue=only-hardware-queue
/queue tree
add bucket-size=0.01 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=1M name=DOWN packet-mark="" parent=bridge priority=8 queue=redCustom
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="1. VOIP" packet-mark=VOIP parent=DOWN priority=1 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="2. DNS" packet-mark=DNS parent=DOWN priority=2 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="3. ACK" packet-mark=ACK parent=DOWN priority=3 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="4. UDP" packet-mark=UDP parent=DOWN priority=3 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="5. ICMP" packet-mark=ICMP parent=DOWN priority=4 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="6. HTTP" packet-mark=HTTP parent=DOWN priority=5 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="7. HTTP_BIG" packet-mark=HTTP_BIG parent=DOWN priority=6 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="8. QUIC" packet-mark=QUIC parent=DOWN priority=7 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="9. OTHER" packet-mark=OTHER parent=DOWN priority=8 queue=redCustom
add bucket-size=0.01 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=1M name=UP packet-mark="" parent=lte1 priority=8 queue=redCustom
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="1. VOIP_" packet-mark=VOIP parent=UP priority=1 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="2. DNS_" packet-mark=DNS parent=UP priority=2 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="3. ACK_" packet-mark=ACK parent=UP priority=3 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="4. UDP_" packet-mark=UDP parent=UP priority=3 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="5. ICMP_" packet-mark=ICMP parent=UP priority=4 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="6. HTTP_" packet-mark=HTTP parent=UP priority=5 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="7. HTTP_BIG_" packet-mark=HTTP_BIG parent=UP priority=6 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="8. QUIC_" packet-mark=QUIC parent=UP priority=7 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="9. OTHER_" packet-mark=OTHER parent=UP priority=8 queue=redCustom
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name="0. IOT_CORE_" packet-mark=Google_IoT_Core-Packet parent=UP priority=1 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=yes limit-at=0 max-limit=0 name="10. no-mark_" packet-mark=no-mark parent=UP priority=8 queue=default
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=yes limit-at=0 max-limit=0 name="10. no-mark" packet-mark=no-mark parent=DOWN priority=8 queue=redCustom
add bucket-size=0.1 burst-limit=0 burst-threshold=0 burst-time=0s disabled=no limit-at=0 max-limit=0 name=SSH packet-mark=SSH parent=DOWN priority=1 queue=default
/routing bgp instance
set default as=65530 client-to-client-reflection=yes !cluster-id !confederation disabled=no ignore-as-path-len=no name=default out-filter="" redistribute-connected=no redistribute-ospf=no redistribute-other-bgp=no redistribute-rip=no \
    redistribute-static=no router-id=0.0.0.0 routing-table=""
/routing ospf instance
set [ find default=yes ] disabled=no distribute-default=never !domain-id !domain-tag in-filter=ospf-in metric-bgp=auto metric-connected=20 metric-default=1 metric-other-ospf=auto metric-rip=20 metric-static=20 !mpls-te-area !mpls-te-router-id name=\
    default out-filter=ospf-out redistribute-bgp=no redistribute-connected=no redistribute-other-ospf=no redistribute-rip=no redistribute-static=no router-id=0.0.0.0 !routing-table !use-dn
/routing ospf area
set [ find default=yes ] area-id=0.0.0.0 disabled=no instance=default name=backbone type=default
/snmp community
set [ find default=yes ] addresses=::/0 authentication-password="" authentication-protocol=MD5 disabled=no encryption-password="" encryption-protocol=DES name=public read-access=yes security=none write-access=no
/system logging action
set 0 memory-lines=1000 memory-stop-on-full=no name=memory target=memory
set 1 disk-file-count=2 disk-file-name=flash/log disk-lines-per-file=1000 disk-stop-on-full=no name=disk target=disk
set 2 name=echo remember=yes target=echo
set 3 bsd-syslog=no name=remote remote=0.0.0.0 remote-port=514 src-address=0.0.0.0 syslog-facility=daemon syslog-severity=auto syslog-time-format=bsd-syslog target=remote
/user group
set read name=read policy=local,telnet,ssh,reboot,read,test,winbox,password,web,sniff,sensitive,api,romon,tikapp,!ftp,!write,!policy,!dude skin=default
set write name=write policy=local,telnet,ssh,reboot,read,write,test,winbox,password,web,sniff,sensitive,api,romon,tikapp,!ftp,!policy,!dude skin=default
set full name=full policy=local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,dude,tikapp skin=default
/caps-man aaa
set called-format=mac:ssid interim-update=disabled mac-caching=disabled mac-format=XX:XX:XX:XX:XX:XX mac-mode=as-username
/caps-man manager
set ca-certificate=none certificate=none enabled=no package-path="" require-peer-certificate=no upgrade-policy=none
/caps-man manager interface
set [ find default=yes ] disabled=no forbid=no interface=all
/certificate settings
set crl-download=no crl-store=ram crl-use=no
/interface bridge port
add auto-isolate=no bpdu-guard=no bridge=bridge broadcast-flood=yes comment=defconf disabled=no edge=auto fast-leave=no frame-types=admit-all horizon=none hw=yes ingress-filtering=no interface=ether1 internal-path-cost=10 learn=auto \
    multicast-router=temporary-query path-cost=10 point-to-point=auto priority=0x80 pvid=1 restricted-role=no restricted-tcn=no tag-stacking=no trusted=no unknown-multicast-flood=yes unknown-unicast-flood=yes
add auto-isolate=no bpdu-guard=no bridge=bridge broadcast-flood=yes comment=defconf disabled=no edge=auto fast-leave=no frame-types=admit-all horizon=none ingress-filtering=no interface=*2 internal-path-cost=10 learn=auto multicast-router=\
    temporary-query path-cost=10 point-to-point=auto priority=0x80 pvid=1 restricted-role=no restricted-tcn=no tag-stacking=no trusted=no unknown-multicast-flood=yes unknown-unicast-flood=yes
/interface bridge port-controller
# disabled
set bridge=none cascade-ports="" switch=none
/interface bridge port-extender
# disabled
set control-ports="" excluded-ports="" switch=none
/interface bridge settings
set allow-fast-path=yes use-ip-firewall=no use-ip-firewall-for-pppoe=no use-ip-firewall-for-vlan=no
/ip firewall connection tracking
set enabled=auto generic-timeout=10m icmp-timeout=10s loose-tcp-tracking=yes tcp-close-timeout=10s tcp-close-wait-timeout=10s tcp-established-timeout=1d tcp-fin-wait-timeout=10s tcp-last-ack-timeout=10s tcp-max-retrans-timeout=5m \
    tcp-syn-received-timeout=5s tcp-syn-sent-timeout=5s tcp-time-wait-timeout=10s tcp-unacked-timeout=5m udp-stream-timeout=3m udp-timeout=10s
/ip neighbor discovery-settings
set discover-interface-list=LAN lldp-med-net-policy-vlan=disabled protocol=cdp,lldp,mndp
/ip settings
set accept-redirects=no accept-source-route=no allow-fast-path=yes arp-timeout=30s icmp-rate-limit=10 icmp-rate-mask=0x1818 ip-forward=yes max-neighbor-entries=8192 route-cache=yes rp-filter=no secure-redirects=yes send-redirects=yes tcp-syncookies=\
    yes
/interface detect-internet
set detect-interface-list=none internet-interface-list=none lan-interface-list=none wan-interface-list=none
/interface l2tp-server server
set allow-fast-path=no authentication=pap,chap,mschap1,mschap2 caller-id-type=ip-address default-profile=energydrive enabled=yes ipsec-secret=KdeKveZJbc0YR19uYUWMH7rZlkP6TSPC6qOtZ2wXKk3 keepalive-timeout=30 max-mru=1450 max-mtu=1450 max-sessions=\
    unlimited mrru=disabled one-session-per-host=no use-ipsec=yes
/interface list member
add comment=defconf disabled=no interface=bridge list=LAN
add comment=defconf disabled=no interface=lte1 list=WAN
/interface ovpn-server server
set auth=sha1,md5 cipher=blowfish128,aes128 default-profile=default enabled=no keepalive-timeout=60 mac-address=FE:7A:A8:4C:9C:AA max-mtu=1500 mode=ip netmask=24 port=1194 require-client-certificate=no
/interface pptp-server server
set authentication=chap,mschap1,mschap2 default-profile=PPTP-Profile enabled=yes keepalive-timeout=30 max-mru=1450 max-mtu=1450 mrru=disabled
/interface sstp-server server
set authentication=pap,chap,mschap1,mschap2 certificate=none default-profile=default enabled=no force-aes=no keepalive-timeout=60 max-mru=1500 max-mtu=1500 mrru=disabled pfs=no port=443 tls-version=any verify-client-certificate=no
/interface wireless align
set active-mode=yes audio-max=-20 audio-min=-100 audio-monitor=00:00:00:00:00:00 filter-mac=00:00:00:00:00:00 frame-size=300 frames-per-second=25 receive-all=no ssid-all=no
/interface wireless cap
set bridge=none caps-man-addresses="" caps-man-certificate-common-names="" caps-man-names="" certificate=none discovery-interfaces="" enabled=no interfaces="" lock-to-caps-man=no static-virtual=no
/interface wireless sniffer
set channel-time=200ms file-limit=10 file-name="" memory-limit=10 multiple-channels=no only-headers=no receive-errors=no streaming-enabled=no streaming-max-rate=0 streaming-server=0.0.0.0
/interface wireless snooper
set channel-time=200ms multiple-channels=yes receive-errors=no
/ip accounting
set account-local-traffic=no enabled=no threshold=256
/ip accounting web-access
set accessible-via-web=no address=0.0.0.0/0
/ip address
add address=192.168.88.1/24 comment=defconf disabled=no interface=ether1 network=192.168.88.0
/ip cloud
set ddns-enabled=yes ddns-update-interval=1m update-time=yes
/ip cloud advanced
set use-local-address=no
/ip dhcp-server config
set accounting=yes interim-update=0s store-leases-disk=5m
/ip dhcp-server network
add address=192.168.88.0/24 caps-manager="" comment=defconf dhcp-option="" dns-server="" gateway=192.168.88.1 ntp-server="" wins-server=""
/ip dns
set allow-remote-requests=yes cache-max-ttl=1w cache-size=2048KiB max-concurrent-queries=100 max-concurrent-tcp-sessions=20 max-udp-packet-size=4096 query-server-timeout=2s query-total-timeout=10s servers=1.1.1.1,1.0.0.1 use-doh-server="" \
    verify-doh-cert=no
/ip dns static
add address=192.168.88.1 comment=defconf disabled=no name=router.lan ttl=1d
/ip firewall address-list
add address=192.168.88.200 comment="RPi 4" disabled=no list=support
add address=192.168.88.201 comment="WAP (Wifi)" disabled=no list=support
add address=192.168.88.202 comment="Site Users (202 - 210)" disabled=no list=support
add address=165.255.239.93 comment="Permitted Public IP's" disabled=no list=support_external
add address=37.48.118.94 disabled=no list=support_external
add address=105.23.225.106 disabled=no list=support_external
add address=192.168.88.203 disabled=no list=support
add address=192.168.88.204 disabled=no list=support
add address=192.168.88.205 disabled=no list=support
add address=192.168.88.206 disabled=no list=support
add address=192.168.88.207 disabled=no list=support
add address=192.168.88.208 disabled=no list=support
add address=192.168.88.209 disabled=no list=support
add address=192.168.88.210 disabled=no list=support
add address=192.168.99.0/24 comment="VPN users" disabled=no list=support
add address=192.168.88.1 comment=Gwy_IP disabled=no list=support
add address=41.78.247.35 disabled=no list=support_external
add address=165.255.239.57 disabled=no list=support_external
add address=0.0.0.0/8 comment="Self-Identification [RFC 3330]" disabled=no list=bogons
add address=10.0.0.0/8 comment="Private[RFC 1918] - CLASS A # Check if you need this subnet before enable it" disabled=no list=bogons
add address=127.0.0.0/8 comment="Loopback [RFC 3330]" disabled=no list=bogons
add address=169.254.0.0/16 comment="Link Local [RFC 3330]" disabled=no list=bogons
add address=172.16.0.0/12 comment="Private[RFC 1918] - CLASS B # Check if you need this subnet before enable it" disabled=no list=bogons
add address=192.168.0.0/16 comment="Private[RFC 1918] - CLASS C # Check if you need this subnet before enable it" disabled=yes list=bogons
add address=192.0.2.0/24 comment="Reserved - IANA - TestNet1" disabled=no list=bogons
add address=192.88.99.0/24 comment="6to4 Relay Anycast [RFC 3068]" disabled=no list=bogons
add address=198.18.0.0/15 comment="NIDB Testing" disabled=no list=bogons
add address=198.51.100.0/24 comment="Reserved - IANA - TestNet2" disabled=no list=bogons
add address=203.0.113.0/24 comment="Reserved - IANA - TestNet3" disabled=no list=bogons
add address=224.0.0.0/4 comment="MC, Class D, IANA # Check if you need this subnet before enable it" disabled=no list=bogons
add address=192.0.0.0/24 comment="Reserved - IANA - TestNet1" disabled=no list=bogons
add address=0.0.0.0/8 comment=RFC6890 disabled=no list=NotPublic
add address=10.0.0.0/8 comment=RFC6890 disabled=no list=NotPublic
add address=100.64.0.0/10 comment=RFC6890 disabled=no list=NotPublic
add address=127.0.0.0/8 comment=RFC6890 disabled=no list=NotPublic
add address=169.254.0.0/16 comment=RFC6890 disabled=no list=NotPublic
add address=172.16.0.0/12 comment=RFC6890 disabled=no list=NotPublic
add address=192.0.0.0/24 comment=RFC6890 disabled=no list=NotPublic
add address=192.0.2.0/24 comment=RFC6890 disabled=no list=NotPublic
add address=192.168.0.0/16 comment=RFC6890 disabled=no list=NotPublic
add address=192.88.99.0/24 comment=RFC3068 disabled=no list=NotPublic
add address=198.18.0.0/15 comment=RFC6890 disabled=no list=NotPublic
add address=198.51.100.0/24 comment=RFC6890 disabled=no list=NotPublic
add address=203.0.113.0/24 comment=RFC6890 disabled=no list=NotPublic
add address=224.0.0.0/4 comment=RFC4601 disabled=no list=NotPublic
add address=240.0.0.0/4 comment=RFC6890 disabled=no list=NotPublic
add address=192.168.88.1-192.168.88.254 disabled=no list=allowed_to_router
add address=37.48.118.94 disabled=no list=allowed_to_router
add address=165.255.239.57 disabled=no list=allowed_to_router
add address=105.23.225.106 disabled=no list=allowed_to_router
add address=127.0.0.0/8 comment="defconf: RFC6890" disabled=no list=bad_ipv4
add address=192.0.0.0/24 comment="defconf: RFC6890" disabled=no list=bad_ipv4
add address=192.0.2.0/24 comment="defconf: RFC6890 documentation" disabled=no list=bad_ipv4
add address=198.51.100.0/24 comment="defconf: RFC6890 documentation" disabled=no list=bad_ipv4
add address=203.0.113.0/24 comment="defconf: RFC6890 documentation" disabled=no list=bad_ipv4
add address=240.0.0.0/4 comment="defconf: RFC6890 reserved" disabled=no list=bad_ipv4
add address=0.0.0.0/8 comment="defconf: RFC6890" disabled=no list=not_global_ipv4
add address=10.0.0.0/8 comment="defconf: RFC6890" disabled=no list=not_global_ipv4
add address=100.64.0.0/10 comment="defconf: RFC6890" disabled=no list=not_global_ipv4
add address=169.254.0.0/16 comment="defconf: RFC6890" disabled=no list=not_global_ipv4
add address=172.16.0.0/12 comment="defconf: RFC6890" disabled=no list=not_global_ipv4
add address=192.0.0.0/29 comment="defconf: RFC6890" disabled=no list=not_global_ipv4
add address=192.168.0.0/16 comment="defconf: RFC6890" disabled=no list=not_global_ipv4
add address=198.18.0.0/15 comment="defconf: RFC6890 benchmark" disabled=no list=not_global_ipv4
add address=255.255.255.255 comment="defconf: RFC6890" disabled=no list=not_global_ipv4
add address=224.0.0.0/4 comment="defconf: multicast" disabled=no list=bad_src_ipv4
add address=255.255.255.255 comment="defconf: RFC6890" disabled=no list=bad_src_ipv4
add address=0.0.0.0/8 comment="defconf: RFC6890" disabled=no list=bad_dst_ipv4
add address=224.0.0.0/4 comment="defconf: RFC6890" disabled=no list=bad_dst_ipv4
add address=0.0.0.0/8 comment="defconf: RFC6890" disabled=no list=no_forward_ipv4
add address=169.254.0.0/16 comment="defconf: RFC6890" disabled=no list=no_forward_ipv4
add address=224.0.0.0/4 comment="defconf: multicast" disabled=no list=no_forward_ipv4
add address=255.255.255.255 comment="defconf: RFC6890" disabled=no list=no_forward_ipv4
add address=34.90.83.14 disabled=no list=allowed_to_router
add address=169.1.1.2 comment="AXXESS upstream DNS servers" disabled=no list=public_DNS
add address=169.1.1.4 comment="AXXESS upstream DNS servers" disabled=no list=public_DNS
add address=1.1.1.1 comment="AXXESS upstream DNS servers" disabled=no list=public_DNS
add address=1.0.0.3 comment="AXXESS upstream DNS servers" disabled=no list=public_DNS
add address=172.217.170.78 disabled=no list=youtube
add address=172.217.170.46 disabled=no list=youtube
add address=102.132.100.35 disabled=no list=facebook
add address=102.132.100.60 disabled=no list=whatsapp
add address=149.154.167.99 disabled=no list=telegram
add address=8.8.8.8 comment="AXXESS upstream DNS servers" disabled=no list=public_DNS
add address=8.8.4.4 comment="AXXESS upstream DNS servers" disabled=no list=public_DNS
add address=1.1.1.3 comment="AXXESS upstream DNS servers" disabled=no list=public_DNS
add address=172.217.170.42 disabled=no list=googleapis
add address=172.217.170.106 disabled=no list=googleapis
add address=172.217.170.74 disabled=no list=googleapis
add address=216.58.223.138 disabled=no list=googleapis
/ip firewall filter
add action=passthrough chain=output comment="special dummy rule to show fasttrack counters" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp \
    !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit \
    log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=passthrough chain=input comment="special dummy rule to show fasttrack counters" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp \
    !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit \
    log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=forward comment="This rule blocks access to facebook" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=yes !dscp !dst-address \
    dst-address-list=facebook !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes \
    log-prefix="[Block] facebook" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="### DO NOT DISABLE-Address-list of IP's that are allowed to access the router" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type \
    !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark \
    !routing-table !src-address src-address-list=allowed_to_router !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="### DO NOT DISABLE-Address-list of Permitted Public DNS resolvers " !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content \
    disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy !ipv4-options \
    !layer7-protocol !limit log=yes log-prefix="[ACCEPT DNS] :: PERMITTED RESOLVER-LIST : " !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol \
    !psd !random !routing-mark !routing-table !src-address src-address-list=public_DNS !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=forward comment="### DEBUG forwarding DNS not required - Address-list of Permitted Public DNS resolvers " !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state \
    !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random \
    !routing-mark !routing-table !src-address src-address-list=public_DNS !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="### DO NOT DISABLE-Address-list of IP's that are allowed to access the router" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type \
    !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=bridge !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark \
    !routing-table !src-address src-address-list=allowed_to_router !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=fasttrack-connection chain=input comment="Services -- Counters --  access to the winbox" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no \
    !dscp !dst-address !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol \
    !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="Services -- Counters -- External access to the winbox " !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no \
    !dscp !dst-address !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy !ipv4-options \
    !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !routing-mark \
    !routing-table !src-address src-address-list=support_external !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="Services -- Counters -- Local access to the winbox " !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp \
    !dst-address !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=bridge !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol \
    !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="defconf: accept established,related,untracked after RAW" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=established,related,untracked \
    !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="Accept established and related packets" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=established,related !connection-type !content disabled=no \
    !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol \
    !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="Accept all connections from local network" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=bridge !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=input comment="defconf: accept ICMP after RAW" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Drop invalid packets" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=invalid !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Drop all packets which are not destined to routes IP address" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no \
    !dscp !dst-address !dst-address-list dst-address-type=!local !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options \
    !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Drop all packets which does not have unicast source IP address" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no \
    !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol \
    !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list src-address-type=!unicast !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Drop all packets from public internet which should not exist in public network" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type \
    !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark \
    !routing-table !src-address src-address-list=NotPublic !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=jump chain=input comment="Jump for icmp input flow" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options jump-target=ICMP !layer7-protocol !limit log=no \
    log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Block all access to the winbox - except to support list # DO NOT ENABLE THIS RULE BEFORE ADD YOUR SUBNET IN THE SUPPORT ADDRESS LIST" !connection-bytes !connection-limit !connection-mark !connection-nat-state \
    !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface \
    !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier \
    !port !priority protocol=tcp !psd !random !routing-mark !routing-table !src-address src-address-list=!allowed_to_router !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Block all access to the winbox - except to support list # DO NOT ENABLE THIS RULE BEFORE ADD YOUR SUBNET IN THE SUPPORT ADDRESS LIST" !connection-bytes !connection-limit !connection-mark !connection-nat-state \
    !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface \
    !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier \
    !port !priority protocol=tcp !psd !random !routing-mark !routing-table !src-address src-address-list=!support_external !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=add-src-to-address-list address-list=Syn_Flooder address-list-timeout=1w chain=input comment="Add Syn Flood IP to the list" !connection-bytes connection-limit=30,32 !connection-mark !connection-nat-state !connection-rate !connection-state \
    !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=tcp !psd \
    !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port tcp-flags=syn !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Drop to syn flood list" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address src-address-list=Syn_Flooder \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=add-src-to-address-list address-list=Port_Scanner address-list-timeout=1w chain=input comment="Port Scanner Detect" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state \
    !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=tcp psd=\
    21,3s,3,1 !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Drop to port scan list" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address src-address-list=Port_Scanner \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=input comment="Default Policy" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes log-prefix=\
    "[INPUT-BLOCKED] :: " !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=add-dst-to-address-list address-list=Facebook address-list-timeout=4d chain=forward comment=Google_IoT_Core !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type \
    content=cloudiotdevice.googleapis.com disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority \
    !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=add-dst-to-address-list address-list=Facebook address-list-timeout=4d chain=forward comment=Google_IoT_Core !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type \
    content=.googleapis.com disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=fasttrack-connection chain=forward comment="This rule blocks access to googleapis" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp \
    !dst-address dst-address-list=googleapis !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol \
    !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=forward comment="This rule blocks access to googleapis" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    dst-address-list=googleapis !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=\
    no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=fasttrack-connection chain=forward comment="defconf: fasttrack established and related packets" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=established,related \
    !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=forward comment="Accept established and related packets" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=established,related,untracked !connection-type !content \
    disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options \
    !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=forward comment="Drop invalid packets" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=invalid !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=forward comment="Drop new connections from internet which are not dst-natted" !connection-bytes !connection-limit !connection-mark connection-nat-state=!dstnat !connection-rate connection-state=new !connection-type !content \
    disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy !ipv4-options \
    !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=forward comment="Drop all packets from local network to internet which should not exist in public network" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state \
    !connection-type !content disabled=no !dscp !dst-address dst-address-list=NotPublic !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=bridge !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority \
    !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=forward comment="Drop new connections from internet which are not dst-natted" !connection-bytes !connection-limit !connection-mark connection-nat-state=!dstnat !connection-rate connection-state=new !connection-type !content \
    disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy !ipv4-options \
    !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=forward comment="Allow established, related connections from internet which are dst-natted" !connection-bytes !connection-limit !connection-mark connection-nat-state=dstnat !connection-rate connection-state=\
    established,related !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority \
    !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=forward comment="defconf: drop bad forward IPs" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address src-address-list=\
    no_forward_ipv4 !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=forward comment="defconf: drop bad forward IPs" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    dst-address-list=no_forward_ipv4 !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit \
    log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=jump chain=output comment="Jump for icmp output" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options jump-target=ICMP !layer7-protocol !limit log=no \
    log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=ICMP comment="Echo request - Avoiding Ping Flood, adjust the limit as needed" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no \
    !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=8:0 !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol \
    limit=2,5:packet log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=ICMP comment="Echo reply" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=0:0 !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=ICMP comment="Time Exceeded" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=11:0 !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=ICMP comment="Destination unreachable" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=3:0-1 !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=ICMP comment=PMTUD !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot icmp-options=3:4 !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port \
    !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=ICMP comment="Drop to the other ICMPs" !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=yes !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
/ip firewall mangle
add action=mark-connection chain=prerouting comment=Google_IoT_Core !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" new-connection-mark=Google_IoT_Core-Conn !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority !protocol !psd !random \
    !routing-mark !routing-table !src-address src-address-list=googleapis !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit connection-mark=Google_IoT_Core-Conn !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-packet-mark=Google_IoT_Core-Packet !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark \
    !routing-table !src-address src-address-list=googleapis !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=postrouting comment=Google_IoT_Core !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    dst-address-list=googleapis !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=\
    no log-prefix="" new-connection-mark=Google_IoT_Core-Conn !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority !protocol !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=postrouting !connection-bytes !connection-limit connection-mark=Google_IoT_Core-Conn !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address dst-address-list=\
    googleapis !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-packet-mark=Google_IoT_Core-Packet !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark \
    !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=ssh_connt_mark !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit dst-port=22 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" new-connection-mark=SSH-conn !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority protocol=tcp !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting comment=ssh_packet_mark !connection-bytes !connection-limit connection-mark=SSH-conn !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit dst-port=22 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" new-packet-mark=SSH !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority protocol=tcp !psd !random !routing-mark \
    !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=winbox_connt_mark !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" new-connection-mark=winbox_conn !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority protocol=tcp !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting comment=winbox_packet_mark !connection-bytes !connection-limit connection-mark=winbox_conn !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" new-packet-mark=winbox !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority protocol=tcp !psd !random !routing-mark \
    !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=postrouting comment=winbox_connt_mark !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" new-connection-mark=winbox_conn !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority protocol=tcp !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=postrouting comment=winbox_packet_mark !connection-bytes !connection-limit connection-mark=winbox_conn !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit dst-port=8291 !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no \
    log-prefix="" new-packet-mark=winbox !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority protocol=tcp !psd !random !routing-mark \
    !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=DNS !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes log-prefix=\
    "[MARK-DNS-UDP] :: " new-connection-mark=DNS !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier port=53 !priority protocol=udp !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit connection-mark=DNS !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes log-prefix="[MARK-DNS-UDP-PACKET] :: " \
    new-packet-mark=DNS !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=postrouting !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-connection-mark=DNS !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier port=53 !priority protocol=udp !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=postrouting !connection-bytes !connection-limit connection-mark=DNS !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=DNS !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=VOIP !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-connection-mark=VOIP !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier port=5060-5062,10000-10050 !priority protocol=udp !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit connection-mark=VOIP !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=VOIP !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=QUIC !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-connection-mark=QUIC !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier port=80,443 !priority protocol=udp !psd !random !routing-mark \
    !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit connection-mark=QUIC !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=QUIC !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=UDP !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-connection-mark=UDP !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority protocol=udp !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit connection-mark=UDP !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=UDP !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=ICMP !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-connection-mark=ICMP !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit connection-mark=ICMP !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=ICMP !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=postrouting !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-connection-mark=ICMP !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority protocol=icmp !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=postrouting !connection-bytes !connection-limit connection-mark=ICMP !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=ICMP !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=postrouting comment=ACK !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-packet-mark=ACK !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark packet-size=0-123 passthrough=no !per-connection-classifier !port !priority protocol=tcp !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address !src-port tcp-flags=ack !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=ACK !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark packet-size=0-123 passthrough=no !per-connection-classifier !port !priority protocol=tcp !psd !random !routing-mark !routing-table !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port tcp-flags=ack !tcp-mss !time !tls-host !ttl
add action=fasttrack-connection chain=prerouting comment=FASTTRACK_HTTP_normal_mark !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp \
    !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit \
    log=no log-prefix="[MANGLE-PASS-HTTP] :: " !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier port=80,443 !priority protocol=tcp !psd !random !routing-mark \
    !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=HTTP_normal_mark !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes \
    log-prefix="[MANGLE-PASS-HTTP] :: " new-connection-mark=HTTP !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier port=80,443 !priority protocol=tcp \
    !psd !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting comment=HTTP_normal_packet_mark !connection-bytes !connection-limit connection-mark=HTTP !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes \
    log-prefix="[PACKET-MARK-80] :: " new-packet-mark=HTTP !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random \
    !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=HTTP_BIG_CONN_MARK connection-bytes=5000000-0 !connection-limit connection-mark=HTTP !connection-nat-state connection-rate=2M-100M !connection-state !connection-type !content disabled=no !dscp \
    !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit \
    log=yes log-prefix="[MANGLE-PASS-80-BIG] :: " new-connection-mark=HTTP_BIG !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority \
    protocol=tcp !psd !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting comment=HTTP_BIG_PACKET_MARK !connection-bytes !connection-limit connection-mark=HTTP_BIG !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address \
    !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes \
    log-prefix="[PACKET-MARK-80-BIG] ::" new-packet-mark=HTTP_BIG !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd \
    !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting comment=OTHER !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate connection-state=new !connection-type !content disabled=no !dscp !dst-address !dst-address-list \
    !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    new-connection-mark=POP3 !nth !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier port=995,465,587 !priority protocol=tcp !psd !random !routing-mark \
    !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit connection-mark=POP3 !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=OTHER !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-connection chain=prerouting !connection-bytes !connection-limit !connection-mark !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-connection-mark=OTHER !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=yes !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=mark-packet chain=prerouting !connection-bytes !connection-limit connection-mark=OTHER !connection-nat-state !connection-rate !connection-state !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" new-packet-mark=OTHER !nth \
    !out-bridge-port !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size passthrough=no !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" !connection-bytes !connection-limit !connection-mark !connection-rate !connection-type !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port \
    !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority ipsec-policy=out,none !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port !out-bridge-port-list \
    !out-interface out-interface-list=WAN !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-mss \
    !time !tls-host !to-addresses !to-ports !ttl
add action=masquerade chain=srcnat comment="src-NAT for Allowed clients" !connection-bytes !connection-limit !connection-mark !connection-rate !connection-type !content disabled=yes !dscp !dst-address !dst-address-list !dst-address-type !dst-limit \
    !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix=egress_lan_NAT !nth !out-bridge-port \
    !out-bridge-port-list !out-interface out-interface-list=WAN !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-mss !time !tls-host !to-addresses !to-ports !ttl
add action=masquerade chain=srcnat comment="src-NAT for Allowed clients" !connection-bytes !connection-limit !connection-mark !connection-rate !connection-type !content disabled=yes !dscp !dst-address !dst-address-list !dst-address-type !dst-limit \
    !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes log-prefix=egress_lan_NAT !nth !out-bridge-port \
    !out-bridge-port-list !out-interface out-interface-list=WAN !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address src-address-list=support !src-address-type \
    !src-mac-address !src-port !tcp-mss !time !tls-host !to-addresses !to-ports !ttl
add action=dst-nat chain=dstnat comment="DNAT to RPi SSH" !connection-bytes !connection-limit !connection-mark !connection-rate !connection-type !content disabled=yes !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port \
    !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=yes log-prefix=SSH_to_RPi4 !nth !out-bridge-port \
    !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier port=22 !priority protocol=tcp !psd !random !routing-mark !routing-table !src-address src-address-list=support_external \
    !src-address-type !src-mac-address !src-port !tcp-mss !time !tls-host to-addresses=192.168.88.200 to-ports=22 !ttl
add action=accept chain=dstnat comment="dst-nat for allowed Public_IP's" !connection-bytes !connection-limit !connection-mark !connection-rate !connection-type !content disabled=yes !dscp !dst-address !dst-address-list !dst-address-type !dst-limit \
    !dst-port !fragment !hotspot !icmp-options !in-bridge-port !in-bridge-port-list !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" !nth !out-bridge-port \
    !out-bridge-port-list !out-interface !out-interface-list !packet-mark !packet-size !per-connection-classifier !port !priority !protocol !psd !random !routing-mark !routing-table !src-address src-address-list=support_external !src-address-type \
    !src-mac-address !src-port !tcp-mss !time !tls-host !to-addresses !to-ports !ttl
/ip firewall raw
add action=accept chain=prerouting comment="defconf: enable for transparent firewall ### Only enable when doing debug so that traffic bypasses all prerouting rules" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type \
    !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier \
    !port !priority !protocol !psd !random !src-address !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=prerouting comment="### DO NOT DISABLE-Address-list of IP's that are allowed to access the router" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot \
    !icmp-options in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority !protocol !psd !random \
    !src-address src-address-list=allowed_to_router !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=prerouting comment="### DO NOT DISABLE - MikroTik Cloud DDNS servers" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options in-interface=lte1 \
    !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !limit log=yes log-prefix="[DDNS-IP-REFRESH] ::" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=udp !psd !random \
    src-address=159.148.172.251 !src-address-list !src-address-type !src-mac-address src-port=15252 !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=prerouting comment="### DO NOT DISABLE - MikroTik Cloud DDNS servers" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options in-interface=lte1 \
    !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !limit log=yes log-prefix="[DDNS-IP-REFRESH] ::" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=udp !psd !random \
    src-address=159.148.147.229 !src-address-list !src-address-type !src-mac-address src-port=15252 !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=prerouting comment="### DO NOT DISABLE-Address-list of Permitted Public DNS resolvers " !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options \
    in-interface=lte1 !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority !protocol !psd !random !src-address \
    src-address-list=public_DNS !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=prerouting comment="### DO NOT DISABLE-Address-list of IP's that are allowed to access the router" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot \
    !icmp-options in-interface=bridge !in-interface-list !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority !protocol !psd !random \
    !src-address src-address-list=allowed_to_router !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=prerouting comment="defconf: drop bogon IP's" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority !protocol !psd !random !src-address src-address-list=bad_ipv4 !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=prerouting comment="defconf: drop bogon IP's" !content disabled=no !dscp !dst-address dst-address-list=bad_ipv4 !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority !protocol !psd !random !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=prerouting comment="defconf: drop bogon IP's" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority !protocol !psd !random !src-address src-address-list=bad_src_ipv4 !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=prerouting comment="defconf: drop bogon IP's" !content disabled=no !dscp !dst-address dst-address-list=bad_dst_ipv4 !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority !protocol !psd !random !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=prerouting comment="defconf: drop bad UDP" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=yes log-prefix="[BLOCKED-BY-RAW-RULES] :: UDP = 0 IS BANNED : " !nth !out-interface !out-interface-list !packet-size !per-connection-classifier port=0 !priority protocol=udp !psd !random !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=jump chain=prerouting comment="defconf: jump to ICMP chain" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options jump-target=icmp4 !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=jump chain=prerouting comment="defconf: jump to TCP chain" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options jump-target=bad_tcp !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address \
    !src-address-list !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=prerouting comment="defconf: drop the rest" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=yes log-prefix="[BLOCKED-BY-RAW-RULES] : " !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority !protocol !psd !random !src-address !src-address-list \
    !src-address-type !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment="defconf: TCP flag filter" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port tcp-flags=!fin,!syn,!rst,!ack !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment="defconf: TCP flag filter" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port tcp-flags=!psh,!ack !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment=defconf !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address !src-port \
    tcp-flags=fin,syn !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment=defconf !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address !src-port \
    tcp-flags=fin,rst !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment=defconf !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address !src-port \
    tcp-flags=fin,!ack !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment=defconf !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address !src-port \
    tcp-flags=fin,urg !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment=defconf !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address !src-port \
    tcp-flags=syn,rst !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment=defconf !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority !ipsec-policy \
    !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address !src-port \
    tcp-flags=rst,urg !tcp-mss !time !tls-host !ttl
add action=accept chain=bad_tcp comment="defconf: TCP flag filter" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port tcp-flags=syn,ack !tcp-mss !time !tls-host !ttl
add action=accept chain=bad_tcp comment="defconf: TCP flag filter" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port tcp-flags=ack !tcp-mss !time !tls-host !ttl
add action=accept chain=bad_tcp comment="defconf: TCP flag filter" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port tcp-flags=psh,ack !tcp-mss !time !tls-host !ttl
add action=drop chain=bad_tcp comment="defconf: TCP port 0 drop" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier port=0 !priority protocol=tcp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=icmp4 comment="defconf: echo reply" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=0:0 !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options limit=5,10:packet log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=icmp4 comment="defconf: net unreachable" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=3:0 !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=icmp4 comment="defconf: host unreachable" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=3:1 !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=icmp4 comment="defconf: protocol unreachable" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=3:2 !in-interface !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=icmp4 comment="defconf: port unreachable" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=3:3 !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=icmp4 comment="defconf: fragmentation needed" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=3:4 !in-interface !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=icmp4 comment="defconf: echo" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=8:0 !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options limit=5,10:packet log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=accept chain=icmp4 comment="defconf: time exceeded " !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot icmp-options=11:0-255 !in-interface !in-interface-list \
    !ingress-priority !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type \
    !src-mac-address !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
add action=drop chain=icmp4 comment="defconf: drop other icmp" !content disabled=no !dscp !dst-address !dst-address-list !dst-address-type !dst-limit !dst-port !fragment !hotspot !icmp-options !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !limit log=no log-prefix="" !nth !out-interface !out-interface-list !packet-size !per-connection-classifier !port !priority protocol=icmp !psd !random !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port !tcp-flags !tcp-mss !time !tls-host !ttl
/ip firewall service-port
set ftp disabled=yes ports=21
set tftp disabled=yes ports=69
set irc disabled=yes ports=6667
set h323 disabled=yes
set sip disabled=yes ports=5060,5061 sip-direct-media=yes sip-timeout=1h
set pptp disabled=yes
set udplite disabled=yes
set dccp disabled=yes
set sctp disabled=yes
/ip hotspot service-port
set ftp disabled=no ports=21
/ip hotspot user
set [ find default=yes ] comment="counters and limits for trial users" disabled=no name=default-trial
/ip ipsec policy
set 0 disabled=no dst-address=::/0 group=default proposal=default protocol=all src-address=::/0 template=yes
/ip ipsec settings
set accounting=yes interim-update=0s xauth-use-radius=no
/ip proxy
set always-from-cache=no anonymous=no cache-administrator=webmaster cache-hit-dscp=4 cache-on-disk=no cache-path=web-proxy enabled=no max-cache-object-size=2048KiB max-cache-size=unlimited max-client-connections=600 max-fresh-time=3d \
    max-server-connections=600 parent-proxy=:: parent-proxy-port=0 port=8080 serialize-connections=no src-address=::
/ip service
set telnet address="" disabled=yes port=23
set ftp address="" disabled=yes port=21
set www address=105.23.225.106/32,37.48.118.94/32,34.90.83.14/32 disabled=no port=80
set ssh address="" disabled=yes port=22
set www-ssl address="" certificate=none disabled=yes port=443 tls-version=any
set api address="" disabled=yes port=8728
set winbox address=192.168.88.0/24,37.48.118.94/32,165.255.239.57/32,105.23.225.106/32,34.90.83.14/32,188.34.190.74/32 disabled=no port=8291
set api-ssl address="" certificate=none disabled=yes port=8729 tls-version=any
/ip smb
set allow-guests=yes comment=MikrotikSMB domain=MSHOME enabled=no interfaces=all
/ip smb shares
set [ find default=yes ] comment="default share" directory=/flash/pub disabled=no max-sessions=10 name=pub
/ip smb users
set [ find default=yes ] disabled=no name=guest password="" read-only=yes
/ip socks
set auth-method=none connection-idle-timeout=2m enabled=no max-connections=200 port=1080 version=4
/ip ssh
set allow-none-crypto=no always-allow-password-login=no forwarding-enabled=no host-key-size=2048 strong-crypto=no
/ip tftp settings
set max-block-size=4096
/ip traffic-flow
set active-flow-timeout=30m cache-entries=16k enabled=no inactive-flow-timeout=15s interfaces=all packet-sampling=no sampling-interval=0 sampling-space=0
/ip traffic-flow ipfix
set bytes=yes dst-address=yes dst-address-mask=yes dst-mac-address=yes dst-port=yes first-forwarded=yes gateway=yes icmp-code=yes icmp-type=yes igmp-type=yes in-interface=yes ip-header-length=yes ip-total-length=yes ipv6-flow-label=yes is-multicast=\
    yes last-forwarded=yes nat-dst-address=yes nat-dst-port=yes nat-events=no nat-src-address=yes nat-src-port=yes out-interface=yes packets=yes protocol=yes src-address=yes src-address-mask=yes src-mac-address=yes src-port=yes sys-init-time=yes \
    tcp-ack-num=yes tcp-flags=yes tcp-seq-num=yes tcp-window-size=yes tos=yes ttl=yes udp-length=yes
/ip upnp
set allow-disable-external-interface=no enabled=no show-dummy-rule=yes
/mpls
set allow-fast-path=yes dynamic-label-range=16-1048575 propagate-ttl=yes
/mpls interface
set [ find default=yes ] disabled=no interface=all mpls-mtu=1508
/mpls ldp
set distribute-for-default-route=no enabled=no hop-limit=255 loop-detect=no lsr-id=0.0.0.0 path-vector-limit=255 transport-address=0.0.0.0 use-explicit-null=no
/port firmware
set directory=firmware ignore-directip-modem=no
/ppp aaa
set accounting=yes interim-update=0s use-circuit-id-in-nas-port-id=no use-radius=no
/ppp secret
add caller-id="" disabled=no ipv6-routes="" limit-bytes-in=0 limit-bytes-out=0 !local-address name=tim password=fromtheotherside profile=PPTP-Profile !remote-address routes="" service=any
add caller-id="" disabled=no ipv6-routes="" limit-bytes-in=0 limit-bytes-out=0 !local-address name=energydrive password=vCRkVHj16m2RdF9j profile=PPTP-Profile !remote-address routes="" service=any
add caller-id="" disabled=yes ipv6-routes="" limit-bytes-in=0 limit-bytes-out=0 !local-address name=energydrv password=fromtheotherside profile=PPTP-Profile !remote-address routes="" service=pptp
/radius incoming
set accept=no port=3799
/routing bfd interface
set [ find default=yes ] disabled=no interface=all interval=0.2s min-rx=0.2s multiplier=5
/routing mme
set bidirectional-timeout=2 gateway-class=none gateway-keepalive=1m gateway-selection=no-gateway origination-interval=5s preferred-gateway=0.0.0.0 timeout=1m ttl=50
/routing rip
set distribute-default=never garbage-timer=2m metric-bgp=1 metric-connected=1 metric-default=1 metric-ospf=1 metric-static=1 redistribute-bgp=no redistribute-connected=no redistribute-ospf=no redistribute-static=no routing-table=main timeout-timer=\
    3m update-timer=30s
/snmp
set contact="" enabled=no engine-id="" location="" trap-community=public trap-generators=temp-exception trap-target="" trap-version=1
/system clock
set time-zone-autodetect=yes time-zone-name=Africa/Johannesburg
/system clock manual
set dst-delta=+00:00 dst-end="jan/01/1970 00:00:00" dst-start="jan/01/1970 00:00:00" time-zone=+02:00
/system identity
set name=AMS001-LADLE-FURNACE-BAGHOUSE-FANS-LTE
/system leds
# using RSRP, modem-signal-threshold ignored
set 0 disabled=no interface=lte1 leds=,,,, modem-signal-threshold=-91 type=modem-signal
set 1 disabled=no interface=lte1 leds=user-led type=modem-technology
/system leds settings
set all-leds-off=never
/system logging
set 0 action=memory disabled=no prefix="" topics=info
set 1 action=memory disabled=no prefix="" topics=error
set 2 action=memory disabled=no prefix="" topics=warning
set 3 action=echo disabled=no prefix="" topics=critical
/system note
set note="" show-at-login=yes
/system ntp client
set enabled=no primary-ntp=0.0.0.0 secondary-ntp=0.0.0.0 server-dns-names=""
/system resource irq
set 0 cpu=auto
set 1 cpu=auto
/system routerboard settings
# Warning: cpu not running at default frequency
set auto-upgrade=yes boot-device=nand-if-fail-then-ethernet boot-protocol=bootp cpu-frequency=750MHz force-backup-booter=no protected-routerboot=disabled reformat-hold-button=20s reformat-hold-button-max=10m silent-boot=no
/system routerboard mode-button
set enabled=no hold-time=0s..1m on-event=""
/system scheduler
add disabled=yes interval=12h name=Reboot on-event="system reboot" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
add comment="Crontab for auto-block script" disabled=yes interval=1m name=auto-blockcrontab on-event="/system script run auto-block" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
add comment="Crontab for telegram-block-script" disabled=yes interval=1m name="telegram-block-script crontab" on-event="/system script run telegram-block-script" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=\
    jan/01/1970 start-time=00:00:01
add comment="Crontab for no-mark" disabled=yes interval=30m name="no-mark crontab" on-event="/system script run no-mark" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
add comment="Crontab for watchdog" disabled=yes interval=6h name="watchdog crontab" on-event="/system script run watchdog" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
add comment="Crontab for auto-block script" disabled=no interval=10m name=googleapis.com on-event="/system script run googleapis.com" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jan/01/1970 start-time=00:00:01
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
/system upgrade mirror
set check-interval=1d enabled=no primary-server=0.0.0.0 secondary-server=0.0.0.0 user=""
/system watchdog
set auto-send-supout=no automatic-supout=yes ping-start-after-boot=5m ping-timeout=1m watch-address=none watchdog-timer=yes
/tool bandwidth-server
set allocate-udp-ports-from=2000 authenticate=yes enabled=yes max-sessions=100
/tool e-mail
set address=0.0.0.0 from=<> password="" port=25 start-tls=no user=""
/tool graphing
set page-refresh=300 store-every=5min
/tool graphing interface
add allow-address=0.0.0.0/0 disabled=no interface=bridge store-on-disk=yes
add allow-address=0.0.0.0/0 disabled=no interface=lte1 store-on-disk=yes
/tool graphing queue
add allow-address=0.0.0.0/0 allow-target=yes disabled=no store-on-disk=yes
add allow-address=0.0.0.0/0 allow-target=yes disabled=no store-on-disk=yes
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
/tool mac-server ping
set enabled=yes
/tool netwatch
add disabled=no down-script="log info \"Netwatch missed a ping to 8.8.8.8 - starting 5 minute timeout script\" ; /system script run watchdog\r\
    \n" host=8.8.8.8 interval=1m timeout=1s up-script=""
/tool romon
set enabled=no id=00:00:00:00:00:00 secrets=""
/tool romon port
set [ find default=yes ] cost=100 disabled=no forbid=no interface=all secrets=""
/tool sms
set allowed-number="" auto-erase=no channel=0 port=none receive-enabled=no secret="" sim-pin=""
/tool sniffer
set file-limit=1000KiB file-name="" filter-cpu="" filter-direction=any filter-interface="" filter-ip-address="" filter-ip-protocol="" filter-ipv6-address="" filter-mac-address="" filter-mac-protocol="" filter-operator-between-entries=or filter-port=\
    "" filter-size="" filter-stream=no memory-limit=100KiB memory-scroll=yes only-headers=no streaming-enabled=no streaming-server=0.0.0.0:37008
/tool traffic-generator
set latency-distribution-max=100us measure-out-of-order=yes stats-samples-to-keep=100 test-id=0
/user aaa
set accounting=yes default-group=read exclude-groups="" interim-update=0s use-radius=no
[admin@AMS001-LADLE-FURNACE-BAGHOUSE-FANS-LTE] > 
