/interface bridge
add mtu=1500 name=mirror
/interface vlan
add interface=sfp1 l2mtu=1586 name=vlan10 vlan-id=10
add interface=sfp1 l2mtu=1586 name=vlan11 vlan-id=11
/routing bgp instance
set default as=64496 out-filter=bgp-blackhole-out router-id=10.11.11.11
/system logging action
set 0 memory-lines=10000
/interface bridge port
add bridge=mirror interface=sfpplus1
/interface bridge settings
set use-ip-firewall=yes use-ip-firewall-for-vlan=yes
/ip firewall connection tracking
set enabled=no
/ip address
add address=10.10.10.10/24 interface=vlan10
add address=10.11.11.11/24 interface=vlan11
/ip firewall address-list
add address=1.2.3.4 list=PASS
add address=5.6.7.8 list=DDOSOWANI
/ip firewall mangle
add chain=prerouting comment="wybij PASS z blackhole" dst-address-list=PASS
add chain=prerouting comment="TCP 20tys pkt na dst" dst-limit=\
    10000,10000,dst-address in-bridge-port=sfpplus1 protocol=tcp
add chain=prerouting comment="TCP 20tys pkt na dst" dst-limit=\
    10000,10000,dst-address in-bridge-port=sfpplus1 protocol=tcp
add chain=prerouting comment="TCP 20tys pkt na dst" dst-limit=\
    10000,10000,dst-address in-bridge-port=sfpplus1 protocol=tcp
add chain=prerouting comment="ICMP 20tys pkt na dst" dst-limit=\
    10000,10000,dst-address in-bridge-port=sfpplus1 protocol=icmp
add chain=prerouting comment="20tys pkt na dst" dst-limit=\
    10000,10000,dst-address in-bridge-port=sfpplus1
add chain=prerouting comment="20tys pkt na dst" dst-limit=\
    10000,10000,dst-address in-bridge-port=sfpplus1
add chain=prerouting comment="20tys pkt na dst" dst-limit=\
    10000,10000,dst-address in-bridge-port=sfpplus1
add chain=prerouting comment="20tys pkt na dst" dst-limit=\
    10000,10000,dst-address in-bridge-port=sfpplus1
add action=mark-packet chain=prerouting in-bridge-port=sfpplus1 \
    new-packet-mark=DDOS
add action=log chain=prerouting dst-limit=1/1m,0,src-and-dst-addresses \
    log-prefix=DDOS: packet-mark=DDOS
add action=add-dst-to-address-list address-list=DDOSOWANI \
    address-list-timeout=5m chain=prerouting dst-limit=1/1m,0,dst-address \
    packet-mark=DDOS
/routing bgp peer
add in-filter=bgp-blackhole-in multihop=yes name=router_bgp1 out-filter=\
    bgp-blackhole-out remote-address=10.11.11.1 remote-as=64496 ttl=\
    default
add in-filter=bgp-blackhole-in multihop=yes name=router_bgp2 out-filter=\
    bgp-blackhole-out remote-address=10.11.11.2 remote-as=64496 ttl=\
    default
/routing filter
add action=accept append-bgp-communities=64496:997 chain=bgp-blackhole-out \
    set-in-nexthop=192.168.192.168
add action=discard chain=bgp-blackhole-in
/system scheduler
add interval=4s name=blackhole on-event="/system script run update-blackhole" \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive \
    start-time=startup
/system script
add name=update-blackhole owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source="#:log i\
    nfo \"BGP Blackhole updater starting\";\r\
    \n\r\
    \n:local refresh;\r\
    \n:set refresh false;\r\
    \n\r\
    \n# Add addresses to BGP networks\r\
    \n:foreach address in=[/ip firewall address-list find list=DDOSOWANI disab\
    led=no] do={\r\
    \n :local id;\r\
    \n :set id [/ip firewall address-list get \$address address]\r\
    \n\r\
    \n :local rtExists;\r\
    \n :set rtExists false;\r\
    \n\r\
    \n :foreach nets in=[/routing bgp network find network=\"\$id/32\"] do={\r\
    \n  :set rtExists true;\r\
    \n  :put \"\$id already in BGP networks\"; \r\
    \n }\r\
    \n :if (\$rtExists = false) do={\r\
    \n  /routing bgp network add network=\"\$id/32\" synchronize=no;\r\
    \n  :set refresh true;\r\
    \n  :put \"\$id added to BGP networks\";\r\
    \n /tool e-mail send to=\"noc@domena.pl\" subject=\"Moja siec BGP blackho\
    le update - \$id added for 5 min\" from=notice@domena.pl server=3.4.\
    5.6 body=\"IP \$id dodane na 5 min\"\r\
    \n } \r\
    \n}\r\
    \n\r\
    \n# Remove addresses from BGP networks that are not in ACL\r\
    \n:foreach route in=[/routing bgp network find synchronize=no] do={\r\
    \n :local addr;\r\
    \n :set addr [/routing bgp network get \$route network]\r\
    \n \r\
    \n :local addrsize;\r\
    \n :set addrsize [:len \$addr]\r\
    \n :set addr [ :pick \$addr 0 (\$addrsize-3) ];\r\
    \n \r\
    \n :local aclExists;\r\
    \n :set aclExists false;\r\
    \n \r\
    \n :foreach addrs in=[/ip firewall address-list find list=DDOSOWANI addres\
    s=\$addr disabled=no] do={\r\
    \n  :set aclExists true;\r\
    \n  :put \"\$addr still listed in ACL\";\r\
    \n }\r\
    \n :if (\$aclExists = false) do={\r\
    \n  :local netid;\r\
    \n  :set netid [/routing bgp network find network=\"\$addr/32\"]\r\
    \n  \r\
    \n  /routing bgp network remove \$netid;\r\
    \n  :set refresh true;\r\
    \n  \r\
    \n  :put \"\$addr removed from BGP networks\";\r\
    \n #/tool e-mail send to=\"noc@domena.pl\" subject=\"Moja siec BGP blackho\
    le update - \$addr removed\" from=notice@domena.pl server=3.4.5.6\
     body=\"IP \$addr removed\"\r\
    \n }\r\
    \n}\r\
    \n:if (\$refresh = true) do={\r\
    \n#:log info \"BGP Blackhole updater triggered BGP peer resend-all\"\r\
    \n:put \"Doing BGP peer resend-all\"\r\
    \n/routing bgp peer resend-all\r\
    \n}\r\
    \n#:log info \"BGP Blackhole updater finished\";\r\
    \n"
