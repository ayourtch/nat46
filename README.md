mapmin
======

A very minimal, self-contained, and not necessarily standards-conformant 
implementation of MAP and its provisioning for experimental use.

For now it is probably not very useful for anyone besides me, 
as it is nothing that really works. Anyway, enough of how it does not work,
let's talk about what it should be.

The Idea
========

This code explores the approach to MAP as a two-stage process: 

1.  NAT44 into the portranges 
2.  Transport transformation (tunneling for -E or NAT46 for -T)

The (1) is (almost) doable with the following configuration (for MAP-T):

```
iptables -t nat --flush
iptables -t nat -A POSTROUTING -p tcp -o mapmint -j SNAT --to 1.1.1.1:1025-2047
iptables -t nat -A POSTROUTING -p udp -o mapmint -j SNAT --to 1.1.1.1:1025-2047
iptables -t nat -A POSTROUTING -p icmp -o mapmint -j SNAT --to 1.1.1.1:1025-2047
```

The "mapmint" interface is provided by a kernel module and does the transport
transformation, called roughly as follows:

```
insmod mapmint.ko ipv4_address=1.1.1.1/32
ifconfig mapmint up
ip -4 route add default dev mapmint
ip -6 route add 2001:db8::/64 dev mapmint
```

This adds the default IPv4 route via the transport interface - which means after 
the NAT44 it will be transformed, and then sent out of the wire.

The traffic received towards the BMR prefix is also routed to this interface, and this
does the reverse transformation.

MAP-E
=====

For MAP-E the picture will be similar, except the kernel does already support something 
very close to what we need - ipv4-in-ipv6 tunnel. It does not help us with p2p traffic, 
but let's leave this aside for now.

Multiple ranges when NATting in iptables
========================================

Alas, folks have removed the support for multiple --to targets within the single statement,
so you can not fall back to the "next" slice if the range of the ports is already full.

But we can use the "connlimit" iptables extension. 

With it, we can express the MAP multiple ranges logic with the following configuration:

```
iptables -t nat -A POSTROUTING -p icmp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:7168-8191
iptables -t nat -A POSTROUTING -p tcp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:7168-8191
iptables -t nat -A POSTROUTING -p udp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:7168-8191
iptables -t nat -A POSTROUTING -p icmp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:11264-12287
iptables -t nat -A POSTROUTING -p tcp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:11264-12287
iptables -t nat -A POSTROUTING -p udp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:11264-12287
iptables -t nat -A POSTROUTING -p icmp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:15360-16383
iptables -t nat -A POSTROUTING -p tcp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:15360-16383
iptables -t nat -A POSTROUTING -p udp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:15360-16383
iptables -t nat -A POSTROUTING -p icmp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:19456-20479
iptables -t nat -A POSTROUTING -p tcp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:19456-20479
iptables -t nat -A POSTROUTING -p udp -m connlimit --connlimit-daddr --connlimit-upto 1024 -o mapmint -j SNAT --to 172.17.2.243:19456-20479
.....
```

Each line counts the number of connections within this clause, and if the number is bigger than the allocated number of ports - it rolls over.

Compiling
=========

With Barrier Breaker (trunk), add the following line to *feeds.conf.default*:
```
src-git mapmin https://github.com/ayourtch/mapmin.git
```

then issue:

```
./scripts/feeds update -a
./scripts/feeds install -a -p mapmin
```

This will cause the following to appear in the "make menuconfig":

 * Kernel modules -> Network Support -> kmod-mapmint
 * Network -> mapminctl

Just select the "mapminctl", which will also automatically select the "map-mdpc" package
as well as the kernel module and the required iptables packages.

If you are using the latest version of the openwrt-map feed, then mdpc included 
there will start using MAPMIN automatically, and announce that in /tmp/map.log

Of course, the DHCPv6 client and the device has to be configured accordingly.

Here is a preliminary example of the configuration with the mapmin pieces included:

/etc/config/network:
```
config interface 'wan'
        option ifname 'eth0.2'
        option _orig_ifname 'eth0.2'
        option _orig_bridge 'false'
        option proto 'pppoe'
        option username 'user'
        option password 'user_pass'
        option ipv6 '1'
        option keepalive '2 30'

config interface 'wan6'
        option ifname '@wan'
        option proto 'dhcpv6'
        option reqopts '48879'   # Add this to request the test MAP DHCPv6 option
        
config interface 'mapmint'       # Add this interface to place it into firewall
        option ifname 'mapmint'
        option proto 'none'
```

/etc/config/firewall:

```
config zone
        option name             wan
        list   network          'wan'
        list   network          'wan6'
        list   network          'mapmint' # Add this interface to the WAN zone
        option input            REJECT
        option output           ACCEPT
        option forward          ACCEPT    # Allow forwarding
        option masq             1
        option mtu_fix          1

```

