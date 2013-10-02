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

