#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <net/ip6_route.h>


#ifndef IP6_OFFSET
#define IP6_OFFSET      0xFFF8
#endif

#define assert(x) printk("Assertion failed: %s", #x)

