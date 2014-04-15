#pragma once

#include <linux/netdevice.h>
#include <net/ip6_checksum.h>
#include <linux/proc_fs.h>

extern struct net_device	*nat64_v4_dev;
extern struct net_device	*nat64_dev;

extern int debug;

extern __be32			ipv4_addr;
extern __be32			ipv4_netmask;
extern int			ipv4_prefixlen;

extern int			dmr_prefix_len;
extern struct in6_addr		dmr_prefix_base;

extern int			local_prefix_len;
extern struct in6_addr		local_prefix_base;

extern int			psid;

void nat64_ipv6_input(struct sk_buff *old_skb);
unsigned int nat64_ipv4_input(struct sk_buff *skb);

int nat64_netdev_create(struct net_device **dev);
void nat64_netdev_destroy(struct net_device *dev);

static inline uint32_t extract_ipv4(struct in6_addr addr, int prefix)
{
	switch(prefix) {
	case 32:
		return 0;	//FIXME
	case 40:
		return 0;	//FIXME
	case 48:
		return 0;	//FIXME
	case 56:
		return 0;	//FIXME
	case 64:
		return htonl((((((addr.s6_addr[9] << 8) + addr.s6_addr[10]) << 8) + 
                                 addr.s6_addr[11]) << 8) + addr.s6_addr[12]); 

		//return 0;	//FIXME
	case 96:
		return htonl(addr.s6_addr32[3]);
	default:
		return 0;
	}
}

static inline void assemble_ipv6_bmr(struct in6_addr *dest, __be32 addr)
{
	uint32_t addr_n = (addr);
	uint8_t *pa = (void*) &addr_n;
	memcpy(dest, &dmr_prefix_base, sizeof(dmr_prefix_base));
	switch(dmr_prefix_len) {
	case 64:
		dest->s6_addr[9] = *pa++;
		dest->s6_addr[10] = *pa++;
		dest->s6_addr[11] = *pa++;
		dest->s6_addr[12] = *pa++;
		
		break;
	case 96:
		dest->s6_addr32[3] = addr_n;
		break;
	}
}

static inline void assemble_ipv6_local(struct in6_addr *dest, __be32 addr)
{
	uint32_t addr_n = (addr);
	uint8_t *pa = (void*) &addr_n;

	memcpy(dest, &local_prefix_base, sizeof(local_prefix_base));

		dest->s6_addr[9] = *pa++;
		dest->s6_addr[10] = *pa++;
		dest->s6_addr[11] = *pa++;
		dest->s6_addr[12] = *pa++;

		dest->s6_addr[14] = psid & 0xff;
		dest->s6_addr[15] = (psid >> 8) & 0xff;
}
