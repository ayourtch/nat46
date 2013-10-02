#pragma once

#include <linux/netdevice.h>
#include <net/ip6_checksum.h>
#include <linux/proc_fs.h>

#define UDP_DEFAULT_ 5*60
#define ICMP_DEFAULT_ 1*60

#define BIB_ICMP	3

#define	NUM_EXPIRY_QUEUES	5
struct expiry_q
{
	struct list_head	queue;
	int			timeout;
};

enum state_type {
	CLOSED = 0,
	V6_SYN_RCV,
	V4_SYN_RCV,
	FOUR_MIN,
	ESTABLISHED,
	V6_FIN_RCV,
	V4_FIN_RCV,
	V6_FIN_V4_FIN,
};

enum expiry_type {
	UDP_DEFAULT = 0,
	TCP_TRANS,
	TCP_EST,
	TCP_INCOMING_SYN,
	ICMP_DEFAULT
};

struct bib_entry
{
	struct hlist_node	byremote;
	struct hlist_node	bylocal;

	int			type;
	struct in6_addr		remote6_addr;
	__be32			local4_addr;

	__be16			remote6_port;
	__be16			local4_port;

	struct list_head	sessions;
};

struct session_entry
{
	struct list_head	list;
	struct list_head	byexpiry;
	unsigned long		expires;
	int			state;
	__be32			remote4_addr;
	__be16			remote4_port;
};

extern struct expiry_q	expiry_base[NUM_EXPIRY_QUEUES];

extern struct kmem_cache	*session_cache;
extern struct kmem_cache	*bib_cache;
extern struct list_head		exipry_queue;
extern struct net_device	*nat64_v4_dev;
extern struct net_device	*nat64_dev;

extern struct hlist_head	*hash6;
extern struct hlist_head	*hash4;
extern unsigned int		hash_size;

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

static inline void ipv6_addr_copy(struct in6_addr *a1, const struct in6_addr *a2)
{
        memcpy(a1, a2, sizeof(struct in6_addr));
}

static inline __be16 nat64_hash4(__be32 addr, __be16 port)
{
	//return (addr >> 16) ^ addr ^ port;
	return port;
}

static inline __be16 nat64_hash6(struct in6_addr addr6, __be16 port)
{
	__be32 addr4 = addr6.s6_addr32[0] ^ addr6.s6_addr32[1] ^ addr6.s6_addr32[2] ^ addr6.s6_addr32[3];
	return (addr4 >> 16) ^ addr4 ^ port;
}

static inline __be32 map_6to4(struct in6_addr *addr6)
{
	__be32 addr_hash = addr6->s6_addr32[0] ^ addr6->s6_addr32[1] ^ addr6->s6_addr32[2] ^ addr6->s6_addr32[3];
	__be32 addr4 = htonl(ntohl(ipv4_addr) + (addr_hash % (1<<(32 - ipv4_prefixlen))));

//	printk("nat64: [inline] map_6to4 %pI6c mod %pI4/%d -> %pI4 + %d -> %pI4\n", addr6, &ipv4_addr, ipv4_prefixlen, &ipv4_addr, (addr_hash % (1<<(32 - ipv4_prefixlen))), &addr4);
	return addr4;
}

static inline __be32 extract_ipv4(struct in6_addr addr, int prefix)
{
	switch(prefix) {
	case 32:
		return addr.s6_addr32[1];
	case 40:
		return 0;	//FIXME
	case 48:
		return 0;	//FIXME
	case 56:
		return 0;	//FIXME
	case 64:
		return (((((addr.s6_addr[12] << 8) + addr.s6_addr[11]) << 8) + addr.s6_addr[10]) << 8) + addr.s6_addr[9]; 
		//return 0;	//FIXME
	case 96:
		return addr.s6_addr32[3];
	default:
		return 0;
	}
}

static inline void assemble_ipv6_bmr(struct in6_addr *dest, __be32 addr)
{
	memcpy(dest, &dmr_prefix_base, sizeof(dmr_prefix_base));
	switch(dmr_prefix_len) {
	case 64:
		dest->s6_addr[9] = (addr & 0xff);
		dest->s6_addr[10] = (addr >> 8) & 0xff;
		dest->s6_addr[11] = (addr >> 16) & 0xff;
		dest->s6_addr[12] = (addr >> 24);
		break;
	case 96:
		dest->s6_addr32[3] = addr;
		break;
	}
}

static inline void assemble_ipv6_local(struct in6_addr *dest, __be32 addr)
{
	memcpy(dest, &local_prefix_base, sizeof(local_prefix_base));
		dest->s6_addr[9] = (addr & 0xff);
		dest->s6_addr[10] = (addr >> 8) & 0xff;
		dest->s6_addr[11] = (addr >> 16) & 0xff;
		dest->s6_addr[12] = (addr >> 24);
	dest->s6_addr16[7] = psid;
	return;
	dest->s6_addr16[5] = (addr >> 16);
	dest->s6_addr16[6] = (addr & 0xffff);
	dest->s6_addr16[7] = psid;
/*
	switch(local_prefix_len) {
	case 96:
		dest->s6_addr32[3] = addr;
		break;
	}
*/
}
