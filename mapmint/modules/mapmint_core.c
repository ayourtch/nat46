#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/icmpv6.h>
#include <linux/inetdevice.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>


#include <linux/fs.h>		// for basic filesystem
#include <linux/proc_fs.h>	// for the proc filesystem
#include <linux/seq_file.h>	// for sequence files

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ipv6.h>

#include "mapmint.h"
#include "mapmint_factory.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrew Yourtchenko <ayourtch@gmail.com>, originally by Julius Kriukas <julius.kriukas@gmail.com>");
MODULE_DESCRIPTION("Linux MAP(min)-T stateless translation portion implementation");


struct net_device	*nat64_v4_dev;
struct net_device	*nat64_dev;

__be32			ipv4_addr = 0xc0000201; // 192.0.2.1
int			ipv4_prefixlen = 32;
__be32			ipv4_netmask = 0xffffffff;
static char			*ipv4_address = "192.0.2.1";
module_param(ipv4_address, charp, 0);
MODULE_PARM_DESC(ipv4_address, "MAP-T IPv4 public address.");

struct in6_addr		dmr_prefix_base = {.s6_addr32[0] = 0, .s6_addr32[1] = 0, .s6_addr32[2] = 0, .s6_addr32[3] = 0};
static char			*dmr_prefix_address = "2001:db8:FFFF::";
module_param(dmr_prefix_address, charp, 0);
MODULE_PARM_DESC(dmr_prefix_address, "MAP-T Default Mapping Rule (default 2001:db8:ffff::)");

int			dmr_prefix_len = 64;
module_param(dmr_prefix_len, int, 0);
MODULE_PARM_DESC(dmr_prefix_len, "DMR prefix length (default /64)");

struct in6_addr		local_prefix_base = {.s6_addr32[0] = 0, .s6_addr32[1] = 0, .s6_addr32[2] = 0, .s6_addr32[3] = 0};
static char			*local_prefix_address = "2001:db8::";
module_param(local_prefix_address, charp, 0);
MODULE_PARM_DESC(local_prefix_address, "Local IPv6 prefix (default 2001:db8::)");

int			local_prefix_len = 64;
module_param(local_prefix_len, int, 0);
MODULE_PARM_DESC(local_prefix_len, "local prefix length (default /64)");

int			psid = 0;
module_param(psid, int, 0);
MODULE_PARM_DESC(psid, "port set ID (default 0)");

#define IPV6_PREF_LEN (5*8+1+3)
#define MAX_PROC_SIZE ((4*IPV6_PREF_LEN)+100)

static struct proc_dir_entry *mapmint_proc_entry;

static int mapmint_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,"%s/%d %s/%d %s/%d\n", dmr_prefix_address, dmr_prefix_len, 
	                                                local_prefix_address, local_prefix_len,
                                                        ipv4_address, ipv4_prefixlen);
        return 0;
}


static int mapmint_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, mapmint_proc_show, NULL);
}

static ssize_t mapmint_proc_write(struct file *file, const char __user *buffer,
                              size_t count, loff_t *ppos)
{
        char *buf = NULL;

        buf = kmalloc(sizeof(char) * (count + 1), GFP_KERNEL);
        if (!buf)
                return -ENOMEM;

        if (copy_from_user(buf, buffer, count)) {
                kfree(buf);
                return -EFAULT;
        }

        buf[count] = '\0';

        /* work around \n when echo'ing into proc */
        if (buf[count - 1] == '\n')
                buf[count - 1] = '\0';

        if (!strcmp(buf, "on")) {
	}

	kfree(buf);
	return count;
}


static const struct file_operations mapmint_proc_fops = {
        .owner          = THIS_MODULE,
        .open           = mapmint_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
        .write          = mapmint_proc_write,
};

void create_new_proc_entry(void) {
	mapmint_proc_entry = proc_create("mapmint",0666,NULL, &mapmint_proc_fops );
	if(!mapmint_proc_entry) {
    		printk(KERN_INFO "Error creating proc entry");
    		return; // -ENOMEM;
    	}
}


static void nat64_translate_6to4(struct sk_buff *old_skb, __be16 dport, int proto)
{
	struct sk_buff	*skb;
	int 		sport = 0;
	int		skb_len = LL_MAX_HEADER + sizeof(struct iphdr) + old_skb->len;

	switch(proto) {
	case IPPROTO_UDP:
		skb_len += sizeof(struct udphdr);
		break;
	case IPPROTO_TCP:
		skb_len += tcp_hdrlen(old_skb);
		break;
	case IPPROTO_ICMP:
		skb_len += sizeof(struct icmphdr);
		break;
	}

	//printk("nat64: [6to4] Generating IPv4 packet %d.\n", skb_len);
	skb = alloc_skb(skb_len, GFP_ATOMIC);


	if (!skb) {
		printk("nat64: [6to4] Unable to allocate memory for new skbuff structure X(.\n");
		return;
	}
//	skb_reserve(skb, LL_MAX_HEADER);
	skb_reserve(skb, skb_len);
	factory_clone_data(old_skb, skb);

	switch(proto) {
	case IPPROTO_UDP:
		factory_clone_udp(old_skb, skb);
 		break;
	case IPPROTO_TCP:
		factory_clone_tcp(old_skb, skb, tcp_hdrlen(old_skb));
		break;
	case IPPROTO_ICMP:
		factory_clone_icmp(old_skb, skb, dport);
		break;
	}

	factory_translate_ip6(old_skb, skb, proto);

	if(nat64_v4_dev) {
		if(route_ipv4_away(skb, sport, dport))
			kfree_skb(skb);
	} else {
		skb->dev = nat64_dev;
		//nat64_dev->stats.rx_packets++;
		//nat64_dev->stats.rx_bytes += skb->len;
		netif_rx(skb);
	}
}

void inline nat64_handle_icmp6(struct sk_buff *skb, struct ipv6hdr *ip6h)
{
	struct icmphdr		*icmph;
	__be16			new_type;

	icmph = (struct icmphdr *)skb->data;
	skb_pull(skb, sizeof(struct icmphdr));
	printk("ICMP type: %d code %d\n", icmph->type, icmph->code);

	if(icmph->type >> 7) {
		// Informational ICMP
		if(icmph->type == ICMPV6_ECHO_REQUEST)
			new_type = (ICMP_ECHO << 8) + icmph->code;
		else if(icmph->type == ICMPV6_ECHO_REPLY)
			new_type = (ICMP_ECHOREPLY << 8) + icmph->code;
		else
			return;

		nat64_translate_6to4(skb, new_type, IPPROTO_ICMP);
	} else {
		// Error ICMP
		switch(icmph->type) {
		case ICMPV6_TIME_EXCEED:
			printk("nat64: [icmp6] Time Exceeded ICMPv6 type %hhu (Code: %hhu)\n", icmph->type, icmph->code);
			break;
		case 1:
			printk("nat64: [icmp6] Known ICMPv6 type %hhu (Code: %hhu)\n", icmph->type, icmph->code);
			nat64_translate_6to4(skb, ICMP_DEST_UNREACH, IPPROTO_ICMP);
			break;
		default:
			printk("nat64: [icmp6] Unknown ICMPv6 type %hhu (Code: %hhu)\n", icmph->type, icmph->code);
		}
		return;
	}
	//printk("nat64: [icmp6] Forwarding ECHO, new_type = %d\n", new_type);
}

void nat64_ipv6_input(struct sk_buff *old_skb)
{
	struct ipv6hdr	*ip6h = ipv6_hdr(old_skb);
	const struct udphdr	*udph;
	const struct tcphdr	*tcph;
	u8			proto;

	printk("IPv6 input mapmint\n");

	/* Skip empty or non IPv6 packets */
	if(old_skb->len < sizeof(struct ipv6hdr) || ip6h->version != 6)
		return;

	if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST)) {//||
	    //(!(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST))) {
		printk("nat64: [ipv6] source address is not unicast.\n");
		return;
	}

	printk("IPv6 check dst\n");
	// Check if destination address falls into local prefix
	 //if(memcmp(&ip6h->daddr, &local_prefix_base, local_prefix_len / 8))
	//	return;

	skb_pull(old_skb, sizeof(struct ipv6hdr));
	proto = ip6h->nexthdr;
	// FIXME!!!!! this needs to check that the fragment is atomic
	if(ip6h->nexthdr == 44) {
          proto = *(char *)old_skb->data;
	  skb_pull(old_skb, 8);
	}

	printk("NAT64: Incoming packet properties: proto: %d [nexthdr = %d] [payload_len = %d] [old_skb->len = %d]\n", proto, ip6h->nexthdr, ntohs(ip6h->payload_len), old_skb->len);
	// pr_debug("NAT64: Target registration information min_ip = %d, max_ip = %d\n", info->min_ip, info->max_ip);


	switch(proto) {
	case NEXTHDR_TCP:
		tcph = (struct tcphdr *)old_skb->data;
		skb_pull(old_skb, tcp_hdrlen(old_skb));

		nat64_translate_6to4(old_skb, tcph->dest, IPPROTO_TCP);
		//nat64_generate_tcp(old_skb, ip6h, bib);
		break;
	case NEXTHDR_UDP:
		udph = (struct udphdr *)old_skb->data;
		skb_pull(old_skb, sizeof(struct udphdr));

		nat64_translate_6to4(old_skb, udph->dest, IPPROTO_UDP);
		break;
	case NEXTHDR_ICMP:
		printk("mapmint: ICMP6\n");
		nat64_handle_icmp6(old_skb, ip6h);
		break;
	default:
		printk("nat64: [ipv6] Next header %d. Currently only TCP, UDP and ICMP6 is supported.\n", proto);
		break;
	}
}

static void nat64_translate_4to6_deep(struct sk_buff *old_skb, __be16 sport)
{
	struct sk_buff	*skb;
	struct iphdr	*iph;
	struct tcphdr	*tcph = NULL;
	struct udphdr	*udph = NULL;
	struct in6_addr	remote6;
	struct in6_addr	local6;
	int		skb_len = LL_MAX_HEADER + sizeof(struct ipv6hdr) + sizeof(struct icmphdr) + sizeof(struct ipv6hdr);

	iph = (struct iphdr *)old_skb->data;
 	skb_pull(old_skb, iph->ihl * 4);

	switch(iph->protocol) {
	case IPPROTO_UDP:
		udph = (struct udphdr *)old_skb->data;
		skb_len += sizeof(struct udphdr);
		skb_pull(old_skb, sizeof(struct udphdr));
		break;
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)old_skb->data;
		skb_len += tcph->doff * 4;
		skb_pull(old_skb, tcph->doff * 4);
		break;
	}

	skb_len += old_skb->len;

	//printk("nat64: [4to6] Generating IPv6 packet.\n");
	skb = alloc_skb(skb_len, GFP_ATOMIC);

	if (!skb) {
		printk("nat64: [4to6] Unable to allocate memory for new skbuff structure X(.\n");
		return;
	}

	skb_reserve(skb, skb_len);
	factory_clone_data(old_skb, skb);

	switch(iph->protocol) {
	case IPPROTO_UDP:
		factory_clone_udp(old_skb, skb);
		break;
	case IPPROTO_TCP:
		factory_clone_tcp(old_skb, skb, tcph->doff * 4);
		break;
	}

	assemble_ipv6_bmr(&remote6, iph->daddr);
	assemble_ipv6_local(&local6, iph->saddr);
	factory_translate_ip4(old_skb, skb, &local6, &remote6, iph->protocol, iph->ihl * 4);
	factory_clone_icmp(old_skb, skb, sport);
	assemble_ipv6_bmr(&remote6, ip_hdr(old_skb)->saddr); 
	factory_translate_ip4(old_skb, skb, &remote6, &local6, IPPROTO_ICMPV6, ip_hdrlen(old_skb));

	skb->dev = nat64_dev;
	nat64_dev->stats.rx_packets++;
	nat64_dev->stats.rx_bytes += skb->len;
	netif_rx(skb);

//	printk("nat64: [ipv4] Sending translated IPv6 packet.\n");
}

static void nat64_translate_4to6(struct sk_buff *old_skb, __be16 sport, int proto)
{
	struct sk_buff	*skb;
	struct in6_addr	remote6;
	struct in6_addr	local6;
	int		skb_len = LL_MAX_HEADER + sizeof(struct ipv6hdr) + old_skb->len;

	switch(proto) {
	case IPPROTO_UDP:
		skb_len += sizeof(struct udphdr);
		break;
	case IPPROTO_TCP:
		skb_len += tcp_hdrlen(old_skb);
		break;
	case IPPROTO_ICMPV6:
		skb_len += sizeof(struct icmphdr);
		break;
	}

	//printk("nat64: [4to6] Generating IPv6 packet.\n");
	skb = alloc_skb(skb_len, GFP_ATOMIC);

	if (!skb) {
		printk("nat64: [4to6] Unable to allocate memory for new skbuff structure X(.\n");
		return;
	}
	skb_reserve(skb, skb_len);
	factory_clone_data(old_skb, skb);

	switch(proto) {
	case IPPROTO_UDP:
		factory_clone_udp(old_skb, skb);
		break;
	case IPPROTO_TCP:
		factory_clone_tcp(old_skb, skb, tcp_hdrlen(old_skb));
		break;
	case IPPROTO_ICMPV6:
		factory_clone_icmp(old_skb, skb, sport);
		break;
	}
	assemble_ipv6_local(&remote6, ip_hdr(old_skb)->saddr);
	assemble_ipv6_bmr(&local6, ip_hdr(old_skb)->daddr);
	factory_translate_ip4(old_skb, skb, &remote6, &local6, proto, ip_hdrlen(old_skb));

	skb->dev = nat64_dev;
	nat64_dev->stats.rx_packets++;
	nat64_dev->stats.rx_bytes += skb->len;
	netif_rx(skb);

//	printk("nat64: [ipv4] Sending translated IPv6 packet.\n");
}

static inline unsigned int nat64_handle_tcp4(struct sk_buff *skb, struct iphdr *iph)
{
	struct tcphdr		*tcph = tcp_hdr(skb);

	if(skb->len < sizeof(struct tcphdr) && skb->len < tcp_hdrlen(skb))
		return NF_ACCEPT;

	skb_pull(skb, tcp_hdrlen(skb));

	nat64_translate_4to6(skb, tcph->source, IPPROTO_TCP);
	return NF_DROP;
}

static inline unsigned int nat64_handle_udp4(struct sk_buff *skb, struct iphdr *iph)
{
	struct udphdr		*udph = udp_hdr(skb);

	if(skb->len < sizeof(struct udphdr))
		return NF_ACCEPT;

	skb_pull(skb, sizeof(struct udphdr));

	nat64_translate_4to6(skb, udph->source, IPPROTO_UDP);
	return NF_DROP;
}

static inline unsigned int nat64_handle_icmp4(struct sk_buff *skb, struct iphdr *iph)
{
	__be16			new_type;
	struct icmphdr		*icmph = icmp_hdr(skb);

	if(skb->len < sizeof(struct icmphdr))
		return NF_ACCEPT;

	printk("AY: nat64_handle_icmp4\n");

	switch(icmph->type) {
	//		Informational messages
	case ICMP_ECHO:
		new_type = (ICMPV6_ECHO_REQUEST << 8) + icmph->code;
		break;
	case ICMP_ECHOREPLY:
		new_type = (ICMPV6_ECHO_REPLY << 8) + icmph->code;
		break;
	//		Error messages
	case ICMP_DEST_UNREACH:

		switch(icmph->code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
		case ICMP_SR_FAILED:
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
		case ICMP_HOST_ISOLATED:
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			new_type = (ICMPV6_DEST_UNREACH << 8) + ICMPV6_NOROUTE;
			break;
		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
		case ICMP_PKT_FILTERED:
		case ICMP_PREC_CUTOFF:
			new_type = (ICMPV6_DEST_UNREACH << 8) + ICMPV6_ADM_PROHIBITED;
			break;
		case ICMP_PROT_UNREACH:
			new_type = (ICMPV6_PARAMPROB << 8) + ICMPV6_UNK_NEXTHDR;
		/*
		Code 2 (Protocol unreachable):  Translate to an ICMPv6
		Parameter Problem (Type 4, Code value 1) and make the
		Pointer point to the IPv6 Next Header field.
		*/
			return NF_ACCEPT;
			break;
		case ICMP_FRAG_NEEDED:
			new_type = (ICMPV6_PKT_TOOBIG << 8);
		/*
		Code 4 (Fragmentation needed and DF set):  Translate to an
		ICMPv6 Packet Too Big message (Type 2) with Code value
		set to 0.  The MTU field MUST be adjusted for the
		difference between the IPv4 and IPv6 header sizes, i.e.
		minimum(advertised MTU+20, MTU_of_IPv6_nexthop,
		(MTU_of_IPv4_nexthop)+20).  Note that if the IPv4 router
		set the MTU field to zero, i.e., the router does not
		implement [RFC1191], then the translator MUST use the
		plateau values specified in [RFC1191] to determine a
		likely path MTU and include that path MTU in the ICMPv6
		packet.  (Use the greatest plateau value that is less
		than the returned Total Length field.)  In order to avoid
		back holes caused by ICMPv4 filtering or non [RFC2460]
		compatible IPv6 hosts (a workaround discussed in Section
		4), the translator MAY set the MTU to 1280 for any MTU
		values which are smaller than 1280.  The translator
		HOULD provide a method for operators to enable or
		disable this function.
		*/
			return NF_ACCEPT;
			break;
		case ICMP_PORT_UNREACH:
			new_type = (ICMPV6_DEST_UNREACH << 8) + ICMPV6_PORT_UNREACH;
			break;
		case ICMP_PREC_VIOLATION:
		default:
			return NF_ACCEPT;
		}
		skb_pull(skb, sizeof(struct icmphdr));
		nat64_translate_4to6_deep(skb, new_type);
		return NF_DROP;
	case ICMP_PARAMETERPROB:

		switch(icmph->code) {
		case 0:
			/*
			Code 0 (Pointer indicates the error):  Set the Code value to
			0 (Erroneous header field encountered) and update the
			pointer as defined in Figure 3 (If the Original IPv4
			Pointer Value is not listed or the Translated IPv6
			Pointer Value is listed as "n/a", silently drop the
			packet).
			*/
			return NF_ACCEPT;
			break;
		case 2:
			/*
			Code 2 (Bad length):  Set the Code value to 0 (Erroneous
			header field encountered) and update the pointer as
			defined in Figure 3 (If the Original IPv4 Pointer Value
			is not listed or the Translated IPv6 Pointer Value is
			listed as "n/a", silently drop the packet).
			*/
			return NF_ACCEPT;
			break;
		case 1:
		default:
			return NF_ACCEPT;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		new_type = (ICMPV6_TIME_EXCEED << 8) + icmph->code;

		skb_pull(skb, sizeof(struct icmphdr));
		nat64_translate_4to6_deep(skb, new_type);
		return NF_DROP;
	//		All drops
	case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT:
	case 6:		// Alternative address
	case 9:		// Router advertisment
	case 10:	// Router solicitation
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
	case ICMP_INFO_REQUEST:
	case ICMP_INFO_REPLY:
	case ICMP_ADDRESS:
	case ICMP_ADDRESSREPLY:
	default:
		printk("nat64: [icmp] Unsupported = %d, code = %hu\n", icmph->type, icmph->code);
		return NF_ACCEPT;
	}


	skb_pull(skb, sizeof(struct icmphdr));

	nat64_translate_4to6(skb, new_type, IPPROTO_ICMPV6);
	return NF_DROP;
}

unsigned int nat64_ipv4_input(struct sk_buff *skb)
{
	struct iphdr	*iph = ip_hdr(skb);
	printk("nat64: [ipv4] Got IPv4 packet (len %d). before check\n", skb->len);

	if(skb->len < sizeof(struct iphdr) || iph->version != 4)
		return NF_ACCEPT;

	printk("nat64: [ipv4] Got IPv4 packet (len %d).\n", skb->len);

	skb_pull(skb, ip_hdrlen(skb));
	skb_reset_transport_header(skb);

	switch(iph->protocol)
	{
		case IPPROTO_TCP:
			return nat64_handle_tcp4(skb, iph);
			break;
		case IPPROTO_UDP:
			return nat64_handle_udp4(skb, iph);
			break;
		case IPPROTO_ICMP:
			return nat64_handle_icmp4(skb, iph);
			break;
	}
	return NF_ACCEPT;
}

static unsigned int nat64_ipv4_input_wrapper(	unsigned int hooknum,
						struct sk_buff *skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
	unsigned int 	ret = NF_ACCEPT;

	if(skb->pkt_type != PACKET_HOST)
		return NF_ACCEPT;

	if (skb_linearize(skb) < 0) {
		printk("nat64: Unable to lineralize incoming IPv4 packet X(.\n");
		return NF_ACCEPT;
	}

	ret = nat64_ipv4_input(skb);

	if(ret == NF_ACCEPT) {
		skb_push(skb, ip_hdrlen(skb));
		printk("nat64: [ipv4] Returning packet to netfiler chain.\n");
	}
	return ret;
}

static struct nf_hook_ops nat64_nf_hook __read_mostly =
{
	.hook		= nat64_ipv4_input_wrapper,
	.owner		= THIS_MODULE,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_LOCAL_IN,
	.priority	= NF_IP_PRI_NAT_SRC,
};

static struct net_device *find_netdev_by_ip(__u32 ip_address)
{
	struct net_device	*dev, *ret;
	struct in_device	*in_dev;

	ret = NULL;

	rcu_read_lock();
	for_each_netdev(&init_net, dev) {
		in_dev = __in_dev_get_rtnl(dev);
		for_ifa(in_dev) {
			if(ifa->ifa_address == ip_address)
				ret = dev;
		} endfor_ifa(in_dev);

		if(ret)
			break;
	}
	rcu_read_unlock();

	return ret;
}


int parse_ipv4_address(char *ipv4_address) {
  int ret;
  char *pos;
  ret = in4_pton(ipv4_address, -1, (u8 *)&ipv4_addr, '/', NULL);
  if (!ret) {
    printk("nat64: ipv4 is malformed [%s] X(.\n", ipv4_address);
    ret = -1;
    goto error;
  }
  pos = strchr(ipv4_address, '/');

  if(pos) {
    ipv4_prefixlen = simple_strtol(++pos, NULL, 10);
    if(ipv4_prefixlen > 32 || ipv4_prefixlen < 1) {
      printk("nat64: ipv4 prefix is malformed [%s] X(.\n", ipv4_address);
      ret = -1;
      goto error;
    }
    ipv4_netmask = inet_make_mask(ipv4_prefixlen);
    ipv4_addr = ipv4_addr & ipv4_netmask;
    printk("nat64: using IPv4 subnet %pI4/%d (netmask %pI4).\n", &ipv4_addr, ipv4_prefixlen, &ipv4_netmask);
  }
  return ret;
error:
  return ret;
}

static int __init nat64_init(void)
{
	int ret = -1;

	printk("nat64: module loaded.\n");

	if(ipv4_address) {
	  if(!parse_ipv4_address(ipv4_address)) {
	    printk("nat64: ipv4_address parameter error\n");
	    ret = -1;
	    goto error;
          }
	}


	ret = in6_pton(dmr_prefix_address, -1, (u8 *)&dmr_prefix_base, '\0', NULL);
	if (!ret)
	{
		printk("nat64: prefix address is malformed [%s] X(.\n", dmr_prefix_address);
		ret = -1;
		goto error;
	}

	ret = in6_pton(local_prefix_address, -1, (u8 *)&local_prefix_base, '\0', NULL);
	if (!ret)
	{
		printk("nat64: local prefix address is malformed [%s] X(.\n", local_prefix_address);
		ret = -1;
		goto error;
	}

	printk("nat64: translating %s/%d to %s\n", dmr_prefix_address, dmr_prefix_len, ipv4_address);
	nat64_v4_dev = find_netdev_by_ip(ipv4_addr);

	if(nat64_v4_dev) {
		printk("nat64: %pI4 belongs to %s interface. Switching to packet hijacking and self routing mode.\n", &ipv4_addr, nat64_v4_dev->name);
		ret = nf_register_hook(&nat64_nf_hook);
		if (ret) {
			printk("NAT64: Unable to register netfilter hooks X(.\n");
			ret = -1;
			goto error;
		}
	}
	else
		printk("nat64: Packets will be transmitted via nat64 device.\n");


	bib_cache = kmem_cache_create("nat64_bib", sizeof(struct bib_entry), 0, 0, NULL);
	if (!bib_cache) {
		printk(KERN_ERR "nat64: Unable to create bib_entry slab cache\n");
		ret = -ENOMEM;
		goto cache_bib_error;
	}


	ret = nat64_netdev_create(&nat64_dev);
	if(ret)
	{
		printk(KERN_ERR "nat64: Unable to create nat64 device\n");
		goto dev_error;
	}
        create_new_proc_entry();

	return 0;

dev_error:
	kmem_cache_destroy(bib_cache);
cache_bib_error:
	kmem_cache_destroy(session_cache);
error:
	return ret;
}

static void __exit nat64_exit(void)
{
	nat64_netdev_destroy(nat64_dev);

        remove_proc_entry("mapmint", NULL);
	printk("mapmint: Removed proc entry\n");

	if(nat64_v4_dev)
		nf_unregister_hook(&nat64_nf_hook);

	kmem_cache_destroy(bib_cache);
	kmem_cache_destroy(session_cache);

	printk("nat64: module unloaded.\n");
}

module_init(nat64_init);
module_exit(nat64_exit);
