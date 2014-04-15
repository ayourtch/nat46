/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */
/* 
 * core nat46 functionality.
 * It does not know about network devices, modules or anything similar: 
 * those are abstracted away by other layers.
 */ 

#include <net/route.h>

#include "nat46-glue.h"
#include "nat46-core.h"

void
nat46debug_dump(int level, void *addr, int len)
{
  char tohex[] = "0123456789ABCDEF";
  int i = 0;
  int k = 0;
  unsigned char *pc = addr;

  char buf0[32];                // offset
  char buf1[64];                // hex
  char buf2[64];                // literal

  char *pc1;
  char *pc2;

  while(--len >= 0) {
    if(i % 16 == 0) {
      for(k=0; k<9; k++) {
        buf0[k] = 0;
      }
      for(k=0; k<8; k++) {
        buf0[7-k] = tohex[ 0xf & (i >> k) ];
      }
      buf0[8] = 0;
      buf1[0] = 0;
      buf2[0] = 0;
      pc1 = buf1;
      pc2 = buf2;
    }
    *pc1++ = tohex[*pc >> 4];
    *pc1++ = tohex[*pc & 15];
    *pc1++ = ' ';

    if(*pc >= 32 && *pc < 127) {
      *pc2++ = *pc;
    } else {
      *pc2++ = '.';
    }
    i++;
    pc++;
    if(i % 16 == 0) {
      *pc1 = 0;
      *pc2 = 0;
      nat46_reasm_debug(level, "%s:   %s  %s", buf0, buf1, buf2);
    }

  }
  if(i % 16 != 0) {
    while(i % 16 != 0) {
      *pc1++ = ' ';
      *pc1++ = ' ';
      *pc1++ = ' ';
      *pc2++ = ' ';
      i++;
    }
    *pc1 = 0;
    *pc2 = 0;
    nat46_reasm_debug(level, "%s:   %s  %s", buf0, buf1, buf2);
  }
}



/* return the current arg, and advance the tail to the next space-separated word */
char *get_next_arg(char **ptail) {
  char *pc = NULL;
  while ((*ptail) && (**ptail) && ((**ptail == ' ') || (**ptail == '\n'))) { 
    **ptail = 0;
    (*ptail)++;
  }
  pc = *ptail;
  
  while ((*ptail) && (**ptail) && ((**ptail != ' ') && (**ptail != '\n'))) { 
    (*ptail)++;
  }

  while ((*ptail) && (**ptail) && ((**ptail == ' ') || (**ptail == '\n'))) { 
    **ptail = 0;
    (*ptail)++;
  }

  if ((pc) && (0 == *pc)) {
    pc = NULL;
  }
  return pc;
}

/* 
 * Parse an IPv6 address (if pref_len is NULL), or prefix (if it isn't).
 * parses destructively (places \0 between address and prefix len)
 */
int try_parse_ipv6_prefix(struct in6_addr *pref, int *pref_len, char *arg) {
  int err = 0;
  char *arg_plen = strchr(arg, '/');
  if (arg_plen) {
    *arg_plen++ = 0;
    if (pref_len) {
      *pref_len = simple_strtol(arg_plen, NULL, 10);
    }
  }
  err = (1 != in6_pton(arg, -1, (u8 *)pref, '\0', NULL));
  return err;
}

int try_parse_v4_addr(u32 *v4addr, char *arg) {
  int err = (1 != in4_pton(arg, -1, (u8 *)v4addr, '/', NULL));
  return err;
}

/* 
 * Parse the config commands in the buffer, 
 * destructive (puts zero between the args) 
 */

int nat46_set_config(nat46_instance_t *nat46, char *buf, int count) {
  char *tail = buf;
  char *arg_name;
  int err = 0;
  while ((0 == err) && (NULL != (arg_name = get_next_arg(&tail)))) {
    if (0 == strcmp(arg_name, "debug")) {
      nat46->debug = simple_strtol(get_next_arg(&tail), NULL, 10);
    } else if (0 == strcmp(arg_name, "nat64pref")) {
      err = try_parse_ipv6_prefix(&nat46->nat64pref, &nat46->nat64pref_len, get_next_arg(&tail)); 
    } else if (0 == strcmp(arg_name, "v6bits")) {
      err = try_parse_ipv6_prefix(&nat46->my_v6bits, NULL, get_next_arg(&tail)); 
    } else if (0 == strcmp(arg_name, "v6mask")) {
      err = try_parse_ipv6_prefix(&nat46->my_v6mask, NULL, get_next_arg(&tail)); 
    } else if (0 == strcmp(arg_name, "v4addr")) {
      err = try_parse_v4_addr(&nat46->my_v4addr, get_next_arg(&tail));
    }
  }
  return err;
}


/* 
 * Get the nat46 configuration into a supplied buffer (if non-null),
 * return the needed buffer size to get the configuration into.
 */
int nat46_get_config(nat46_instance_t *nat46, char *buf, int count) {
  int ret = 0;
  return ret;
}


void ipv4_update_csum(struct sk_buff * skb, struct iphdr *iph) {
  __wsum sum1=0;
  __sum16 sum2=0;
  __sum16 oldsum=0;

  int iphdrlen = ip_hdrlen(skb);

  switch (iph->protocol) {
    case IPPROTO_TCP: {
      /* ripped from tcp_v4_send_check fro tcp_ipv4.c */
      struct tcphdr *th = tcp_hdr(skb);
      unsigned tcplen = 0;

      /* printk(KERN_ALERT "iph=%p th=%p copy->len=%d, th->check=%x iphdrlen=%d thlen=%d\n",
         iph, th, skb->len, ntohs(th->check), iphdrlen, thlen); */

      skb->csum = 0;
      skb->ip_summed = CHECKSUM_COMPLETE;

      // calculate payload
      oldsum = th->check;
      th->check = 0;
      tcplen = ntohs(iph->tot_len) - iphdrlen; /* skb->len - iphdrlen; (may cause trouble due to padding) */
      sum1 = csum_partial((char*)th, tcplen, 0); /* calculate checksum for TCP hdr+payload */
      sum2 = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, iph->protocol, sum1); /* add pseudoheader */
      th->check = sum2;
      break;
      }
    case IPPROTO_UDP: {
      struct udphdr *udp = udp_hdr(skb);
      unsigned udplen = 0;

      oldsum = udp->check;
      udp->check = 0;
      udplen = ntohs(iph->tot_len) - iphdrlen;

      sum1 = csum_partial((char*)udp, udplen, 0);
      sum2 = csum_tcpudp_magic(iph->saddr, iph->daddr, udplen, iph->protocol, sum1);
      udp->check = sum2;

      break;
      }
    case IPPROTO_ICMP: {
      struct icmphdr *icmph = (struct icmphdr *)(iph+1);
      unsigned icmplen = 0;
      icmplen = ntohs(iph->tot_len) - iphdrlen;
      icmph->checksum = 0;
      sum1 = csum_partial((char*)icmph, icmplen, 0);
      sum2 = csum_fold(sum1);
      icmph->checksum = sum2;
      nat46debug(5, "ICMP checksum %04x", icmph->checksum);
      break;
      }
    default:
      break;
  }
}


void nat46_fixup_icmp6(nat46_instance_t *nat46, struct ipv6hdr *ip6h, struct sk_buff *old_skb) {
  struct icmp6hdr *icmp6h = (struct icmp6hdr *)(ip6h + 1);
  if(icmp6h->icmp6_type & 128) {
    /* Informational ICMP */
    switch(icmp6h->icmp6_type) {
      case ICMPV6_ECHO_REQUEST:
        icmp6h->icmp6_type = ICMP_ECHO;
        break;
      case ICMPV6_ECHO_REPLY:
        icmp6h->icmp6_type = ICMP_ECHOREPLY;
        break;
    }
  } else {
    /* ICMPv6 errors */
  }
  ip6h->nexthdr = IPPROTO_ICMP;
}


int ip6_input_not_interested(nat46_instance_t *nat46, struct ipv6hdr *ip6h, struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IPV6)) {
    nat46debug(3, "Not an IPv6 packet", 0);
    return 1;
  }
  if(old_skb->len < sizeof(struct ipv6hdr) || ip6h->version != 6) {
    nat46debug(3, "Len short or not correct version: %d", ip6h->version);
    return 1;
  }
  if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST)) {
    nat46debug(3, "Source address not unicast", ip6h->version);
    return 1;
  }
  // FIXME: add the verification that the source is within the DMR
  // FIXME: add the verification that the destination matches our v6 "outside" address
  return 0;
}


__u32 xxx_my_v4addr;

struct sk_buff *try_reassembly(nat46_instance_t *nat46, struct sk_buff *old_skb) {
  struct ipv6hdr * hdr = ipv6_hdr(old_skb);
  struct frag_hdr *fh = (struct frag_hdr*)(hdr + 1);
  struct sk_buff *new_frag = NULL;
  struct sk_buff *ret_skb = NULL;
  struct sk_buff *first_frag = NULL;
  struct sk_buff *second_frag = NULL;
  int i;
  nat46_reasm_debug(1, "try_reassembly, frag_off value: %04x, nexthdr: %02x", fh->frag_off, fh->nexthdr);
  if(fh->frag_off == 0) {
    hdr->nexthdr = fh->nexthdr;
    hdr->payload_len = htons(ntohs(hdr->payload_len) - sizeof(struct frag_hdr));
    memmove(fh, (fh+1), old_skb->len - sizeof(struct frag_hdr));
    old_skb->len -= sizeof(struct frag_hdr);
    old_skb->end -= sizeof(struct frag_hdr);
    old_skb->tail -= sizeof(struct frag_hdr);
    nat46_reasm_debug(1, "reassembly successful, %d bytes shorter!", sizeof(struct frag_hdr));
    ret_skb = old_skb;
  } else {
    nat46_reasm_debug(1, "reassembly can not be done because fragment offset is nonzero: %04x", fh->frag_off); 
    
    for(i=0; 
            i < nat46->nfrags && 
            nat46->frags[i].identification != fh->identification && 
            (0 != ipv6_addr_cmp(&hdr->saddr, &nat46->frags[i].saddr)) &&
            (0 != ipv6_addr_cmp(&hdr->daddr, &nat46->frags[i].daddr));
        i++);
    if(i < nat46->nfrags) {
      /* Found a matching fragment in the queue, try to coalesce. */
        nat46_reasm_debug(1, "Found a matching frag id %08x queued at index %d", fh->identification, i);
        nat46_reasm_debug(1, "Queue frag_off: %04x, len: %04x; Current frag_off: %04x, len: %04x", ntohs(nat46->frags[i].frag_off), ntohs(ipv6_hdr(nat46->frags[i].skb)->payload_len), ntohs(fh->frag_off), ntohs(hdr->payload_len));

        if ( 
               (ntohs(nat46->frags[i].frag_off) & IP6_MF) && (0 == (ntohs(nat46->frags[i].frag_off) & IP6_OFFSET)) &&
               (0 == (ntohs(fh->frag_off) & IP6_MF)) && (ntohs(fh->frag_off) & IP6_OFFSET) ) {
          first_frag = nat46->frags[i].skb;
          second_frag = old_skb;
          nat46_reasm_debug(1, "First fragment is in the queue, second fragment just arrived", 0);
        } else if (
               (0 == (ntohs(nat46->frags[i].frag_off) & IP6_MF)) && (ntohs(nat46->frags[i].frag_off) & IP6_OFFSET) &&
               (ntohs(fh->frag_off) & IP6_MF) && (0 == (ntohs(fh->frag_off) & IP6_OFFSET)) ) {
          first_frag = old_skb;
          second_frag = nat46->frags[i].skb;
          nat46_reasm_debug(1, "Second fragment is in the queue, first fragment just arrived", 0);
        } else {
          first_frag = NULL;
          second_frag = nat46->frags[i].skb;
          nat46_reasm_debug(1, "Not sure which fragment is where, will just delete the frag from queue", 0);
        }
        if (first_frag) {
          struct frag_hdr *fh1 = (struct frag_hdr*)(ipv6_hdr(first_frag) + 1);
          struct frag_hdr *fh2 = (struct frag_hdr*)(ipv6_hdr(second_frag) + 1);

          if (ntohs(ipv6_hdr(first_frag)->payload_len) - sizeof(struct frag_hdr) == (IP6_OFFSET & ntohs(fh2->frag_off))) {
            nat46_reasm_debug(1, "pointers: head: %08x, data: %08x, tail: %08x, end: %08x", old_skb->head, old_skb->data, old_skb->tail, old_skb->end);
            nat46_reasm_debug(1, "expanding by: %d\n", ntohs(ipv6_hdr(second_frag)->payload_len) - 2*sizeof(struct frag_hdr));
            pskb_expand_head(first_frag, 0, ntohs(ipv6_hdr(second_frag)->payload_len) - 2*sizeof(struct frag_hdr), GFP_ATOMIC);
            fh1 = (struct frag_hdr*)(ipv6_hdr(first_frag) + 1);
            hdr = ipv6_hdr(first_frag);
            hdr->nexthdr = fh1->nexthdr;
            nat46_reasm_debug(1, "Reassembled next header: %d", hdr->nexthdr);
            memmove(fh1, (fh1+1), first_frag->len - sizeof(struct frag_hdr));
            first_frag->len -= sizeof(struct frag_hdr);
            first_frag->tail -= sizeof(struct frag_hdr);

            memcpy(skb_tail_pointer(first_frag), (fh2+1), ntohs(ipv6_hdr(second_frag)->payload_len) - sizeof(struct frag_hdr));
            first_frag->len += ntohs(ipv6_hdr(second_frag)->payload_len) - sizeof(struct frag_hdr);
            first_frag->tail += ntohs(ipv6_hdr(second_frag)->payload_len) - sizeof(struct frag_hdr);

            hdr->payload_len = htons(ntohs(hdr->payload_len) + ntohs(ipv6_hdr(second_frag)->payload_len) - 2*sizeof(struct frag_hdr));
            nat46_reasm_debug(1, "reassembly successful from 2 frags, len: %d!", first_frag->len);
            nat46_reasm_debug(1, "pointers: head: %08x, data: %08x, tail: %08x, end: %08x", old_skb->head, old_skb->data, old_skb->tail, old_skb->end);
            // nat46debug_dump(-1, old_skb->head, old_skb->len);
            
          } else {
            nat46_reasm_debug(1, "Can not reassemble two fragments, drop both", 0);
            // nat46debug_dump(-1, first_frag->head, first_frag->len);
          }
        }
        if (first_frag == nat46->frags[i].skb) {
          pskb_expand_head(old_skb, 0, first_frag->len - old_skb->len, GFP_ATOMIC);
          memcpy(old_skb->data, first_frag->data, first_frag->len);
        }
        kfree_skb(nat46->frags[i].skb); 
        ret_skb = old_skb;
           
        if(nat46->nfrags > 1) {
          memcpy(&nat46->frags[i], &nat46->frags[nat46->nfrags-1], sizeof(nat46->frags[i]));
        }
        if (nat46->nfrags > 0) { 
          memset(&nat46->frags[nat46->nfrags-1], 0, sizeof(nat46->frags[nat46->nfrags-1]));
          nat46->nfrags--;
        }
        nat46_reasm_debug(1, "Deleted fragment with index %d, new nfrags: %d", i, nat46->nfrags);
     
    } else {
      if (nat46->nfrags < NAT46_MAX_V6_FRAGS) {
        i = nat46->nfrags++;
        new_frag = skb_copy(old_skb, GFP_ATOMIC);
        memcpy(&nat46->frags[i].saddr, &hdr->saddr, 16);
        memcpy(&nat46->frags[i].daddr, &hdr->daddr, 16);
        nat46->frags[i].identification = fh->identification;
        nat46->frags[i].frag_off = fh->frag_off;
        nat46->frags[i].skb = new_frag;
        nat46_reasm_debug(1, "Fragment id %08x queued at index %d", fh->identification, i);
        ret_skb = old_skb;
      } else {
        assert("ran out of fragments!" == NULL);
      }
     
       
    }
  }
  return ret_skb;
}

/********************************************************************

From RFC6052, section 2.2:

    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |PL| 0-------------32--40--48--56--64--72--80--88--96--104---------|
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |32|     prefix    |v4(32)         | u | suffix                    |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |40|     prefix        |v4(24)     | u |(8)| suffix                |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |48|     prefix            |v4(16) | u | (16)  | suffix            |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |56|     prefix                |(8)| u |  v4(24)   | suffix        |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |64|     prefix                    | u |   v4(32)      | suffix    |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |96|     prefix                                    |    v4(32)     |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

********************************************************************/

void v4_to_nat64(nat46_instance_t *nat46, void *pipv4, void *pipv6) {
  char *ipv4 = pipv4;
  char *ipv6 = pipv6;

  /* 'u' byte and suffix are zero */ 
  memset(&ipv6[8], 0, 8); 
  switch(nat46->nat64pref_len) {
    case 32:
      memcpy(ipv6, &nat46->nat64pref, 4);
      memcpy(&ipv6[4], ipv4, 4);
      break;
    case 40:
      memcpy(ipv6, &nat46->nat64pref, 5);
      memcpy(&ipv6[5], ipv4, 3);
      ipv6[9] = ipv4[3];
      break;
    case 48:
      memcpy(ipv6, &nat46->nat64pref, 6);
      ipv6[6] = ipv4[0];
      ipv6[7] = ipv4[1];
      ipv6[9] = ipv4[2];
      ipv6[10] = ipv4[3];
      break;
    case 56:
      memcpy(ipv6, &nat46->nat64pref, 7);
      ipv6[7] = ipv4[0];
      ipv6[9] = ipv4[1];
      ipv6[10] = ipv4[2];
      ipv6[11] = ipv4[3];
      break;
    case 64:
      memcpy(ipv6, &nat46->nat64pref, 8);
      memcpy(&ipv6[9], ipv4, 4);
      break;
    case 96:
      memcpy(ipv6, &nat46->nat64pref, 12);
      memcpy(&ipv6[12], ipv4, 4);
      break;
  }
}

int nat64_to_v4(nat46_instance_t *nat46, void *pipv6, void *pipv4) {
  char *ipv4 = pipv4;
  char *ipv6 = pipv6;
  int cmp = -1;
  switch(nat46->nat64pref_len) {
    case 32:
      cmp = memcmp(ipv6, &nat46->nat64pref, 4);
      break;
    case 40:
      cmp = memcmp(ipv6, &nat46->nat64pref, 5);
      break;
    case 48:
      cmp = memcmp(ipv6, &nat46->nat64pref, 6);
      break;
    case 56:
      cmp = memcmp(ipv6, &nat46->nat64pref, 7);
      break;
    case 64:
      cmp = memcmp(ipv6, &nat46->nat64pref, 8);
      break;
    case 96:
      cmp = memcmp(ipv6, &nat46->nat64pref, 12);
      break;
  }
  if (cmp) {
    /* Not in NAT64 prefix */
    return 0;
  }
  switch(nat46->nat64pref_len) {
    case 32:
      memcpy(ipv4, &ipv6[4], 4);
      break;
    case 40:
      memcpy(ipv4, &ipv6[5], 3);
      ipv4[3] = ipv6[9];
      break;
    case 48:
      ipv4[0] = ipv6[6];
      ipv4[1] = ipv6[7];
      ipv4[2] = ipv6[9];
      ipv4[3] = ipv6[10];
      break;
    case 56:
      ipv4[0] = ipv6[7];
      ipv4[1] = ipv6[9];
      ipv4[2] = ipv6[10];
      ipv4[3] = ipv6[11];
      break;
    case 64:
      memcpy(ipv4, &ipv6[9], 4);
      break;
    case 96:
      memcpy(ipv4, &ipv6[12], 4);
      break;
  }
  return 1;
}


void nat46_fixup_icmp(nat46_instance_t *nat46, struct iphdr *iph, struct sk_buff *old_skb) {
  struct icmphdr *icmph = (struct icmphdr *)(iph+1);
  switch(icmph->type) {
    case ICMP_ECHO:
      icmph->type = ICMPV6_ECHO_REQUEST;
      nat46debug(3, "ICMP echo request translated into IPv6", icmph->type); 
      break;
    case ICMP_ECHOREPLY:
      icmph->type = ICMPV6_ECHO_REPLY;
      nat46debug(3, "ICMP echo reply translated into IPv6", icmph->type); 
      break;
  }
  iph->protocol = NEXTHDR_ICMP;
}



void nat46_ipv6_input(struct sk_buff *old_skb) {
  struct ipv6hdr *ip6h = ipv6_hdr(old_skb);
  nat46_instance_t *nat46 = get_nat46_instance(old_skb);
  uint16_t proto;

  struct ipv6hdr * hdr = ipv6_hdr(old_skb);
  struct iphdr * iph;
  __u32 v4saddr, v4daddr;
  struct sk_buff * new_skb = 0;
  int err = -1;
  int truncSize = 0;

  nat46debug(1, "nat46_ipv6_input packet", 0);

  if(ip6_input_not_interested(nat46, ip6h, old_skb)) {
    nat46debug(1, "nat46_ipv6_input not interested", 0);
    goto done;
  }
  nat46debug(1, "nat46_ipv6_input next hdr: %d, len: %d", 
                ip6h->nexthdr, old_skb->len);
  // debug_dump(DBG_V6, 1, old_skb->data, 64);

  proto = ip6h->nexthdr;
  if (proto == NEXTHDR_FRAGMENT) {
    old_skb = try_reassembly(nat46, old_skb);
    if (!old_skb) {
      goto done;
    }
    hdr = ipv6_hdr(old_skb);
    ip6h = ipv6_hdr(old_skb);
    proto = ip6h->nexthdr;
  }
  
  switch(proto) {
    case NEXTHDR_TCP:
    case NEXTHDR_UDP:
      break;
    case NEXTHDR_ICMP:
      nat46_fixup_icmp6(nat46, ip6h, old_skb);
      break;
    default:
      nat46debug(0, "[ipv6] Next header: %u. Only TCP, UDP, and ICMP6 are supported.", proto);
      goto done;
  }


  nat64_to_v4(nat46, &hdr->saddr, &v4saddr);
  v4daddr = xxx_my_v4addr;

  new_skb = skb_copy(old_skb, GFP_ATOMIC); // other possible option: GFP_ATOMIC

  /* Remove any debris in the socket control block */
  memset(IPCB(new_skb), 0, sizeof(struct inet_skb_parm));

  /* modify packet: actual IPv6->IPv4 transformation */
  truncSize = sizeof(struct ipv6hdr) - sizeof(struct iphdr); /* chop first 20 bytes */
  skb_pull(new_skb, truncSize);
  skb_reset_network_header(new_skb);
  skb_set_transport_header(new_skb,20); /* transport (TCP/UDP/ICMP/...) header starts after 20 bytes */

  /* build IPv4 header */
  iph = ip_hdr(new_skb);
  iph->ttl = hdr->hop_limit;
  iph->saddr = v4saddr;
  iph->daddr = v4daddr;
  iph->protocol = hdr->nexthdr;
  *((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (0x00/*tos*/ & 0xff));
  iph->frag_off = htons(IP_DF);

  /* iph->tot_len = htons(new_skb->len); // almost good, but it may cause troubles with sizeof(IPv6 pkt)<64 (padding issue) */
  iph->tot_len = htons( ntohs(hdr->payload_len)+ 20 /*sizeof(ipv4hdr)*/ );
  assert(ntohs(iph->tot_len) < 2000);
  iph->check = 0;
  iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
  new_skb->protocol = htons(ETH_P_IP);

  ipv4_update_csum(new_skb, iph); /* update L4 (TCP/UDP/ICMP) checksum */

  /* try to find route for this packet */
  err = ip_route_input(new_skb, v4daddr, v4saddr, 0, new_skb->dev);

  if (err==0) {
    /* FIXME err = ip_forward(new_skb); */
  }
  new_skb->dev = old_skb->dev;

  netif_rx(new_skb);

  /* TBD: should copy be released here? */

done:
  release_nat46_instance(nat46);
}



void ip6_update_csum(struct sk_buff * skb, struct ipv6hdr * ip6hdr)
{
  u32 sum1=0;
  u16 sum2=0;
  __sum16 oldsum = 0;

  switch (ip6hdr->nexthdr) {
    case IPPROTO_TCP: {
      struct tcphdr *th = tcp_hdr(skb);
      unsigned tcplen = 0;

      oldsum = th->check;
      tcplen = ntohs(ip6hdr->payload_len); /* TCP header + payload */
      th->check = 0;
      sum1 = csum_partial((char*)th, tcplen, 0); /* calculate checksum for TCP hdr+payload */
      sum2 = csum_ipv6_magic(&ip6hdr->saddr, &ip6hdr->daddr, tcplen, ip6hdr->nexthdr, sum1); /* add pseudoheader */
      th->check = sum2;
      break;
      }
    case IPPROTO_UDP: {
      struct udphdr *udp = udp_hdr(skb);
      unsigned udplen = ntohs(ip6hdr->payload_len); /* UDP hdr + payload */

      oldsum = udp->check;
      udp->check = 0;

      sum1 = csum_partial((char*)udp, udplen, 0); /* calculate checksum for UDP hdr+payload */
      sum2 = csum_ipv6_magic(&ip6hdr->saddr, &ip6hdr->daddr, udplen, ip6hdr->nexthdr, sum1); /* add pseudoheader */

      udp->check = sum2;

      break;
      }
    case NEXTHDR_ICMP: {
      struct icmp6hdr *icmp6h = (struct icmp6hdr *)(ip6hdr + 1);
      unsigned icmp6len = 0;

      icmp6len = ntohs(ip6hdr->payload_len); /* ICMP header + payload */
      icmp6h->icmp6_cksum = 0;
      sum1 = csum_partial((char*)icmp6h, icmp6len, 0); /* calculate checksum for TCP hdr+payload */
      sum2 = csum_ipv6_magic(&ip6hdr->saddr, &ip6hdr->daddr, icmp6len, ip6hdr->nexthdr, sum1); /* add pseudoheader */
      icmp6h->icmp6_cksum = sum2;
      break;
      }
    }
}

int ip4_input_not_interested(nat46_instance_t *nat46, struct iphdr *iph, struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IP)) {
    nat46debug(3, "Not an IPv4 packet", 0);
    return 1;
  }
  // FIXME: check source to be within our prefix
  return 0;
}

void nat46_ipv4_input(struct sk_buff *old_skb) {
  nat46_instance_t *nat46 = get_nat46_instance(old_skb);
  struct sk_buff *new_skb;

  int tclass = 0;
  int flowlabel = 0;

  struct ipv6hdr * hdr6;
  struct iphdr * hdr4 = ip_hdr(old_skb);

  char v6saddr[16], v6daddr[16];

  memset(v6saddr, 1, 16);
  memset(v6daddr, 2, 16);
  v4_to_nat64(nat46, &hdr4->daddr, v6daddr);
  memcpy(v6saddr, &nat46->my_v6bits, 16);
  memcpy(&xxx_my_v4addr, &hdr4->saddr, 4);

  if (ip4_input_not_interested(nat46, hdr4, old_skb)) {
    goto done;
  }
  nat46debug(1, "nat46_ipv4_input packet", 0);
  // nat46debug_dump(1, old_skb->data, old_skb->len);

  if (ntohs(hdr4->tot_len) > 1480) {
    // FIXME: need to send Packet Too Big here.
    goto done; 
  }

  switch(hdr4->protocol) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
      break;
    case IPPROTO_ICMP:
      nat46_fixup_icmp(nat46, hdr4, old_skb);
      break;
    default:
      nat46debug(3, "[ipv6] Next header: %u. Only TCP, UDP, and ICMP are supported.", hdr4->protocol);
      goto done;
  }

  new_skb = skb_copy(old_skb, GFP_ATOMIC);

  /* Remove any debris in the socket control block */
  memset(IPCB(new_skb), 0, sizeof(struct inet_skb_parm));

  /* expand header (add 20 extra bytes at the beginning of sk_buff) */
  pskb_expand_head(new_skb, 20, 0, GFP_ATOMIC);

  skb_push(new_skb, sizeof(struct ipv6hdr) - sizeof(struct iphdr)); /* push boundary by extra 20 bytes */

  skb_reset_network_header(new_skb);
  skb_set_transport_header(new_skb, 40); /* transport (TCP/UDP/ICMP/...) header starts after 40 bytes */

  hdr6 = ipv6_hdr(new_skb);
  memset(hdr6, 0, sizeof(*hdr6));

  /* build IPv6 header */
  tclass = 0; /* traffic class */
  *(__be32 *)hdr6 = htonl(0x60000000 | (tclass << 20)) | flowlabel; /* version, priority, flowlabel */

  /* IPv6 length is a payload length, IPv4 is hdr+payload */
  hdr6->payload_len = htons(ntohs(hdr4->tot_len) - sizeof(struct iphdr)); 

  hdr6->nexthdr = hdr4->protocol;
  hdr6->hop_limit = hdr4->ttl;
  memcpy(&hdr6->saddr, v6saddr, 16);
  memcpy(&hdr6->daddr, v6daddr, 16);

  new_skb->priority = old_skb->priority;
  // new_skb->mark = old_skb->mark;
  new_skb->protocol = htons(ETH_P_IPV6);

  ip6_update_csum(new_skb, hdr6);

  // FIXME: check if you can not fit the packet into the cached MTU
  // if (dst_mtu(skb_dst(new_skb))==0) { }

  new_skb->dev = old_skb->dev;
  netif_rx(new_skb);


done:
  release_nat46_instance(nat46);
}


int is_valid_nat46(nat46_instance_t *nat46) {
  return (nat46 && (nat46->sig == NAT46_SIGNATURE));
}

