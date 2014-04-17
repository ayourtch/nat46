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
nat46debug_dump(nat46_instance_t *nat46, int level, void *addr, int len)
{
  char tohex[] = "0123456789ABCDEF";
  int i = 0;
  int k = 0;
  unsigned char *pc = addr;

  char buf0[32];                // offset
  char buf1[64];                // hex
  char buf2[64];                // literal

  char *pc1 = buf1;
  char *pc2 = buf2;

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

int try_parse_ipv4_prefix(u32 *v4addr, int *pref_len, char *arg) {
  int err = 0;
  char *arg_plen = strchr(arg, '/');
  if (arg_plen) {
    *arg_plen++ = 0;
    if (pref_len) {
      *pref_len = simple_strtol(arg_plen, NULL, 10);
    }
  }
  err = (1 != in4_pton(arg, -1, (u8 *)v4addr, '/', NULL));
  return err;
}


/* 
 * parse a rule argument and put config into a rule.
 * advance the tail to prepare for the next arg parsing.
 * destructive.
 */ 

int try_parse_rule_arg(nat46_xlate_rule_t *rule, char *arg_name, char **ptail) {
  int err = 0;
  char *val = get_next_arg(ptail);
  if (NULL == val) {
    err = -1;
  } else if (0 == strcmp(arg_name, "v6")) {
    err = try_parse_ipv6_prefix(&rule->v6_pref, &rule->v6_pref_len, val); 
  } else if (0 == strcmp(arg_name, "v4")) {
    err = try_parse_ipv4_prefix(&rule->v4_pref, &rule->v4_pref_len, val);
  } else if (0 == strcmp(arg_name, "ea-len")) {
    rule->ea_len = simple_strtol(val, NULL, 10);
  } else if (0 == strcmp(arg_name, "psid-offset")) {
    rule->psid_offset = simple_strtol(val, NULL, 10);
  } else if (0 == strcmp(arg_name, "style")) {
    if (0 == strcmp("MAP", val)) {
      rule->style = NAT46_XLATE_MAP;
    } else if (0 == strcmp("MAP0", val)) {
      rule->style = NAT46_XLATE_MAP0;
    } else if (0 == strcmp("RFC6052", val)) {
      rule->style = NAT46_XLATE_RFC6052;
    } else if (0 == strcmp("NONE", val)) {
      rule->style = NAT46_XLATE_NONE;
    } else {
      err = 1;
    }
  }
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
  char *val;
  while ((0 == err) && (NULL != (arg_name = get_next_arg(&tail)))) {
    if (0 == strcmp(arg_name, "debug")) {
      val = get_next_arg(&tail);
      if (val) {
        nat46->debug = simple_strtol(val, NULL, 10);
      }
    } else if (arg_name == strstr(arg_name, "local.")) {
      arg_name += strlen("local.");
      nat46debug(13, "Setting local xlate parameter");
      err = try_parse_rule_arg(&nat46->local_rule, arg_name, &tail);
    } else if (arg_name == strstr(arg_name, "remote.")) {
      arg_name += strlen("remote.");
      nat46debug(13, "Setting remote xlate parameter");
      err = try_parse_rule_arg(&nat46->remote_rule, arg_name, &tail);
    }
  }
  return err;
}

char *xlate_style_to_string(nat46_xlate_style_t style) {
  switch(style) {
    case NAT46_XLATE_NONE:
      return "NONE";
    case NAT46_XLATE_MAP:
      return "MAP";
    case NAT46_XLATE_MAP0:
      return "MAP0";
    case NAT46_XLATE_RFC6052:
      return "RFC6052";
  }
  return "unknown";
}

/* 
 * Get the nat46 configuration into a supplied buffer (if non-null).
 */
int nat46_get_config(nat46_instance_t *nat46, char *buf, int count) {
  int ret = 0;
  char *format = "local.v4 %pI4/%d local.v6 %pI6c/%d local.style %s local.ea-len %d local.psid-offset %d remote.v4 %pI4/%d remote.v6 %pI6c/%d remote.style %s remote.ea-len %d remote.psid-offset %d debug %d";

  ret = snprintf(buf, count, format,
		&nat46->local_rule.v4_pref, nat46->local_rule.v4_pref_len, 
		&nat46->local_rule.v6_pref, nat46->local_rule.v6_pref_len, 
		xlate_style_to_string(nat46->local_rule.style), nat46->local_rule.ea_len, nat46->local_rule.psid_offset,
		
		&nat46->remote_rule.v4_pref, nat46->remote_rule.v4_pref_len, 
		&nat46->remote_rule.v6_pref, nat46->remote_rule.v6_pref_len, 
		xlate_style_to_string(nat46->remote_rule.style), nat46->remote_rule.ea_len, nat46->remote_rule.psid_offset,
		nat46->debug);
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
      break;
      }
    default:
      break;
  }
}


static uint16_t nat46_fixup_icmp6(nat46_instance_t *nat46, struct ipv6hdr *ip6h, struct sk_buff *old_skb) {
  struct icmp6hdr *icmp6h = (struct icmp6hdr *)(ip6h + 1);
  uint16_t ret = 0;
  if(icmp6h->icmp6_type & 128) {
    /* Informational ICMP */
    switch(icmp6h->icmp6_type) {
      case ICMPV6_ECHO_REQUEST:
        icmp6h->icmp6_type = ICMP_ECHO;
        ret = icmp6h->icmp6_identifier;
        nat46debug(3, "ICMPv6 echo request translated into IPv4, id: %d", ntohs(ret)); 
        break;
      case ICMPV6_ECHO_REPLY:
        icmp6h->icmp6_type = ICMP_ECHOREPLY;
        ret = icmp6h->icmp6_identifier;
        nat46debug(3, "ICMPv6 echo reply translated into IPv4, id: %d", ntohs(ret)); 
        break;
    }
  } else {
    /* ICMPv6 errors */
  }
  ip6h->nexthdr = IPPROTO_ICMP;
  return ret;
}


int ip6_input_not_interested(nat46_instance_t *nat46, struct ipv6hdr *ip6h, struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IPV6)) {
    nat46debug(3, "Not an IPv6 packet");
    return 1;
  }
  if(old_skb->len < sizeof(struct ipv6hdr) || ip6h->version != 6) {
    nat46debug(3, "Len short or not correct version: %d", ip6h->version);
    return 1;
  }
  if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST)) {
    nat46debug(3, "Source address not unicast");
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
    nat46_reasm_debug(1, "reassembly successful, %ld bytes shorter!", sizeof(struct frag_hdr));
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
          nat46_reasm_debug(1, "First fragment is in the queue, second fragment just arrived");
        } else if (
               (0 == (ntohs(nat46->frags[i].frag_off) & IP6_MF)) && (ntohs(nat46->frags[i].frag_off) & IP6_OFFSET) &&
               (ntohs(fh->frag_off) & IP6_MF) && (0 == (ntohs(fh->frag_off) & IP6_OFFSET)) ) {
          first_frag = old_skb;
          second_frag = nat46->frags[i].skb;
          nat46_reasm_debug(1, "Second fragment is in the queue, first fragment just arrived");
        } else {
          first_frag = NULL;
          second_frag = nat46->frags[i].skb;
          nat46_reasm_debug(1, "Not sure which fragment is where, will just delete the frag from queue");
        }
        if (first_frag) {
          struct frag_hdr *fh1 = (struct frag_hdr*)(ipv6_hdr(first_frag) + 1);
          struct frag_hdr *fh2 = (struct frag_hdr*)(ipv6_hdr(second_frag) + 1);

          if (ntohs(ipv6_hdr(first_frag)->payload_len) - sizeof(struct frag_hdr) == (IP6_OFFSET & ntohs(fh2->frag_off))) {
/*
            nat46_reasm_debug(1, "oldskb delta from head: data: %d, tail: %d, end: %d", old_skb->data - old_skb->head, 
                                 old_skb->tail - old_skb->head, old_skb->end - old_skb->head);
*/
            nat46_reasm_debug(1, "expanding by: %ld\n", ntohs(ipv6_hdr(second_frag)->payload_len) - 2*sizeof(struct frag_hdr));
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
            // nat46_reasm_debug(1, "pointers: head: %08x, data: %08x, tail: %08x, end: %08x", old_skb->head, old_skb->data, old_skb->tail, old_skb->end);
            // nat46debug_dump(nat46, 1, old_skb->head, old_skb->len);
            
          } else {
            nat46_reasm_debug(1, "Can not reassemble two fragments, drop both");
            // nat46debug_dump(-1, first_frag->head, first_frag->len);
          }
        }
        if (first_frag == nat46->frags[i].skb) {
          int old_len = old_skb->len;
          nat46_reasm_debug(1, "Need to copy the data from the first fragment into the current and increase the len: (%d -> %d+%d)", old_len, old_len, first_frag->len);
          skb_put(old_skb, first_frag->len - old_len);
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

void xlate_v4_to_nat64(nat46_instance_t *nat46, nat46_xlate_rule_t *rule, void *pipv4, void *pipv6) {
  char *ipv4 = pipv4;
  char *ipv6 = pipv6;

  /* 'u' byte and suffix are zero */ 
  memset(&ipv6[8], 0, 8); 
  switch(rule->v6_pref_len) {
    case 32:
      memcpy(ipv6, &rule->v6_pref, 4);
      memcpy(&ipv6[4], ipv4, 4);
      break;
    case 40:
      memcpy(ipv6, &rule->v6_pref, 5);
      memcpy(&ipv6[5], ipv4, 3);
      ipv6[9] = ipv4[3];
      break;
    case 48:
      memcpy(ipv6, &rule->v6_pref, 6);
      ipv6[6] = ipv4[0];
      ipv6[7] = ipv4[1];
      ipv6[9] = ipv4[2];
      ipv6[10] = ipv4[3];
      break;
    case 56:
      memcpy(ipv6, &rule->v6_pref, 7);
      ipv6[7] = ipv4[0];
      ipv6[9] = ipv4[1];
      ipv6[10] = ipv4[2];
      ipv6[11] = ipv4[3];
      break;
    case 64:
      memcpy(ipv6, &rule->v6_pref, 8);
      memcpy(&ipv6[9], ipv4, 4);
      break;
    case 96:
      memcpy(ipv6, &rule->v6_pref, 12);
      memcpy(&ipv6[12], ipv4, 4);
      break;
  }
}

int xlate_nat64_to_v4(nat46_instance_t *nat46, nat46_xlate_rule_t *rule, void *pipv6, void *pipv4) {
  char *ipv4 = pipv4;
  char *ipv6 = pipv6;
  int cmp = -1;
  int v6_pref_len = rule->v6_pref_len;

  switch(v6_pref_len) {
    case 32:
      cmp = memcmp(ipv6, &rule->v6_pref, 4);
      break;
    case 40:
      cmp = memcmp(ipv6, &rule->v6_pref, 5);
      break;
    case 48:
      cmp = memcmp(ipv6, &rule->v6_pref, 6);
      break;
    case 56:
      cmp = memcmp(ipv6, &rule->v6_pref, 7);
      break;
    case 64:
      cmp = memcmp(ipv6, &rule->v6_pref, 8);
      break;
    case 96:
      cmp = memcmp(ipv6, &rule->v6_pref, 12);
      break;
  }
  if (cmp) {
    /* Not in NAT64 prefix */
    return 0;
  }
  switch(v6_pref_len) {
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

/*

The below bitarray copy code is from 

http://stackoverflow.com/questions/3534535/whats-a-time-efficient-algorithm-to-copy-unaligned-bit-arrays
 
*/

#define CHAR_BIT 8
#define PREPARE_FIRST_COPY()                                      \
    do {                                                          \
    if (src_len >= (CHAR_BIT - dst_offset_modulo)) {              \
        *dst     &= reverse_mask[dst_offset_modulo];              \
        src_len -= CHAR_BIT - dst_offset_modulo;                  \
    } else {                                                      \
        *dst     &= reverse_mask[dst_offset_modulo]               \
              | reverse_mask_xor[dst_offset_modulo + src_len + 1];\
         c       &= reverse_mask[dst_offset_modulo + src_len    ];\
        src_len = 0;                                              \
    } } while (0)


static void
bitarray_copy(const void *src_org, int src_offset, int src_len,
                    void *dst_org, int dst_offset)
{
/*
    static const unsigned char mask[] =
        { 0x55, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff };
*/
    static const unsigned char reverse_mask[] =
        { 0x55, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
    static const unsigned char reverse_mask_xor[] =
        { 0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01, 0x00 };

    if (src_len) {
        const unsigned char *src;
              unsigned char *dst;
        int                  src_offset_modulo,
                             dst_offset_modulo;

        src = src_org + (src_offset / CHAR_BIT);
        dst = dst_org + (dst_offset / CHAR_BIT);

        src_offset_modulo = src_offset % CHAR_BIT;
        dst_offset_modulo = dst_offset % CHAR_BIT;

        if (src_offset_modulo == dst_offset_modulo) {
            int              byte_len;
            int              src_len_modulo;
            if (src_offset_modulo) {
                unsigned char   c;

                c = reverse_mask_xor[dst_offset_modulo]     & *src++;

                PREPARE_FIRST_COPY();
                *dst++ |= c;
            }

            byte_len = src_len / CHAR_BIT;
            src_len_modulo = src_len % CHAR_BIT;

            if (byte_len) {
                memcpy(dst, src, byte_len);
                src += byte_len;
                dst += byte_len;
            }
            if (src_len_modulo) {
                *dst     &= reverse_mask_xor[src_len_modulo];
                *dst |= reverse_mask[src_len_modulo]     & *src;
            }
        } else {
            int             bit_diff_ls,
                            bit_diff_rs;
            int             byte_len;
            int             src_len_modulo;
            unsigned char   c;
            /*
             * Begin: Line things up on destination. 
             */
            if (src_offset_modulo > dst_offset_modulo) {
                bit_diff_ls = src_offset_modulo - dst_offset_modulo;
                bit_diff_rs = CHAR_BIT - bit_diff_ls;

                c = *src++ << bit_diff_ls;
                c |= *src >> bit_diff_rs;
                c     &= reverse_mask_xor[dst_offset_modulo];
            } else {
                bit_diff_rs = dst_offset_modulo - src_offset_modulo;
                bit_diff_ls = CHAR_BIT - bit_diff_rs;

                c = *src >> bit_diff_rs     &
                    reverse_mask_xor[dst_offset_modulo];
            }
            PREPARE_FIRST_COPY();
            *dst++ |= c;

            /*
             * Middle: copy with only shifting the source. 
             */
            byte_len = src_len / CHAR_BIT;

            while (--byte_len >= 0) {
                c = *src++ << bit_diff_ls;
                c |= *src >> bit_diff_rs;
                *dst++ = c;
            }

            /*
             * End: copy the remaing bits; 
             */
            src_len_modulo = src_len % CHAR_BIT;
            if (src_len_modulo) {
                c = *src++ << bit_diff_ls;
                c |= *src >> bit_diff_rs;
                c     &= reverse_mask[src_len_modulo];

                *dst     &= reverse_mask_xor[src_len_modulo];
                *dst |= c;
            }
        }
    }
}

int xlate_map_v4_to_v6(nat46_instance_t *nat46, nat46_xlate_rule_t *rule, void *pipv4, void *pipv6, uint16_t l4id, int map_version) {
  int ret = 0;
  u32 *pv4u32 = pipv4;
  uint8_t *p6 = pipv6;

  uint16_t psid;
  uint8_t psid_bits_len;
  uint8_t v4_lsb_bits_len = 32 - rule->v4_pref_len;


  /* check that the ipv4 address is within the IPv4 map domain and reject if not */

  if ( (ntohl(*pv4u32) & (0xffffffff << v4_lsb_bits_len)) != ntohl(rule->v4_pref) ) {
    nat46debug(0, "xlate_map_v4_to_v6: IPv4 address %pI4 outside of MAP domain %pI4/%d", pipv4, &rule->v4_pref, rule->v4_pref_len);
    return 0;
  }

  if (rule->ea_len < (32 - rule->v4_pref_len) ) {
    nat46debug(0, "xlate_map_v4_to_v6: rule->ea_len < (32 - rule->v4_pref_len)");
    return 0;
  } 
  /* zero out the IPv6 address */
  memset(pipv6, 0, 16);

  psid_bits_len = rule->ea_len - (32 - rule->v4_pref_len);
  psid = (ntohs(l4id) >> (16 - psid_bits_len - rule->psid_offset)) & (0xffff >> (16 - psid_bits_len));
  nat46debug(10, "xlate_map_v4_to_v6: ntohs(l4id): %04x psid_bits_len: %d, rule psid-offset: %d, psid: %d\n", ntohs(l4id), psid_bits_len, rule->psid_offset, psid);

  /* 
   *     create the IID. pay the attention there can be two formats:
   *
   *     draft-ietf-softwire-map-t-00:
   *
   *
   *   +--+---+---+---+---+---+---+---+---+
   *   |PL|   8  16  24  32  40  48  56   |
   *   +--+---+---+---+---+---+---+---+---+
   *   |64| u | IPv4 address  |  PSID | 0 |
   *   +--+---+---+---+---+---+---+---+---+
   *
   *
   *     latest draft-ietf-softwire-map-t:
   *  
   *   |        128-n-o-s bits            |
   *   | 16 bits|    32 bits     | 16 bits|
   *   +--------+----------------+--------+
   *   |   0    |  IPv4 address  |  PSID  |
   *   +--------+----------------+--------+    
   *
   *   In the case of an IPv4 prefix, the IPv4 address field is right-padded
   *   with zeros up to 32 bits.  The PSID is zero left-padded to create a
   *   16 bit field.  For an IPv4 prefix or a complete IPv4 address, the
   *   PSID field is zero.
   *
   *   If the End-user IPv6 prefix length is larger than 64, the most
   *   significant parts of the interface identifier is overwritten by the
   *   prefix.
   *  
   */
  if (map_version) {
    p6[8] = p6[9] = 0;
    p6[10] = 0xff & (ntohl(*pv4u32) >> 24);
    p6[11] = 0xff & (ntohl(*pv4u32) >> 16);
    p6[12] = 0xff & (ntohl(*pv4u32) >> 8);
    p6[13] = 0xff & (ntohl(*pv4u32));
    p6[14] = 0xff & (psid >> 8);
    p6[15] = 0xff & (psid);
  } else {
    p6[8]  = 0;
    p6[9]  = 0xff & (ntohl(*pv4u32) >> 24);
    p6[10] = 0xff & (ntohl(*pv4u32) >> 16);
    p6[11] = 0xff & (ntohl(*pv4u32) >> 8);
    p6[12] = 0xff & (ntohl(*pv4u32));
    p6[13] = 0xff & (psid >> 8);
    p6[14] = 0xff & (psid);
    p6[15] = 0;
    /* old EID */
  }
 
  /* copy the necessary part of domain IPv6 prefix into place, w/o overwriting the existing data */
  bitarray_copy(&rule->v6_pref, 0, rule->v6_pref_len, p6, 0);

  if (v4_lsb_bits_len) {
    /* insert the lower 32-v4_pref_len bits of IPv4 address at rule->v6_pref_len */
    bitarray_copy(pipv4, rule->v4_pref_len, v4_lsb_bits_len, p6, rule->v6_pref_len);
  }

  if (psid_bits_len) {
    /* insert the psid bits at rule->v6_pref_len + v4_lsb_bits */
    bitarray_copy(&l4id, rule->psid_offset, psid_bits_len, p6, rule->v6_pref_len + v4_lsb_bits_len);
  }

  ret = 1;

  return ret;
}

int xlate_map_v6_to_v4(nat46_instance_t *nat46, nat46_xlate_rule_t *rule, void *pipv6, void *pipv4, uint16_t l4id, int version) {
  int ret = 0;

  uint8_t psid_bits_len;
  uint8_t v4_lsb_bits_len = 32 - rule->v4_pref_len;


  if (memcmp(pipv6, &rule->v6_pref, rule->v6_pref_len/8)) {
    /* address not within the MAP IPv6 prefix */
    nat46debug(0, "xlate_map_v6_to_v4: IPv6 address %pI6 outside of MAP domain %pI6/%d", pipv6, &rule->v6_pref, rule->v6_pref_len);
    return 0;
  }
  if (rule->v6_pref_len % 8) {
    /* FIXME: add comparison here for the remaining 1..7 bits, if v6_pref_len % 8 is not zero */
  }

  if (rule->ea_len < (32 - rule->v4_pref_len) ) {
    nat46debug(0, "xlate_map_v6_to_v4: rule->ea_len < (32 - rule->v4_pref_len)");
    return 0;
  } 
  psid_bits_len = rule->ea_len - (32 - rule->v4_pref_len);

  memcpy(pipv4, &rule->v4_pref, 4);
  if (v4_lsb_bits_len) {
    bitarray_copy(pipv6, rule->v6_pref_len, v4_lsb_bits_len, pipv4, rule->v4_pref_len);
  }
  /* 
   * FIXME: I do not verify the PSID here. The idea is that if the destination port is incorrect, this
   * will be caught in the NAT44 module. 
   */ 
  ret = 1;
  return ret;
}

int xlate_v4_to_v6(nat46_instance_t *nat46, nat46_xlate_rule_t *rule, void *pipv4, void *pipv6, uint16_t l4id) {
  int ret = 0;
  switch(rule->style) {
    case NAT46_XLATE_NONE: /* always fail unless it is a host 1:1 translation */
      if ( (rule->v6_pref_len == 128) && (rule->v4_pref_len == 32) && 
           (0 == memcmp(pipv4, &rule->v4_pref, sizeof(rule->v4_pref))) ) {
         memcpy(pipv6, &rule->v6_pref, sizeof(rule->v6_pref));
         ret = 1;
      }
      break;
    case NAT46_XLATE_MAP0: 
      ret = xlate_map_v4_to_v6(nat46, rule, pipv4, pipv6, l4id, 0);
      break;
    case NAT46_XLATE_MAP: 
      ret = xlate_map_v4_to_v6(nat46, rule, pipv4, pipv6, l4id, 1);
      break;
    case NAT46_XLATE_RFC6052:
      xlate_v4_to_nat64(nat46, rule, pipv4, pipv6);
      /* NAT46 rules using RFC6052 always succeed since they can map any IPv4 address */
      ret = 1;
      break;
  }
  return ret;
}

int xlate_v6_to_v4(nat46_instance_t *nat46, nat46_xlate_rule_t *rule, void *pipv6, void *pipv4, uint16_t l4id) {
  int ret = 0;
  switch(rule->style) {
    case NAT46_XLATE_NONE: /* always fail unless it is a host 1:1 translation */
      if ( (rule->v6_pref_len == 128) && (rule->v4_pref_len == 32) && 
           (0 == memcmp(pipv6, &rule->v6_pref, sizeof(rule->v6_pref))) ) {
         memcpy(pipv4, &rule->v4_pref, sizeof(rule->v4_pref));
         ret = 1;
      }
      break;
    case NAT46_XLATE_MAP0: 
      ret = xlate_map_v6_to_v4(nat46, rule, pipv6, pipv4, l4id, 0);
      break;
    case NAT46_XLATE_MAP: 
      ret = xlate_map_v6_to_v4(nat46, rule, pipv6, pipv4, l4id, 1);
      break;
    case NAT46_XLATE_RFC6052:
      ret = xlate_nat64_to_v4(nat46, rule, pipv6, pipv4);
      break;
  }
  return ret;
}

static uint16_t nat46_fixup_icmp(nat46_instance_t *nat46, struct iphdr *iph, struct sk_buff *old_skb) {
  struct icmphdr *icmph = (struct icmphdr *)(iph+1);
  uint16_t ret = 0;

  switch(icmph->type) {
    case ICMP_ECHO:
      icmph->type = ICMPV6_ECHO_REQUEST;
      ret = icmph->un.echo.id;
      nat46debug(3, "ICMP echo request translated into IPv6, id: %d", ntohs(ret)); 
      break;
    case ICMP_ECHOREPLY:
      icmph->type = ICMPV6_ECHO_REPLY;
      ret = icmph->un.echo.id;
      nat46debug(3, "ICMP echo reply translated into IPv6, id: %d", ntohs(ret)); 
      break;
  }
  iph->protocol = NEXTHDR_ICMP;
  return ret;
}



void nat46_ipv6_input(struct sk_buff *old_skb) {
  struct ipv6hdr *ip6h = ipv6_hdr(old_skb);
  nat46_instance_t *nat46 = get_nat46_instance(old_skb);
  uint16_t proto, sport = 0, dport = 0;

  struct iphdr * iph;
  __u32 v4saddr, v4daddr;
  struct sk_buff * new_skb = 0;
  int truncSize = 0;

  nat46debug(1, "nat46_ipv6_input packet");

  if(ip6_input_not_interested(nat46, ip6h, old_skb)) {
    nat46debug(1, "nat46_ipv6_input not interested");
    goto done;
  }
  nat46debug(1, "nat46_ipv6_input next hdr: %d, len: %d, is_fragment: %d", 
                ip6h->nexthdr, old_skb->len, ip6h->nexthdr == NEXTHDR_FRAGMENT);
  // debug_dump(DBG_V6, 1, old_skb->data, 64);

  proto = ip6h->nexthdr;
  if (proto == NEXTHDR_FRAGMENT) {
    nat46debug(5, "Trying reassembly for fragment");
    old_skb = try_reassembly(nat46, old_skb);
    if (!old_skb) {
      goto done;
    }
    ip6h = ipv6_hdr(old_skb);
    proto = ip6h->nexthdr;
    nat46debug(5, "New proto after reassembly: %d", proto);
  }
  
  switch(proto) {
    case NEXTHDR_TCP: {
      struct tcphdr *th = tcp_hdr(old_skb);
      sport = th->source;
      dport = th->dest;
      break;
      }
    case NEXTHDR_UDP: {
      struct udphdr *udp = udp_hdr(old_skb);
      sport = udp->source;
      dport = udp->dest;
      break;
      }
    case NEXTHDR_ICMP:
      sport = dport = nat46_fixup_icmp6(nat46, ip6h, old_skb);
      break;
    case NEXTHDR_FRAGMENT:
      nat46debug(2, "[ipv6] Next header is fragment. Not doing anything.");
      goto done;
      break;
    default:
      nat46debug(0, "[ipv6] Next header: %u. Only TCP, UDP, and ICMP6 are supported.", proto);
      goto done;
  }


  if(!xlate_v6_to_v4(nat46, &nat46->remote_rule, &ip6h->saddr, &v4saddr, sport)) {
    nat46debug(0, "[nat46] Could not translate remote address v6->v4");
    goto done;
  }
  if(!xlate_v6_to_v4(nat46, &nat46->local_rule, &ip6h->daddr, &v4daddr, dport)) {
    nat46debug(0, "[nat46] Could not translate local address v6->v4");
    goto done;
  }
    

  new_skb = skb_copy(old_skb, GFP_ATOMIC); // other possible option: GFP_ATOMIC
  

  /* Remove any debris in the socket control block */
  memset(IPCB(new_skb), 0, sizeof(struct inet_skb_parm));
  new_skb->nf_trace = 0;
  new_skb->peeked = 0;
  new_skb->nfctinfo = 0;
  new_skb->ipvs_property = 0;
  new_skb->nfct = NULL;

  /* modify packet: actual IPv6->IPv4 transformation */
  truncSize = sizeof(struct ipv6hdr) - sizeof(struct iphdr); /* chop first 20 bytes */
  skb_pull(new_skb, truncSize);
  skb_reset_network_header(new_skb);
  skb_set_transport_header(new_skb,20); /* transport (TCP/UDP/ICMP/...) header starts after 20 bytes */

  /* build IPv4 header */
  iph = ip_hdr(new_skb);
  iph->ttl = ip6h->hop_limit;
  iph->saddr = v4saddr;
  iph->daddr = v4daddr;
  iph->protocol = ip6h->nexthdr;
  *((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (0x00/*tos*/ & 0xff));
  iph->frag_off = htons(IP_DF);

  /* iph->tot_len = htons(new_skb->len); // almost good, but it may cause troubles with sizeof(IPv6 pkt)<64 (padding issue) */
  iph->tot_len = htons( ntohs(ip6h->payload_len)+ 20 /*sizeof(ipv4hdr)*/ );
  if (ntohs(iph->tot_len) >= 2000) {
    nat46debug(0, "Too big IP len: %d", ntohs(iph->tot_len));
  }
  iph->check = 0;
  iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
  new_skb->protocol = htons(ETH_P_IP);

  ipv4_update_csum(new_skb, iph); /* update L4 (TCP/UDP/ICMP) checksum */

  new_skb->dev = old_skb->dev;
  nat46debug(5, "about to send v4 packet, flags: %02x",  IPCB(new_skb)->flags);
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
    nat46debug(3, "Not an IPv4 packet");
    return 1;
  }
  // FIXME: check source to be within our prefix
  return 0;
}

void nat46_ipv4_input(struct sk_buff *old_skb) {
  nat46_instance_t *nat46 = get_nat46_instance(old_skb);
  struct sk_buff *new_skb;
  uint16_t sport = 0, dport = 0;

  int tclass = 0;
  int flowlabel = 0;

  struct ipv6hdr * hdr6;
  struct iphdr * hdr4 = ip_hdr(old_skb);

  char v6saddr[16], v6daddr[16];

  memset(v6saddr, 1, 16);
  memset(v6daddr, 2, 16);

  if (ip4_input_not_interested(nat46, hdr4, old_skb)) {
    goto done;
  }
  nat46debug(1, "nat46_ipv4_input packet");
  nat46debug(5, "v4 packet flags: %02x",  IPCB(old_skb)->flags);

  if (ntohs(hdr4->tot_len) > 1480) {
    // FIXME: need to send Packet Too Big here.
    goto done; 
  }

  switch(hdr4->protocol) {
    case IPPROTO_TCP: {
      struct tcphdr *th = tcp_hdr(old_skb);
      sport = th->source;
      dport = th->dest;
      break;
      }
    case IPPROTO_UDP: {
      struct udphdr *udp = udp_hdr(old_skb);
      sport = udp->source;
      dport = udp->dest;
      break;
      }
    case IPPROTO_ICMP:
      sport = dport = nat46_fixup_icmp(nat46, hdr4, old_skb);
      break;
    default:
      nat46debug(3, "[ipv6] Next header: %u. Only TCP, UDP, and ICMP are supported.", hdr4->protocol);
      goto done;
  }

  if(!xlate_v4_to_v6(nat46, &nat46->remote_rule, &hdr4->daddr, v6daddr, dport)) {
    nat46debug(0, "[nat46] Could not translate remote address v4->v6");
    goto done;
  }
  if(!xlate_v4_to_v6(nat46, &nat46->local_rule, &hdr4->saddr, v6saddr, sport)) {
    nat46debug(0, "[nat46] Could not translate local address v4->v6");
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

