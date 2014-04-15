#ifndef __NAT46_CORE_H__
#define __NAT46_CORE_H__

#include "nat46-glue.h"

// #define nat46debug(level, format, ...) debug(DBG_V6, level, format, __VA_ARGS__)
// #define nat46debug(level, format, ...)
#define nat46debug(level, format, ...) printk(format, __VA_ARGS__)

// #define nat46_reasm_debug(level, format, ...) debug(DBG_REASM, level, format, __VA_ARGS__)
#define nat46_reasm_debug(level, format, ...)

typedef struct {
  struct  in6_addr        saddr;
  struct  in6_addr        daddr;
  __be32  identification;
  struct sk_buff *skb;
  __be16  frag_off;
} reasm_item_t;

#define NAT46_MAX_V6_FRAGS 32
#define NAT46_SIGNATURE 0x544e3634

typedef struct {
  u32 sig; /* nat46 signature */
  int debug;

  /* Fixed portion of the IPv6 address on my side */
  struct in6_addr my_v6bits;
  struct in6_addr my_v6mask;
  struct in6_addr nat64pref;
  u32		  my_v4addr;
  int nat64pref_len;
  reasm_item_t frags[NAT46_MAX_V6_FRAGS];
  int nfrags;
} nat46_instance_t;

void nat46_ipv6_input(struct sk_buff *old_skb);
void nat46_ipv4_input(struct sk_buff *old_skb);

int nat46_set_config(nat46_instance_t *nat46, char *buf, int count);
char *get_next_arg(char **ptail);
nat46_instance_t *get_nat46_instance(struct sk_buff *sk);
void release_nat46_instance(nat46_instance_t *nat46);
int is_valid_nat46(nat46_instance_t *nat46);

#endif
