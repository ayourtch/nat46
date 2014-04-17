#ifndef __NAT46_CORE_H__
#define __NAT46_CORE_H__

#include "nat46-glue.h"

// #define nat46debug(level, format, ...) debug(DBG_V6, level, format, __VA_ARGS__)
// #define nat46debug(level, format, ...)
#define nat46debug(level, format, ...) do { if(nat46->debug >= level) { printk(format "\n", ##__VA_ARGS__); } } while (0)

// #define nat46_reasm_debug(level, format, ...) debug(DBG_REASM, level, format, __VA_ARGS__)
// #define nat46_reasm_debug(level, format, ...)
#define nat46_reasm_debug(level, format, ...) do { if(nat46->debug >= level) { printk(format "\n", ##__VA_ARGS__); } } while (0)

typedef struct {
  struct  in6_addr        saddr;
  struct  in6_addr        daddr;
  __be32  identification;
  struct sk_buff *skb;
  __be16  frag_off;
} reasm_item_t;

#define NAT46_MAX_V6_FRAGS 32
#define NAT46_SIGNATURE 0x544e3634


/* 
 * A generic v4<->v6 translation structure.
 * The currently supported translation styles:
 */

typedef enum {
  NAT46_XLATE_NONE = 0,
  NAT46_XLATE_MAP,
  NAT46_XLATE_MAP0,
  NAT46_XLATE_RFC6052
} nat46_xlate_style_t;
     
typedef struct {
  nat46_xlate_style_t style;
  struct in6_addr v6_pref;
  int 		  v6_pref_len;
  u32		  v4_pref;
  int             v4_pref_len;
  int		  ea_len;
  int             psid_offset;
} nat46_xlate_rule_t;


typedef struct {
  u32 sig; /* nat46 signature */
  int debug;

  nat46_xlate_rule_t local_rule;
  nat46_xlate_rule_t remote_rule;

  reasm_item_t frags[NAT46_MAX_V6_FRAGS];
  int nfrags;
} nat46_instance_t;

void nat46_ipv6_input(struct sk_buff *old_skb);
void nat46_ipv4_input(struct sk_buff *old_skb);

int nat46_set_config(nat46_instance_t *nat46, char *buf, int count);
int nat46_get_config(nat46_instance_t *nat46, char *buf, int count);

char *get_next_arg(char **ptail);
nat46_instance_t *get_nat46_instance(struct sk_buff *sk);
void release_nat46_instance(nat46_instance_t *nat46);
int is_valid_nat46(nat46_instance_t *nat46);

#endif
