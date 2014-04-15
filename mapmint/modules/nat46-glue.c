/* glue functions, candidates to go to -core */

#include "nat46-glue.h"
#include "nat46-core.h"

nat46_instance_t *get_nat46_instance(struct sk_buff *sk) {
  nat46_instance_t *nat46 = netdev_priv(sk->dev);
  if (is_valid_nat46(nat46)) {
    return nat46;
  } else {
    printk("Could not find NAT46 instance!");
    return NULL;
  }
}

void release_nat46_instance(nat46_instance_t *nat46) {
}
