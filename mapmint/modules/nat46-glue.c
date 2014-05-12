/*
 * glue functions, candidates to go to -core
 *
 * Copyright (c) 2013-2014 Andrew Yourtchenko <ayourtch@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */


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
