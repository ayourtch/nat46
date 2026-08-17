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

static DEFINE_SPINLOCK(ref_lock);
static int is_valid_nat46(nat46_instance_t *nat46) {
  return (nat46 && (nat46->sig == NAT46_SIGNATURE));
}

nat46_instance_t *alloc_nat46_instance(int npairs, nat46_instance_t *old, int from_ipair, int to_ipair, int remove_ipair) {
  nat46_instance_t *nat46 = kzalloc(sizeof(nat46_instance_t) + npairs*sizeof(nat46_xlate_rulepair_t), GFP_KERNEL);
  if (!nat46) {
    pr_err("[nat46] make_nat46_instance: can not alloc a nat46 instance with %d pairs\n", npairs);
    return NULL;
  } else {
    pr_info("[nat46] make_nat46_instance: allocated nat46 instance with %d pairs\n", npairs);
  }
  nat46->sig = NAT46_SIGNATURE;
  nat46->npairs = npairs;
  nat46->refcount = 1; /* The caller gets the reference */
  if (old) {
    nat46->debug = old->debug;
    for(; (from_ipair >= 0) && (to_ipair >= 0) &&
          (from_ipair < old->npairs) && (to_ipair < nat46->npairs); from_ipair++) {
      if (from_ipair != remove_ipair) {
        nat46->pairs[to_ipair] = old->pairs[from_ipair];
        to_ipair++;
      }
    }
  }
  return nat46;
}


nat46_instance_t *get_nat46_instance(struct sk_buff *sk) {
  nat46_instance_t *nat46;
  /* Read priv->nat46 and take our reference while holding ref_lock so that a
   * concurrent netdev_nat46_set_instance() (which releases/frees the old
   * instance under the same lock) can never free it underneath us - the
   * pointer we validate is always kept alive by our refcount++ (Issue 4). */
  spin_lock_bh(&ref_lock);
  nat46 = netdev_nat46_instance(sk->dev);
  if (is_valid_nat46(nat46)) {
    nat46->refcount++;
    spin_unlock_bh(&ref_lock);
    return nat46;
  } else {
    spin_unlock_bh(&ref_lock);
    pr_err("[nat46] get_nat46_instance: Could not find a valid NAT46 instance!");
    return NULL;
  }
}

nat46_instance_t *get_nat46_instance_dev(struct net_device *dev) {
  nat46_instance_t *nat46;

  spin_lock_bh(&ref_lock);
  nat46 = netdev_nat46_instance(dev);
  if (is_valid_nat46(nat46)) {
    nat46->refcount++;
    spin_unlock_bh(&ref_lock);
    return nat46;
  }
  spin_unlock_bh(&ref_lock);
  pr_err("[nat46] get_nat46_instance_dev: Could not find a valid NAT46 instance!\n");
  return NULL;
}

/* Atomically swap the instance pointer in *slot to new_nat46 and return the old
 * value. The swap is done under ref_lock so it is fully synchronized with the
 * unlocked-read-free get_nat46_instance() path (review2 Issue 3): the caller
 * must release the returned old instance outside the lock (via
 * release_nat46_instance) to avoid self-deadlock. */
nat46_instance_t *nat46_swap_instance(nat46_instance_t **slot, nat46_instance_t *new_nat46) {
  nat46_instance_t *old;
  spin_lock_bh(&ref_lock);
  old = *slot;
  *slot = new_nat46;
  spin_unlock_bh(&ref_lock);
  return old;
}

void release_nat46_instance(nat46_instance_t *nat46) {
  spin_lock_bh(&ref_lock);
  nat46->refcount--;
  if(0 == nat46->refcount) {
    nat46->sig = FREED_NAT46_SIGNATURE;
    spin_unlock_bh(&ref_lock);
    pr_info("[nat46] release_nat46_instance: freeing nat46 instance with %d pairs\n", nat46->npairs);
    kfree(nat46);
    return;
  }
  spin_unlock_bh(&ref_lock);
}
