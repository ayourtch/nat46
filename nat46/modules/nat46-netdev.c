/*
 * Network device related boilerplate functions
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



#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/route.h>
#include <linux/skbuff.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <linux/version.h>
#include "nat46-core.h"
#include "nat46-module.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
#define dev_lock_list() rcu_read_lock()
#define dev_unlock_list() rcu_read_unlock()
#else
#define dev_lock_list() read_lock(&dev_base_lock)
#define dev_unlock_list() read_unlock(&dev_base_lock)
#endif

#define NETDEV_DEFAULT_NAME "nat46."

typedef struct {
  u32 sig;
  nat46_instance_t *nat46;
} nat46_netdev_priv_t;

static u8 netdev_count = 0;

static int nat46_netdev_up(struct net_device *dev);
static int nat46_netdev_down(struct net_device *dev);

static netdev_tx_t nat46_netdev_xmit(struct sk_buff *skb, struct net_device *dev);


static const struct net_device_ops nat46_netdev_ops = {
	.ndo_open       = nat46_netdev_up,      /* Called at ifconfig nat46 up */
	.ndo_stop       = nat46_netdev_down,    /* Called at ifconfig nat46 down */
	.ndo_start_xmit = nat46_netdev_xmit,    /* REQUIRED, must return NETDEV_TX_OK */
};

static int nat46_netdev_up(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int nat46_netdev_down(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t nat46_netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int ret = 0;

	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;
	if(ETH_P_IP == ntohs(skb->protocol)) {
		ret = nat46_ipv4_input(skb);
	}
	if(ETH_P_IPV6 == ntohs(skb->protocol)) {
		ret = nat46_ipv6_input(skb);
	}
	if(0 == ret) {
		dev_kfree_skb_any(skb);
	}
	return NETDEV_TX_OK;
}

void nat46_netdev_count_xmit(struct sk_buff *skb, struct net_device *dev) {
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;
}

void *netdev_nat46_instance(struct net_device *dev) {
	nat46_netdev_priv_t *priv = netdev_priv(dev);
	return priv->nat46;
}

static void netdev_nat46_set_instance(struct net_device *dev, nat46_instance_t *new_nat46) {
	nat46_netdev_priv_t *priv = netdev_priv(dev);
	/* Swap the instance pointer under ref_lock so the write is synchronized with
	 * get_nat46_instance()'s locked read (no unlocked data race on priv->nat46,
	 * review2 Issue 3), and so priv->nat46 never transiently points at a freed
	 * instance that a concurrent reader could validate. Release the old instance
	 * outside the lock (release_nat46_instance takes ref_lock itself). */
	nat46_instance_t *old = nat46_swap_instance(&priv->nat46, new_nat46);
	if (old) {
		release_nat46_instance(old);
	}
}

static void nat46_netdev_setup(struct net_device *dev)
{
	nat46_netdev_priv_t *priv = netdev_priv(dev);
	nat46_instance_t *nat46 = alloc_nat46_instance(1, NULL, -1, -1, -1);

	memset(priv, 0, sizeof(*priv));
	priv->sig = NAT46_DEVICE_SIGNATURE;
	priv->nat46 = nat46;

	dev->netdev_ops = &nat46_netdev_ops;
	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = 16384; /* iptables does reassembly. Rather than using ETH_DATA_LEN, let's try to get as much mileage as we can with the Linux stack */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)
	dev->features = NETIF_F_NETNS_LOCAL;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)
	dev->netns_local = true;
#else
	dev->netns_immutable = true;
#endif
	dev->flags = IFF_NOARP | IFF_POINTOPOINT;
}

static int nat46_netdev_create(struct net *net, char *basename, struct net_device **dev)
{
	int ret = 0;
	char *devname = NULL;
	int automatic_name = 0;

	if (basename && strcmp("", basename)) {
		devname = kmalloc(strlen(basename)+1, GFP_KERNEL);
	} else {
		devname = kmalloc(strlen(NETDEV_DEFAULT_NAME)+3+1, GFP_KERNEL);
		automatic_name = 1;
	}
	if (!devname) {
		pr_err("nat46: can not allocate memory to store device name.\n");
		ret = -ENOMEM;
		goto err;
	}
	if (automatic_name) {
		snprintf(devname, strlen(NETDEV_DEFAULT_NAME)+3, "%s%d", NETDEV_DEFAULT_NAME, netdev_count);
		netdev_count++;
	} else {
		strcpy(devname, basename);
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,17,0)
	*dev = alloc_netdev(sizeof(nat46_instance_t), devname, nat46_netdev_setup);
#else
	*dev = alloc_netdev(sizeof(nat46_instance_t), devname, NET_NAME_UNKNOWN, nat46_netdev_setup);
#endif
	if (!*dev) {
		pr_err("nat46: Unable to allocate nat46 device '%s'.\n", devname);
		ret = -ENOMEM;
		goto err_alloc_dev;
	}

	dev_net_set(*dev, net);
	ret = register_netdev(*dev);
	if(ret) {
		pr_err("nat46: Unable to register nat46 device.\n");
		ret = -ENOMEM;
		goto err_register_dev;
	}

	pr_info("nat46: netdevice nat46 '%s' created successfully.\n", devname);
	kfree(devname);

	return 0;

err_register_dev:
	free_netdev(*dev);
err_alloc_dev:
	kfree(devname);
err:
	return ret;
}

static void nat46_netdev_destroy(struct net_device *dev)
{
	dev->flags &= ~IFF_UP;
	netif_stop_queue(dev);
	netdev_nat46_set_instance(dev, NULL);
	unregister_netdev(dev);
	free_netdev(dev);
	pr_info("nat46: Destroying nat46 device.\n");
}

static int is_nat46(struct net_device *dev) {
	nat46_netdev_priv_t *priv;
	if (dev->netdev_ops != &nat46_netdev_ops) {
		return 0;
	}
	priv = netdev_priv(dev);
	return (priv && (NAT46_DEVICE_SIGNATURE == priv->sig));
}

static struct net_device *find_dev(struct net *net, char *name) {
	struct net_device *dev;
	struct net_device *out = NULL;

	if(!name) {
		return NULL;
	}

	dev_lock_list();
	dev = first_net_device(net);
	while (dev) {
		if((0 == strcmp(dev->name, name)) && is_nat46(dev)) {
			if(debug) {
				pr_info("found [%s]\n", dev->name);
			}
			out = dev;
			break;
		}
		dev = next_net_device(dev);
	}
	dev_unlock_list();
	return out;
}

int nat46_create(struct net *net, char *devname) {
	int ret = 0;
	struct net_device *dev = find_dev(net, devname);
	if (dev) {
		pr_err("Can not add: device '%s' already exists!\n", devname);
		return -1;
	}
	ret = nat46_netdev_create(net, devname, &dev);
	return ret;
}

int nat46_destroy(struct net *net, char *devname) {
	struct net_device *dev = find_dev(net, devname);
	if(dev) {
		pr_info("Destroying '%s'\n", devname);
		nat46_netdev_destroy(dev);
		return 0;
	} else {
		pr_err("Could not find device '%s'\n", devname);
		return -1;
	}
}

int nat46_insert(struct net *net, char *devname, char *buf) {
	struct net_device *dev = find_dev(net, devname);
	int ret = -1;
	if(dev) {
		nat46_instance_t *nat46 = netdev_nat46_instance(dev);
		nat46_instance_t *nat46_new = alloc_nat46_instance(nat46->npairs+1, nat46, 0, 1, -1);
		if(nat46_new) {
			ret = nat46_set_ipair_config(nat46_new, 0, buf, strlen(buf));
			if (0 == ret) {
				netdev_nat46_set_instance(dev, nat46_new);
			} else {
				release_nat46_instance(nat46_new);
			}
		} else {
			pr_err("Could not insert a new rule on device %s\n", devname);
		}
	}
	return ret;
}

int nat46_configure(struct net *net, char *devname, char *buf) {
	struct net_device *dev = find_dev(net, devname);
	if(dev) {
		nat46_instance_t *nat46 = netdev_nat46_instance(dev);
		nat46_instance_t *nat46_new = alloc_nat46_instance(nat46->npairs, nat46, 0, 0, -1);
		int ret = -1;
		if(nat46_new) {
			ret = nat46_set_config(nat46_new, buf, strlen(buf));
			if (0 == ret) {
				netdev_nat46_set_instance(dev, nat46_new);
			} else {
				release_nat46_instance(nat46_new);
			}
		}
		return ret;
	} else {
		return -1;
	}
}

static int nat46_rule_equal(const nat46_xlate_rule_t *a,
			    const nat46_xlate_rule_t *b) {
	return a->style == b->style &&
	       ipv6_addr_equal(&a->v6_pref, &b->v6_pref) &&
	       a->v6_pref_len == b->v6_pref_len &&
	       a->v4_pref == b->v4_pref &&
	       a->v4_pref_len == b->v4_pref_len &&
	       a->ea_len == b->ea_len &&
	       a->psid_offset == b->psid_offset &&
	       a->fmr_flag == b->fmr_flag;
}

static int nat46_rulepair_equal(const nat46_xlate_rulepair_t *a,
				const nat46_xlate_rulepair_t *b) {
	return nat46_rule_equal(&a->local, &b->local) &&
	       nat46_rule_equal(&a->remote, &b->remote);
}

int nat46_remove(struct net *net, char *devname, char *buf) {
	int ret = -1;
	struct net_device *dev;
	nat46_instance_t *nat46;
	nat46_instance_t *nat46_remove;
	int i;

	if((dev = find_dev(net, devname)) == NULL ||
	   (nat46 = netdev_nat46_instance(dev)) == NULL ||
	   (nat46_remove = alloc_nat46_instance(1, NULL, -1, -1, -1)) == NULL) {
		return ret;
	}

	if(nat46_set_ipair_config(nat46_remove, 0, buf, strlen(buf)) < 0) {
		release_nat46_instance(nat46_remove);
		return ret;
	}

	for(i = 0; i < nat46->npairs; i++) {
		if (nat46_rulepair_equal(&nat46_remove->pairs[0],
					 &nat46->pairs[i])) {
			nat46_instance_t *nat46_new = alloc_nat46_instance(nat46->npairs-1, nat46, 0, 0, i);
			if(nat46_new) {
				netdev_nat46_set_instance(dev, nat46_new);
				ret = 0;
			} else {
				pr_err("Could not remove the rule from device %s\n", devname);
			}
			break;
		}
	}
	release_nat46_instance(nat46_remove);
	return ret;
}

void nat64_show_all_configs(struct net *net, struct seq_file *m) {
	struct nat46_config_snapshot {
		char devname[IFNAMSIZ];
		nat46_instance_t *nat46;
	};
	struct nat46_config_snapshot *snapshots = NULL;
	struct net_device *dev;
	char dummy;
	char *buf = NULL;
	size_t snapshot_capacity = 0;
	size_t snapshot_count = 0;
	int max_config_len = 0;
	size_t snapshot;
	int ipair;

	/* First count devices so all sleeping allocations happen without the
	 * device-list lock held. If the device set grows between passes, entries
	 * beyond this capacity belong to the next proc snapshot; removed devices
	 * are simply absent below. */
	dev_lock_list();
	dev = first_net_device(net);
	while (dev) {
		if(is_nat46(dev))
			snapshot_capacity++;
		dev = next_net_device(dev);
	}
	dev_unlock_list();

	if (!snapshot_capacity)
		return;

	snapshots = kcalloc(snapshot_capacity, sizeof(*snapshots), GFP_KERNEL);
	if (!snapshots)
		return;

	/* Pin each immutable configuration while still holding the device-list
	 * lock, and copy the stable device name. Configuration swaps can then
	 * proceed while this proc snapshot is sized and formatted. */
	dev_lock_list();
	dev = first_net_device(net);
	while (dev && snapshot_count < snapshot_capacity) {
		if(is_nat46(dev)) {
			nat46_instance_t *nat46 = get_nat46_instance_dev(dev);

			if (nat46) {
				memcpy(snapshots[snapshot_count].devname,
				       dev->name, IFNAMSIZ);
				snapshots[snapshot_count].devname[IFNAMSIZ - 1] = '\0';
				snapshots[snapshot_count].nat46 = nat46;
				snapshot_count++;
			}
		}
		dev = next_net_device(dev);
	}
	dev_unlock_list();

	/* snprintf returns the required length when the supplied size is zero.
	 * Measure every rule in the stable snapshots, then allocate one reusable
	 * buffer large enough for the longest complete record. */
	for (snapshot = 0; snapshot < snapshot_count; snapshot++) {
		nat46_instance_t *nat46 = snapshots[snapshot].nat46;

		for (ipair = 0; ipair < nat46->npairs; ipair++) {
			int len = nat46_get_ipair_config(nat46, ipair, &dummy, 0);

			if (len > max_config_len)
				max_config_len = len;
		}
	}
	buf = kmalloc((size_t)max_config_len + 1, GFP_KERNEL);
	if (!buf)
		goto release_snapshots;

	for (snapshot = 0; snapshot < snapshot_count; snapshot++) {
		nat46_instance_t *nat46 = snapshots[snapshot].nat46;
		const char *devname = snapshots[snapshot].devname;

		seq_printf(m, "add %s\n", devname);
		for (ipair = 0; ipair < nat46->npairs; ipair++) {
			int len = nat46_get_ipair_config(
				nat46, ipair, buf, max_config_len + 1);

			if (len < 0 || len > max_config_len)
				continue;
			if(ipair < nat46->npairs-1)
				seq_printf(m,"insert %s %s\n", devname, buf);
			else
				seq_printf(m,"config %s %s\n", devname, buf);
		}
		seq_printf(m,"\n");
	}

	kfree(buf);
release_snapshots:
	for (snapshot = 0; snapshot < snapshot_count; snapshot++)
		release_nat46_instance(snapshots[snapshot].nat46);
	kfree(snapshots);
}

void nat46_destroy_all(struct net *net) {
        struct net_device *dev;
        struct net_device *nat46dev;
	do {
		dev_lock_list();
		nat46dev = NULL;
		dev = first_net_device(net);
		while (dev) {
			if(is_nat46(dev)) {
				nat46dev = dev;
			}
			dev = next_net_device(dev);
		}
		dev_unlock_list();
		if(nat46dev) {
			nat46_netdev_destroy(nat46dev);
		}
	} while (nat46dev);

}
