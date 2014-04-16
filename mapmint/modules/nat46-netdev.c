/* Network device related boilerplate functions */


#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/route.h>
#include <linux/skbuff.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include "nat46-core.h"

#define NETDEV_DEFAULT_NAME "nat46."

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
	if(ETH_P_IP == ntohs(skb->protocol)) {
               	nat46_ipv4_input(skb); 
        }
	if(ETH_P_IPV6 == ntohs(skb->protocol)) {
               	nat46_ipv6_input(skb); 
        }
        kfree_skb(skb);
        return NETDEV_TX_OK;
}

static void nat46_netdev_setup(struct net_device *dev)
{
	nat46_instance_t *nat46 = netdev_priv(dev);

	memset(nat46, 0, sizeof(nat46_instance_t));
	nat46->sig = NAT46_SIGNATURE;
	nat46->nat46_dev = dev;

        dev->netdev_ops = &nat46_netdev_ops;
        dev->type = ARPHRD_NONE;
        dev->hard_header_len = 0;
        dev->addr_len = 0;
        dev->mtu = ETH_DATA_LEN;
        dev->features = NETIF_F_NETNS_LOCAL;
        dev->flags = IFF_NOARP | IFF_POINTOPOINT;
}

int nat46_netdev_create(char *basename, struct net_device **dev)
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
		printk("nat46: can not allocate memory to store device name.\n");
		ret = -ENOMEM;
		goto err;
	}
	if (automatic_name) {
		snprintf(devname, strlen(NETDEV_DEFAULT_NAME)+3, "%s%d", NETDEV_DEFAULT_NAME, netdev_count);
		netdev_count++;
	} else {
		strcpy(devname, basename);
	}

        *dev = alloc_netdev(sizeof(nat46_instance_t), devname, nat46_netdev_setup);
        if (!*dev) {
                printk("nat46: Unable to allocate nat46 device '%s'.\n", devname);
		ret = -ENOMEM;
		goto err_alloc_dev;
        }

        ret = register_netdev(*dev);
        if(ret) {
                printk("nat46: Unable to register nat46 device.\n");
		ret = -ENOMEM;
		goto err_register_dev;
        }

        printk("nat46: netdevice nat46 '%s' created successfully.\n", devname);
	kfree(devname);

        return 0;

err_register_dev:
	free_netdev(*dev);
err_alloc_dev:
	kfree(devname);
err:
        return ret;
}

void nat46_netdev_destroy(struct net_device *dev)
{
        unregister_netdev(dev);

        printk("nat46: Destroying nat46 device.\n");
}

static int is_nat46(struct net_device *dev) {
	nat46_instance_t *nat46 = netdev_priv(dev);
	return is_valid_nat46(nat46);
}


static struct net_device *find_dev(char *name) {
	struct net_device *dev;
	struct net_device *out = NULL;

	if(!name) {
		return NULL;
	}

	read_lock(&dev_base_lock);
	dev = first_net_device(&init_net);
	while (dev) {
		if((0 == strcmp(dev->name, name)) && is_nat46(dev)) {
    			printk(KERN_INFO "found [%s]\n", dev->name);
			out = dev;
			break;
		}
    		dev = next_net_device(dev);
	}
	read_unlock(&dev_base_lock);
	return out;
}

int nat46_create(char *devname) {
	int ret = 0;
	struct net_device *dev = find_dev(devname);
	if (dev) {
		printk("Can not add: device '%s' already exists!\n", devname);
		return -1;
	}
	ret = nat46_netdev_create(devname, &dev);
	return ret;
}

int nat46_destroy(char *devname) {
	struct net_device *dev = find_dev(devname);
	if(dev) {
		printk("Destroying '%s'\n", devname);
		nat46_netdev_destroy(dev);
		return 0;
	} else {
		printk("Could not find device '%s'\n", devname);
		return -1;
	}
}

int nat46_configure(char *devname, char *buf) {
	struct net_device *dev = find_dev(devname);
	if(dev) {
		nat46_instance_t *nat46 = netdev_priv(dev);
		return nat46_set_config(nat46, buf, strlen(buf));
	} else {
		return -1;
	}
}

void nat64_show_all_configs(struct seq_file *m) {
        struct net_device *dev;
        read_lock(&dev_base_lock);
        dev = first_net_device(&init_net);
        while (dev) {
		if(is_nat46(dev)) {
			nat46_instance_t *nat46 = netdev_priv(dev);
			int buflen = 1024;
			char *buf = kmalloc(buflen+1, GFP_KERNEL);
			seq_printf(m, "add %s\n", dev->name);
			if(buf) {
				nat46_get_config(nat46, buf, buflen);
				seq_printf(m,"config %s %s\n\n", dev->name, buf);
				kfree(buf);
			}
		}
               	dev = next_net_device(dev);
	}
        read_unlock(&dev_base_lock);

}

void nat46_destroy_all(void) {
        struct net_device *dev;
        struct net_device *nat46dev;
	do {
        	read_lock(&dev_base_lock);
		nat46dev = NULL;
        	dev = first_net_device(&init_net);
        	while (dev) {
			if(is_nat46(dev)) {
				nat46dev = dev;
               	 	}
                	dev = next_net_device(dev);
        	}
        	read_unlock(&dev_base_lock);
		if(nat46dev) {
			nat46_netdev_destroy(nat46dev);
		}
	} while (nat46dev);

}
