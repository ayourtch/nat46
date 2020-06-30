/*
 *
 * module-wide functions, mostly boilerplate
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


#include <linux/fs.h>           // for basic filesystem
#include <linux/proc_fs.h>      // for the proc filesystem
#include <linux/seq_file.h>     // for sequence files

#ifdef PROTO_NETLINK
/* Netlink IPC */
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#endif

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ipv6.h>

#include "nat46-core.h"
#include "nat46-netdev.h"

#define NAT46_PROC_NAME	"nat46"
#define NAT46_CONTROL_PROC_NAME "control"

#ifndef NAT46_VERSION
#define NAT46_VERSION __DATE__ " " __TIME__
#endif

#ifdef PROTO_NETLINK
#define NETLINK_USER 31
#endif /* PROTO_NETLINK */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrew Yourtchenko <ayourtch@gmail.com>");
MODULE_DESCRIPTION("NAT46 stateless translation");

int debug = 0;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "debugging messages level (default=1)");

static struct proc_dir_entry *nat46_proc_entry;
static struct proc_dir_entry *nat46_proc_parent;

#ifdef PROTO_NETLINK
struct sock *nl_sk = NULL;
#endif /* PROTO_NETLINK */

static int nat46_proc_show(struct seq_file *m, void *v)
{
	nat64_show_all_configs(m);
	return 0;
}


static int nat46_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, nat46_proc_show, NULL);
}

static char *get_devname(char **ptail)
{
	const int maxlen = IFNAMSIZ-1;
	char *devname = get_next_arg(ptail);
	if(strlen(devname) > maxlen) {
		printk(KERN_INFO "nat46: '%s' is "
			"longer than %d chars, truncating\n", devname, maxlen);
		devname[maxlen] = 0;
	}
	return devname;
}

static void
nat46_proc_cmd(char *cmd)
{
	char *arg = NULL;
	char *devname = NULL;

	while(NULL != (arg = get_next_arg (&cmd))) {
		if(0 == strcmp(arg, "add")) {
			devname = get_devname(&cmd);
			printk(KERN_INFO "nat46: adding device (%s)\n", devname);
			nat46_create(devname);
		}
		else if(0 == strcmp(arg, "del")) {
			devname = get_devname(&cmd);
			printk(KERN_INFO "nat46: deleting device (%s)\n", devname);
			nat46_destroy(devname);
		}
		else if(0 == strcmp(arg, "config")) {
			devname = get_devname(&cmd);
			printk(KERN_INFO "nat46: configure device (%s) with '%s'\n", devname, cmd);
			nat46_configure(devname, cmd);
		}
		else if(0 == strcmp(arg, "insert")) {
			devname = get_devname(&cmd);
			printk(KERN_INFO "nat46: insert new rule into device (%s) with '%s'\n",
				devname, cmd);
			nat46_insert(devname, cmd);
		}
	}
}

#ifdef PROTO_NETLINK
static void
nat46_nl_recv_msg(struct sk_buff *skb_in)
{
	struct nlmsghdr *nl_hdr;
	int pid;
	char *cmd = NULL;

	nl_hdr = (struct nlmsghdr *) skb_in->data;
	pid = nl_hdr->nlmsg_pid;
	cmd = (char *) nlmsg_data (nl_hdr);

	nat46_proc_cmd(cmd);
}
#endif /* PROTO_NETLINK */

static ssize_t nat46_proc_write(struct file *file, const char __user *buffer,
                              size_t count, loff_t *ppos)
{
	char *buf = NULL;
	char *tail = NULL;

	buf = kmalloc(sizeof(char) * (count + 1), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, buffer, count)) {
		kfree(buf);
		return -EFAULT;
	}
	tail = buf;
	buf[count] = '\0';
	if( (count > 0) && (buf[count-1] == '\n') ) {
		buf[count-1] = '\0';
	}

	nat46_proc_cmd(tail);

	kfree(buf);
	return count;
}

static const struct file_operations nat46_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= nat46_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= nat46_proc_write,
};


int create_nat46_proc_entry(void) {
	nat46_proc_parent = proc_mkdir(NAT46_PROC_NAME, init_net.proc_net);
	if (nat46_proc_parent) {
		nat46_proc_entry = proc_create(NAT46_CONTROL_PROC_NAME, 0644, nat46_proc_parent, &nat46_proc_fops );
		if(!nat46_proc_entry) {
			printk(KERN_INFO "Error creating proc entry");
			return -ENOMEM;
		}
	}
	return 0;
}


static int __init nat46_init(void)
{
#ifdef PROTO_NETLINK
	struct netlink_kernel_cfg nl_cfg = {
		.input = nat46_nl_recv_msg
	};
	printk("nat46: module (version %s) loaded.\n", NAT46_VERSION);

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &nl_cfg);
	if (!nl_sk)
	{
		printk(KERN_ALERT "nat46: error creating socket\n");
		return -1;
	}

	return 0;
#else
	int ret = 0;

	printk("nat46: module (version %s) loaded.\n", NAT46_VERSION);
	ret = create_nat46_proc_entry();
	if(ret) {
		goto error;
	}
	return 0;

error:
	return ret;
#endif /* PROTO_NETLINK */
}

static void __exit nat46_exit(void)
{
#ifdef PROTO_NETLINK
	netlink_kernel_release(nl_sk);
	nat46_destroy_all();
#else
	nat46_destroy_all();
	if (nat46_proc_parent) {
		if (nat46_proc_entry) {
			remove_proc_entry(NAT46_CONTROL_PROC_NAME, nat46_proc_parent);
		}
		remove_proc_entry(NAT46_PROC_NAME, init_net.proc_net);
	}
#endif /* PROTO_NETLINK */
	printk("nat46: module unloaded.\n");
}

module_init(nat46_init);
module_exit(nat46_exit);


