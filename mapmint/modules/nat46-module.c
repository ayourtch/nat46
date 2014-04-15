/* module-wide functions, mostly boilerplate */

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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrew Yourtchenko <ayourtch@gmail.com>");
MODULE_DESCRIPTION("NAT46 stateless translation");

int                     debug = 1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "debugging messages level (default=1)");

static struct proc_dir_entry *nat46_proc_entry;
static struct proc_dir_entry *nat46_proc_parent;


static int nat46_proc_show(struct seq_file *m, void *v)
{
        seq_printf(m,"contents for proc here\n");
        seq_printf(m,"more contents for proc here\n");
        return 0;
}


static int nat46_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, nat46_proc_show, NULL);
}

static ssize_t nat46_proc_write(struct file *file, const char __user *buffer,
                              size_t count, loff_t *ppos)
{
        char *buf = NULL;
	char *tail = NULL;
	char *devname = NULL;
	char *arg_name = NULL;

        buf = kmalloc(sizeof(char) * (count + 1), GFP_KERNEL);
        if (!buf)
                return -ENOMEM;

        if (copy_from_user(buf, buffer, count)) {
                kfree(buf);
                return -EFAULT;
        }
	tail = buf;
        buf[count] = '\0';

        while (NULL != (arg_name = get_next_arg(&tail))) {
		if (0 == strcmp(arg_name, "add")) {
			devname = get_next_arg(&tail);
			printk(KERN_INFO "nat46: adding device (%s)\n", devname);
			nat46_create(devname);
		} else if (0 == strcmp(arg_name, "del")) {
			devname = get_next_arg(&tail);
			printk(KERN_INFO "nat46: deleting device (%s)\n", devname);
			nat46_destroy(devname);
		} else if (0 == strcmp(arg_name, "config")) {
			devname = get_next_arg(&tail);
			printk(KERN_INFO "nat46: deleting device (%s)\n", devname);
			nat46_configure(devname, tail);
		}
	}

        kfree(buf);
        return count;
}

static const struct file_operations nat46_proc_fops = {
        .owner          = THIS_MODULE,
        .open           = nat46_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
        .write          = nat46_proc_write,
};


int create_nat46_proc_entry(void) {
        nat46_proc_parent = proc_mkdir(NAT46_PROC_NAME, init_net.proc_net);
	if (nat46_proc_parent) {
        	nat46_proc_entry = proc_create(NAT46_CONTROL_PROC_NAME, 0666, nat46_proc_parent, &nat46_proc_fops );
        	if(!nat46_proc_entry) {
                	printk(KERN_INFO "Error creating proc entry");
                	return -ENOMEM; 
		}
        }
	return 0;
}


static int __init nat46_init(void)
{
        int ret = 0;

        printk("nat46: module loaded.\n");
	ret = create_nat46_proc_entry();
	if(ret) {
		goto error;
        }
        return 0;

error:
        return ret;
}

static void __exit nat46_exit(void)
{
	nat46_destroy_all();
	if (nat46_proc_parent) {
		if (nat46_proc_entry) {
			remove_proc_entry(NAT46_CONTROL_PROC_NAME, nat46_proc_parent);
		}
		remove_proc_entry(NAT46_PROC_NAME, init_net.proc_net);
	}
        printk("nat46: module unloaded.\n");
}

module_init(nat46_init);
module_exit(nat46_exit);


