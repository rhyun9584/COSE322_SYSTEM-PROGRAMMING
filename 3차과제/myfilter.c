// writer: Jeonghwa Yu
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>

#define PROC_DIRNAME "mynf"
#define PROC_FILENAME_F "fw"
#define PROC_FILENAME_D "drop"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file_f;
static struct proc_dir_entry *proc_file_d;

// port number needed to forward/drop
unsigned short forward_port;
unsigned short drop_port;

// convert numeric string to unsigned short
static int str2short(char* string, ssize_t count){
	int num, length, i;

	// last character in string is 'LF' -> not need
	length = count-1;

	num = 0;
	for (i=0; i<length; i++){
		// if character is not numeric string, return err(-1)
		if (string[i] < '0' || string[i] > '9'){
			printk(KERN_ERR "ERR in str2short inputs\n");
			return -1;
		}

		num = num*10 + (string[i] - '0');
	}

	// port range is 0~65535(USHRT_MAX)
	// so, if num is higher than USHRT_MAX, return err(-1)
	if (num > USHRT_MAX){
		printk(KERN_ERR "input is higher than USHRT_MAX\n");
		return -1;
	}

	return num;
}

// hooking function in NF_INET_PRE_ROUTING
static unsigned int pre_routing(void *priv,
							   struct sk_buff *skb,
							   const struct nf_hook_state *state){
	struct iphdr *nh;
	struct tcphdr *tcp;
	unsigned short sport, dport;

	// get ip header to get saddr & daddr
	nh = ip_hdr(skb);
	
	// get tcp header to get source & dest port
	tcp = tcp_hdr(skb);
	sport = ntohs(tcp->source); // __be16
	dport = ntohs(tcp->dest);   // __be16

	// forwarding
	if (sport == forward_port){
		// print packet before change
		printk(KERN_INFO "forward: PRE_ROUTING packet[(%u;%hu;%hu;%pI4;%pI4)]\n",
						nh->protocol, sport, dport, &nh->saddr, &nh->daddr);

		// change port to 7777
		unsigned short nport = 7777;
		tcp->source = htons(nport);
		tcp->dest = htons(nport);

		// change ip address for routing
		// add route rule about "192.168.56.103" -> (hex)"C0.A8.38.67"
		nh->daddr = htonl(0xc0a83867);

		// print changed packet
		printk(KERN_INFO "forward: PRE_ROUTING packet[(%u;%hu;%hu;%pI4;%pI4)]\n",
						nh->protocol, ntohs(tcp->source), ntohs(tcp->dest), &nh->saddr, &nh->daddr);

		return NF_ACCEPT;
	}
	// drop
	else if(sport == drop_port){
		// print packet before change
		printk(KERN_INFO "drop: PRE_ROUTING packet[(%u;%hu;%hu;%pI4;%pI4)]\n",
						nh->protocol, sport, dport, &nh->saddr, &nh->daddr);

		// change port to 3333
		unsigned short nport = 3333;
		tcp->source = htons(nport);
		tcp->dest = htons(nport);

		// print changed packet
		printk(KERN_INFO "drop: PRE_ROUTING packet[(%u;%hu;%hu;%pI4;%pI4)]\n",
						nh->protocol, ntohs(tcp->source), ntohs(tcp->dest), &nh->saddr, &nh->daddr);

		// packet drop
		return NF_DROP;
	}

	return NF_ACCEPT;
}
// hooking function in NF_INET_FORWARD
static unsigned int forward(void *priv,
							struct sk_buff *skb,
							const struct nf_hook_state *state){
	struct iphdr *nh;
	struct tcphdr *tcp;
	unsigned short sport, dport;

	// get ip header to get saddr & daddr
	nh = ip_hdr(skb);
	
	// get tcp header to get source & dest port
	tcp = tcp_hdr(skb);
	sport = ntohs(tcp->source);
	dport = ntohs(tcp->dest);

	// monitoring
	if (sport == 7777 && dport == 7777){
		printk(KERN_INFO "forward: FORWARD packet[(%u;%hu;%hu;%pI4;%pI4)]\n",
						nh->protocol, sport, dport, &nh->saddr, &nh->daddr);
	}

	return NF_ACCEPT;
}

// hooking function in NF_INET_POST_ROUTING
static unsigned int post_routing(void *priv,
								 struct sk_buff *skb,
								 const struct nf_hook_state *state){
	struct iphdr *nh;
	struct tcphdr *tcp;
	unsigned short sport, dport;

	// get ip header to get saddr & daddr
	nh = ip_hdr(skb);

	// get tcp header to get source & dest port
	tcp = tcp_hdr(skb);
	sport = ntohs(tcp->source);
	dport = ntohs(tcp->dest);

	// monitoring
	if (sport == 7777 && dport == 7777){
		printk(KERN_INFO "forward: POST_ROUTING packet[(%u;%hu;%hu;%pI4;%pI4)]\n",
						nh->protocol, sport, dport, &nh->saddr, &nh->daddr);
	}

	return NF_ACCEPT;
}

// hooking function in NF_INET_LOCAL_IN
static unsigned int local_in(void *priv,
							 struct sk_buff *skb,
							 const struct nf_hook_state *state){
	struct iphdr *nh;
	struct tcphdr *tcp;
	unsigned short sport, dport;

	// get ip header to get saddr & daddr
	nh = ip_hdr(skb);

	// get tcp header to get source & dest port
	tcp = tcp_hdr(skb);
	sport = ntohs(tcp->source);
	dport = ntohs(tcp->dest);

	// monitoring
	if (sport == 3333 && dport == 3333){
		printk(KERN_INFO "drop: LOCAL_IN packet[(%u;%hu;%hu;%pI4;%pI4)]\n",
						  nh->protocol, sport, dport, &nh->saddr, &nh->daddr);
	}

	return NF_ACCEPT;
}

// register hooking functions in proper hooking point
static struct nf_hook_ops pre_routing_ops = {
	.hook = pre_routing,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops forward_ops = {
	.hook = forward,
	.pf = PF_INET,
	.hooknum = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops post_routing_ops = {
	.hook = post_routing,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops local_in_ops = {
	.hook = local_in,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST
};

static int my_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "OPEN!\n");

	return 0;
}

// write call to "fw" to change forward port
static ssize_t fw_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos){
	char *buf;
	int err, port_num;

	printk(KERN_INFO "fw WRITE!\n");

	buf = kmalloc(count, GFP_KERNEL);

	// copy from user to kernel
	err = copy_from_user(buf, user_buffer, count);
	if (err > 0){
		return -EFAULT;
	}

	// convert string to unsigned short
	port_num = str2short(buf, count);
	if (port_num < 0){
		return -EFAULT;
	}

	// change forward port number
	forward_port = (unsigned short)port_num;

	kfree(buf);

	return count;
}

// write call to "drop" to change drop port
static ssize_t drop_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos){
	char *buf;
	int err, port_num;

	printk(KERN_INFO "drop WRITE!\n");

	buf = kmalloc(count, GFP_KERNEL);

	// copy from user to kernel
	err = copy_from_user(buf, user_buffer, count);
	if (err > 0){
		return -EFAULT;
	}

	// convert string to unsigned short
	port_num = str2short(buf, count);
	if (port_num < 0){
		return -EFAULT;
	}

	// change drop port number
	drop_port = (unsigned short)port_num;

	kfree(buf);

	return count;
}

static const struct file_operations fw_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = fw_write
};
static const struct file_operations drop_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = drop_write
};

static int __init simple_init(void){
	// register hooking function
	nf_register_hook(&pre_routing_ops);
	nf_register_hook(&forward_ops);	
	nf_register_hook(&post_routing_ops);	
	nf_register_hook(&local_in_ops);

	// create proc_dir, proc_file_f, proc_file_d
	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	proc_file_f = proc_create(PROC_FILENAME_F, 0600, proc_dir, &fw_fops);
	proc_file_d = proc_create(PROC_FILENAME_D, 0600, proc_dir, &drop_fops);

	// init port number
	forward_port = 1111;
	drop_port = 2222;

	return 0;
}
static void __exit simple_exit(void){
	// unregister hooking function
	nf_unregister_hook(&pre_routing_ops);
	nf_unregister_hook(&forward_ops);
	nf_unregister_hook(&post_routing_ops);
	nf_unregister_hook(&local_in_ops);

	// remove proc_dir, proc_file_f, proc_file_d
	remove_proc_entry(PROC_FILENAME_F, proc_dir);
	remove_proc_entry(PROC_FILENAME_D, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);

	return;
}
// register module init/exit function
module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("JH");
MODULE_DESCRIPTION("Simple");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");

