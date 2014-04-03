#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/time.h>
#include "hook.h"

static struct nf_hook_ops nfho;
int pid;
struct sock *nl_sk =  NULL;

EXPORT_SYMBOL_GPL(nl_sk);

static int icmp_off = 0;
static unsigned int drop_ip = 0;
static int drop_port = -1;


void input (struct sk_buff* __skb)
{
  struct sk_buff* skb = NULL;
  struct nlmsghdr* nlh = NULL;
  ;
	
  printk("net _link: data is ready to read.\n");
  skb = skb_get(__skb);
   
    nlh = nlmsg_hdr(skb);
	pid = nlh->nlmsg_pid;
    icmp_off = ((OWN *)NLMSG_DATA(nlh))->icmp_off;
    drop_ip = ((OWN *)NLMSG_DATA(nlh))->drop_ip;
	drop_port = ((OWN *)NLMSG_DATA(nlh))->drop_port;
	//sendnlmsg("I am from kernel!");
   

  return;
}

static int test_netlink(void) {
	printk("before creat");
  nl_sk = netlink_kernel_create(&init_net ,NETLINK_TEST, 0, input, NULL,THIS_MODULE);

  if (!nl_sk) {
    printk(KERN_ERR "net_link: Cannot create netlink socket.\n");
    return -EIO;
  }
  printk("net_link: create socket ok.\n");
  return 0;
}

unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	
   struct sk_buff *sb = skb;
   struct iphdr     *iph ;

   iph = ip_hdr(sb);
   switch(iph->protocol)
    {
     case IPPROTO_ICMP:{
          struct icmphdr _icmph;
          struct icmphdr* ich;

         ich = skb_header_pointer(sb, iph->ihl*4, sizeof(_icmph), &_icmph);
         printk("icmp type %u\n", ich->type);
         if(icmp_off == 1)
          {
            printk("now we drop icmp from %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
            return NF_DROP;
          }
         break;
       }
     case IPPROTO_TCP:{
         struct tcphdr* th = NULL;
         struct tcphdr _tcph;
         th = skb_header_pointer(sb, iph->ihl*4, sizeof(_tcph), &_tcph);
         if(th == NULL)
          {
            printk("get tcp header error\n");
            return NF_DROP;
          }
         //unsigned int sip = ntohs(th->source);
         printk("saddr:%d.%d.%d.%d,sport:%u\n", NIPQUAD(iph->saddr),ntohs(th->source));
         printk("daddr:%d.%d.%d.%d,dport:%u\n", NIPQUAD(iph->daddr),ntohs(th->dest));
		 printk("%d\n", drop_port);
         if(iph->saddr == drop_ip || ntohs(th->source) == (short)drop_port)
          {
            printk("now we drop tcp from %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
             return NF_DROP;
          }
         break;
       }
     default:
         break;
    } 
	
  return NF_ACCEPT;
}

static int __init hook_init(void)
{
       printk("insmod hook test!\n");
       test_netlink();
       
       nfho.hooknum   = NF_INET_PRE_ROUTING;
       nfho.pf        = PF_INET;
       nfho.priority  = NF_IP_PRI_FIRST;
	   nfho.hook      = hook_func;
       nf_register_hook(&nfho);

       return 0;
}

static void __exit hook_exit(void)
{
    printk("rmmod hook test!\n");
    nf_unregister_hook(&nfho);
    if (nl_sk != NULL){
      sock_release(nl_sk->sk_socket);
  }
}

module_init(hook_init);
module_exit(hook_exit);

    
