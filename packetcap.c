#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/string.h> /* Needed for strcat */
#include <linux/skbuff.h> /* Needed for skbuff struct */
#include <linux/netfilter.h> /* Needed for hook　function */
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h> /* Needed for ip header */
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/byteorder/generic.h>
#include <linux/vfs.h>
#include <linux/namei.h>  /* Needed for path_lookup */
#include <linux/fs.h> /* Needed for  */
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/path.h> /* Needed for  */
#include <linux/mount.h> /* Needed for kern_path */

MODULE_AUTHOR("mouri-lab yfujieda");
MODULE_DESCRIPTION("packet dump");
MODULE_LICENSE("GPL");

// my linux kernel version is 4.4.0




struct ethhdr *mac;
struct iphdr *ip;
struct tcphdr *tcp;
struct udphdr *udp;
struct ethhdr *ether_header;
struct skbbf *skb_bf;
static struct nf_hook_ops nfhook;

// write_log modules


// function kern_path
/*
#include <linux/mount.h>
int kern_path(const char *name, unsigned int flags, struct path *path)
*/





void write_data(char *buf)
{
	struct file *file;
	char *filename = "/home/fuppaubuntu/android_lkm/packet_log/packetlog.txt";
	struct nameidata *nd;
	int error;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	// /fs/namei.c line-2118

	// /fs/namei.c line-1829
	  error = path_lookup(filename, LOOKUP_PARENT, &nd);
		if(error){
	file = filp_open(filename, O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
}else{
		file = filp_open(filename, O_CREAT | O_WRONLY | O_APPEND | O_LARGEFILE, 0);
	}


if (IS_ERR(file)){
	printk(KERN_WARNING "[DEBUG] sys_write_log > file->f_pos is negative\n");
	return;
}


/*  fs/read_write.c  function is defined ssize_t vfs_write(struct file *file,
const char __user *buf, size_t count, loff_t *pos) {   */

vfs_write(file, buf, strlen(buf), &file->f_pos);
filp_close(file, NULL);
set_fs(old_fs);
return;
}



//main modules

static unsigned int payload_dump(unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff*))

	{
		char *tcp_pl;
		unsigned int ipa, ipa2;
		int i;



		ip = (struct iphdr *)ip_hdr(skb);
		/*
		if(ip){
		printk(KERN_WARNING "[DEBUG]ip header hook failed ");
	}

	*/

 char adress[16];



	printk("source adoress:(->)");
	for (i=0;i<4;i++){

		ipa=(le32_to_cpu(ip->saddr)>>8*i)&0xff;
    strcat(adress, (char)ipa);

		printk("%d", ipa);
		if(i<3)
		printk(".");
	}
	printk("\n");
  printk("%s", &adress);


	printk("destination adress:(<-)");

	for (i=0;i<4;i++){

		ipa2=(le32_to_cpu(ip->daddr)>>8*i)&0xff;
		printk("%d", ipa2);
		if(i<3)
		printk(".");
	}
	printk("\n");
	/*  printk("s_addr   :%x      \t\t",be32_to_cpu(ip->saddr));

	printk("d_addr :%x\n",be32_to_cpu(ip->daddr));*/
	/*-------------UDP------------------*/

	write_data("unnko");
	if(ip->protocol == 17) {
		udp = (struct udphdr *)ipip_hdr(skb);
		/*
		printk(KERN_ALERT "\n---- UDP Header -------------------\n");
		printk("source port : %7u\t",ntohs(udp->source));
		printk("dest port   : %7u\t",ntohs(udp->dest));
		printk("UDP_packet_length    : %7u\t",ntohl(udp->len));
		printk("check     : %7u\n",ntohl(udp->check));
		*/
		if(ntohs(udp->source) == 53 || ntohs(udp->dest) == 53){
			//  printk(KERN_ALERT"----Domain Name System-------------\n");
			/*	  int s[] = udp+(int)udp->len;

			printk("iiiii%d", *s);
			*/

		}

	}

	/*--------------TCP-----------------*/


	if(ip->protocol == 6) {
		tcp = (struct tcphdr *)ipip_hdr(skb);
		/*
		printk(KERN_ALERT"\n---- TCP Header -------------------\n");
		printk("source port : %7u\t",ntohs(tcp->source));
		printk("dest port   : %7u\t",ntohs(tcp->dest));
		printk("sequence    : %7x\t",ntohl(tcp->seq));
		printk("ack seq     : %7x\n",ntohl(tcp->ack_seq));
		//4bit
		printk("data offset : %7u\n",tcp->doff);
		//1bit
		printk("frags       :");
		tcp->fin ? printk(" FIN") : 0 ;
		tcp->syn ? printk(" SYN") : 0 ;
		tcp->rst ? printk(" RST") : 0 ;
		tcp->psh ? printk(" PSH") : 0 ;
		tcp->ack ? printk(" ACK") : 0 ;
		tcp->urg ? printk(" URG") : 0 ;
		printk("\t");




		//limit size
		printk("window      : %7u\t",ntohs(tcp->window));
		//checksum
		printk("check       : 0x%x   \t",ntohs(tcp->check));
		//if contorol flag is urg only
		printk("urt_ptr     : %7u\n",tcp->urg_ptr);

		*/
		if(ntohs(tcp->source) == 23 || ntohs(tcp->dest) == 23){
			//  printk(KERN_ALERT "----TELNET-------------\n");


			//disputed point


			tcp_pl = (char *)tcp;
			tcp_pl =tcp_pl+tcp_hdrlen(skb);

			if(ntohs(tcp->source) == 23)
			{
				/*
				printk("telnet->:");
				printk("%s\n", tcp_pl);
				*/
			}else{
				/*    printk("telnet<-:");
				printk("%s\n", tcp_pl);
				*/ }

				//      printk("tail: %s", skb->head+skb->tail);






			}
			if(ntohs(tcp->source) == 80 || ntohs(tcp->dest) == 80){
				printk(KERN_ALERT "----HTTP-------------\n");
				//disputed point


				/*
				tcp = tcp+offset;
				while(tcp){

				printk("%s", tcp+i);
				i++;
			}

			tcp = tcp-offset;
			*/
		}


		if(ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 443){
			printk(KERN_ALERT "----HTTPS-------------\n");
		}







		/*
		printk(KERN_ALERT"\n---- skbuff -----------------------\n");
		printk("csum      :%3x\t",skb->csum);
		printk("ip_summed :%3x\t",skb->ip_summed);
		printk("priority  :%3x\t",skb->priority);
		printk("cloned    :%3x\t",skb->cloned);
		printk("nohdr     :%3x\n",skb->nohdr);
		printk("fclone    :%3x\t",skb->fclone);
		printk("peeked    :%3x\t",skb->peeked);
		printk("nf_trace  :%3x\t",skb->nf_trace);
		printk("protocol  :%3x\n",skb->protocol);
		printk("----end----\n\n\n");
		*/
	}



	return NF_ACCEPT;
}

static int __init init_main(void)
{
	nfhook.hook     = payload_dump;
	nfhook.hooknum  = 0;
	nfhook.pf       = PF_INET;
	nfhook.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfhook);



	return 0;
}

static void __exit cleanup_main(void)
{
	nf_unregister_hook(&nfhook);
	printk("refused protomodule");

}

module_init(init_main);
module_exit(cleanup_main);
