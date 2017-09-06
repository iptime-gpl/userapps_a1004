#include <linux/config.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/socket.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/string.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>

#include <linux/in.h>
#include <linux/if_tunnel.h>
#include <linux/if_ether.h>
#include <linux/delay.h>

#include <linux/skbuff.h>
#include "fast_path.h"
#include "pptp_l2tp_fdb.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include "ra_nat.h"
#include <linux/config.h>
#include <linux/if_vlan.h>
#include "util.h"

#define FAST_PPTP_PRINT	printk

extern PktParseResult          PpeParseResult;
extern uint32_t         DebugLevel;

struct net_dev *wan_dev;
char *ifname="eth2";
char *pppname="ppp0";

struct pptp_info {
    struct net_device *wan_dev;
    unsigned int tx_seqno;
    unsigned int rx_seqno;
    __u32 saddr;
    __u32 daddr;
    __u16 callID;
    __u16 callID_udp;/*tcp udp with different ID*/
    __u16 callID_tcp;
    __u16 peer_callID;
    __u16 tx_ipID;
    __u16 ipID;
    struct net_device *ppp0_dev;
    struct net_device *lan_dev;
    unsigned char mac_header[ETH_HLEN];
    unsigned int tx_seqno_daemon;
    unsigned int rx_seqno_daemon;
    int ppp_hdr_len;
    unsigned char ppp_hdr[4];
    __u32 key;/*MT7620:add key*/
};

static struct pptp_info pptpInfo={NULL};
extern unsigned int sync_tx_sequence;
static struct pptp_info pptpTunnel={NULL};



/*L2TP*/
struct l2tp_info
{
    struct net_device *wan_dev;
    struct net_device *ppp0_dev;	
    __u32 daddr;
    __u32 saddr;
    __u16 tid;                     /* Tunnel ID */
    __u16 sid;                     /* Session ID */
    __u16 source;                  /* UDP source port */
    __u16 dest;                    /* UDP dest port */
    unsigned char mac_header[ETH_HLEN];
};

struct l2tp_ext_hdr
{
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 checksum;
    __u16 type;
    __u16 tid;
    __u16 sid;
    __u16 addr_control;
    __u16 protocol;
};

struct l2tp_header
{
    __u16 ver;                   /* Version and friends */
    __u16 length;                /* Optional Length */
    __u16 tid;                   /* Tunnel ID */
    __u16 cid;                   /* Caller ID */
    __u16 Ns;                    /* Optional next sent */
    __u16 Nr;                    /* Optional next received */
};


static struct l2tp_info l2tpInfo={NULL};
static struct l2tp_info l2tpTunnel={NULL};/*for wan->lan*/
extern void skb_dump(struct sk_buff* sk);

static inline void bcopy(unsigned char *dst, unsigned char *src, int len)
{	int i;
    for (i=0; i<len; i++)
	dst[i] = src[i];
}


// Packet come from WAN, and it is GRE data
//	  delete IP+GRE+PPP header 
//
extern int fast_bind;
int fast_pptp_to_lan(struct sk_buff **pskb)
{		
    struct	iphdr *iph = NULL;
    struct	iphdr *iph_ppp0 = NULL;
    struct	ethhdr *eth = NULL;
    struct	pptp_gre_hdr *greh;					
    unsigned char ppp_type=0;
    void	*ppp;    
    struct	sk_buff *skb = *pskb;
    int	pull_offset=0;
    struct	tcphdr *th = NULL;
    struct	udphdr *uh = NULL;	
    int	check_stats=0;
    unsigned int addr = 0;

    iph = (struct iphdr *)(skb->data + 4);

    if (iph->protocol != IPPROTO_GRE || skb->len < sizeof(struct iphdr)){
	return 1;
    }
    greh = (struct pptp_gre_hdr *)(skb->data + (iph->ihl*4) + 4);

    if ((greh->version&7) == PPTP_GRE_VERSION &&
	    ntohs(greh->protocol) == PPTP_GRE_PROTOCOL) {
	unsigned char *ppp_data;	
	int offset = sizeof(*greh) - 8;	// delete seq and ack no
	int ppp_offset=0;

	if (PPTP_GRE_IS_S(greh->flags)) {	
	    pptpInfo.rx_seqno = ntohl(greh->seq);						
	    offset += 4;
	}	

	if (PPTP_GRE_IS_A(greh->version))
	    offset += 4;

	ppp_data = ((char *)greh) + offset;				
	ppp_offset = 0;				
	if (greh->payload_len > 0) {	
	    // check PPP IP protocol
	    if (*ppp_data == 0) {
		ppp_offset = 1;
		ppp_data++;
	    }
	    else if (*ppp_data == 0xff && *(ppp_data+1) == 0x03) {									
		ppp_offset = 2;
		ppp_data += 2;
		if (*ppp_data == 0x00) {
		    ppp_offset++;
		    ppp_data++;
		}
	    }											
	    if (*ppp_data == 0x21 || *ppp_data == 0xfd) {
		ppp_offset++;					
		ppp_type = *ppp_data;
	    }
	    else
		ppp_offset = 0;		
	}	
	if (ppp_offset ==  0)
	{
	    return 1;
	}
	offset = iph->ihl*4 + offset + ppp_offset;	// tunnel IP offset	

	iph_ppp0 = (struct iphdr *)(skb->data + offset + 4);

	if(!fast_bind)
	{
	    pptpTunnel.saddr = iph_ppp0->saddr;
	    pptpTunnel.daddr = iph_ppp0->daddr;
	}
	//printk("PPTP SIP=%s\n", Ip2Str(pptpInfo.saddr));
	//printk("PPTP DIP=%s\n", Ip2Str(pptpInfo.daddr));

	if(iph_ppp0->protocol == IPPROTO_TCP)
	{
	    th = (struct tcphdr *)(skb->data + offset + 4 + 20);
	    addr = ((th->source << 16)|th->dest);
	    //printk("TCP src port=%d, dst port=%d", ntohs(th->source), ntohs(th->dest));
	}
	else if (iph_ppp0->protocol == IPPROTO_UDP)
	{
	    uh = (struct udphdr *)(skb->data + offset + 4 + 20);
	    addr = ((uh->source << 16)|uh->dest);

	    //printk("UDP src port=%d, dst port=%d", ntohs(uh->source), ntohs(uh->dest));
	}
	else
	{
	    printk("0.1 Non TCP/UDP to lan, pass up, line %d!!\n", __LINE__);
	    return 1;

	}


	// !PPP_IP  pass up
	if (ppp_type != 0x21) 
	{						
	    return 1;				
	}
	else {
	    int rev = 0;
	    // header removal section

	    //skb_dump(skb);
	    rev = is_pptp_l2tp_bind(iph_ppp0->protocol, addr);
	    if(rev)
	    {
		//printk("original packet!!!\n");
		//skb_dump(skb);

		/*Kurts:memory remove from head*/    
		memcpy(skb->data + 4, skb->data - offset + 4, offset);
		//printk("afater memmove  GRE + PPTP header\n");
		//redirect to PPE
		FOE_AI(skb) = UN_HIT;
		FOE_MAGIC_TAG(skb) = FOE_MAGIC_PPE;
		skb_pull(skb, offset);
		skb_push(skb, 14);
#if defined (CONFIG_HNAT_V2)	    
		/*make mac table transparent*/
		eth = (struct ethhdr *)skb->data;
		eth->h_source[0] = 0x01;
#endif
		skb->dev = wan_dev;
		dev_queue_xmit(skb);
		return 0;
	    }
	    else{
		FOE_MAGIC_TAG(skb) = FOE_MAGIC_FASTPATH;

		if(iph_ppp0->protocol == IPPROTO_TCP)
		{
		    th = (struct tcphdr *)(skb->data + offset + 4 + 20);

		    FOE_SOURCE(skb) = ntohs(th->source);
		    FOE_DEST(skb) = ntohs(th->dest);
		}
		else if (iph_ppp0->protocol == IPPROTO_UDP)
		{
		    uh = (struct udphdr *)(skb->data + offset + 4 + 20);

		    FOE_SOURCE(skb) = ntohs(uh->source);
		    FOE_DEST(skb) = ntohs(uh->dest);
		}
		else
		{
		    return 1;

		}

		return 1;
	    }
	}

	//FAST_PPTP_PRINT("delete GRE + PPTP header\n");
	LAYER3_HEADER(skb) = skb->data;
	LAYER4_HEADER(skb) = skb->data;

	FAST_PPTP_PRINT("pass up\n");
    }




    return 1;		
}

// Packet come from LAN and dst dev is ppp0, 
// add IP+GRE+PPTP header
int fast_pptp_to_wan(struct sk_buff *skb)
{
    int	header_len;
    struct iphdr *iph_new, iph_newone;
    struct pptp_gre_hdr	*greh, grehone;	
    unsigned char tos;
    unsigned short frag_off;
    int ppp_hdr_len=0;		
    struct iphdr *iph;
    struct net_dev *dev;
    struct vlan_ethhdr *veth=NULL;
    struct vlan_hdr *ppph=NULL;

    iph = (struct iphdr *)(skb->data + 4);	
    /*set tcp udp with different call ID*/
    if(iph->protocol == IPPROTO_TCP){
	pptpInfo.callID = pptpInfo.callID_tcp;
    }
    else {
	pptpInfo.callID = pptpInfo.callID_udp;
    }

    {
	extern int ppp_start_xmit(struct sk_buff *skb, struct net_device *dev);
	extern void *get_ppp_vj(void *ppp);
	extern unsigned int get_ppp_xstate(void *ppp);
	extern void *get_ppp_xc_state(void *ppp);
	extern struct sk_buff *get_ppp_xmit_pending(void *ppp);
	extern void set_ppp_xmit_pending(void *ppp, struct sk_buff *skb);		
	void *ppp ;
	/*no compression support*/

	tos = iph->tos;
	frag_off = iph->frag_off;

	header_len = ETH_HLEN + sizeof(*iph_new) + sizeof(*greh); // mac-header+ip+gre+ppp-4 for gre key	

	if (skb_headroom(skb) < header_len || skb_cloned(skb) || skb_shared(skb)) {	
	    struct sk_buff *new_skb = skb_realloc_headroom(skb, header_len);				
	    if (!new_skb) {				
		printk("%s: skb_realloc_headroom failed!\n", __FUNCTION__);	
		return 0;
	    }									
	    dev_kfree_skb(skb);
	    skb = new_skb;
	}			

	// build mac header						
	memcpy(skb_push(skb, header_len), pptpInfo.mac_header, ETH_HLEN);

	veth = (struct vlan_ethhdr *)(skb->data);
	veth->h_vlan_proto = htons(ETH_P_8021Q);
	veth->h_vlan_TCI = htons(0x2);
	veth->h_vlan_encapsulated_proto = htons(ETH_P_IP);

	// build ip header							
	iph_new = &iph_newone;	
	iph_new->version	=	4;
	iph_new->ihl		=	sizeof(struct iphdr) >> 2;
	iph_new->frag_off	=	0x0;	
	iph_new->protocol	=	IPPROTO_GRE;
	iph_new->tos		=	0x0;
	iph_new->daddr	=	pptpInfo.daddr;
	iph_new->saddr	=	pptpInfo.saddr;
	iph_new->ttl 		=	IPDEFTTL;   
	/*TODO:To enable checksum offload*/		

	skb->ip_summed	=	CHECKSUM_NONE;			
	iph_new->tot_len	=	htons(skb->len - ETH_HLEN-4);		
	iph_new->id		=	htons(++pptpInfo.tx_ipID);
	iph_new->check	=	0;
	iph_new->check	=	ip_fast_csum((unsigned char *)iph_new, iph_new->ihl);	
	pptpInfo.ipID	=	iph_new->id; // save id to check in sync_pptp_gre_seqno()
	memcpy(skb->data + ETH_HLEN + 4, &iph_newone, sizeof(iph_newone)); 					

	// build gre header
	greh 			= &grehone;
	greh->flags		= PPTP_GRE_FLAG_K | PPTP_GRE_FLAG_S;
	//greh->version	= PPTP_GRE_VERSION | PPTP_GRE_FLAG_A;
	greh->version	= PPTP_GRE_VERSION;
	greh->protocol	= htons(PPTP_GRE_PROTOCOL);
	greh->payload_len	= htons(skb->len - header_len + ppp_hdr_len);    	
	greh->call_id		= pptpInfo.callID;			
	greh->seq 		= htonl(++sync_tx_sequence);		
	memcpy(skb->data+ETH_HLEN+sizeof(struct iphdr)+4, &grehone, sizeof(grehone)-4);
	//printk("add GRE header, id=%d, gre-len=%d seq=%d!\n", iph_new->id, skb->len-header_len, ntohl(greh->seq));

	ppph = (struct vlan_hdr *)(skb->data+ETH_HLEN+sizeof(struct iphdr)+sizeof(grehone));
	ppph->h_vlan_TCI = htons(PPP_ADDRESS_CONTROL);
	ppph->h_vlan_encapsulated_proto = htons(PPP_PROTOCOL);

	skb->dev=wan_dev;

	FOE_AI(skb) = UN_HIT;
	dev_queue_xmit(skb);

	return 0;						
    }

    return 0;	
}		
int  fast_pptp_init(void)
{
    if(wan_dev=ra_dev_get_by_name(ifname)){
	//printk("wan_dev name is %s!\n", wan_dev->name);
    }

    return 0;
}

int  fast_pptp_clean(void)
{
    if (wan_dev != NULL) {
	dev_put(wan_dev);
    }

    if (pptpInfo.ppp0_dev != NULL) {
	dev_put(pptpInfo.ppp0_dev);
    }
    return 0;
}



int32_t SendL2TPHashPkt(struct sk_buff *pskb)
{
    struct net_dev *dev;
    struct sk_buff *skb = NULL;
    struct iphdr *iph = NULL;
    struct iphdr *iph_new = NULL;
    struct tcphdr *th = NULL;
    struct udphdr *uh = NULL;

    unsigned char pkt[]={
	//0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dest bcast mac
	0x00, 0x30, 0xda, 0x01, 0x02, 0x0f, // dest macA
	//0x00, 0x30, 0xdb, 0x02, 0x02, 0x01, // dest macB
	0x00, 0x88, 0x99, 0x00, 0xaa, 0xbb, // src mac
	0x81, 0x00, // vlan tag
	//0x00, 0x01, // pri=0, vlan=1
	0x01, 0x23, // pri=0, vlan=1
	0x08, 0x00, // eth type=ip
	//0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00, 0xff, 0x11,//UDP
	0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00, 0xff, 0x06, //TCP
	0x40, 0x74, 0x0a, 0x0a, 0x1e, 0x0a, 0x0a, 0x0a, 0x1e, 0x0b,
	0x00, 0x1e, 0x00, 0x28, 0x00, 0x1c, 0x81, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    skb = alloc_skb(256, GFP_ATOMIC);
    if( skb == NULL){
	return 1;
    }
    if (DebugLevel >= 1) {
	printk("Ori source port = %d\n",FOE_SOURCE(pskb));
    }
    //printk("Ori dest port = %d\n",FOE_DEST(pskb));
    /*TODO:need to consider HW vlan*/
    iph = (struct iphdr *)(pskb->data+14 + 4);

    // skb_dump(pskb);

    if(1)
    {
	skb->dev=wan_dev;
	//skb->dev = DstPort[DP_GMAC];  //we use GMAC1 to send the packet to PPE
	//redirect to PPE
	FOE_AI(skb) = UN_HIT;
	FOE_MAGIC_TAG(skb) = FOE_MAGIC_PPE;

	skb_reserve(skb, 32);
	skb_put(skb,sizeof(pkt));
	memcpy(skb->data, pkt, sizeof(pkt));

	iph_new = (struct iphdr *)(skb->data+14 + 4);

	/*from wan -> lan*/
	iph_new->saddr = l2tpTunnel.saddr;
	iph_new->daddr = l2tpTunnel.daddr;

	if(iph->protocol == IPPROTO_TCP)
	{
	    skb_put(skb, (14+4+sizeof(struct iphdr)+sizeof(struct tcphdr)));
	    memcpy(skb->data+14+4+40, pskb->data, (14+4+sizeof(struct iphdr)+sizeof(struct tcphdr)));

	    th = (struct tcphdr *)(skb->data +20 +14 + 4);
	    th->source = htons(FOE_SOURCE(pskb));
	    th->dest = htons(FOE_DEST(pskb));
	    //printk("original pkt is TCP \n");

	    if (DebugLevel >= 1) {
		printk("send pingpong TCP  pkt:\n");
	    }
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
	    uh = (struct udphdr *)(skb->data +20 +14 + 4);
	    uh->source = htons(FOE_SOURCE(pskb));
	    uh->dest = htons(FOE_DEST(pskb));

	    printk("send pingpong UDP pkt\n");
	}

	if (DebugLevel >= 1) {
	    printk("send L2TP Hash pkt(len=%d) dport=%d to %s\n", skb->len,FOE_DEST(pskb), skb->dev->name);
	}
	dev_queue_xmit(skb);
    }else{
	printk("interface %s not found\n",ifname);
	return 1;
    }

    return 0;
}


int32_t SendHashPkt(struct sk_buff *pskb)
{
    struct net_dev *dev;
    struct sk_buff *skb = NULL;
    struct iphdr *iph = NULL;
    struct iphdr *iph_new = NULL;
    struct tcphdr *th = NULL;
    struct udphdr *uh = NULL;

    unsigned char pkt[]={
	//0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dest bcast mac
	0x00, 0x30, 0xda, 0x01, 0x02, 0x0f, // dest macA
	//0x00, 0x30, 0xdb, 0x02, 0x02, 0x01, // dest macB
	0x00, 0x88, 0x99, 0x00, 0xaa, 0xbb, // src mac
	0x81, 0x00, // vlan tag
	//0x00, 0x01, // pri=0, vlan=1
	0x01, 0x23, // pri=0, vlan=0x123
	0x08, 0x00, // eth type=ip
	//0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00, 0xff, 0x11,//UDP
	0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00, 0xff, 0x06, //TCP
	0x40, 0x74, 0x0a, 0x0a, 0x1e, 0x0a, 0x0a, 0x0a, 0x1e, 0x0b,
	0x00, 0x1e, 0x00, 0x28, 0x00, 0x1c, 0x81, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    skb = alloc_skb(256, GFP_ATOMIC);
    if( skb == NULL){
	return 1;
    }
    if (DebugLevel >= 1) {
	printk("Ori source port = %d\n",FOE_SOURCE(pskb));
    }
    //printk("Ori dest port = %d\n",FOE_DEST(pskb));
    /*no  HW vlan*/
    iph = (struct iphdr *)(pskb->data+14 + 4);

    if(1)
    {
	skb->dev=wan_dev;
	//skb->dev = DstPort[DP_GMAC];  //we use GMAC1 to send the packet to PPE

	//redirect to PPE
	FOE_AI(skb) = UN_HIT;
	FOE_MAGIC_TAG(skb) = FOE_MAGIC_PPE;

	skb_reserve(skb, 32);
	skb_put(skb,sizeof(pkt));
	memcpy(skb->data, pkt, sizeof(pkt));

	iph_new = (struct iphdr *)(skb->data+14 + 4);

	/*from wan -> lan*/
	iph_new->saddr = pptpTunnel.saddr;
	iph_new->daddr = pptpTunnel.daddr;

	if(iph->protocol == IPPROTO_TCP)
	{
	    skb_put(skb, (14+4+sizeof(struct iphdr)+sizeof(struct tcphdr)));
	    memcpy(skb->data+14+4+40, pskb->data, (14+4+sizeof(struct iphdr)+sizeof(struct tcphdr)));

	    th = (struct tcphdr *)(skb->data +20 +14 + 4);
	    th->source = htons(FOE_SOURCE(pskb));
	    th->dest = htons(FOE_DEST(pskb));
	    //printk("original pkt is TCP \n");
	    //printk("original pkt:\n");

	    if (DebugLevel >= 1) {
		printk("send pingpong TCP  pkt:\n");
	    }
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
	    uh = (struct udphdr *)(skb->data +20 +14 + 4);
	    uh->source = htons(FOE_SOURCE(pskb));
		uh->dest = htons(FOE_DEST(pskb));

		printk("send pingpong UDP pkt\n");
	}

	if (DebugLevel >= 1) {
		printk("send Hash pkt(len=%d) dport=%d to %s\n", skb->len,FOE_DEST(pskb), skb->dev->name);
	}

	dev_queue_xmit(skb);
    }else{
	printk("interface %s not found\n",ifname);
        //kfree_skb(skb);
	return 1;
    }

    return 0;
}


int32_t PptpToLanParseLayerInfo(struct sk_buff * skb)
{
	struct vlan_hdr *vh = NULL;
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;

	struct iphdr *iph_ori = NULL;
	int offset = 0;
#ifdef CONFIG_RAETH_HW_VLAN_TX
	struct vlan_hdr pseudo_vhdr;
#endif
	memset(&PpeParseResult, 0, sizeof(PpeParseResult));

	vh = (struct vlan_hdr *)(skb->data);
	if(ntohs(vh->h_vlan_TCI) != 0x123){
	    printk("drop pingpong non vid=0x123 vh->h_vlan_TCI is 0x%4x\n", vh->h_vlan_TCI);
    	    return 1;
	}

	iph_ori = (struct iphdr *)(skb->data + 4);
	if (iph_ori->protocol == IPPROTO_TCP) {
	    offset = VLAN_HLEN + (iph_ori->ihl * 4) + sizeof(struct tcphdr);
	}
	else if (iph_ori->protocol == IPPROTO_TCP) {
	    offset = VLAN_HLEN + (iph_ori->ihl * 4) + sizeof(struct udphdr);
	}
	else{
	    printk("FastPathParseLayerInfo error type!!\n");
	    return 1;
	}

	//skb_dump(skb);

	eth = (struct ethhdr *)(skb->data + offset);
	memcpy(PpeParseResult.dmac, eth->h_dest, ETH_ALEN);
	memcpy(PpeParseResult.smac, eth->h_source, ETH_ALEN);
	PpeParseResult.eth_type = eth->h_proto;

	// we cannot speed up multicase packets because both wire and wireless PCs might join same multicast group.
#if defined(CONFIG_RALINK_MT7620)
	if(is_multicast_ether_addr(&eth->h_dest[0])) {
		PpeParseResult.is_mcast = 1;
	}else {
		PpeParseResult.is_mcast = 0;
	}
#else
	if(is_multicast_ether_addr(&eth->h_dest[0])) {
		return 1;
	}
#endif
	if (is8021Q(PpeParseResult.eth_type) || isSpecialTag(PpeParseResult.eth_type) || isHwVlanTx(skb)) {
		//printk("PpeParseResult!!!!!!!!!!!!!\n");
#ifdef CONFIG_RAETH_HW_VLAN_TX
		PpeParseResult.vlan1_gap = 0;
		PpeParseResult.vlan_layer++;
		pseudo_vhdr.h_vlan_TCI = htons(vlan_tx_tag_get(skb));
		pseudo_vhdr.h_vlan_encapsulated_proto = eth->h_proto;
		vh = (struct vlan_hdr *)&pseudo_vhdr;
#else
		PpeParseResult.vlan1_gap = VLAN_HLEN;
		PpeParseResult.vlan_layer++;
		vh = (struct vlan_hdr *)(skb->data + offset + ETH_HLEN);
#endif
		PpeParseResult.vlan1 = vh->h_vlan_TCI;
		PpeParseResult.eth_type = vh->h_vlan_encapsulated_proto;
	}
	/* set layer2 start addr */
	LAYER2_HEADER(skb) = skb->data + offset;

	/* set layer3 start addr */
	LAYER3_HEADER(skb) =
	    (skb->data + offset +ETH_HLEN + PpeParseResult.vlan1_gap +
	     PpeParseResult.vlan2_gap + PpeParseResult.pppoe_gap);

	/* set layer4 start addr */
	if ((PpeParseResult.eth_type == htons(ETH_P_IP))) {
		iph = (struct iphdr *)LAYER3_HEADER(skb);

		//prepare layer3/layer4 info
		memcpy(&PpeParseResult.iph, iph, sizeof(struct iphdr));
		if (iph->protocol == IPPROTO_TCP) {
			LAYER4_HEADER(skb) = ((uint8_t *) iph + (iph->ihl * 4));
			th = (struct tcphdr *)LAYER4_HEADER(skb);
			memcpy(&PpeParseResult.th, th, sizeof(struct tcphdr));
			PpeParseResult.pkt_type = IPV4_HNAPT;

			if(iph->frag_off & htons(IP_MF|IP_OFFSET)) {
				return 1;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			LAYER4_HEADER(skb) = ((uint8_t *) iph + iph->ihl * 4);
			uh = (struct udphdr *)LAYER4_HEADER(skb);
			memcpy(&PpeParseResult.uh, uh, sizeof(struct udphdr));
			PpeParseResult.pkt_type = IPV4_HNAPT;
			
			if(iph->frag_off & htons(IP_MF|IP_OFFSET)) {
				return 1;
			}
		}
#if defined (CONFIG_HNAT_V2)
		else if (iph->protocol == IPPROTO_GRE) {
			/* do nothing */
		}
#endif
		else {
			/* Packet format is not supported */
			return 1;
		}

	} else {
		return 1;
	}

	if (DebugLevel >= 6) {
		printk("--------------\n");
		printk("DMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
		       PpeParseResult.dmac[0], PpeParseResult.dmac[1],
		       PpeParseResult.dmac[2], PpeParseResult.dmac[3],
		       PpeParseResult.dmac[4], PpeParseResult.dmac[5]);
		printk("SMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
		       PpeParseResult.smac[0], PpeParseResult.smac[1],
		       PpeParseResult.smac[2], PpeParseResult.smac[3],
		       PpeParseResult.smac[4], PpeParseResult.smac[5]);
		printk("Eth_Type=%x\n", PpeParseResult.eth_type);
		if (PpeParseResult.vlan1_gap > 0) {
			printk("VLAN1 ID=%x\n", ntohs(PpeParseResult.vlan1));
		}

		if (PpeParseResult.vlan2_gap > 0) {
			printk("VLAN2 ID=%x\n", ntohs(PpeParseResult.vlan2));
		}

		if (PpeParseResult.pppoe_gap > 0) {
			printk("PPPOE Session ID=%x\n",
			       PpeParseResult.pppoe_sid);
			printk("PPP Tag=%x\n", ntohs(PpeParseResult.ppp_tag));
		}
#if defined (CONFIG_HNAT_V2)
		printk("PKT_TYPE=%s\n",
		       PpeParseResult.pkt_type ==
		       0 ? "IPV4_HNAT" : PpeParseResult.pkt_type ==
		       1 ? "IPV4_HNAPT" : PpeParseResult.pkt_type ==
		       3 ? "IPV4_DSLITE" : PpeParseResult.pkt_type ==
		       4 ? "IPV6_ROUTE" : PpeParseResult.pkt_type ==
		       5 ? "IPV6_6RD" : "Unknown");
#else
		printk("PKT_TYPE=%s\n",
		       PpeParseResult.pkt_type ==
		       0 ? "IPV4_HNAPT" : PpeParseResult.pkt_type ==
		       1 ? "IPV4_HNAT" : PpeParseResult.pkt_type ==
		       2 ? "IPV6_ROUTE" : "Unknown");
#endif

		if (PpeParseResult.pkt_type == IPV4_HNAT) {
			printk("SIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.saddr)));
			printk("DIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.daddr)));
			printk("TOS=%x\n", ntohs(PpeParseResult.iph.tos));
		} else if (PpeParseResult.pkt_type == IPV4_HNAPT) {
			printk("SIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.saddr)));
			printk("DIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.daddr)));
			printk("TOS=%x\n", ntohs(PpeParseResult.iph.tos));
			
			if (PpeParseResult.iph.protocol == IPPROTO_TCP) {
			    printk("TCP SPORT=%d\n", ntohs(PpeParseResult.th.source));
			    printk("TCP DPORT=%d\n", ntohs(PpeParseResult.th.dest));
			}else if(PpeParseResult.iph.protocol == IPPROTO_UDP) {
			    printk("UDP SPORT=%d\n", ntohs(PpeParseResult.uh.source));
			    printk("UDP DPORT=%d\n", ntohs(PpeParseResult.uh.dest));
			}
		}
	}

	return 0;/*OK*/
}



int32_t PptpToWanParseLayerInfo(struct sk_buff * skb)
{
	struct vlan_hdr *vh = NULL;
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	struct iphdr *iph_ppp0 = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;

	struct pptp_gre_hdr *greh = NULL;			
	unsigned char *ppp_data = NULL;	
	unsigned char ppp_type=0;
	int offset = sizeof(*greh) - 8; // delete seq and ack no
	int ppp_offset=0;
#ifdef CONFIG_RAETH_HW_VLAN_TX
	struct vlan_hdr pseudo_vhdr;
#endif
	memset(&PpeParseResult, 0, sizeof(PpeParseResult));

	eth = (struct ethhdr *)(skb->data);
	iph_ppp0 = (struct iphdr *)(skb->data + 14 + 4);
	
	memcpy(PpeParseResult.smac, eth->h_dest, ETH_ALEN);
	memcpy(PpeParseResult.dmac, eth->h_source, ETH_ALEN);
	PpeParseResult.smac[0] = 0x01;

	greh = (struct pptp_gre_hdr *)(skb->data + 14 + (iph_ppp0->ihl*4) + 4);
	
/*log pptp info*/	
    pptpInfo.callID = greh->call_id;
    pptpInfo.saddr = iph_ppp0->saddr;
    pptpInfo.daddr = iph_ppp0->daddr;
    memcpy(pptpInfo.mac_header, eth->h_dest, ETH_ALEN);
    memcpy(&pptpInfo.mac_header[6], eth->h_source, ETH_ALEN);

    if (DebugLevel >= 1) {
	printk("greh->flags is 0x%1x\n", greh->flags);
	printk("greh->versions is 0x%1x\n", greh->version);
    }
	PpeParseResult.eth_type = eth->h_proto;

		if (PPTP_GRE_IS_S(greh->flags)) 
		{	
			if (DebugLevel >= 1) {
				printk("greh->seq is %d\n", ntohl(greh->seq));    
				printk("log pptpInfo.tx_seqno!!!!!!!!!!\n");
			}
			pptpInfo.tx_seqno = ntohl(greh->seq);						
			if (DebugLevel >= 1) {
				printk("log pptpInfo. IP ID!!!!!!!!!!\n");
			}
			pptpInfo.tx_ipID = ntohs(iph_ppp0->id);
			offset += 4;
		}	
			
		if (PPTP_GRE_IS_A(greh->version))
		{
			if (DebugLevel >= 1) {
				printk("log pptpInfo.rx_seqno ACK!!!!!!!!!!\n");
			}
			pptpInfo.rx_seqno =  ntohl(greh->ack);
			offset += 4;
		}			
		ppp_data = ((char *)greh) + offset;				

		ppp_offset = 0;				
		if (greh->payload_len > 0) {	
			// check PPP IP protocol
			if (*ppp_data == 0) {
				ppp_offset = 1;
				ppp_data++;
			}
			else if (*ppp_data == 0xff && *(ppp_data+1) == 0x03) {									
				ppp_offset = 2;
				ppp_data += 2;
				if (*ppp_data == 0) {
					ppp_offset++;
					ppp_data++;
				}
			}											
			if (*ppp_data == 0x21 || *ppp_data == 0xfd) {
				ppp_offset++;					
				ppp_type = *ppp_data;
			}
			else
				ppp_offset = 0;		
		}	

	if (ppp_offset ==  0) 
			return 1;

		offset = iph_ppp0->ihl*4 + offset + ppp_offset;	// tunnel IP offset	
		//offset = iph->ihl*4 + offset + ppp_offset + 4;	// tunnel IP offset + vlan	
	
	if (DebugLevel >= 1) {
		printk("pptp offset is 0x%d\n", offset);
	}

	//skb_dump(skb);
	if (is8021Q(PpeParseResult.eth_type) || isSpecialTag(PpeParseResult.eth_type) || isHwVlanTx(skb)) {

#ifdef CONFIG_RAETH_HW_VLAN_TX
		PpeParseResult.vlan1_gap = 0;
		PpeParseResult.vlan_layer++;
		pseudo_vhdr.h_vlan_TCI = htons(vlan_tx_tag_get(skb));
		pseudo_vhdr.h_vlan_encapsulated_proto = eth->h_proto;
		vh = (struct vlan_hdr *)&pseudo_vhdr;
#else
		PpeParseResult.vlan1_gap = VLAN_HLEN;
		PpeParseResult.vlan_layer++;
		vh = (struct vlan_hdr *)(skb->data + ETH_HLEN);
#endif
		PpeParseResult.vlan1 = vh->h_vlan_TCI;

		PpeParseResult.eth_type = vh->h_vlan_encapsulated_proto;
	}

	/* set layer2 start addr, original L2 MAC */
	LAYER2_HEADER(skb) = skb->data;

	/* set layer3 start addr, inner IP */
	LAYER3_HEADER(skb) =
	    (skb->data + offset +ETH_HLEN + PpeParseResult.vlan1_gap +
	     PpeParseResult.vlan2_gap);

	if (DebugLevel >= 1) {
		printk("LAN -> WAN set layer4 start addr\n");
	}
	/* set layer4 start addr */
	if ((PpeParseResult.eth_type == htons(ETH_P_IP))) {
		iph = (struct iphdr *)LAYER3_HEADER(skb);

		if(iph->protocol == IPPROTO_TCP)
		{
			//th = (struct tcphdr *)((uint8_t *) iph + (iph->ihl * 4));
			th = (struct tcphdr *)((uint8_t *) iph + 20);
			pptpInfo.callID_tcp = greh->call_id;
			//printk("LAN -> WAN TCP src port=%d, dst port=%d \n", ntohs(th->source), ntohs(th->dest));
			//printk("LAN -> WAN pptpInfo.callID_tcp =%4x\n", pptpInfo.callID_tcp);
		}
		else if (iph->protocol == IPPROTO_UDP)
		{
			uh = (struct udphdr *)((uint8_t *)iph + 20);
			pptpInfo.callID_udp = greh->call_id;
			//printk("UDP src port=%d, dst port=%d", ntohs(uh->source), ntohs(uh->dest));
		}

		//prepare layer3/layer4 info
		memcpy(&PpeParseResult.iph, iph, sizeof(struct iphdr));
		if (iph->protocol == IPPROTO_TCP) {
			LAYER4_HEADER(skb) = ((uint8_t *) iph + (iph->ihl * 4));
			th = (struct tcphdr *)LAYER4_HEADER(skb);
			memcpy(&PpeParseResult.th, th, sizeof(struct tcphdr));
			PpeParseResult.pkt_type = IPV4_HNAPT;
			if (DebugLevel >= 1) {
				printk("LAN -> WAN TCP src port=%d, dst port=%d \n", ntohs(th->source), ntohs(th->dest));
			}
			if(iph->frag_off & htons(IP_MF|IP_OFFSET)) {
			        printk("iph->frag_off  return\n");
				return 1;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			LAYER4_HEADER(skb) = ((uint8_t *) iph + iph->ihl * 4);
			uh = (struct udphdr *)LAYER4_HEADER(skb);
			memcpy(&PpeParseResult.uh, uh, sizeof(struct udphdr));
			PpeParseResult.pkt_type = IPV4_HNAPT;
			
			if(iph->frag_off & htons(IP_MF|IP_OFFSET)) {
				return 1;
			}
		}
#if defined (CONFIG_HNAT_V2)
		else if (iph->protocol == IPPROTO_GRE) {
			/* do nothing */
		}
#endif
		else {
			/* Packet format is not supported */
			return 1;
		}

	} else {
		return 1;
	}

	if (DebugLevel >= 6) {
		printk("--------------\n");
		printk("DMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
		       PpeParseResult.dmac[0], PpeParseResult.dmac[1],
		       PpeParseResult.dmac[2], PpeParseResult.dmac[3],
		       PpeParseResult.dmac[4], PpeParseResult.dmac[5]);
		printk("SMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
		       PpeParseResult.smac[0], PpeParseResult.smac[1],
		       PpeParseResult.smac[2], PpeParseResult.smac[3],
		       PpeParseResult.smac[4], PpeParseResult.smac[5]);
		printk("Eth_Type=%x\n", PpeParseResult.eth_type);
		if (PpeParseResult.vlan1_gap > 0) {
			printk("VLAN1 ID=%x\n", ntohs(PpeParseResult.vlan1));
		}

		if (PpeParseResult.vlan2_gap > 0) {
			printk("VLAN2 ID=%x\n", ntohs(PpeParseResult.vlan2));
		}

		if (PpeParseResult.pppoe_gap > 0) {
			printk("PPPOE Session ID=%x\n",
			       PpeParseResult.pppoe_sid);
			printk("PPP Tag=%x\n", ntohs(PpeParseResult.ppp_tag));
		}
#if defined (CONFIG_HNAT_V2)
		printk("PKT_TYPE=%s\n",
		       PpeParseResult.pkt_type ==
		       0 ? "IPV4_HNAT" : PpeParseResult.pkt_type ==
		       1 ? "IPV4_HNAPT" : PpeParseResult.pkt_type ==
		       3 ? "IPV4_DSLITE" : PpeParseResult.pkt_type ==
		       4 ? "IPV6_ROUTE" : PpeParseResult.pkt_type ==
		       5 ? "IPV6_6RD" : "Unknown");
#else
		printk("PKT_TYPE=%s\n",
		       PpeParseResult.pkt_type ==
		       0 ? "IPV4_HNAPT" : PpeParseResult.pkt_type ==
		       1 ? "IPV4_HNAT" : PpeParseResult.pkt_type ==
		       2 ? "IPV6_ROUTE" : "Unknown");
#endif

		if (PpeParseResult.pkt_type == IPV4_HNAT) {
			printk("SIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.saddr)));
			printk("DIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.daddr)));
			printk("TOS=%x\n", ntohs(PpeParseResult.iph.tos));
		} else if (PpeParseResult.pkt_type == IPV4_HNAPT) {
			printk("SIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.saddr)));
			printk("DIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.daddr)));
			printk("TOS=%x\n", ntohs(PpeParseResult.iph.tos));
			
			if (PpeParseResult.iph.protocol == IPPROTO_TCP) {
			    printk("TCP SPORT=%d\n", ntohs(PpeParseResult.th.source));
			    printk("TCP DPORT=%d\n", ntohs(PpeParseResult.th.dest));
			}else if(PpeParseResult.iph.protocol == IPPROTO_UDP) {
			    printk("UDP SPORT=%d\n", ntohs(PpeParseResult.uh.source));
			    printk("UDP DPORT=%d\n", ntohs(PpeParseResult.uh.dest));
			}
		}
	}

	return 0;/*0 means OK here*/
}


/*L2TP*/

int fast_l2tp_to_lan(struct sk_buff **pskb)
{		
	struct iphdr *iph_ppp0 = NULL;
	struct ethhdr *eth = NULL;
	struct l2tp_header  *l2tph;
	unsigned char ppp_type=0;
	void *ppp;    
	struct sk_buff *skb = *pskb;
	struct iphdr *iph = NULL;
	int pull_offset=0;
        struct tcphdr *th = NULL;
        struct udphdr *uh = NULL;	
	int check_stats=0;
	unsigned int addr = 0;

	iph = (struct iphdr *)(skb->data + 4);
	
	if (iph->protocol != IPPROTO_UDP || skb->len < sizeof(struct iphdr)){
    	    return 1;
	}

	uh = (struct udp_hdr *)(skb->data + (iph->ihl*4) + 4);
	l2tph = (struct l2tp_header *)(skb->data + (iph->ihl*4) + 4 + 8);

	if(ntohs(uh->source)!=1701) /*port:1701*/
	{
	    return 1;
	}
	{
		unsigned char *ppp_data;	
		int offset = 6;	//l2tp header from 6 
		int ppp_offset=0;
			
		if(l2tph->ver & 0x4000)
		{	
			offset += 2;
		}	
			
		if(l2tph->ver & 0x0200)
			offset += 2;

		ppp_data = ((char *)l2tph) + offset;				
		ppp_offset = 0;				
		// check PPP IP protocol
		if (*ppp_data == 0) {
		    ppp_offset = 1;
		    ppp_data++;
		}
		else if (*ppp_data == 0xff && *(ppp_data+1) == 0x03) {									
		    ppp_offset = 2;
		    ppp_data += 2;
		    if (*ppp_data == 0x00) {
			ppp_offset++;
			ppp_data++;
		    }
		}											
		if (*ppp_data == 0x21 || *ppp_data == 0xfd) {
		    ppp_offset++;					
		    ppp_type = *ppp_data;
		}
		else
		    ppp_offset = 0;		

		if (ppp_offset ==  0)
		{
		    return 1;
		}
		offset = iph->ihl*4 + 8/*UDP*/ + offset + ppp_offset;	// tunnel IP offset	
		iph_ppp0 = (struct iphdr *)(skb->data + offset + 4 );/*inner IP, 8:UDP in offset*/

		if(!fast_bind)
		{
		    l2tpTunnel.saddr = iph_ppp0->saddr;
		    l2tpTunnel.daddr = iph_ppp0->daddr;
		}
		/*get source&dest port to check if binded*/
		if(iph_ppp0->protocol == IPPROTO_TCP)
		{
		    th = (struct tcphdr *)(skb->data + offset + 4 + 20);
		    addr = ((th->source << 16)|th->dest);
		    //printk("TCP src port=%d, dst port=%d", ntohs(th->source), ntohs(th->dest));
		}
		else if (iph_ppp0->protocol == IPPROTO_UDP)
		{
		    uh = (struct udphdr *)(skb->data + offset + 4 + 20);
		    addr = ((uh->source << 16)|uh->dest);
		}
		else
		{
		    printk("0.1 Non TCP/UDP to lan, pass up, line %d!!\n", __LINE__);
		    return 1;

		}
		// !PPP_IP  pass up
		if (ppp_type != 0x21) 
		{						
		    printk("3.1 ppp_type !=0x21, pass up, line %d!!\n", __LINE__);
		    return 1;				
		}
		else 
		{
		    int rev = 0;
		    // header removal section

		    //skb_dump(skb);
		    rev = is_pptp_l2tp_bind(iph_ppp0->protocol, addr);
		    //if(fast_bind)
		    if(rev)
		    {
			/*Kurts:memory remove from head*/    
			memcpy(skb->data + 4, skb->data - offset + 4, offset);
			//printk("afater memmove L2TP header send to PPE\n");
			//redirect to PPE
			FOE_AI(skb) = UN_HIT;
			FOE_MAGIC_TAG(skb) = FOE_MAGIC_PPE;
			skb_pull(skb, offset);
			skb_push(skb, 14);
#if defined (CONFIG_HNAT_V2)	    
		/*make mac table transparent*/
		eth = (struct ethhdr *)skb->data;
		eth->h_source[0] = 0x01;
#endif
		skb->dev = wan_dev;
		dev_queue_xmit(skb);
		return 0;
	    }
	    else{
		FOE_MAGIC_TAG(skb) = FOE_MAGIC_FASTPATH;

		if(iph_ppp0->protocol == IPPROTO_TCP)
		{
		    th = (struct tcphdr *)(skb->data + offset + 4 + 20);
		    //printk("TCP src port=%d, dst port=%d", ntohs(th->source), ntohs(th->dest));
		    FOE_SOURCE(skb) = ntohs(th->source);
		    FOE_DEST(skb) = ntohs(th->dest);
		}
		else if (iph_ppp0->protocol == IPPROTO_UDP)
		{
		    uh = (struct udphdr *)(skb->data + offset + 4 + 20);
		    //printk("UDP src port=%d, dst port=%d", ntohs(uh->source), ntohs(uh->dest));
		    FOE_SOURCE(skb) = ntohs(uh->source);
		    FOE_DEST(skb) = ntohs(uh->dest);
		}
		else
		{
		    printk("0.1 return line %d!!\n", __LINE__);
		    return 1;

		}

		return 1;
	    }
	}
		
	LAYER3_HEADER(skb) = skb->data;
	LAYER4_HEADER(skb) = skb->data;

	FAST_PPTP_PRINT("pass up\n");
	}




	return 1;		
}


 int fast_l2tp_to_wan(struct sk_buff *skb)
{	
	int	header_len;
	struct iphdr *iph,*iph_new, iph_newone;
	struct l2tp_ext_hdr	*l2tph, l2tphone;
	unsigned char tos;
	struct vlan_ethhdr *veth=NULL;

	iph = (struct iphdr *)(skb->data + 4);	
	header_len = ETH_HLEN + sizeof(*iph_new) +18 ;
	if (skb_headroom(skb) < header_len || skb_cloned(skb) || skb_shared(skb)) 
	{
		struct sk_buff *new_skb = skb_realloc_headroom(skb, header_len);				
		if (!new_skb) {
			printk("%s: skb_realloc_headroom failed!\n", __FUNCTION__);
			return 1;
		}
		dev_kfree_skb(skb);
		skb = new_skb;
	}

	// build mac header
	memcpy(skb_push(skb, header_len), l2tpInfo.mac_header, ETH_HLEN);

	/*add vid 2*/
	veth = (struct vlan_ethhdr *)(skb->data);
	veth->h_vlan_proto = htons(ETH_P_8021Q);
	veth->h_vlan_TCI = htons(0x2);
	veth->h_vlan_encapsulated_proto = htons(ETH_P_IP);

	// build ip header
	iph_new = &iph_newone;
	iph_new->version	=	4;
	iph_new->ihl		=	sizeof(struct iphdr) >> 2;
	//iph_new->frag_off	=	frag_off;
	iph_new->frag_off	=	0x0;		
	iph_new->protocol	=	IPPROTO_UDP;
	//iph_new->tos		=	tos;
	iph_new->tos		=	0;
    	iph_new->daddr		=	l2tpInfo.daddr;
    	iph_new->saddr		=	l2tpInfo.saddr;
    	iph_new->ttl 		=	IPDEFTTL;
    	iph_new->tot_len	=	htons(skb->len - ETH_HLEN -4);
    	iph_new->id		=	0;
#if 1
    	skb->ip_summed		=	CHECKSUM_NONE;
    	iph_new->check	=	0;
    	iph_new->check	=	ip_fast_csum((unsigned char *)iph_new, iph_new->ihl);	
#else
/*for checksum offload*/
    	skb->ip_summed		=	CHECKSUM_PARTIAL;
#endif	
	memcpy(skb->data + ETH_HLEN + 4, &iph_newone, sizeof(iph_newone));
    	
	l2tph = &l2tphone;
    	l2tph->source	=	l2tpInfo.source;
    	l2tph->dest	=	l2tpInfo.dest;
	l2tph->len	=	htons(skb->len - ETH_HLEN- 4 - 20);;
	l2tph->checksum =	0;
	l2tph->type	=	0x0200;
	l2tph->tid	=	l2tpInfo.tid;
	l2tph->sid	=	l2tpInfo.sid;
	l2tph->addr_control =	0x03ff;
	l2tph->protocol	=	0x2100;
    	memcpy(skb->data+ETH_HLEN+sizeof(struct iphdr)+4, &l2tphone, sizeof(struct l2tp_ext_hdr));

	skb->dev =	wan_dev;
	
	FOE_AI(skb) = UN_HIT;
	dev_queue_xmit(skb);	
	return 0;
}

int32_t L2tpToWanParseLayerInfo(struct sk_buff * skb)
{

	struct vlan_hdr *vh = NULL;
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	struct iphdr *iph_ppp0 = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;

	struct l2tp_header  *l2tph = NULL;
	unsigned short *tunnel_id = NULL;	
	unsigned short *session_id = NULL;
	unsigned char *ppp_data;	

	int offset = 6;	//l2tp header from 6 
	int ppp_offset=0;
	unsigned char ppp_type=0;
#ifdef CONFIG_RAETH_HW_VLAN_TX
	struct vlan_hdr pseudo_vhdr;
#endif
	
	memset(&PpeParseResult, 0, sizeof(PpeParseResult));

/*let dst to cpu mac*/
	//skb_dump(skb);

	eth = (struct ethhdr *)(skb->data);
	iph_ppp0 = (struct iphdr *)(skb->data + 14 + 4);


	
	memcpy(PpeParseResult.smac, eth->h_dest, ETH_ALEN);
	memcpy(PpeParseResult.dmac, eth->h_source, ETH_ALEN);
	PpeParseResult.smac[0] = 0x01;

	uh = (struct udp_hdr *)(skb->data + 14 + (iph_ppp0->ihl*4) + 4);
	l2tph = (struct l2tp_header *)(skb->data + 14 + (iph_ppp0->ihl*4) + 4 + 8);
	
	if(ntohs(uh->dest)!=1701) /*port:1701*/
	{
		return 1;
	}

	if(ntohs(l2tph->ver) & 0x4000)
	{	
		offset += 2;
	}	
			
	if(ntohs(l2tph->ver) & 0x0200)
		offset += 2;

	tunnel_id = (unsigned short *)(skb->data + 14 + (iph_ppp0->ihl*4) + 4 + 8 + offset - 4);
	session_id = (unsigned short *)(skb->data + 14 + (iph_ppp0->ihl*4) + 4 + 8 + offset - 2);
	
    if (DebugLevel >= 1) {
	printk("tunnel_id is 0x%x\n", tunnel_id);
	printk("offset is 0x%d\n", offset);
    }
#if 1
/*log l2tp info*/	
    l2tpInfo.tid = *tunnel_id;
    l2tpInfo.sid = *session_id;
    l2tpInfo.saddr = iph_ppp0->saddr;
    l2tpInfo.daddr = iph_ppp0->daddr;
    l2tpInfo.source = uh->source;
    l2tpInfo.dest = uh->dest;
    memcpy(l2tpInfo.mac_header, eth->h_dest, ETH_ALEN);
    memcpy(&l2tpInfo.mac_header[6], eth->h_source, ETH_ALEN);

    if (DebugLevel >= 1) {
	printk("l2tpInfo.sid is 0x%4x\n", l2tpInfo.sid);
	printk("l2tpInfo.tid is 0x%4x\n", l2tpInfo.tid);
    }
#endif
	PpeParseResult.eth_type = eth->h_proto;
				
	ppp_data = ((char *)l2tph) + offset;				
	ppp_offset = 0;				
			
	// check PPP IP protocol
	if (*ppp_data == 0) {
		ppp_offset = 1;
		ppp_data++;
	}
	else if (*ppp_data == 0xff && *(ppp_data+1) == 0x03) {									
		ppp_offset = 2;
		ppp_data += 2;
		if (*ppp_data == 0) 
		{
			ppp_offset++;
			ppp_data++;
		}
	}											
	if (*ppp_data == 0x21 || *ppp_data == 0xfd) {
				ppp_offset++;					
				ppp_type = *ppp_data;
	}
	else
		ppp_offset = 0;		

	//printk("l2tp ppp_offset is 0x%d\n", ppp_offset);
	if (ppp_offset ==  0) 
			return 1;

	offset = iph_ppp0->ihl*4+ 8 + offset + ppp_offset;	// tunnel IP offset + udp	
	
	if (ppp_type != 0x21) 
	{						
            printk("3.1 ppp_type !=0x21, pass up, line %d!!\n", __LINE__);
	    return 1;				
	}

	if (DebugLevel >= 1) 
	{
		printk("l2tp offset is 0x%d\n", offset);
	}

	//skb_dump(skb);
	if (is8021Q(PpeParseResult.eth_type) || isSpecialTag(PpeParseResult.eth_type) || isHwVlanTx(skb)) {

#ifdef CONFIG_RAETH_HW_VLAN_TX
		PpeParseResult.vlan1_gap = 0;
		PpeParseResult.vlan_layer++;
		pseudo_vhdr.h_vlan_TCI = htons(vlan_tx_tag_get(skb));
		pseudo_vhdr.h_vlan_encapsulated_proto = eth->h_proto;
		vh = (struct vlan_hdr *)&pseudo_vhdr;
#else
		PpeParseResult.vlan1_gap = VLAN_HLEN;
		PpeParseResult.vlan_layer++;
		vh = (struct vlan_hdr *)(skb->data + ETH_HLEN);
#endif
		PpeParseResult.vlan1 = vh->h_vlan_TCI;
		PpeParseResult.eth_type = vh->h_vlan_encapsulated_proto;
	}


	//printk("LAN -> WAN set layer2 start addr\n");
	/* set layer2 start addr, original L2 MAC */
	LAYER2_HEADER(skb) = skb->data;


	/* set layer3 start addr, inner IP */
	LAYER3_HEADER(skb) =
	    (skb->data + offset +ETH_HLEN + PpeParseResult.vlan1_gap +
	     PpeParseResult.vlan2_gap);

	if (DebugLevel >= 1) 
	{
		printk("LAN -> WAN set layer4 start addr\n");
	}
	/* set layer4 start addr */
	//printk("PpeParseResult.eth_type = 0x%x\n",  ntohs(PpeParseResult.eth_type));
	if ((PpeParseResult.eth_type == htons(ETH_P_IP))) {
		iph = (struct iphdr *)LAYER3_HEADER(skb);
		//prepare layer3/layer4 info
		memcpy(&PpeParseResult.iph, iph, sizeof(struct iphdr));
		if (iph->protocol == IPPROTO_TCP) {
			LAYER4_HEADER(skb) = ((uint8_t *) iph + (iph->ihl * 4));
			th = (struct tcphdr *)LAYER4_HEADER(skb);
			memcpy(&PpeParseResult.th, th, sizeof(struct tcphdr));
			PpeParseResult.pkt_type = IPV4_HNAPT;
			if (DebugLevel >= 1) {
				printk("LAN -> WAN TCP src port=%d, dst port=%d \n", ntohs(th->source), ntohs(th->dest));
			}
			if(iph->frag_off & htons(IP_MF|IP_OFFSET)) {
			        printk("iph->frag_off  return\n");
				return 1;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			LAYER4_HEADER(skb) = ((uint8_t *) iph + iph->ihl * 4);
			uh = (struct udphdr *)LAYER4_HEADER(skb);
			memcpy(&PpeParseResult.uh, uh, sizeof(struct udphdr));
			PpeParseResult.pkt_type = IPV4_HNAPT;
			
			if(iph->frag_off & htons(IP_MF|IP_OFFSET)) {
			        printk("iph->frag_off  return\n");
				return 1;
			}
		}
#if defined (CONFIG_HNAT_V2)
		else if (iph->protocol == IPPROTO_GRE) {
			/* do nothing */
		}
#endif
		else {
			/* Packet format is not supported */
			return 1;
		}

	} 
	else 
	{
		return 1;
	}

	if (DebugLevel >= 6) {
		printk("--------------\n");
		printk("DMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
		       PpeParseResult.dmac[0], PpeParseResult.dmac[1],
		       PpeParseResult.dmac[2], PpeParseResult.dmac[3],
		       PpeParseResult.dmac[4], PpeParseResult.dmac[5]);
		printk("SMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
		       PpeParseResult.smac[0], PpeParseResult.smac[1],
		       PpeParseResult.smac[2], PpeParseResult.smac[3],
		       PpeParseResult.smac[4], PpeParseResult.smac[5]);
		printk("Eth_Type=%x\n", PpeParseResult.eth_type);
		if (PpeParseResult.vlan1_gap > 0) {
			printk("VLAN1 ID=%x\n", ntohs(PpeParseResult.vlan1));
		}

		if (PpeParseResult.vlan2_gap > 0) {
			printk("VLAN2 ID=%x\n", ntohs(PpeParseResult.vlan2));
		}

		if (PpeParseResult.pppoe_gap > 0) {
			printk("PPPOE Session ID=%x\n",
			       PpeParseResult.pppoe_sid);
			printk("PPP Tag=%x\n", ntohs(PpeParseResult.ppp_tag));
		}
#if defined (CONFIG_HNAT_V2)
		printk("PKT_TYPE=%s\n",
		       PpeParseResult.pkt_type ==
		       0 ? "IPV4_HNAT" : PpeParseResult.pkt_type ==
		       1 ? "IPV4_HNAPT" : PpeParseResult.pkt_type ==
		       3 ? "IPV4_DSLITE" : PpeParseResult.pkt_type ==
		       4 ? "IPV6_ROUTE" : PpeParseResult.pkt_type ==
		       5 ? "IPV6_6RD" : "Unknown");
#else
		printk("PKT_TYPE=%s\n",
		       PpeParseResult.pkt_type ==
		       0 ? "IPV4_HNAPT" : PpeParseResult.pkt_type ==
		       1 ? "IPV4_HNAT" : PpeParseResult.pkt_type ==
		       2 ? "IPV6_ROUTE" : "Unknown");
#endif

		if (PpeParseResult.pkt_type == IPV4_HNAT) {
			printk("SIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.saddr)));
			printk("DIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.daddr)));
			printk("TOS=%x\n", ntohs(PpeParseResult.iph.tos));
		} else if (PpeParseResult.pkt_type == IPV4_HNAPT) {
			printk("SIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.saddr)));
			printk("DIP=%s\n",
			       Ip2Str(ntohl(PpeParseResult.iph.daddr)));
			printk("TOS=%x\n", ntohs(PpeParseResult.iph.tos));
			
			if (PpeParseResult.iph.protocol == IPPROTO_TCP) {
			    printk("TCP SPORT=%d\n", ntohs(PpeParseResult.th.source));
			    printk("TCP DPORT=%d\n", ntohs(PpeParseResult.th.dest));
			}else if(PpeParseResult.iph.protocol == IPPROTO_UDP) {
			    printk("UDP SPORT=%d\n", ntohs(PpeParseResult.uh.source));
			    printk("UDP DPORT=%d\n", ntohs(PpeParseResult.uh.dest));
			}
		}
	}

	return 0;/*0 means OK here*/
}


