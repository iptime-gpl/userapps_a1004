#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/rt2880/surfboardint.h>
#if defined (CONFIG_RAETH_TSO)
#include <linux/tcp.h>
#include <net/ipv6.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/in.h>
#include <linux/ppp_defs.h>
#include <linux/if_pppox.h>
#endif
#include <linux/delay.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
#include <linux/sched.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
#include <asm/rt2880/rt_mmap.h>
#else
#include <linux/libata-compat.h>
#endif
 
#include "ra2882ethreg.h"
#include "raether.h"
#include "ra_mac.h"
#include "ra_ioctl.h"
#include "ra_rfrw.h"
#ifdef CONFIG_RAETH_NETLINK
#include "ra_netlink.h"
#endif
#if defined (CONFIG_RAETH_QOS)
#include "ra_qos.h"
#endif

#if defined (CONFIG_RA_HW_NAT) || defined (CONFIG_RA_HW_NAT_MODULE)
#include "../../../net/nat/hw_nat/ra_nat.h"
#endif

#if defined (TASKLET_WORKQUEUE_SW)
int init_schedule;
int working_schedule;
#endif


#if !defined(CONFIG_RA_NAT_NONE)
/* bruce+
 */
extern int (*ra_sw_nat_hook_rx)(struct sk_buff *skb);
extern int (*ra_sw_nat_hook_tx)(struct sk_buff *skb, int gmac_no);
#endif

#if defined(CONFIG_RA_CLASSIFIER)||defined(CONFIG_RA_CLASSIFIER_MODULE)
/* Qwert+
 */
#include <asm/mipsregs.h>
extern int (*ra_classifier_hook_tx)(struct sk_buff *skb, unsigned long cur_cycle);
extern int (*ra_classifier_hook_rx)(struct sk_buff *skb, unsigned long cur_cycle);
#endif /* CONFIG_RA_CLASSIFIER */

#if defined (CONFIG_RALINK_RT3052_MP2)
int32_t mcast_rx(struct sk_buff * skb);
int32_t mcast_tx(struct sk_buff * skb);
#endif

#ifdef RA_MTD_RW_BY_NUM
int ra_mtd_read(int num, loff_t from, size_t len, u_char *buf);
#else
int ra_mtd_read_nm(char *name, loff_t from, size_t len, u_char *buf);
#endif

/* gmac driver feature set config */
#if defined (CONFIG_RAETH_NAPI) || defined (CONFIG_RAETH_QOS)
#undef DELAY_INT
#else
#define DELAY_INT	1
#endif

//#define CONFIG_UNH_TEST
/* end of config */

#if defined (CONFIG_RAETH_JUMBOFRAME)
#define	MAX_RX_LENGTH	4096
#else
#define	MAX_RX_LENGTH	1536
#endif

extern struct net_device		*dev_raether;

#if defined (CONFIG_RAETH_MULTIPLE_RX_RING)
static int rx_dma_owner_idx1;
#ifdef CONFIG_RAETH_RW_PDMAPTR_FROM_VAR
static int rx_calc_idx1;
#endif
#endif
#ifdef CONFIG_RAETH_RW_PDMAPTR_FROM_VAR
static int rx_calc_idx0;
static unsigned long tx_cpu_owner_idx0=0;
#endif
static unsigned long tx_ring_full=0;

#if defined (CONFIG_ETHTOOL) && defined (CONFIG_RAETH_ROUTER)
#include "ra_ethtool.h"
extern struct ethtool_ops	ra_ethtool_ops;
#ifdef CONFIG_PSEUDO_SUPPORT
extern struct ethtool_ops	ra_virt_ethtool_ops;
#endif // CONFIG_PSEUDO_SUPPORT //
#endif // (CONFIG_ETHTOOL //

#ifdef CONFIG_RALINK_VISTA_BASIC
int is_switch_175c = 1;
#endif

//skb->mark to queue mapping table
extern unsigned int M2Q_table[64];


#define KSEG1                   0xa0000000
#define PHYS_TO_VIRT(x)         ((void *)((x) | KSEG1))
#define VIRT_TO_PHYS(x)         ((unsigned long)(x) & ~KSEG1)

extern void set_fe_dma_glo_cfg(void);


/**
 *
 * @brief: get the TXD index from its address
 *
 * @param: cpu_ptr
 *
 * @return: TXD index
*/

static unsigned int GET_TXD_OFFSET(struct QDMA_txdesc **cpu_ptr)
{
	struct net_device *dev = dev_raether;
	END_DEVICE *ei_local = netdev_priv(dev);
	int ctx_offset;
  	ctx_offset = (((((u32)*cpu_ptr) <<8)>>8) - ((((u32)ei_local->txd_pool)<<8)>>8))/ sizeof(struct QDMA_txdesc);
	ctx_offset = (*cpu_ptr - ei_local->txd_pool);

  	return ctx_offset;
} 



/**
 * @brief get free TXD from TXD queue
 *
 * @param free_txd
 *
 * @return 
 */
static int get_free_txd(struct QDMA_txdesc **free_txd)
{
	struct net_device *dev = dev_raether;
	END_DEVICE *ei_local = netdev_priv(dev);
	unsigned int tmp_idx;

	if(ei_local->free_txd_num > 0){
		tmp_idx = ei_local->free_txd_head;
		ei_local->free_txd_head = ei_local->txd_pool_info[tmp_idx];
		ei_local->free_txd_num -= 1;
		*free_txd = &ei_local->txd_pool[tmp_idx];
		return tmp_idx;
	}else
		return NUM_TX_DESC;	
}


/**
 * @brief add free TXD into TXD queue
 *
 * @param free_txd
 *
 * @return 
 */
int put_free_txd(int free_txd_idx)
{
	struct net_device *dev = dev_raether;
	END_DEVICE *ei_local = netdev_priv(dev);
	ei_local->txd_pool_info[ei_local->free_txd_tail] = free_txd_idx;
	ei_local->free_txd_tail = free_txd_idx;
	ei_local->txd_pool_info[free_txd_idx] = NUM_TX_DESC;
        ei_local->free_txd_num += 1;
	return 1;
}

/*define qdma initial alloc*/
/**
 * @brief 
 *
 * @param net_dev
 *
 * @return  0: fail
 *	    1: success
 */
bool qdma_tx_desc_alloc(void)
{
	struct net_device *dev = dev_raether;
	END_DEVICE *ei_local = netdev_priv(dev);
	struct QDMA_txdesc *free_txd = NULL;
	unsigned int txd_idx;
	int i = 0;


	ei_local->txd_pool = pci_alloc_consistent(NULL, sizeof(struct QDMA_txdesc) * NUM_TX_DESC, &ei_local->phy_txd_pool);
	printk("txd_pool=%p phy_txd_pool=%08X\n", ei_local->txd_pool , ei_local->phy_txd_pool);

	if (ei_local->txd_pool == NULL) {
		printk("adapter->txd_pool allocation failed!\n");
		return 0;
	}
	printk("ei_local->skb_free start address is 0x%p.\n", ei_local->skb_free);
	//set all txd_pool_info to 0.
	for ( i = 0; i < NUM_TX_DESC; i++)
	{
		ei_local->skb_free[i]= 0;
		ei_local->txd_pool_info[i] = i + 1;
		ei_local->txd_pool[i].txd_info3.LS_bit = 1;
		ei_local->txd_pool[i].txd_info3.OWN_bit = 1;
	}

	ei_local->free_txd_head = 0;
	ei_local->free_txd_tail = NUM_TX_DESC - 1;
	ei_local->free_txd_num = NUM_TX_DESC;
	

	//get free txd from txd pool
	txd_idx = get_free_txd(&free_txd);
	if( txd_idx == NUM_TX_DESC) {
		printk("get_free_txd fail\n");
		return 0;
	}
	
	//add null TXD for transmit
	ei_local->tx_dma_ptr = VIRT_TO_PHYS(free_txd);
	ei_local->tx_cpu_ptr = VIRT_TO_PHYS(free_txd);
	sysRegWrite(QTX_CTX_PTR, ei_local->tx_cpu_ptr);
	sysRegWrite(QTX_DTX_PTR, ei_local->tx_dma_ptr);
	
	//get free txd from txd pool

	txd_idx = get_free_txd(&free_txd);
	if( txd_idx == NUM_TX_DESC) {
		printk("get_free_txd fail\n");
		return 0;
	}
	// add null TXD for release
	sysRegWrite(QTX_CRX_PTR, VIRT_TO_PHYS(free_txd));
	sysRegWrite(QTX_DRX_PTR, VIRT_TO_PHYS(free_txd));
	
	printk("free_txd: %p, ei_local->cpu_ptr: %08X\n", free_txd, ei_local->tx_cpu_ptr);
	
	printk(" POOL  HEAD_PTR | DMA_PTR | CPU_PTR \n");
	printk("----------------+---------+--------\n");
#if 1
	printk("     0x%p 0x%08X 0x%08X\n",ei_local->txd_pool,
			ei_local->tx_dma_ptr, ei_local->tx_cpu_ptr);
#endif
	return 1;
}

bool fq_qdma_init(void)
{
	struct QDMA_txdesc *free_head = NULL;
	unsigned int free_head_phy;
	unsigned int free_tail_phy;
	unsigned int *free_page_head = NULL;
	unsigned int free_page_head_phy;
	int i;
    
	free_head = pci_alloc_consistent(NULL, NUM_QDMA_PAGE * sizeof(struct QDMA_txdesc), &free_head_phy);
	if (unlikely(free_head == NULL)){
		printk(KERN_ERR "QDMA FQ decriptor not available...\n");
		return 0;
	}
	memset(free_head, 0x0, sizeof(struct QDMA_txdesc) * NUM_QDMA_PAGE);

	free_page_head = pci_alloc_consistent(NULL, NUM_QDMA_PAGE * QDMA_PAGE_SIZE, &free_page_head_phy);
	if (unlikely(free_page_head == NULL)){
		printk(KERN_ERR "QDMA FQ pager not available...\n");
		return 0;
	}	
	for (i=0; i < NUM_QDMA_PAGE; i++) {
		free_head[i].txd_info1.SDP = (free_page_head_phy + (i * QDMA_PAGE_SIZE));
		if(i < (NUM_QDMA_PAGE-1)){
			free_head[i].txd_info2.NDP = (free_head_phy + ((i+1) * sizeof(struct QDMA_txdesc)));


#if 0
			printk("free_head_phy[%d] is 0x%x!!!\n",i, VIRT_TO_PHYS(&free_head[i]) );
			printk("free_head[%d] is 0x%x!!!\n",i, &free_head[i] );
			printk("free_head[%d].txd_info1.SDP is 0x%x!!!\n",i, free_head[i].txd_info1.SDP );
			printk("free_head[%d].txd_info2.NDP is 0x%x!!!\n",i, free_head[i].txd_info2.NDP );
#endif
		}
		free_head[i].txd_info3.SDL = QDMA_PAGE_SIZE;

	}
	free_tail_phy = (free_head_phy + (u32)((NUM_QDMA_PAGE-1) * sizeof(struct QDMA_txdesc)));

	printk("free_head_phy is 0x%x!!!\n", free_head_phy);
	printk("free_tail_phy is 0x%x!!!\n", free_tail_phy);
	sysRegWrite(QDMA_FQ_HEAD, (u32)free_head_phy);
	sysRegWrite(QDMA_FQ_TAIL, (u32)free_tail_phy);
	sysRegWrite(QDMA_FQ_CNT, ((NUM_TX_DESC << 16) | NUM_QDMA_PAGE));
	sysRegWrite(QDMA_FQ_BLEN, QDMA_PAGE_SIZE << 16);
    return 1;
}

int fe_dma_init(struct net_device *dev)
{

	int i;
	unsigned int	regVal;
	END_DEVICE* ei_local = netdev_priv(dev);

	fq_qdma_init();

	while(1)
	{
		regVal = sysRegRead(QDMA_GLO_CFG);
		if((regVal & RX_DMA_BUSY))
		{
			printk("\n  RX_DMA_BUSY !!! ");
			continue;
		}
		if((regVal & TX_DMA_BUSY))
		{
			printk("\n  TX_DMA_BUSY !!! ");
			continue;
		}
		break;
	}
	/*tx desc alloc, add a NULL TXD to HW*/

	qdma_tx_desc_alloc();


	/* Initial RX Ring 0*/
#ifdef CONFIG_32B_DESC
    	ei_local->rx_ring0 = kmalloc(NUM_RX_DESC * sizeof(struct PDMA_rxdesc), GFP_KERNEL);
	ei_local->phy_rx_ring0 = virt_to_phys(ei_local->rx_ring0);
#else
	ei_local->rx_ring0 = pci_alloc_consistent(NULL, NUM_RX_DESC * sizeof(struct PDMA_rxdesc), &ei_local->phy_rx_ring0);
#endif
	for (i = 0; i < NUM_RX_DESC; i++) {
		memset(&ei_local->rx_ring0[i],0,sizeof(struct PDMA_rxdesc));
	    	ei_local->rx_ring0[i].rxd_info2.DDONE_bit = 0;
#if defined (CONFIG_RAETH_SCATTER_GATHER_RX_DMA)
		ei_local->rx_ring0[i].rxd_info2.LS0 = 0;
		ei_local->rx_ring0[i].rxd_info2.PLEN0 = MAX_RX_LENGTH;
#else
		ei_local->rx_ring0[i].rxd_info2.LS0 = 1;
#endif
		ei_local->rx_ring0[i].rxd_info1.PDP0 = dma_map_single(NULL, ei_local->netrx0_skbuf[i]->data, MAX_RX_LENGTH, PCI_DMA_FROMDEVICE);
	}
	printk("\nphy_rx_ring0 = 0x%08x, rx_ring0 = 0x%p\n",ei_local->phy_rx_ring0,ei_local->rx_ring0);

#if defined (CONFIG_RAETH_MULTIPLE_RX_RING)
	/* Initial RX Ring 1*/
#ifdef CONFIG_32B_DESC
    	ei_local->rx_ring1 = kmalloc(NUM_RX_DESC * sizeof(struct PDMA_rxdesc), GFP_KERNEL);
	ei_local->phy_rx_ring1 = virt_to_phys(ei_local->rx_ring1);
#else
	ei_local->rx_ring1 = pci_alloc_consistent(NULL, NUM_RX_DESC * sizeof(struct PDMA_rxdesc), &ei_local->phy_rx_ring1);
#endif
	for (i = 0; i < NUM_RX_DESC; i++) {
		memset(&ei_local->rx_ring1[i],0,sizeof(struct PDMA_rxdesc));
	    	ei_local->rx_ring1[i].rxd_info2.DDONE_bit = 0;
#if defined (CONFIG_RAETH_SCATTER_GATHER_RX_DMA)
		ei_local->rx_ring0[i].rxd_info2.LS0 = 0;
		ei_local->rx_ring0[i].rxd_info2.PLEN0 = MAX_RX_LENGTH;
#else
		ei_local->rx_ring1[i].rxd_info2.LS0 = 1;
#endif
		ei_local->rx_ring1[i].rxd_info1.PDP0 = dma_map_single(NULL, ei_local->netrx1_skbuf[i]->data, MAX_RX_LENGTH, PCI_DMA_FROMDEVICE);
	}
	printk("\nphy_rx_ring1 = 0x%08x, rx_ring1 = 0x%p\n",ei_local->phy_rx_ring1,ei_local->rx_ring1);
#endif

	regVal = sysRegRead(QDMA_GLO_CFG);
	regVal &= 0x000000FF;
   	sysRegWrite(QDMA_GLO_CFG, regVal);
	regVal=sysRegRead(QDMA_GLO_CFG);

	/* Tell the adapter where the TX/RX rings are located. */
	
	sysRegWrite(QRX_BASE_PTR_0, phys_to_bus((u32) ei_local->phy_rx_ring0));
	sysRegWrite(QRX_MAX_CNT_0,  cpu_to_le32((u32) NUM_RX_DESC));
	sysRegWrite(QRX_CRX_IDX_0, cpu_to_le32((u32) (NUM_RX_DESC - 1)));
#ifdef CONFIG_RAETH_RW_PDMAPTR_FROM_VAR
	rx_calc_idx0 = rx_dma_owner_idx0 =  sysRegRead(QRX_CRX_IDX_0);
#endif
	sysRegWrite(QDMA_RST_CFG, PST_DRX_IDX0);
#if defined (CONFIG_RAETH_MULTIPLE_RX_RING)
	sysRegWrite(QRX_BASE_PTR_1, phys_to_bus((u32) ei_local->phy_rx_ring1));
	sysRegWrite(QRX_MAX_CNT_1,  cpu_to_le32((u32) NUM_RX_DESC));
	sysRegWrite(QRX_CRX_IDX_1, cpu_to_le32((u32) (NUM_RX_DESC - 1)));
#ifdef CONFIG_RAETH_RW_PDMAPTR_FROM_VAR
	rx_calc_idx1 = rx_dma_owner_idx1 =  sysRegRead(QRX_CRX_IDX_1);
#endif
	sysRegWrite(QDMA_RST_CFG, PST_DRX_IDX1);
#endif

	set_fe_dma_glo_cfg();
	
	return 1;
}

inline int rt2880_eth_send(struct net_device* dev, struct sk_buff *skb, int gmac_no)
{
	unsigned int	length=skb->len;
	END_DEVICE*	ei_local = netdev_priv(dev);
	
	struct QDMA_txdesc *cpu_ptr;

	struct QDMA_txdesc *dma_ptr __maybe_unused;
	struct QDMA_txdesc *free_txd;
	int  ctx_offset;
#if defined (CONFIG_RAETH_TSO)
	struct iphdr *iph = NULL;
        struct QDMA_txdesc *init_cpu_ptr;
        struct tcphdr *th = NULL;
	struct skb_frag_struct *frag;
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
	int i=0;
	int init_txd_idx;
#endif // CONFIG_RAETH_TSO //

#if defined (CONFIG_RAETH_TSOV6)
	struct ipv6hdr *ip6h = NULL;
#endif

#ifdef CONFIG_PSEUDO_SUPPORT
	PSEUDO_ADAPTER *pAd;
#endif
	cpu_ptr = PHYS_TO_VIRT(ei_local->tx_cpu_ptr);
	dma_ptr = PHYS_TO_VIRT(ei_local->tx_dma_ptr);
	ctx_offset = GET_TXD_OFFSET(&cpu_ptr);
	ei_local->skb_free[ctx_offset] = skb;
#if defined (CONFIG_RAETH_TSO)
        init_cpu_ptr = cpu_ptr;
        init_txd_idx = ctx_offset;
#endif

#if !defined (CONFIG_RAETH_TSO)

	//2. prepare data
	cpu_ptr->txd_info1.SDP = VIRT_TO_PHYS(skb->data);
	cpu_ptr->txd_info3.SDL = skb->len;
	
	if (gmac_no == 1) {
		cpu_ptr->txd_info4.FPORT = 1;
	}else {
		cpu_ptr->txd_info4.FPORT = 2;
	}


  cpu_ptr->txd_info3.QID = M2Q_table[skb->mark];
#if 0 
	iph = (struct iphdr *)skb_network_header(skb);
        if (iph->tos == 0xe0)
		cpu_ptr->txd_info3.QID = 3;
	else if (iph->tos == 0xa0) 
		cpu_ptr->txd_info3.QID = 2;	
        else if (iph->tos == 0x20)
		cpu_ptr->txd_info3.QID = 1;
        else 
		cpu_ptr->txd_info3.QID = 0;
#endif

#if defined (CONFIG_RAETH_CHECKSUM_OFFLOAD) && ! defined(CONFIG_RALINK_RT5350) && !defined (CONFIG_RALINK_MT7628)
	if (skb->ip_summed == CHECKSUM_PARTIAL){
	    cpu_ptr->txd_info4.TUI_CO = 7;
	}else {
	    cpu_ptr->txd_info4.TUI_CO = 0;
	}
#endif

#ifdef CONFIG_RAETH_HW_VLAN_TX
	if(vlan_tx_tag_present(skb)) {
	    cpu_ptr->txd_info4.VLAN_TAG = 0x10000 | vlan_tx_tag_get(skb);
	}else {
	    cpu_ptr->txd_info4.VLAN_TAG = 0;
	}
#endif

#if defined (CONFIG_RA_HW_NAT) || defined (CONFIG_RA_HW_NAT_MODULE)
	if(FOE_MAGIC_TAG(skb) == FOE_MAGIC_PPE) {
		if(ra_sw_nat_hook_rx!= NULL){
		    cpu_ptr->txd_info4.FPORT = 4; /* PPE */
		    FOE_MAGIC_TAG(skb) = 0;
	    }
  }
#endif
#if 0
	cpu_ptr->txd_info4.FPORT = 4; /* PPE */
	cpu_ptr->txd_info4.UDF = 0x2F;
#endif
		
	dma_cache_sync(NULL, skb->data, skb->len, DMA_TO_DEVICE);
	cpu_ptr->txd_info3.SWC_bit = 1;

	//3. get NULL TXD and decrease free_tx_num by 1.
	ctx_offset = get_free_txd(&free_txd);
	if(ctx_offset == NUM_TX_DESC) {
	    printk("get_free_txd fail\n"); // this should not happen. free_txd_num is 2 at least.
	    return 0;
	}

	//4. hook new TXD in the end of queue
	cpu_ptr->txd_info2.NDP = VIRT_TO_PHYS(free_txd);


	//5. move CPU_PTR to new TXD
	ei_local->tx_cpu_ptr = VIRT_TO_PHYS(free_txd);	
	cpu_ptr->txd_info3.OWN_bit = 0;
	sysRegWrite(QTX_CTX_PTR, ei_local->tx_cpu_ptr);
	
#if 0 
	printk("----------------------------------------------\n");
	printk("txd_info1:%08X \n",*(int *)&cpu_ptr->txd_info1);
	printk("txd_info2:%08X \n",*(int *)&cpu_ptr->txd_info2);
	printk("txd_info3:%08X \n",*(int *)&cpu_ptr->txd_info3);
	printk("txd_info4:%08X \n",*(int *)&cpu_ptr->txd_info4);
#endif			

#else //#if !defined (CONFIG_RAETH_TSO)	
        cpu_ptr->txd_info1.SDP = VIRT_TO_PHYS(skb->data);
	cpu_ptr->txd_info3.SDL = (length - skb->data_len);
	cpu_ptr->txd_info3.LS_bit = nr_frags ? 0:1;
	if (gmac_no == 1) {
		cpu_ptr->txd_info4.FPORT = 1;
	}else {
		cpu_ptr->txd_info4.FPORT = 2;
	}
	
	cpu_ptr->txd_info4.TSO = 0;
        cpu_ptr->txd_info3.QID = M2Q_table[skb->mark]; 	
#if defined (CONFIG_RAETH_CHECKSUM_OFFLOAD) && ! defined(CONFIG_RALINK_RT5350) && !defined (CONFIG_RALINK_MT7628)
	if (skb->ip_summed == CHECKSUM_PARTIAL){
	    cpu_ptr->txd_info4.TUI_CO = 7;
	}else {
	    cpu_ptr->txd_info4.TUI_CO = 0;
	}
#endif

#ifdef CONFIG_RAETH_HW_VLAN_TX
	if(vlan_tx_tag_present(skb)) {
	    cpu_ptr->txd_info4.VLAN_TAG = 0x10000 | vlan_tx_tag_get(skb);
	}else {
	    cpu_ptr->txd_info4.VLAN_TAG = 0;
	}
#endif

#if defined (CONFIG_RA_HW_NAT) || defined (CONFIG_RA_HW_NAT_MODULE)
	if(FOE_MAGIC_TAG(skb) == FOE_MAGIC_PPE) {
	    if(ra_sw_nat_hook_rx!= NULL){
		    cpu_ptr->txd_info4.FPORT = 4; /* PPE */
		    FOE_MAGIC_TAG(skb) = 0;
	    }
	}
#endif

        cpu_ptr->txd_info3.SWC_bit = 1;

        ctx_offset = get_free_txd(&free_txd);
        if(ctx_offset == NUM_TX_DESC) {
            printk("get_free_txd fail\n"); 
        return 0;
	}
        cpu_ptr->txd_info2.NDP = VIRT_TO_PHYS(free_txd);
        ei_local->tx_cpu_ptr = VIRT_TO_PHYS(free_txd);
  
        if(nr_frags > 0) {
            for(i=0;i<nr_frags;i++) {
	        frag = &skb_shinfo(skb)->frags[i];
                cpu_ptr = free_txd;
		cpu_ptr->txd_info3.QID = M2Q_table[skb->mark];
            	cpu_ptr->txd_info1.SDP = pci_map_page(NULL, frag->page, frag->page_offset, frag->size, PCI_DMA_TODEVICE);
	        cpu_ptr->txd_info3.SDL = frag->size;
	        cpu_ptr->txd_info3.LS_bit = (i==nr_frags-1)?1:0;
	        cpu_ptr->txd_info3.OWN_bit = 0;
	        cpu_ptr->txd_info3.SWC_bit = 1;
                ei_local->skb_free[ctx_offset] = (i==nr_frags-1)?skb:(struct  sk_buff *)0xFFFFFFFF; //MAGIC ID
 	  
          	ctx_offset = get_free_txd(&free_txd);
	        cpu_ptr->txd_info2.NDP = VIRT_TO_PHYS(free_txd);
	        ei_local->tx_cpu_ptr = VIRT_TO_PHYS(free_txd);				
	    }
	    ei_local->skb_free[init_txd_idx]= (struct  sk_buff *)0xFFFFFFFF; //MAGIC ID
	}

	if(skb_shinfo(skb)->gso_segs > 1) {

//		TsoLenUpdate(skb->len);

		/* TCP over IPv4 */
		iph = (struct iphdr *)skb_network_header(skb);
#if defined (CONFIG_RAETH_TSOV6)
		/* TCP over IPv6 */
		ip6h = (struct ipv6hdr *)skb_network_header(skb);
#endif				
		if((iph->version == 4) && (iph->protocol == IPPROTO_TCP)) {
			th = (struct tcphdr *)skb_transport_header(skb);

			init_cpu_ptr->txd_info4.TSO = 1;

			th->check = htons(skb_shinfo(skb)->gso_size);
			dma_cache_sync(NULL, th, sizeof(struct tcphdr), DMA_TO_DEVICE);
		} 
	    
#if defined (CONFIG_RAETH_TSOV6)
		/* TCP over IPv6 */
		//ip6h = (struct ipv6hdr *)skb_network_header(skb);
		else if ((ip6h->version == 6) && (ip6h->nexthdr == NEXTHDR_TCP)) {
			th = (struct tcphdr *)skb_transport_header(skb);
#ifdef CONFIG_RAETH_RW_PDMAPTR_FROM_VAR
			init_cpu_ptr->txd_info4.TSO = 1;
#else
			init_cpu_ptr->txd_info4.TSO = 1;
#endif
			th->check = htons(skb_shinfo(skb)->gso_size);
			dma_cache_sync(NULL, th, sizeof(struct tcphdr), DMA_TO_DEVICE);
		}
#endif
	}

		
//	dma_cache_sync(NULL, skb->data, skb->len, DMA_TO_DEVICE);  

	init_cpu_ptr->txd_info3.OWN_bit = 0;
#endif // CONFIG_RAETH_TSO //

	sysRegWrite(QTX_CTX_PTR, ei_local->tx_cpu_ptr);

#ifdef CONFIG_PSEUDO_SUPPORT
	if (gmac_no == 2) {
		if (ei_local->PseudoDev != NULL) {
				pAd = netdev_priv(ei_local->PseudoDev);
				pAd->stat.tx_packets++;
				pAd->stat.tx_bytes += length;
			}
		} else
		
#endif
        {
	ei_local->stat.tx_packets++;
	ei_local->stat.tx_bytes += skb->len;
	}
	return length;
}

int ei_start_xmit(struct sk_buff* skb, struct net_device *dev, int gmac_no)
{
	END_DEVICE *ei_local = netdev_priv(dev);
	unsigned long flags;
	unsigned int num_of_txd;
#if defined (CONFIG_RAETH_TSO)
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
#endif
#ifdef CONFIG_PSEUDO_SUPPORT
	PSEUDO_ADAPTER *pAd;
#endif

#if !defined(CONFIG_RA_NAT_NONE)
         if(ra_sw_nat_hook_tx!= NULL)
         {
	   spin_lock_irqsave(&ei_local->page_lock, flags);
           if(ra_sw_nat_hook_tx(skb, gmac_no)==1){
	   	spin_unlock_irqrestore(&ei_local->page_lock, flags);
	   }else{
	        kfree_skb(skb);
	   	spin_unlock_irqrestore(&ei_local->page_lock, flags);
	   	return 0;
	   }
         }
#endif



	dev->trans_start = jiffies;	/* save the timestamp */
	spin_lock_irqsave(&ei_local->page_lock, flags);
	dma_cache_sync(NULL, skb->data, skb->len, DMA_TO_DEVICE);


//check free_txd_num before calling rt288_eth_send()

#if defined (CONFIG_RAETH_TSO)
	num_of_txd = (nr_frags==0) ? 1 : (nr_frags + 1);
#else
	num_of_txd = 1;
#endif
   
#if defined(CONFIG_RALINK_MT7621)
    if(sysRegRead(0xbe00000c)==0x00030101) {
	    ei_xmit_housekeeping(0);
    }
#endif
	

    if ((ei_local->free_txd_num > num_of_txd + 1) && (ei_local->free_txd_num != NUM_TX_DESC))
    {
        rt2880_eth_send(dev, skb, gmac_no); // need to modify rt2880_eth_send() for QDMA
		if (ei_local->free_txd_num < 3)
		{
#if defined (CONFIG_RAETH_STOP_RX_WHEN_TX_FULL) 		    
		    netif_stop_queue(dev);
#ifdef CONFIG_PSEUDO_SUPPORT
		    netif_stop_queue(ei_local->PseudoDev);
#endif
		    tx_ring_full = 1;
#endif
		}
    } else {  
#ifdef CONFIG_PSEUDO_SUPPORT
		if (gmac_no == 2) 
		{
			if (ei_local->PseudoDev != NULL) 
			{
			    pAd = netdev_priv(ei_local->PseudoDev);
			    pAd->stat.tx_dropped++;
		    }
		} else
#endif
		ei_local->stat.tx_dropped++;
		kfree_skb(skb);
                spin_unlock_irqrestore(&ei_local->page_lock, flags);
		return 0;
     }	
	spin_unlock_irqrestore(&ei_local->page_lock, flags);
	return 0;
}

void ei_xmit_housekeeping(unsigned long unused)
{
    struct net_device *dev = dev_raether;
    END_DEVICE *ei_local = netdev_priv(dev);
#ifndef CONFIG_RAETH_NAPI
    unsigned long reg_int_mask=0;
#endif
    struct QDMA_txdesc *dma_ptr = NULL;
    struct QDMA_txdesc *cpu_ptr = NULL;
    struct QDMA_txdesc *tmp_ptr = NULL;
    unsigned int htx_offset = 0;

    dma_ptr = PHYS_TO_VIRT(sysRegRead(QTX_DRX_PTR));
    cpu_ptr = PHYS_TO_VIRT(sysRegRead(QTX_CRX_PTR));
    if(cpu_ptr != dma_ptr && (cpu_ptr->txd_info3.OWN_bit == 1)) {
	while(cpu_ptr != dma_ptr && (cpu_ptr->txd_info3.OWN_bit == 1)) {

	    //1. keep cpu next TXD			
	    tmp_ptr = PHYS_TO_VIRT(cpu_ptr->txd_info2.NDP);
            htx_offset = GET_TXD_OFFSET(&tmp_ptr);
            //2. free skb meomry
#if defined (CONFIG_RAETH_TSO)
	    if(ei_local->skb_free[htx_offset]!=(struct  sk_buff *)0xFFFFFFFF) {
		    dev_kfree_skb_any(ei_local->skb_free[htx_offset]); 
	    }
#else
	    dev_kfree_skb_any(ei_local->skb_free[htx_offset]); 
#endif			
                
	    //3. release TXD
	    htx_offset = GET_TXD_OFFSET(&cpu_ptr);			
	    put_free_txd(htx_offset);

            netif_wake_queue(dev);
#ifdef CONFIG_PSEUDO_SUPPORT
	    netif_wake_queue(ei_local->PseudoDev);
#endif			
	    tx_ring_full=0;
                
	    //4. update cpu_ptr to next ptr
	    cpu_ptr = tmp_ptr;
	}
    }
    sysRegWrite(QTX_CRX_PTR, VIRT_TO_PHYS(cpu_ptr));
#ifndef CONFIG_RAETH_NAPI
    reg_int_mask=sysRegRead(QFE_INT_ENABLE);
#if defined (DELAY_INT)
    sysRegWrite(FE_INT_ENABLE, reg_int_mask| RLS_DLY_INT);
#else

    sysRegWrite(FE_INT_ENABLE, reg_int_mask | RLS_DONE_INT);
#endif
#endif //CONFIG_RAETH_NAPI//
}

EXPORT_SYMBOL(ei_start_xmit);
EXPORT_SYMBOL(ei_xmit_housekeeping);
EXPORT_SYMBOL(fe_dma_init);
EXPORT_SYMBOL(rt2880_eth_send);
