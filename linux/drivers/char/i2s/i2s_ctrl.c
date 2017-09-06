#include <linux/init.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
#include <linux/sched.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/fs.h> /* everything... */
#include <linux/errno.h> /* error codes */
#include <linux/types.h> /* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h> /* O_ACCMODE */
#include <asm/system.h> /* cli(), *_flags */
#include <asm/uaccess.h> /* copy_from/to_user */
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <asm/rt2880/surfboardint.h>
#include <linux/pci.h>
#include "../ralink_gdma.h"

#ifdef  CONFIG_DEVFS_FS
#include <linux/devfs_fs_kernel.h>
static	devfs_handle_t devfs_handle;
#endif

#include "i2s_ctrl.h"

#if defined(CONFIG_SND_RALINK_SOC)
#include <sound/soc/mtk/mtk_audio_device.h>
#else
#if defined(CONFIG_I2S_WM8750)
#include "wm8750.h"
#endif
#if defined(CONFIG_I2S_WM8751)
#include "wm8751.h"
#endif
#if defined(CONFIG_I2S_WM8960)
#include "wm8960.h"
#endif
#endif

static int i2sdrv_major =  234;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
#else
static struct class *i2smodule_class;
#endif

/* external functions declarations */
#if defined(CONFIG_I2S_WM8960)
extern void audiohw_set_frequency(int fsel, int codec_pll_en);
void audiohw_set_apll(int srate);
#elif defined(CONFIG_I2S_WM8750)||defined(CONFIG_I2S_WM8751)
extern void audiohw_set_frequency(int fsel);
#endif
#if defined(CONFIG_I2S_WM8960)||defined(CONFIG_I2S_WM8750)||defined(CONFIG_I2S_WM8751)
extern int audiohw_set_lineout_vol(int Aout, int vol_l, int vol_r);
extern int audiohw_set_linein_vol(int vol_l, int vol_r);
#endif

/* internal functions declarations */
irqreturn_t i2s_irq_isr(int irq, void *irqaction);
void i2s_dma_handler(u32 dma_ch);
void i2s_unmask_handler(u32 dma_ch);
int i2s_debug_cmd(unsigned int cmd, unsigned long arg);

/* forward declarations for _fops */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
static long i2s_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#else
static int i2s_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);
#endif
static int i2s_mmap(struct file *file, struct vm_area_struct *vma);
int i2s_open(struct inode *inode, struct file *file);
static int i2s_release(struct inode *inode, struct file *file);

/* global varable definitions */
i2s_config_type* pi2s_config;
i2s_status_type* pi2s_status;

static dma_addr_t i2s_txdma_addr, i2s_rxdma_addr;
static dma_addr_t i2s_mmap_addr[MAX_I2S_PAGE*2];
					     /* 8khz  11.025khz	12khz	16khz 22.05khz	24Khz	32khz	44.1khz	 48khz	 88.2khz  96khz*/
unsigned long i2sMaster_inclk_15p625Mhz[11] = {60<<8, 	43<<8, 	40<<8, 	30<<8, 	21<<8, 	19<<8, 	14<<8,   10<<8,  9<<8, 	 7<<8, 	  4<<8};
unsigned long i2sMaster_exclk_12p288Mhz[11] = {47<<8, 	34<<8, 	31<<8,  23<<8, 	16<<8, 	15<<8, 	11<<8,    8<<8,  7<<8, 	 5<<8, 	  3<<8};
unsigned long i2sMaster_exclk_12Mhz[11]     = {46<<8, 	33<<8, 	30<<8,  22<<8, 	16<<8, 	15<<8, 	11<<8,    8<<8,  7<<8, 	 5<<8, 	  3<<8};
#if defined(CONFIG_I2S_WM8750)
unsigned long i2sSlave_exclk_12p288Mhz[11]  = {0x0C,  	0x00,   0x10,    0x14,  0x38,	 0x38,  0x18,     0x20,  0x00,	 0x00, 	  0x1C};
unsigned long i2sSlave_exclk_12Mhz[11]    = {0x0C,  	0x32,  	0x10,    0x14,  0x37,  	 0x38,  0x18,     0x22,  0x00, 	 0x3E, 	  0x1C};
/* Setting for Xtal 24.576MHz */
//unsigned long i2sSlave_exclk_12Mhz[11]      = {0x4C,  	0x00,  	0x50,    0x54,  0x00,  	 0x78,  0x58,     0x00,  0x40, 	 0x00, 	  0x5C};

#endif
#if defined(CONFIG_I2S_WM8751)
unsigned long i2sSlave_exclk_12p288Mhz[11]  = {0x04,  	0x00,   	0x10,    0x14,  	0x38,	 	0x38,  	 0x18,     0x20,  	0x00,	 0x00, 	  0x1C};
unsigned long i2sSlave_exclk_12Mhz[11]      = {0x04,  	0x32,  		0x10,    0x14,  	0x37,  		0x38,  	 0x18,     0x22,  	0x00, 	 0x3E, 	  0x1C};
#endif
#if defined(CONFIG_I2S_WM8960)
					    /*8k  11.025k  12k   16k  22.05k  24k  32k   44.1k  48k  88.2k  96k*/
unsigned long i2sSlave_exclk_12p288Mhz[11]={0x36,  0x24,  0x24, 0x1b,  0x12, 0x12, 0x09, 0x00, 0x00, 0x00, 0x00};
unsigned long i2sSlave_exclk_12Mhz[11]=    {0x36,  0x24,  0x24, 0x1b,  0x12, 0x12, 0x09, 0x00, 0x00, 0x00, 0x00};
#endif

#if defined(CONFIG_RALINK_RT6855A)
unsigned long i2sMaster_inclk_int[11] = {97, 70, 65, 48, 35, 32, 24, 17, 16, 12, 8};
unsigned long i2sMaster_inclk_comp[11] = {336, 441, 53, 424, 220, 282, 212, 366, 141, 185, 70};
#elif defined (CONFIG_RALINK_MT7621)
#ifdef MT7621_ASIC_BOARD
#if defined (CONFIG_I2S_MCLK_12P288MHZ)
				        /*  8K  11.025k 12k  16k  22.05k  24k  32k  44.1K  48k  88.2k  96k */
unsigned long i2sMaster_inclk_int[11] = {  576,   384,   0,  288,  192,   192, 144,   96,   96,   48,  48};
unsigned long i2sMaster_inclk_comp[11] = {  0,     0,    0,   0,   0,      0,   0,    0,    0,     0,   0};
#elif defined(CONFIG_I2S_MCLK_12MHZ)
				        /*  8K  11.025k 12k  16k  22.05k  24k  32k  44.1K  48k  88.2k  96k */
unsigned long i2sMaster_inclk_int[11] = {  1171,   850,  0,  585,  425,   390, 292,  212,  195,  106,  97};
unsigned long i2sMaster_inclk_comp[11] = {  448,   174,  0,  480,   87,   320, 496,  299,  160,  149,  336};
#endif
#else
					/* 8K  11.025k 12k  16k  22.05k  24k   32k  44.1K  48k  88.2k  96k */
unsigned long i2sMaster_inclk_int[11] = { 529,   384,   0,  264,  192,   176,  132,   96,   88,   48,   44};
unsigned long i2sMaster_inclk_comp[11] = {102,    0,    0,  307,   0,    204,  153,    0,  102,    0,   51};
#endif
#elif defined (CONFIG_RALINK_MT7628)
				              /*  8K  11.025k 12k  16k  22.05k  24k  32k  44.1K  48k  88.2k  96k 176k 192k */
unsigned long i2sMaster_inclk_int_16bit[13] = {  468,   340,   0,  234,  170,   156, 117,   85,   78,   42,  39,  21,  19};
unsigned long i2sMaster_inclk_comp_16bit[13] = { 384,    69,   0,  192,   34,   128,  96,   17,   64,  264,  32, 133, 272};

unsigned long i2sMaster_inclk_int_24bit[13] = {  312,   202,   0,  156,  113,   104,  78,   56,   52,   28,  26,  14,  13};
unsigned long i2sMaster_inclk_comp_24bit[13] = { 256,   202,   0,  128,  193,    85,  64,  352,   42,  176,  21,  88,  10};

#else
unsigned long i2sMaster_inclk_int[11] = {78, 56, 52, 39, 28, 26, 19, 14, 13, 9, 6};
unsigned long i2sMaster_inclk_comp[11] = {64, 352, 42, 32, 176, 21, 272, 88, 10, 455, 261};
#endif

/* USB mode 22.05Khz register value in datasheet is 0x36 but will cause slow clock, 0x37 is correct value */
/* USB mode 44.1Khz register value in datasheet is 0x22 but will cause slow clock, 0x23 is correct value */

static const struct file_operations i2s_fops = {
	owner		: THIS_MODULE,
	mmap		: i2s_mmap,
	open		: i2s_open,
	release		: i2s_release,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	unlocked_ioctl:     i2s_ioctl,
#else	
	ioctl		: i2s_ioctl,
#endif	
};

int __init i2s_mod_init(void)
{
	/* register device with kernel */
#ifdef  CONFIG_DEVFS_FS
    if(devfs_register_chrdev(i2sdrv_major, I2SDRV_DEVNAME , &i2s_fops)) {
		printk(KERN_WARNING " i2s: can't create device node - %s\n", I2SDRV_DEVNAME);
		return -EIO;
    }

    devfs_handle = devfs_register(NULL, I2SDRV_DEVNAME, DEVFS_FL_DEFAULT, i2sdrv_major, 0, 
	    S_IFCHR | S_IRUGO | S_IWUGO, &i2s_fops, NULL);
#else
    int result=0;
    result = register_chrdev(i2sdrv_major, I2SDRV_DEVNAME, &i2s_fops);
    if (result < 0) {
		printk(KERN_WARNING "i2s: can't get major %d\n",i2sdrv_major);
        return result;
    }

    if (i2sdrv_major == 0) {
		i2sdrv_major = result; /* dynamic */
    }
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
#else	
	i2smodule_class=class_create(THIS_MODULE, I2SDRV_DEVNAME);
	if (IS_ERR(i2smodule_class)) 
		return -EFAULT;
	device_create(i2smodule_class, NULL, MKDEV(i2sdrv_major, 0), I2SDRV_DEVNAME);
#endif	

	return 0;
}

void i2s_mod_exit(void)
{
		
#ifdef  CONFIG_DEVFS_FS
    devfs_unregister_chrdev(i2sdrv_major, I2SDRV_DEVNAME);
    devfs_unregister(devfs_handle);
#else
    unregister_chrdev(i2sdrv_major, I2SDRV_DEVNAME);
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
#else
	device_destroy(i2smodule_class,MKDEV(i2sdrv_major, 0));
	class_destroy(i2smodule_class); 
#endif	
	return ;
}


int i2s_open(struct inode *inode, struct file *filp)
{
#if 0
	int Ret;
#endif

#if !defined(CONFIG_SND_RALINK_SOC)
	int minor = iminor(inode);


	if (minor >= I2S_MAX_DEV)
		return -ENODEV;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT;
#else
	try_module_get(THIS_MODULE);
#endif

	if (filp->f_flags & O_NONBLOCK) {
		MSG("filep->f_flags O_NONBLOCK set\n");
		return -EAGAIN;
	}
#endif
	/* set i2s_config */
	pi2s_config = (i2s_config_type*)kmalloc(sizeof(i2s_config_type), GFP_KERNEL);
	if(pi2s_config==NULL)
		return -1;
#if !defined(CONFIG_SND_RALINK_SOC)
	filp->private_data = pi2s_config;
#endif
	memset(pi2s_config, 0, sizeof(i2s_config_type));
	
#ifdef I2S_STATISTIC
	pi2s_status = (i2s_status_type*)kmalloc(sizeof(i2s_status_type), GFP_KERNEL);
	if(pi2s_status==NULL)
		return -1;
	memset(pi2s_status, 0, sizeof(i2s_status_type));	
#endif

	pi2s_config->flag = 0;
	pi2s_config->dmach = GDMA_I2S_TX0;
	pi2s_config->tx_ff_thres = CONFIG_I2S_TFF_THRES;
	pi2s_config->tx_ch_swap = CONFIG_I2S_CH_SWAP;
	pi2s_config->rx_ff_thres = CONFIG_I2S_TFF_THRES;
	pi2s_config->rx_ch_swap = CONFIG_I2S_CH_SWAP;
	pi2s_config->slave_en = CONFIG_I2S_SLAVE_EN; /*FIXME*/
	pi2s_config->codec_pll_en = CONFIG_I2S_CODEC_PLL_EN;
	printk("Codec PLL EN = %d\n", pi2s_config->codec_pll_en);
	pi2s_config->wordlen_24b = 0;

	pi2s_config->srate = 44100;
	pi2s_config->txvol = 0;
	pi2s_config->rxvol = 0;
	pi2s_config->lbk = CONFIG_I2S_INLBK;
	pi2s_config->extlbk = CONFIG_I2S_EXLBK;
	pi2s_config->fmt = CONFIG_I2S_FMT;
#if defined(CONFIG_RALINK_MT7628)
	pi2s_config->sys_endian = 0;
#endif
#if 0	
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	Ret = request_irq(SURFBOARDINT_I2S, i2s_irq_isr, IRQF_DISABLED, "Ralink_I2S", NULL);
#else
	Ret = request_irq(SURFBOARDINT_I2S, i2s_irq_isr, SA_INTERRUPT, "Ralink_I2S", NULL);
#endif
	
	if(Ret){
		MSG("IRQ %d is not free.\n", SURFBOARDINT_I2S);
		i2s_release(inode, filp);
		return -1;
	}
#endif	
 
    	init_waitqueue_head(&(pi2s_config->i2s_tx_qh));
    	init_waitqueue_head(&(pi2s_config->i2s_rx_qh));
	
	/* CPU and DRAM run robin */
    	//i2s_outw(0xb0000380, 0x04fac688);
    	//i2s_outw(0xb0000384, 0x8210ff10);
	//i2s_outw(0xb0000384, 0x9210ff10);

	//i2s_outw(0xb0000400, 0x07fac688);
	//i2s_outw(0xb0000404, 0x91208020);
	    
	return 0;
}


static int i2s_release(struct inode *inode, struct file *filp)
{
	int i;
	i2s_config_type* ptri2s_config;
	
	/* decrement usage count */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_DEC_USE_COUNT;
#else
	module_put(THIS_MODULE);
#endif

	//free_irq(SURFBOARDINT_I2S, NULL);
	
	ptri2s_config = filp->private_data;
	if(ptri2s_config==NULL)
		goto EXIT;
#ifdef CONFIG_MMAP	
	for(i = 0 ; i < MAX_I2S_PAGE*2 ; i ++)
	{
		if(ptri2s_config->pMMAPBufPtr[i])
		{ 
			printk("ummap MMAP[%d]=0x%08X\n",i,ptri2s_config->pMMAPBufPtr[i]);
			dma_unmap_single(NULL, i2s_mmap_addr[i], I2S_PAGE_SIZE, DMA_BIDIRECTIONAL);
			kfree(ptri2s_config->pMMAPBufPtr[i]);	
		}
	}
	ptri2s_config->mmap_index = 0;
#else
	for(i = 0 ; i < MAX_I2S_PAGE ; i ++) {
		if(ptri2s_config->pMMAPRxBufPtr[i])
			kfree(ptri2s_config->pMMAPRxBufPtr[i]);
		if(ptri2s_config->pMMAPTxBufPtr[i])
			kfree(ptri2s_config->pMMAPTxBufPtr[i]);
	}
#endif	
	/* free buffer */
	if(ptri2s_config->pPage0TxBuf8ptr)
	{
		pci_free_consistent(NULL, I2S_PAGE_SIZE*2, ptri2s_config->pPage0TxBuf8ptr, i2s_txdma_addr);
		ptri2s_config->pPage0TxBuf8ptr = NULL;
	}
	
	if(ptri2s_config->pPage0RxBuf8ptr)
	{
		pci_free_consistent(NULL, I2S_PAGE_SIZE*2, ptri2s_config->pPage0RxBuf8ptr, i2s_rxdma_addr);
		ptri2s_config->pPage0RxBuf8ptr = NULL;
	}
	
	kfree(ptri2s_config);
	printk("i2s_release succeeds\n");
	
EXIT:			
#ifdef I2S_STATISTIC
	kfree(pi2s_status);
#endif

	MSG("i2s_release succeeds\n");
	return 0;
}

static int i2s_mmap(struct file *filp, struct vm_area_struct *vma)
{
   	int nRet;
	unsigned long size = vma->vm_end-vma->vm_start;
	
	if((pi2s_config->pMMAPBufPtr[0]==NULL)&&(pi2s_config->mmap_index!=0))
		pi2s_config->mmap_index = 0;
		
	if(pi2s_config->pMMAPBufPtr[pi2s_config->mmap_index]!=NULL)
		goto EXIT;

	pi2s_config->pMMAPBufPtr[pi2s_config->mmap_index] = kmalloc(size, GFP_DMA);
	i2s_mmap_addr[pi2s_config->mmap_index] = (dma_addr_t)dma_map_single(NULL, pi2s_config->pMMAPBufPtr[pi2s_config->mmap_index], size, DMA_BIDIRECTIONAL);
	MSG("MMAP[%d]=0x%08X, vm_start=%08X,vm_end=%08X\n",pi2s_config->mmap_index, (u32)pi2s_config->pMMAPBufPtr[pi2s_config->mmap_index], (u32)vma->vm_start, (u32)vma->vm_end);	
	if( pi2s_config->pMMAPBufPtr[pi2s_config->mmap_index] == NULL ) 
	{
		MSG("i2s_mmap failed\n");
		return -1;
	}
EXIT:	 	
	memset(pi2s_config->pMMAPBufPtr[pi2s_config->mmap_index], 0, size);
		
	nRet = remap_pfn_range(vma, vma->vm_start, virt_to_phys((void *)pi2s_config->pMMAPBufPtr[pi2s_config->mmap_index]) >> PAGE_SHIFT,  size, vma->vm_page_prot);
	
	if( nRet != 0 )
	{
		MSG("i2s_mmap->remap_pfn_range failed\n");
		return -EIO;
	}

	pi2s_config->mmap_index++;
	
#if defined(CONFIG_I2S_TXRX)
	if(pi2s_config->mmap_index>MAX_I2S_PAGE*2)
#else	
	if(pi2s_config->mmap_index>MAX_I2S_PAGE)
#endif	
		pi2s_config->mmap_index = 0;
	return 0;
}

int i2s_reset_tx_config(i2s_config_type* ptri2s_config)
{
	ptri2s_config->bTxDMAEnable = 0;
	ptri2s_config->nTxDMAStopped = 0;
	ptri2s_config->tx_isr_cnt = 0;
	ptri2s_config->tx_w_idx = 0;
	ptri2s_config->tx_r_idx = 0;	
	ptri2s_config->enLable = 0;
	pi2s_status->txbuffer_unrun = 0;
	pi2s_status->txbuffer_ovrun = 0;
	pi2s_status->txdmafault = 0;
	pi2s_status->txovrun = 0;
	pi2s_status->txunrun = 0;
	pi2s_status->txthres = 0;
	pi2s_status->txbuffer_len = 0;
	
	return 0;
}

int i2s_reset_rx_config(i2s_config_type* ptri2s_config)
{
	ptri2s_config->bRxDMAEnable = 0;
	ptri2s_config->nRxDMAStopped = 0;
	ptri2s_config->rx_isr_cnt = 0;
	ptri2s_config->rx_w_idx = 0;
	ptri2s_config->rx_r_idx = 0;	
	ptri2s_config->enLable = 0;
	pi2s_status->rxbuffer_unrun = 0;
	pi2s_status->rxbuffer_ovrun = 0;
	pi2s_status->rxdmafault = 0;
	pi2s_status->rxovrun = 0;
	pi2s_status->rxunrun = 0;
	pi2s_status->rxthres = 0;
	pi2s_status->rxbuffer_len = 0;
	
	return 0;
}	
#ifdef MT7621_ASIC_BOARD
int i2s_pll_config(unsigned long index)
{
        unsigned long data;
	unsigned long regValue;
	bool xtal_20M_en = 0;
//	bool xtal_25M_en = 0;
	bool xtal_40M_en = 0;

	regValue = i2s_inw(RALINK_SYSCTL_BASE + 0x10);
       	regValue = (regValue >> 6) & 0x7;
	if (regValue < 3)
	{
		xtal_20M_en = 1;
		printk("Xtal is 20MHz. \n");
	}
	else if (regValue < 6)
	{
		xtal_40M_en = 1;
		printk("Xtal is 40M.\n");
	}
	else
	{
		//xtal_25M_en = 1;
		printk("Xtal is 25M.\n");
	}

#if defined (CONFIG_I2S_MCLK_12P288MHZ)
	printk("MT7621 provide 12.288M/11.298MHz REFCLK\n");	
	/* Firstly, reset all required register to default value */
	i2s_outw(RALINK_ANA_CTRL_BASE, 0x00008000);
	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, 0x01001d61);//0x01401d61);
	i2s_outw(RALINK_ANA_CTRL_BASE+0x0018, 0x38233d0e);
	i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, 0x80100004);//0x80120004);
	i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x1c7dbf48);

        /* toggle RG_XPTL_CHG */
        i2s_outw(RALINK_ANA_CTRL_BASE, 0x00008800);
        i2s_outw(RALINK_ANA_CTRL_BASE, 0x00008c00);

        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0014);
        data &= ~(0x0000ffc0);
	if ((xtal_40M_en) || (xtal_20M_en))
	{
        	data |= REGBIT(0x1d, 8); /* for 40M or 20M */
	}
	else 
	{
        	data |= REGBIT(0x17, 8); /* for 25M */
	}
	
	if (xtal_40M_en)
	{
        	data |= REGBIT(0x1, 6);  /* for 40M */
	}
	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, data);


        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0018);
        data &= ~(0xf0773f00);
        data |= REGBIT(0x3, 28);
        data |= REGBIT(0x2, 20);
	if ((xtal_40M_en) || (xtal_20M_en))
	{
        	data |= REGBIT(0x3, 16); /* for 40M or 20M */
	}
	else
	{
        	data |= REGBIT(0x2, 16); /* for 25M */
	}
        data |= REGBIT(0x3, 12);
	if ((xtal_40M_en) || (xtal_20M_en))
	{
        	data |= REGBIT(0xd, 8);	/* for 40M or 20M */
	}
	else
	{
        	data |= REGBIT(0x7, 8);	/* for 25M */
	}
        i2s_outw(RALINK_ANA_CTRL_BASE+0x0018, data);

        if((index==1)|(index==4)|(index==7)|(index==9))// 270 MHz for 22.05K, 44.1K, 88.2K, 176.4K
        {
		if ((xtal_40M_en) || (xtal_20M_en))
		{
         	       	i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x1a18548a); /* for 40M or 20M */
		}
		else
		{
                	i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x14ad106e); /* for 25M */
		}
        }
        else if ((index==0)|(index==3)|(index==5)|(index==6)|(index==8)|(index==10))// 294 MHZ for 24K, 48K, 96K, 192K
        {
		if ((xtal_40M_en) || (xtal_20M_en))
		{
                	i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x1c7dbf48); /* for 40M or 20M */
		}
		else
		{
                	i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x1697cc39); /* for 25M */
		}
        }
	else if (index==2)
	{
		printk("Not support 12KHz sampling rate!\n");
		return -1;
	}
        else
        {
                printk("Wrong sampling rate!\n");
                return -1;
        }

        //*Common setting - Set PLLGP_CTRL_4 *//
	/* 1. Bit 31 */
        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        data &= ~(REGBIT(0x1, 31));
        i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

        /* 2. Bit 0 */
        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        data |= REGBIT(0x1, 0);
        i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

        /* 3. Bit 3 */
        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        data |= REGBIT(0x1, 3);
        i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

        /* 4. Bit 8 */
        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        data |= REGBIT(0x1, 8);
        i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

        /* 5. Bit 6 */
        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        data |= REGBIT(0x1, 6);
        i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

        /* 6. Bit 5 & Bit 7*/
        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        data |= REGBIT(0x1, 5);
	data |= REGBIT(0x1, 7);
        i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

        /* 7. Bit 17 */
        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        data |= REGBIT(0x1, 17);
        i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

#elif defined(CONFIG_I2S_MCLK_12MHZ)
	printk("MT7621 provide 12MHz REFCLK\n");
	/* Firstly, reset all required register to default value */
	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, 0x01401d61);//0x01401d61);
	i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, 0x80120004);//0x80100004);
	i2s_outw(RALINK_ANA_CTRL_BASE+0x0018, 0x38233d0e);

	if (xtal_40M_en)
	{
		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        	data &= ~REGBIT(0x1, 17);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0014);
		data &= ~REGBIT(0x3, 4);
        	data |= REGBIT(0x1, 4);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        	data &= ~REGBIT(0x1, 31);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);
	}
	else if (xtal_20M_en)
	{
		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        	data &= ~REGBIT(0x1, 17);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0014);
		data &= ~REGBIT(0x3, 6);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0014);
		data &= ~REGBIT(0x3, 4);
        	data |= REGBIT(0x1, 4);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        	data &= ~REGBIT(0x1, 31);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);
	}
	else
	{
		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        	data &= ~REGBIT(0x1, 17);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0014);
		data &= ~REGBIT(0x7f, 8);
        	data |= REGBIT(0x17, 8);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0014);
		data &= ~REGBIT(0x3, 6);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0018);
		data &= ~REGBIT(0x7, 16);
        	data |= REGBIT(0x2, 16);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x0018, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0018);
		data &= ~REGBIT(0xf, 8);
        	data |= REGBIT(0x7, 8);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x0018, data);


		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0014);
		data &= ~REGBIT(0x3, 4);
        	data |= REGBIT(0x1, 4);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, data);

		data = i2s_inw(RALINK_ANA_CTRL_BASE+0x001c);
        	data &= ~REGBIT(0x1, 31);
        	i2s_outw(RALINK_ANA_CTRL_BASE+0x001c, data);

	}
#endif
        return 0;
}
#endif	

/*
 *  Ralink Audio System Clock Enable
 *	
 *  I2S_WS : signal direction opposite to/same as I2S_CLK 
 *
 *  I2S_CLK : Integer division or fractional division
 *			  REFCLK from Internal or External (external REFCLK not support for fractional division)
 *			  Suppose external REFCLK always be the same as external MCLK
 * 		
 *  MCLK : External OSC or internal generation
 *
 */
int i2s_clock_enable(i2s_config_type* ptri2s_config)
{
	unsigned long data;
	unsigned long index;
	unsigned long* pTable;
	/* audio sampling rate decision */
	switch(ptri2s_config->srate)
	{
		case 8000:
			index = 0;
			break;
		case 11025:
			index = 1;
			break;
		case 12000:
			index = 2;
			break;			
		case 16000:
			index = 3;
			break;
		case 22050:
			index = 4;
			break;
        	case 24000:
			index = 5;
			break;	
		case 32000:
			index = 6;
			break;			
		case 44100:
			index = 7;
			break;
		case 48000:
			index = 8;
			break;
		case 88200:
			index = 9;
			break;	
		case 96000:
			index = 10;
			break;
#if defined(CONFIG_RALINK_MT7628)
		case 176000:
			index = 11;
			break;
		case 192000:
			index = 12;
			break;
#endif
		default:
			index = 7;
	}
#ifdef MT7621_ASIC_BOARD
        /* Set pll config  */
        i2s_pll_config(index);
#endif
	/* enable internal MCLK */
#if defined(CONFIG_I2S_IN_MCLK)
#if defined(CONFIG_RALINK_MT7621)
	/* Set APLL register for REFCLK */
	data = i2s_inw(RALINK_SYSCTL_BASE+0x90);
	data &= ~(0x0000f000);
	data |= REGBIT(0x1, 12);
	i2s_outw(RALINK_SYSCTL_BASE+0x0090, data);

	data = i2s_inw(RALINK_SYSCTL_BASE+0x0090);
	data &= ~(0x00000300);
	i2s_outw(RALINK_SYSCTL_BASE+0x0090, data);
	printk("Set 0x90 register\n");
#endif

#if defined(CONFIG_RALINK_RT6855A)
	data = i2s_inw(RALINK_SYSCTL_BASE+0x860);
#else
	data = i2s_inw(RALINK_SYSCTL_BASE+0x2c);
#endif
#if defined(CONFIG_I2S_MCLK_12MHZ)
	MSG("Enable SoC MCLK 12Mhz\n");
#if defined(CONFIG_RALINK_RT3350)
	data |= (0x1<<8);
#elif defined(CONFIG_RALINK_RT3883)
	data &= ~(0x03<<13);
	data |= (0x1<<13);	
#elif defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350) || defined (CONFIG_RALINK_RT6855) 
	data &= ~(0x0F<<8);
	data |= (0x3<<8);	
#elif defined(CONFIG_RALINK_RT6855A)
	data |= (0x1<<17);
	data &= ~(0x7<<18);
	data |= (0x1<<18);
#elif defined(CONFIG_RALINK_MT7620)
	data &= ~(0x07<<9);
    	data |= (1<<9);
#elif defined(CONFIG_RALINK_MT7621)
	data &= ~(0x1f<<18);
	data |= REGBIT(0x19, 18);
	data &= ~(0x1f<<12);
	data |= REGBIT(0x1, 12);
	data &= ~(0x7<<9);
	data |= REGBIT(0x5, 9);
#elif defined(CONFIG_RALINK_MT7628)
	printk("turn on REFCLK output for MCLK1\n");
	data &= ~(0x7<<9);
	data |= (0x1<<9);  /* output for MCLK */
#else	
	#error "This SoC does not provide 12MHz clock to audio codec\n");	
#endif
#endif /* MCLK_12MHZ */
#if defined(CONFIG_I2S_MCLK_12P288MHZ)
	MSG("Enable SoC MCLK 12.288Mhz\n");
#if defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350) || defined (CONFIG_RALINK_RT6855)
	data &= ~(0x01F<<18);
	data |= 31<<18;
	data &= ~(0x01F<<12);
	data |= 1<<12;
	data |= (0xF<<8);
#elif defined(CONFIG_RALINK_RT6855A)
	//FIXME:need config frac div for 12.288Mhz
#elif defined(CONFIG_RALINK_MT7621)
	data &= ~(0x1f<<18);
	data |= REGBIT(0xc, 18);
	data &= ~(0x1f<<12);
	data |= REGBIT(0x1, 12);
	data &= ~(0x7<<9);
	data |= REGBIT(0x5, 9);
	printk("MT7621 provide REFCLK 12.288MHz/11.289MHz\n");
#else
	#error "This SoC does not provide 12.288Mhz clock to audio codec\n");	
#endif
#endif /* MCLK_12P288MHZ */
#if defined(CONFIG_RALINK_RT6855A)
	i2s_outw(RALINK_SYSCTL_BASE+0x860, data);
#else
	i2s_outw(RALINK_SYSCTL_BASE+0x2c, data);
#endif
	/* Set REFCLK_GPIO ping as REFCLK mode*/
#if defined(CONFIG_RALINK_MT7620)
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60);
    	data &= ~(0x03<<21);  /* WDT */
    	data |= (1<<21);
	//data &= ~(0x03<<16);  /* PERST */
	//data |= (1<<16);
    	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);
#endif
#if defined(CONFIG_RALINK_MT7621)
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60);
	//data &= ~(0x3<<10); /* PERST */
	//data |= (0x2<<10);
	data &= ~(0x3<<8); /* WDT */
	data |= (0x2<<8);
	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);
	printk("Set 0x60 register\n");
#endif
#if defined(CONFIG_RALINK_MT7628)
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60);
	data &= ~(0x1<<18);
	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);
#endif

#else	
	MSG("Disable SoC MCLK, use external OSC\n");
#if defined(CONFIG_RALINK_RT6855A)
    	data = i2s_inw(RALINK_SYSCTL_BASE+0x860);
#else	
	data = i2s_inw(RALINK_SYSCTL_BASE+0x2c);
#endif
#if defined(CONFIG_RALINK_RT3350)
	data &= ~(0x1<<8);
#elif defined(CONFIG_RALINK_RT3883)
#elif defined(CONFIG_RALINK_RT3352)
	data &= ~(0x0F<<8);
#elif defined(CONFIG_RALINK_RT5350)		
	data |= (0x0F<<8);
#elif defined (CONFIG_RALINK_RT6855)
	data &= ~(0x0F<<8);
#elif defined (CONFIG_RALINK_RT6855A)
	data &= ~(1<<17);
#elif defined (CONFIG_RALINK_MT7620) 
	printk("turn off REFCLK output from internal CLK\n");	
#elif defined (CONFIG_RALINK_MT7621)
	printk("turn off REFCLK output from internal CLK\n");
#elif defined (CONFIG_RALINK_MT7628)
	printk("turn off REFCLK output from internal CLK\n"); 
#endif
#if defined(CONFIG_RALINK_RT6855A)
	i2s_outw(RALINK_SYSCTL_BASE+0x860, data);
#else	
	i2s_outw(RALINK_SYSCTL_BASE+0x2c, data);	
#endif

#if defined (CONFIG_RALINK_MT7620)
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60);
    	data &= ~(0x03<<21);  /* WDT */
    	data |= (1<<21);
	//data &= ~(0x03<<16);  /* PERST */
	//data |= (1<<16);
    	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);

	data = i2s_inw(RALINK_PIO_BASE);
	data &= ~(0x1<<17); /* GPIO share ping 17 for WDT */
	i2s_outw(RALINK_PIO_BASE, data);

	//data = i2s_inw(RALINK_PIO_BASE+0x04);
	//data &= ~(0x1<<4); /* GPIO share ping 36 for PERST */
	//i2s_outw(RALINK_PIO_BASE+0x04, data);
#endif
#if defined (CONFIG_RALINK_MT7621)
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60);
	//data &= ~(0x3<<10); /* PERST */
	//data |= (0x1<<10);
	data &= ~(0x3<<8); /* WDT */
	data |= (0x1<<8);
	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);
	
	data = i2s_inw(RALINK_PIO_BASE);
	//data &= ~(0x1<<19); /* GPIO share ping 19 for RERST */
	data &= ~(0x1<<18); /* GPIO share ping 18 for WDT */
	i2s_outw(RALINK_PIO_BASE, data);
#endif
#if defined (CONFIG_RALINK_MT7628)
	/* To use external OSC, set REFCLK_GPIO ping as GPIO mode and set it as input direction */
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60);
	data |= (0x1<<18);
	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);

	data = i2s_inw(RALINK_PIO_BASE+0x04);
	data &= ~(0x1<<5); /* GPIO share ping 37*/
	i2s_outw(RALINK_PIO_BASE+0x04, data);
#endif
#endif	
	
	/* set share pins to i2s/gpio mode and i2c mode */
#if defined(CONFIG_RALINK_RT6855A)
	data = i2s_inw(RALINK_SYSCTL_BASE+0x860);
	data |= 0x00008080;
	i2s_outw(RALINK_SYSCTL_BASE+0x860, data);
#elif defined(CONFIG_RALINK_MT7621)	
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60); 
	data &= 0xFFFFFFE3;
	data |= 0x00000010;
	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);
#elif defined(CONFIG_RALINK_MT7628)	
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60); 
	data &= ~(0x3<<6);    /* I2S_MODE */ 
	data &= ~(0x3<<20);   /* I2C_MODE */
	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);
#else	
	data = i2s_inw(RALINK_SYSCTL_BASE+0x60); 
	data &= 0xFFFFFFE2;
	data |= 0x00000018;
	i2s_outw(RALINK_SYSCTL_BASE+0x60, data);
#endif	
#if defined(CONFIG_RALINK_MT7620)
        data = i2s_inw(RALINK_SYSCTL_BASE+0x60);
        data &= ~(0x03<<21);
        data |= (1<<21);
        i2s_outw(RALINK_SYSCTL_BASE+0x60, data);


        data = i2s_inw(RALINK_SYSCTL_BASE+0x2c);
        data &= ~(0x07<<9);
        data |= (1<<9);
        i2s_outw(RALINK_SYSCTL_BASE+0x2c, data);
#endif
	
	if(ptri2s_config->slave_en==0)
	{
		printk("This SoC is in Master mode\n");
		/* Setup I2S_WS and I2S_CLK */
		#if defined(CONFIG_I2S_IN_CLK)
			/* REFCLK is 15.625Mhz or 40Mhz(fractional division) */
			#if defined(CONFIG_I2S_FRAC_DIV)
				MSG("Internal REFCLK with fractional division\n");
			   #if defined(CONFIG_RALINK_MT7628)
				if (ptri2s_config->wordlen_24b == 1)
				{
					printk("24 bit int table\n");
					pTable = i2sMaster_inclk_int_24bit;
				}
				else
				{
					printk("16 bit int table\n");
					pTable = i2sMaster_inclk_int_16bit;
				}
			   #else
				pTable = i2sMaster_inclk_int;
			   #endif
				data = (unsigned long)(pTable[index]);
				i2s_outw(I2S_DIVINT_CFG, data);

			   #if defined(CONFIG_RALINK_MT7628)
				if (ptri2s_config->wordlen_24b == 1)
				{
					printk("24 bit comp table\n");
					pTable = i2sMaster_inclk_comp_24bit;
				}
				else
				{
					printk("16 bit comp table\n");
					pTable = i2sMaster_inclk_comp_16bit;
				}
			   #else
				pTable = i2sMaster_inclk_comp;
			   #endif
				data = (unsigned long)(pTable[index]);
				data |= REGBIT(1, I2S_CLKDIV_EN); 
				i2s_outw(I2S_DIVCOMP_CFG, data);
			#else
				MSG("Internal REFCLK 15.625Mhz \n");
				pTable = i2sMaster_inclk_15p625Mhz;
				data = i2s_inw(RALINK_SYSCTL_BASE+0x30); 
				data &= 0xFFFF00FF;
				data |= (unsigned long)(pTable[index]);
				data |= 0x00008000;
				i2s_outw(RALINK_SYSCTL_BASE+0x30, data);  
			#endif
		#else
			#if defined(CONFIG_I2S_MCLK_12MHZ)
				/* REFCLK = MCLK = 12Mhz */
				MSG("External REFCLK 12Mhz \n");
				pTable = i2sMaster_exclk_12Mhz;
				data = i2s_inw(RALINK_SYSCTL_BASE+0x30);
				data &= 0xFFFF00FF;
				data |= (unsigned long)(pTable[index]); 
				data |= 0x0000C000;
				i2s_outw(RALINK_SYSCTL_BASE+0x30, data);  	
			#else
				/* REFCLK = MCLK = 12.288Mhz */
				pTable = i2sMaster_exclk_12p288Mhz;
				MSG("External REFCLK 12.288Mhz \n");
				data = i2s_inw(RALINK_SYSCTL_BASE+0x30);
				data &= 0xFFFF00FF;
				data |= (unsigned long)(pTable[index]); 
				data |= 0x0000C000;
				i2s_outw(RALINK_SYSCTL_BASE+0x30, data); 					 
			#endif
		
		#endif /* Not CONFIG_I2S_IN_CLK */
	
		#if defined(CONFIG_I2S_WS_EDGE)
			data = i2s_inw(I2S_I2SCFG);
			data |= REGBIT(0x1, I2S_WS_INV);
			i2s_outw(I2S_I2SCFG, data);
		#endif
		
		#if defined(CONFIG_RALINK_RT3052)
			data = i2s_inw(I2S_I2SCFG);
			data &= ~REGBIT(0x1, I2S_SLAVE_EN);
			data &= ~REGBIT(0x1, I2S_CLK_OUT_DIS);
			i2s_outw(I2S_I2SCFG, data);
		#elif defined(CONFIG_RALINK_RT3883)||defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350)||\
			defined(CONFIG_RALINK_RT6855)||defined(CONFIG_RALINK_MT7620)||defined(CONFIG_RALINK_RT6855A)||\
			defined(CONFIG_RALINK_MT7621)||defined(CONFIG_RALINK_MT7628)
			data = i2s_inw(I2S_I2SCFG);
			data &= ~REGBIT(0x1, I2S_SLAVE_MODE);
			i2s_outw(I2S_I2SCFG, data);
		#else
		#error "a strange clock mode"	
		#endif
	
	#if defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751) || defined(CONFIG_I2S_WM8960)
		i2s_codec_enable(ptri2s_config);
	#endif		
	#if defined(CONFIG_I2S_MCLK_12MHZ)
		#if defined(CONFIG_I2S_WM8960) || defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
	        pTable = i2sSlave_exclk_12Mhz;
	        data = pTable[index];
		#endif
		#if defined(CONFIG_I2S_WM8960)
			audiohw_set_frequency(data, ptri2s_config->codec_pll_en);
		#elif defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
	        	audiohw_set_frequency(data|0x01);
		#endif	
	#else
		#if defined(CONFIG_I2S_WM8960) || defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
	        pTable = i2sSlave_exclk_12p288Mhz;
	        data = pTable[index];
		#endif
		#if defined(CONFIG_I2S_WM8960)
			audiohw_set_frequency(data, ptri2s_config->codec_pll_en);
		#elif defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
	        	audiohw_set_frequency(data);
		#endif
	#endif

	}
	else /* Slave mode*/
	{
		printk("This SoC is in Slave mode\n");
		
		#if defined(CONFIG_RALINK_RT3052)
			data = i2s_inw(I2S_I2SCFG);
			data |= REGBIT(0x1, I2S_SLAVE_EN);
			data |= REGBIT(0x1, I2S_CLK_OUT_DIS);
			i2s_outw(I2S_I2SCFG, data);
		#elif defined(CONFIG_RALINK_RT3883)||defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350)||\
			defined(CONFIG_RALINK_RT6855)||defined(CONFIG_RALINK_MT7620)||defined(CONFIG_RALINK_RT6855A)||\
			defined(CONFIG_RALINK_MT7621)||defined(CONFIG_RALINK_MT7628)
			data = i2s_inw(I2S_I2SCFG);
			data |= REGBIT(0x1, I2S_SLAVE_MODE);
			i2s_outw(I2S_I2SCFG, data);
		#else
		#error "a strange clock mode "	
		#endif


		#if defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)|| defined(CONFIG_I2S_WM8960)
			i2s_codec_enable(ptri2s_config);
		#endif

		#if defined(CONFIG_I2S_MCLK_12MHZ)
		#if defined(CONFIG_I2S_WM8960) || defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
			pTable = i2sSlave_exclk_12Mhz;
			data = pTable[index];
		#endif
			#if defined(CONFIG_I2S_WM8960)
				audiohw_set_frequency(data, ptri2s_config->codec_pll_en);
			#elif defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
				audiohw_set_frequency(data|0x1); /* for MCLK=12Mhz only. */
			#endif
		#else
		#if defined(CONFIG_I2S_WM8960) || defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
			pTable = i2sSlave_exclk_12p288Mhz;
			data = pTable[index];
		#endif
			#if defined(CONFIG_I2S_WM8960)
				audiohw_set_frequency(data, ptri2s_config->codec_pll_en);
			#elif defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
				audiohw_set_frequency(data);
			#endif
		#endif
	}

	return 0;
		
}	

int i2s_clock_disable(i2s_config_type* ptri2s_config)
{
#if defined(CONFIG_I2S_IN_MCLK)
	unsigned long data;
#endif

#if defined(CONFIG_I2S_WM8960) || defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
	i2s_codec_disable(ptri2s_config);
#endif

	/* disable internal MCLK */
#if defined(CONFIG_I2S_IN_MCLK)	
	data = i2s_inw(RALINK_SYSCTL_BASE+0x2c);
#if defined(CONFIG_RALINK_RT3350)	
	data &= ~(0x1<<8);
#elif defined(CONFIG_RALINK_RT3883)
	data &= ~(0x03<<13);
#elif defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350) || defined (CONFIG_RALINK_RT6855)
	data &= ~(0x03<<8);
#elif defined(CONFIG_RALINK_MT7620)||defined(CONFIG_RALINK_MT7621)
	//FIXME	
#elif defined(CONFIG_RALINK_RT6855A)
	//FIXME:REFCLK should be disable
#elif defined(CONFIG_RALINK_MT7628)
	data &= ~(0x07<<9); /* Set REFCLK to defult - Xtal clock(20/25/40 MHz by boot strap) */
#endif	
	i2s_outw(RALINK_SYSCTL_BASE+0x2c, data);	
#endif
	return 0;
}	


int i2s_codec_enable(i2s_config_type* ptri2s_config)
{
	
	int AIn = 0, AOut = 0;
#if defined(CONFIG_I2S_WM8960) || defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
	/* Codec initialization */
	audiohw_preinit();
#endif

#if defined(CONFIG_I2S_WM8960)
	if(ptri2s_config->codec_pll_en)
		audiohw_set_apll(ptri2s_config->srate);
#endif

#if defined(CONFIG_I2S_TXRX)	
	
	if(ptri2s_config->bTxDMAEnable)
		AOut = 1;
	if(ptri2s_config->bRxDMAEnable)
		AIn = 1;
#if defined(CONFIG_I2S_WM8960)
	printk("Code => WM8960\n");
	audiohw_postinit(!(ptri2s_config->slave_en), AIn, AOut, ptri2s_config->codec_pll_en, ptri2s_config->wordlen_24b);
#elif defined(CONFIG_I2S_WM8750)
	printk("Code => WM8750\n");
	audiohw_postinit(!(ptri2s_config->slave_en), AIn, AOut, ptri2s_config->wordlen_24b);
#endif
#else
#if defined(CONFIG_I2S_WM8750)
	audiohw_postinit(!(ptri2s_config->slave_en), 0, 1);
#elif defined(CONFIG_I2S_WM8960)	
	audiohw_postinit(!(ptri2s_config->slave_en), 1, 1, ptri2s_config->codec_pll_en);
#elif defined(CONFIG_I2S_WM8751)	
	if(ptri2s_config->slave_en==0)
		audiohw_postinit(1,1);
	else
		audiohw_postinit(0,1);
#endif		
#endif
	printk("AIn=%d, AOut=%d\n", AIn, AOut);
	return 0;	
}

int i2s_codec_disable(i2s_config_type* ptri2s_config)
{
#if defined(CONFIG_I2S_WM8960) || defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)
	audiohw_close();
#endif
	return 0;
}	


int i2s_tx_config(i2s_config_type* ptri2s_config)
{
	unsigned long data;
	/* set I2S_I2SCFG */
	data = i2s_inw(I2S_I2SCFG);
	data &= 0xFFFFFF81;
	data |= REGBIT(ptri2s_config->tx_ff_thres, I2S_TX_FF_THRES);
	data |= REGBIT(ptri2s_config->tx_ch_swap, I2S_TX_CH_SWAP);
#if defined(CONFIG_RALINK_RT6855A)	
	data |= REGBIT(1, I2S_BYTE_SWAP);
#endif
#if defined(CONFIG_RALINK_MT7628)
	printk("TX:wordLen=%d, sysEndian=%d\n", ptri2s_config->wordlen_24b, ptri2s_config->sys_endian);
	data |= REGBIT(ptri2s_config->wordlen_24b, I2S_DATA_24BIT);
	data |= REGBIT(ptri2s_config->sys_endian, I2S_SYS_ENDIAN);
	data |= REGBIT(ptri2s_config->little_edn, I2S_LITTLE_ENDIAN);
#endif	
	data &= ~REGBIT(1, I2S_TX_CH0_OFF);
	data &= ~REGBIT(1, I2S_TX_CH1_OFF);
	i2s_outw(I2S_I2SCFG, data);
	printk("## I2S_I2SCFG=0x%8x\n", i2s_inw(I2S_I2SCFG));	
#if defined(CONFIG_I2S_EXTENDCFG)	
	/* set I2S_I2SCFG1 */
	printk("internal loopback: %d\n", ptri2s_config->lbk);
	data = i2s_inw(I2S_I2SCFG1);
	data |= REGBIT(ptri2s_config->lbk, I2S_LBK_EN);
	data |= REGBIT(ptri2s_config->extlbk, I2S_EXT_LBK_EN);
	data &= 0xFFFFFFFC;
	data |= REGBIT(ptri2s_config->fmt, I2S_DATA_FMT);
	i2s_outw(I2S_I2SCFG1, data);
#endif
	
	return 0;
}	

int i2s_rx_config(i2s_config_type* ptri2s_config)
{
	unsigned long data;
	/* set I2S_I2SCFG */
	data = i2s_inw(I2S_I2SCFG);
	data &= 0xFFFF81FF;
	data |= REGBIT(ptri2s_config->rx_ff_thres, I2S_RX_FF_THRES);
	data |= REGBIT(ptri2s_config->rx_ch_swap, I2S_RX_CH_SWAP);
	data &= ~REGBIT(1, I2S_RX_CH0_OFF);
	data &= ~REGBIT(1, I2S_RX_CH1_OFF);
#if defined(CONFIG_RALINK_MT7628)
	printk("RX:wordLen=%d, sysEndian=%d\n", ptri2s_config->wordlen_24b, ptri2s_config->sys_endian);
	data |= REGBIT(ptri2s_config->wordlen_24b, I2S_DATA_24BIT);
	data |= REGBIT(ptri2s_config->sys_endian, I2S_SYS_ENDIAN);
	data |= REGBIT(ptri2s_config->little_edn, I2S_LITTLE_ENDIAN);
#endif	
	i2s_outw(I2S_I2SCFG, data);
	printk("** I2S_I2SCFG=0x%8x\n", i2s_inw(I2S_I2SCFG));	
#if defined(CONFIG_I2S_EXTENDCFG)	
	/* set I2S_I2SCFG1 */
	data = i2s_inw(I2S_I2SCFG1);
	data |= REGBIT(ptri2s_config->lbk, I2S_LBK_EN);
	data |= REGBIT(ptri2s_config->extlbk, I2S_EXT_LBK_EN);
	data &= 0xFFFFFFFC;
	data |= REGBIT(ptri2s_config->fmt, I2S_DATA_FMT);
	i2s_outw(I2S_I2SCFG1, data);
#endif
	return 0;	
}

/* Turn On Tx DMA and INT */
int i2s_tx_enable(i2s_config_type* ptri2s_config)
{
	unsigned long data;
	
//	data = i2s_inw(I2S_INT_EN);
//	data |= REGBIT(0x1, I2S_TX_INT3_EN);
//	data |= REGBIT(0x1, I2S_TX_INT2_EN);
//	data |= REGBIT(0x1, I2S_TX_INT1_EN);
//	data |= REGBIT(0x1, I2S_TX_INT0_EN);
//	i2s_outw(I2S_INT_EN, data);
	
	data = i2s_inw(I2S_I2SCFG);
#if defined(CONFIG_I2S_TXRX)	
	data |= REGBIT(0x1, I2S_TX_EN);
#else
	data |= REGBIT(0x1, I2S_EN);
#endif	
	ptri2s_config->bTxDMAEnable = 1;
	data |= REGBIT(0x1, I2S_DMA_EN);
	i2s_outw(I2S_I2SCFG, data);
	
	data = i2s_inw(I2S_I2SCFG);
	data |= REGBIT(0x1, I2S_EN);
	i2s_outw(I2S_I2SCFG, data);
	
	MSG("i2s_tx_enable done\n");
	return I2S_OK;
}

/* Turn On Rx DMA and INT */
int i2s_rx_enable(i2s_config_type* ptri2s_config)
{
	unsigned long data;
	
//	data = i2s_inw(I2S_INT_EN);
//	data |= REGBIT(0x1, I2S_RX_INT3_EN);
//	data |= REGBIT(0x1, I2S_RX_INT2_EN);
//	data |= REGBIT(0x1, I2S_RX_INT1_EN);
//	data |= REGBIT(0x1, I2S_RX_INT0_EN);
//	i2s_outw(I2S_INT_EN, data);
	
	data = i2s_inw(I2S_I2SCFG);
#if defined(CONFIG_I2S_TXRX)	
	data |= REGBIT(0x1, I2S_RX_EN);
#else
	data |= REGBIT(0x1, I2S_EN);
#endif	
	ptri2s_config->bRxDMAEnable = 1;
	data |= REGBIT(0x1, I2S_DMA_EN);
	i2s_outw(I2S_I2SCFG, data);
	
	data = i2s_inw(I2S_I2SCFG);
	data |= REGBIT(0x1, I2S_EN);
	i2s_outw(I2S_I2SCFG, data);
	
	MSG("i2s_rx_enable done\n");
	return I2S_OK;
}
/* Turn Off Tx DMA and INT */
int i2s_tx_disable(i2s_config_type* ptri2s_config)
{
	unsigned long data;
	
	data = i2s_inw(I2S_INT_EN);
	data &= ~REGBIT(0x1, I2S_TX_INT3_EN);
	data &= ~REGBIT(0x1, I2S_TX_INT2_EN);
	data &= ~REGBIT(0x1, I2S_TX_INT1_EN);
	//data &= ~REGBIT(0x1, I2S_TX_INT0_EN);
	i2s_outw(I2S_INT_EN, data);
	
	data = i2s_inw(I2S_I2SCFG);
#if defined(CONFIG_I2S_TXRX)	
	data &= ~REGBIT(0x1, I2S_TX_EN);
#else
	data &= ~REGBIT(0x1, I2S_EN);
#endif	
	if(ptri2s_config->bRxDMAEnable==0)
	{
		ptri2s_config->bTxDMAEnable = 0;
		data &= ~REGBIT(0x1, I2S_DMA_EN);
                data &= ~REGBIT(0x1, I2S_EN);
	}
	i2s_outw(I2S_I2SCFG, data);
	return I2S_OK;
}
/* Turn Off Rx DMA and INT */	
int i2s_rx_disable(i2s_config_type* ptri2s_config)
{
	unsigned long data;
	
	data = i2s_inw(I2S_INT_EN);
	data &= ~REGBIT(0x1, I2S_RX_INT3_EN);
	data &= ~REGBIT(0x1, I2S_RX_INT2_EN);
	data &= ~REGBIT(0x1, I2S_RX_INT1_EN);
	//data &= ~REGBIT(0x1, I2S_RX_INT0_EN);
	i2s_outw(I2S_INT_EN, data);
	
	data = i2s_inw(I2S_I2SCFG);
	//printk("*** I2S_I2SCFG = 0x%8x\n",  i2s_inw(I2S_I2SCFG));
#if defined(CONFIG_I2S_TXRX)	
	data &= ~REGBIT(0x1, I2S_RX_EN);
#else
	data &= ~REGBIT(0x1, I2S_EN);
#endif
	if(ptri2s_config->bTxDMAEnable==0)
	{
		ptri2s_config->bRxDMAEnable = 0;
		data &= ~REGBIT(0x1, I2S_DMA_EN);
                data &= ~REGBIT(0x1, I2S_EN);
	}
	i2s_outw(I2S_I2SCFG, data);
	return I2S_OK;
}
	
void i2s_dma_tx_handler(u32 dma_ch)
{
	pi2s_config->enLable = 1; /* TX:enLabel=1; RX:enLabel=2 */
	
	if(pi2s_config->bTxDMAEnable==0)
	{
		MSG("TxDMA not enable dc=%d, i=%d\n", dma_ch, pi2s_config->tx_isr_cnt);
		pi2s_config->nTxDMAStopped ++;
		if(dma_ch==GDMA_I2S_TX0)
		{
			GdmaI2sTx((u32)pi2s_config->pPage0TxBuf8ptr, I2S_TX_FIFO_WREG, 0, 4, i2s_dma_tx_handler, i2s_unmask_handler);
		}
		else
		{
			GdmaI2sTx((u32)pi2s_config->pPage1TxBuf8ptr, I2S_TX_FIFO_WREG, 1, 4, i2s_dma_tx_handler, i2s_unmask_handler);
		}
		if (pi2s_config->nTxDMAStopped==3)
			wake_up_interruptible(&(pi2s_config->i2s_tx_qh));

		return;
	}
	
	pi2s_config->tx_isr_cnt++;

#ifdef 	I2S_STATISTIC
	i2s_int_status(dma_ch);
#endif

	if(pi2s_config->tx_r_idx==pi2s_config->tx_w_idx)
	{
		/* Buffer Empty */
		MSG("TXBE r=%d w=%d[i=%u,c=%u]\n",pi2s_config->tx_r_idx,pi2s_config->tx_w_idx,pi2s_config->tx_isr_cnt,dma_ch);
#ifdef I2S_STATISTIC		
		pi2s_status->txbuffer_unrun++;
#endif	
		if(dma_ch==GDMA_I2S_TX0)
		{
			memset(pi2s_config->pPage0TxBuf8ptr, 0, I2S_PAGE_SIZE);
			GdmaI2sTx((u32)pi2s_config->pPage0TxBuf8ptr, I2S_TX_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
		}
		else
		{
			memset(pi2s_config->pPage1TxBuf8ptr, 0, I2S_PAGE_SIZE);
			GdmaI2sTx((u32)pi2s_config->pPage1TxBuf8ptr, I2S_TX_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
		}
		
		goto EXIT;	
	}
	
	if(pi2s_config->pMMAPTxBufPtr[pi2s_config->tx_r_idx]==NULL)
	{
		MSG("mmap buf NULL [%d]\n",pi2s_config->tx_r_idx);
		if(dma_ch==GDMA_I2S_TX0)
			GdmaI2sTx((u32)pi2s_config->pPage0TxBuf8ptr, I2S_TX_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
		else
			GdmaI2sTx((u32)pi2s_config->pPage1TxBuf8ptr, I2S_TX_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);

		goto EXIT;	
	}
#ifdef I2S_STATISTIC	
	pi2s_status->txbuffer_len--;
#endif
	if(dma_ch==GDMA_I2S_TX0)
	{	
#if defined(CONFIG_I2S_MMAP)
		dma_sync_single_for_device(NULL,  i2s_mmap_addr[pi2s_config->tx_r_idx], I2S_PAGE_SIZE, DMA_TO_DEVICE);
		GdmaI2sTx((u32)(pi2s_config->pMMAPTxBufPtr[pi2s_config->tx_r_idx]), I2S_TX_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
#else
		memcpy(pi2s_config->pPage0TxBuf8ptr,  pi2s_config->pMMAPTxBufPtr[pi2s_config->tx_r_idx], I2S_PAGE_SIZE);			
		GdmaI2sTx((u32)(pi2s_config->pPage0TxBuf8ptr), I2S_TX_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
#endif
		pi2s_config->dmach = GDMA_I2S_TX0;
		pi2s_config->tx_r_idx = (pi2s_config->tx_r_idx+1)%MAX_I2S_PAGE;
	}
	else
	{
#if defined(CONFIG_I2S_MMAP)
		dma_sync_single_for_device(NULL,  i2s_mmap_addr[pi2s_config->tx_r_idx], I2S_PAGE_SIZE, DMA_TO_DEVICE);
		GdmaI2sTx((u32)(pi2s_config->pMMAPTxBufPtr[pi2s_config->tx_r_idx]), I2S_TX_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
#else
		memcpy(pi2s_config->pPage1TxBuf8ptr,  pi2s_config->pMMAPTxBufPtr[pi2s_config->tx_r_idx], I2S_PAGE_SIZE);
		GdmaI2sTx((u32)(pi2s_config->pPage1TxBuf8ptr), I2S_TX_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
#endif
		pi2s_config->dmach = GDMA_I2S_TX1;
		pi2s_config->tx_r_idx = (pi2s_config->tx_r_idx+1)%MAX_I2S_PAGE;
		
	}
EXIT:
#if defined(CONFIG_SND_RALINK_SOC)
	if(pi2s_config->pss)
		snd_pcm_period_elapsed(pi2s_config->pss);
#endif
	wake_up_interruptible(&(pi2s_config->i2s_tx_qh));		
	return;
}

void i2s_dma_rx_handler(u32 dma_ch)
{
	u32 data;
	static int next_p0_idx, next_p1_idx;
	
	pi2s_config->enLable = 2; /* TX:enLabel=1; RX:enLabel=2 */
#if defined(CONFIG_I2S_TXRX)	
	if(pi2s_config->bRxDMAEnable==0) {
		MSG("RxDMA not enable dc=%d,i=%d\n",dma_ch,pi2s_config->rx_isr_cnt);
		pi2s_config->nRxDMAStopped ++;
		if(dma_ch==GDMA_I2S_RX0)
		{
				data=i2s_inw(GDMA_CTRL_REG(GDMA_I2S_RX0));
				data&=~(1<<CH_EBL_OFFSET);
				i2s_outw(GDMA_CTRL_REG(GDMA_I2S_RX0), data);
		}		
		else
		{	
				data=i2s_inw(GDMA_CTRL_REG(GDMA_I2S_RX1));
				data&=~(1<<CH_EBL_OFFSET);
				i2s_outw(GDMA_CTRL_REG(GDMA_I2S_RX1), data);
		}	
		
		if (pi2s_config->nRxDMAStopped==2)
			wake_up_interruptible(&(pi2s_config->i2s_rx_qh));
		return;
	}
	if(pi2s_config->rx_isr_cnt==0)
	{
		next_p0_idx = 0;
		next_p1_idx = 1;
	}	
	pi2s_config->rx_isr_cnt++;
	
#ifdef  I2S_STATISTIC
	i2s_int_status(dma_ch);
#endif

	if(((pi2s_config->rx_w_idx+1)%MAX_I2S_PAGE)==pi2s_config->rx_r_idx)
	{
		/* Buffer Full */
		MSG("RXBF r=%d w=%d[i=%u,c=%u]\n",pi2s_config->rx_r_idx,pi2s_config->rx_w_idx,
											pi2s_config->rx_isr_cnt,dma_ch);

#ifdef I2S_STATISTIC		
		pi2s_status->rxbuffer_unrun++;
#endif	
		if(dma_ch==GDMA_I2S_RX0)
		{
			GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)pi2s_config->pPage0RxBuf8ptr, 0, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
		}
		else
		{
			GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)pi2s_config->pPage1RxBuf8ptr, 1, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
		}
		
		goto EXIT;	
	}
	
#ifdef I2S_STATISTIC	
	pi2s_status->rxbuffer_len++;
#endif

	if(dma_ch==GDMA_I2S_RX0)
	{
		pi2s_config->rx_w_idx = (pi2s_config->rx_w_idx+1)%MAX_I2S_PAGE;	 	
#ifdef CONFIG_I2S_MMAP 
		dma_sync_single_for_cpu(NULL,  i2s_mmap_addr[next_p0_idx+(pi2s_config->mmap_index-MAX_I2S_PAGE)], I2S_PAGE_SIZE, DMA_FROM_DEVICE);
        next_p0_idx = (pi2s_config->rx_w_idx+1)%MAX_I2S_PAGE;
		dma_sync_single_for_device(NULL,  i2s_mmap_addr[next_p0_idx+(pi2s_config->mmap_index-MAX_I2S_PAGE)], I2S_PAGE_SIZE, DMA_FROM_DEVICE);
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)(pi2s_config->pMMAPRxBufPtr[next_p0_idx]), 0, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#else		
		memcpy(pi2s_config->pMMAPRxBufPtr[pi2s_config->rx_w_idx], pi2s_config->pPage0RxBuf8ptr, I2S_PAGE_SIZE);	
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)(pi2s_config->pPage0RxBuf8ptr), 0, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#endif
		pi2s_config->dmach = GDMA_I2S_RX0;
		
	}
	else
	{
		pi2s_config->rx_w_idx = (pi2s_config->rx_w_idx+1)%MAX_I2S_PAGE; 
#ifdef CONFIG_I2S_MMAP
		dma_sync_single_for_cpu(NULL,  i2s_mmap_addr[next_p1_idx+(pi2s_config->mmap_index-MAX_I2S_PAGE)], I2S_PAGE_SIZE, DMA_FROM_DEVICE);
		next_p1_idx = (pi2s_config->rx_w_idx+1)%MAX_I2S_PAGE;
		dma_sync_single_for_device(NULL,  i2s_mmap_addr[next_p1_idx+(pi2s_config->mmap_index-MAX_I2S_PAGE)], I2S_PAGE_SIZE, DMA_FROM_DEVICE);
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)(pi2s_config->pMMAPRxBufPtr[next_p1_idx]), 1, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#else
		memcpy(pi2s_config->pMMAPRxBufPtr[pi2s_config->rx_w_idx], pi2s_config->pPage1RxBuf8ptr, I2S_PAGE_SIZE);	
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)(pi2s_config->pPage1RxBuf8ptr), 1, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#endif		
		pi2s_config->dmach = GDMA_I2S_RX1;
		
	}
EXIT:
#if defined(CONFIG_SND_RALINK_SOC)
	if(pi2s_config->pss)
		snd_pcm_period_elapsed(pi2s_config->pss);
#endif
	wake_up_interruptible(&(pi2s_config->i2s_rx_qh));
#endif	
	return;
}

#if 1
#ifdef I2S_STATISTIC
void i2s_int_status(u32 dma_ch)
{
	u32 i2s_status;
	
	if((pi2s_config->tx_isr_cnt>0)||(pi2s_config->rx_isr_cnt>0))
	{
		i2s_status = i2s_inw(I2S_INT_STATUS);
		
		if(i2s_status&REGBIT(1, I2S_TX_DMA_FAULT))
		{
			pi2s_status->txdmafault++;
		}
		if(i2s_status&REGBIT(1, I2S_TX_OVRUN))
		{
			pi2s_status->txovrun++;
		}
		if(i2s_status&REGBIT(1, I2S_TX_UNRUN))
		{
			pi2s_status->txunrun++;
		}
		if(i2s_status&REGBIT(1, I2S_TX_THRES))
		{
			pi2s_status->txthres++;
		}
		if(i2s_status&REGBIT(1, I2S_RX_DMA_FAULT))
		{
			pi2s_status->rxdmafault++;
		}
		if(i2s_status&REGBIT(1, I2S_RX_OVRUN))
		{
			pi2s_status->rxovrun++;
		}
		if(i2s_status&REGBIT(1, I2S_RX_UNRUN))
		{
			pi2s_status->rxunrun++;
		}
		if(i2s_status&REGBIT(1, I2S_RX_THRES))
		{
			pi2s_status->rxthres++;
		}
	}

	if(pi2s_config->enLable == 1)
	{
		if((pi2s_config->tx_isr_cnt>0) && (pi2s_config->tx_isr_cnt%40==0))
		{
			MSG("tisr i=%u,ch=%u,o=%u,u=%d,s=%X [r=%d,w=%d]\n",
				pi2s_config->tx_isr_cnt,dma_ch,pi2s_status->txovrun,pi2s_status->txunrun,
				i2s_inw(I2S_INT_STATUS),pi2s_config->tx_r_idx,pi2s_config->tx_w_idx);
		}
	}
	
	if(pi2s_config->enLable == 2)
	{
		if((pi2s_config->rx_isr_cnt>0) && (pi2s_config->rx_isr_cnt%40==0))
		{
			MSG("risr i=%u,ch=%u,o=%u,u=%d,s=%X [r=%d,w=%d]\n",
				pi2s_config->rx_isr_cnt,dma_ch,pi2s_status->rxovrun,pi2s_status->rxunrun,
				i2s_inw(I2S_INT_STATUS),pi2s_config->rx_r_idx,pi2s_config->rx_w_idx);
		}
	}
	
	*(unsigned long*)(I2S_INT_STATUS) = 0xFFFFFFFF;
}
#endif
#endif

irqreturn_t i2s_irq_isr(int irq, void *irqaction)
{
	u32 i2s_status;
	
	//MSG("i2s_irq_isr [0x%08X]\n",i2s_inw(I2S_INT_STATUS));
	if((pi2s_config->tx_isr_cnt>0)||(pi2s_config->rx_isr_cnt>0))
	{
		i2s_status = i2s_inw(I2S_INT_STATUS);
		MSG("i2s_irq_isr [0x%08X]\n",i2s_status);
	}
	else
		return IRQ_HANDLED;
		
	if(i2s_status&REGBIT(1, I2S_TX_DMA_FAULT))
	{
#ifdef I2S_STATISTIC
		pi2s_status->txdmafault++;
#endif
	}
	if(i2s_status&REGBIT(1, I2S_TX_OVRUN))
	{
#ifdef I2S_STATISTIC
		pi2s_status->txovrun++;
#endif
	}
	if(i2s_status&REGBIT(1, I2S_TX_UNRUN))
	{
#ifdef I2S_STATISTIC
		pi2s_status->txunrun++;
#endif
	}
	if(i2s_status&REGBIT(1, I2S_TX_THRES))
	{
#ifdef I2S_STATISTIC
		pi2s_status->txthres++;
#endif
	}
	if(i2s_status&REGBIT(1, I2S_RX_DMA_FAULT))
	{
#ifdef I2S_STATISTIC
		pi2s_status->rxdmafault++;
#endif
	}
	if(i2s_status&REGBIT(1, I2S_RX_OVRUN))
	{
#ifdef I2S_STATISTIC
		pi2s_status->rxovrun++;
#endif
	}
	if(i2s_status&REGBIT(1, I2S_RX_UNRUN))
	{
#ifdef I2S_STATISTIC
		pi2s_status->rxunrun++;
#endif
	}
	if(i2s_status&REGBIT(1, I2S_RX_THRES))
	{
#ifdef I2S_STATISTIC
		pi2s_status->rxthres++;
#endif
	}
	i2s_outw(I2S_INT_STATUS, 0xFFFFFFFF);
	return IRQ_HANDLED;
}


void i2s_unmask_handler(u32 dma_ch)
{
	MSG("i2s_unmask_handler ch=%d\n",dma_ch);
	
	GdmaUnMaskChannel(dma_ch);

	return;
}

void i2s_mask_handler(u32 dma_ch)
{
        MSG("i2s_mask_handler ch=%d\n", dma_ch);
        GdmaMaskChannel(dma_ch);
        return;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
long i2s_ioctl (struct file *filp, unsigned int cmd, unsigned long arg)
#else
int i2s_ioctl (struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
	int i ;
	i2s_config_type* ptri2s_config;
	    
	ptri2s_config = filp->private_data;
	switch (cmd) {
	case I2S_SRATE:
		spin_lock(&ptri2s_config->lock);
		{
#if defined(CONFIG_RALINK_RT6855A)			
			u32 reg_addr = RALINK_SYSCTL_BASE+0x834; 
#else
			u32 reg_addr = RALINK_SYSCTL_BASE+0x34;
#endif			
			*(volatile unsigned long*)(reg_addr) |= (1<<17);
	   
			*(volatile unsigned long*)(reg_addr) &= ~(1<<17);

			printk("I2S_CFG=0x%8x\n", i2s_inw(I2S_I2SCFG));	
#if defined(CONFIG_I2S_WM8960) || defined(CONFIG_I2S_WM8750) || defined(CONFIG_I2S_WM8751)	
	    		audiohw_preinit();
#endif
		}	
		if((arg>MAX_SRATE_HZ)||(arg<MIN_SRATE_HZ))
		{
			MSG("audio sampling rate %u should be %d ~ %d Hz\n", (u32)arg, MIN_SRATE_HZ, MAX_SRATE_HZ);
			break;
		}	
		ptri2s_config->srate = arg;
		MSG("set audio sampling rate to %d Hz\n", ptri2s_config->srate);
		spin_unlock(&ptri2s_config->lock);
		break;
	case I2S_TX_VOL:
		spin_lock(&ptri2s_config->lock);
#if defined(CONFIG_I2S_WM8960)
		if((int)arg > 127)
		{
			ptri2s_config->txvol = 127;
		}
		else if((int)arg < 48)
		{
			ptri2s_config->txvol = 96;
		}	
		else
		{
			ptri2s_config->txvol = arg;
		}	
#elif defined(CONFIG_I2S_WM8750)
		if((int)arg > 127)
		{
			ptri2s_config->txvol = 127;
		}
		else if((int)arg < 96)
		{
			ptri2s_config->txvol = 96;
		}	
		else
		{
			ptri2s_config->txvol = arg;
		}	
#endif
		spin_unlock(&ptri2s_config->lock);
		break;
	case I2S_RX_VOL:
		spin_lock(&ptri2s_config->lock);
#if defined(CONFIG_I2S_WM8960)
		if((int)arg > 127)
		{
			ptri2s_config->rxvol = 127;
		}
		else if((int)arg < 48)
		{
			ptri2s_config->rxvol = 48;
		}	
		else
		{
			ptri2s_config->rxvol = arg;
		}
#else
		if((int)arg > 63)
		{
			ptri2s_config->rxvol = 63;
		}
		else if((int)arg < 0)
		{
			ptri2s_config->rxvol = 0;
		}	
		else
		{
			ptri2s_config->rxvol = arg;
		}
#endif
		spin_unlock(&ptri2s_config->lock);
		break;
#if defined (CONFIG_RALINK_MT7628)
	case I2S_WORD_LEN:
		spin_lock(&ptri2s_config->lock);
		if((int)arg == 16)
		{
			ptri2s_config->wordlen_24b = 0;
			printk("Enable 16 bit word length.\n");
		}
		else if ((int)arg == 24)
		{
			ptri2s_config->wordlen_24b = 1;
			printk("Enable 24 bit word length.\n");
		}
		else
		{
			printk("MT7628 only support 16bit/24bit word length.\n");
		}
		spin_unlock(&ptri2s_config->lock);
		break;
	case I2S_ENDIAN_FMT:
		spin_lock(&ptri2s_config->lock);
		if((int)arg == 1)
		{
			ptri2s_config->little_edn = 1;
			printk("Little endian format.\n");
		}
		else 
		{
			ptri2s_config->little_edn = 0;
			printk("Big endian format.\n");
		}
		spin_unlock(&ptri2s_config->lock);
		break;	
#endif
	case I2S_INTERNAL_LBK:
		spin_lock(&ptri2s_config->lock);
		if((int)arg == 1)
		{
			ptri2s_config->lbk = 1;
			printk("Enable internal loopback.\n");
		}
		else 
		{
			ptri2s_config->lbk = 0;
			printk("Disable internal loopback.\n");
		}
		spin_unlock(&ptri2s_config->lock);
		break;
	case I2S_TX_ENABLE:
		spin_lock(&ptri2s_config->lock);
		MSG("I2S_TXENABLE\n");

		/* allocate tx buffer */
		ptri2s_config->pPage0TxBuf8ptr = (u8*)pci_alloc_consistent(NULL, I2S_PAGE_SIZE*2 , &i2s_txdma_addr);
		if(ptri2s_config->pPage0TxBuf8ptr==NULL)
		{
			MSG("Allocate Tx Page Buffer Failed\n");
			return -1;
		}
		ptri2s_config->pPage1TxBuf8ptr = ptri2s_config->pPage0TxBuf8ptr + I2S_PAGE_SIZE;
		memset(pi2s_config->pPage0TxBuf8ptr, 0, I2S_PAGE_SIZE);
		memset(pi2s_config->pPage1TxBuf8ptr, 0, I2S_PAGE_SIZE);
		for( i = 0 ; i < MAX_I2S_PAGE ; i ++ )
		{
#if defined(CONFIG_I2S_MMAP)
			ptri2s_config->pMMAPTxBufPtr[i] = ptri2s_config->pMMAPBufPtr[i];
#else
			if(ptri2s_config->pMMAPTxBufPtr[i]==NULL)
				ptri2s_config->pMMAPTxBufPtr[i] = kmalloc(I2S_PAGE_SIZE, GFP_KERNEL);
#endif
		}
		GdmaI2sTx((u32)ptri2s_config->pPage0TxBuf8ptr, I2S_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
		GdmaI2sTx((u32)ptri2s_config->pPage1TxBuf8ptr, I2S_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);

		i2s_reset_tx_config(ptri2s_config);
		ptri2s_config->bTxDMAEnable = 1;
		i2s_tx_config(ptri2s_config);
		
		if(ptri2s_config->bRxDMAEnable==0)
			i2s_clock_enable(ptri2s_config);
#if defined(CONFIG_I2S_WM8960)||defined(CONFIG_I2S_WM8750)||defined(CONFIG_I2S_WM8751)
		audiohw_set_lineout_vol(1, ptri2s_config->txvol, ptri2s_config->txvol);
#endif
		i2s_tx_enable(ptri2s_config);
		
		GdmaUnMaskChannel(GDMA_I2S_TX0);
		
		MSG("I2S_TXENABLE done\n");
		spin_unlock(&ptri2s_config->lock);
		break;
	case I2S_TX_DISABLE:
		spin_lock(&ptri2s_config->lock);
		MSG("I2S_TXDISABLE\n");
	
		i2s_reset_tx_config(ptri2s_config);
		spin_unlock(&ptri2s_config->lock);
		
		if (ptri2s_config->nTxDMAStopped<4)
			interruptible_sleep_on(&(ptri2s_config->i2s_tx_qh));

		spin_lock(&ptri2s_config->lock);
		i2s_tx_disable(ptri2s_config);
		if((ptri2s_config->bRxDMAEnable==0)&&(ptri2s_config->bTxDMAEnable==0))
			i2s_clock_disable(ptri2s_config);
		
		for( i = 0 ; i < MAX_I2S_PAGE ; i ++ )
		{
			if(ptri2s_config->pMMAPTxBufPtr[i] != NULL)
			{
#if defined(CONFIG_I2S_MMAP)
				ptri2s_config->pMMAPTxBufPtr[i] = NULL;			
#endif
				kfree(ptri2s_config->pMMAPTxBufPtr[i]);		
				ptri2s_config->pMMAPTxBufPtr[i] = NULL;
			}
		}
		if(ptri2s_config->mmap_index <= MAX_I2S_PAGE)
			ptri2s_config->mmap_index = 0;
		pci_free_consistent(NULL, I2S_PAGE_SIZE*2, ptri2s_config->pPage0TxBuf8ptr, i2s_txdma_addr);
		ptri2s_config->pPage0TxBuf8ptr = NULL;
		spin_unlock(&ptri2s_config->lock);
		break;
	case I2S_RX_ENABLE:
		spin_lock(&ptri2s_config->lock);
		MSG("I2S_RXENABLE\n");
		
		/* allocate rx buffer */
		ptri2s_config->pPage0RxBuf8ptr = (u8*)pci_alloc_consistent(NULL, I2S_PAGE_SIZE*2 , &i2s_rxdma_addr);
		if(ptri2s_config->pPage0RxBuf8ptr==NULL)
		{
			MSG("Allocate Rx Page Buffer Failed\n");
			return -1;
		}
		ptri2s_config->pPage1RxBuf8ptr = ptri2s_config->pPage0RxBuf8ptr + I2S_PAGE_SIZE;
		
		for( i = 0 ; i < MAX_I2S_PAGE ; i ++ )
		{
#if defined(CONFIG_I2S_MMAP)
			ptri2s_config->pMMAPRxBufPtr[i] = ptri2s_config->pMMAPBufPtr[i+(ptri2s_config->mmap_index-MAX_I2S_PAGE)];
#else
			if(ptri2s_config->pMMAPRxBufPtr[i]==NULL)
				ptri2s_config->pMMAPRxBufPtr[i] = kmalloc(I2S_PAGE_SIZE, GFP_KERNEL);
#endif
		}
#if defined(CONFIG_MMAP)
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)ptri2s_config->pMMAPBufPtr[0+(ptri2s_config->mmap_index-MAX_I2S_PAGE]\
				, 0, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)ptri2s_config->pMMAPBufPtr[1+(ptri2s_config->mmap_index-MAX_I2S_PAGE]\
				, 1, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#else		
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)ptri2s_config->pPage0RxBuf8ptr, 0, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)ptri2s_config->pPage1RxBuf8ptr, 1, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#endif

		i2s_reset_rx_config(ptri2s_config);
		ptri2s_config->bRxDMAEnable = 1;
		i2s_rx_config(ptri2s_config);
		
		GdmaUnMaskChannel(GDMA_I2S_RX0);
		
		if(ptri2s_config->bTxDMAEnable==0)
			i2s_clock_enable(ptri2s_config);
#if defined(CONFIG_I2S_TXRX)
#if defined(CONFIG_I2S_WM8960)||defined(CONFIG_I2S_WM8750)||defined(CONFIG_I2S_WM8751)
		audiohw_set_linein_vol(ptri2s_config->rxvol,  ptri2s_config->rxvol);
#endif
#endif
		i2s_rx_enable(ptri2s_config);

		spin_unlock(&ptri2s_config->lock);

		break;
	case I2S_RX_DISABLE:
		spin_lock(&ptri2s_config->lock);
		MSG("I2S_RXDISABLE\n");
		i2s_reset_rx_config(ptri2s_config);
		spin_unlock(&ptri2s_config->lock);
		while(ptri2s_config->nRxDMAStopped<2)
			interruptible_sleep_on(&(ptri2s_config->i2s_rx_qh));
		spin_lock(&ptri2s_config->lock);
		i2s_rx_disable(ptri2s_config);
		if((ptri2s_config->bRxDMAEnable==0)&&(ptri2s_config->bTxDMAEnable==0))
			i2s_clock_disable(ptri2s_config);
		
		for( i = 0 ; i < MAX_I2S_PAGE ; i ++ )
		{
			if(ptri2s_config->pMMAPRxBufPtr[i] != NULL) {
#if defined(CONFIG_I2S_MMAP)
				ptri2s_config->pMMAPRxBufPtr[i] = NULL;
#endif
				kfree(ptri2s_config->pMMAPRxBufPtr[i]);		
				ptri2s_config->pMMAPRxBufPtr[i] = NULL;
			}
		}
		ptri2s_config->mmap_index = 0;	
		pci_free_consistent(NULL, I2S_PAGE_SIZE*2, ptri2s_config->pPage0RxBuf8ptr, i2s_rxdma_addr);
		ptri2s_config->pPage0RxBuf8ptr = NULL;
		spin_unlock(&ptri2s_config->lock);
		break;
	case I2S_PUT_AUDIO:
		//MSG("I2S_PUT_AUDIO\n");	
		do{
			spin_lock(&ptri2s_config->lock);
			
			if(((ptri2s_config->tx_w_idx+4)%MAX_I2S_PAGE)!=ptri2s_config->tx_r_idx)
			{
				ptri2s_config->tx_w_idx = (ptri2s_config->tx_w_idx+1)%MAX_I2S_PAGE;	
				//printk("put TB[%d] for user write\n",ptri2s_config->tx_w_idx);
#if defined(CONFIG_I2S_MMAP)
				put_user(ptri2s_config->tx_w_idx, (int*)arg);
#else
				copy_from_user(ptri2s_config->pMMAPTxBufPtr[ptri2s_config->tx_w_idx], (char*)arg, I2S_PAGE_SIZE);
#endif
				pi2s_status->txbuffer_len++;
				spin_unlock(&ptri2s_config->lock);
				break;
			}
			else
			{
				/* Buffer Full */
				//printk("TBF tr=%d, tw=%d\n", ptri2s_config->tx_r_idx, ptri2s_config->tx_w_idx);
				pi2s_status->txbuffer_ovrun++;
				spin_unlock(&ptri2s_config->lock);
				interruptible_sleep_on(&(ptri2s_config->i2s_tx_qh));
				
			}
		}while(1);
		break;
	case I2S_GET_AUDIO:
		do{
			spin_lock(&ptri2s_config->lock);
			//printk("GA rr=%d, rw=%d,i=%d\n", ptri2s_config->rx_r_idx, ptri2s_config->rx_w_idx,ptri2s_config->rx_isr_cnt);
			if(ptri2s_config->rx_r_idx!=ptri2s_config->rx_w_idx)
			{			
#if defined(CONFIG_I2S_MMAP)
				put_user(ptri2s_config->rx_r_idx, (int*)arg);
#else
				copy_to_user((char*)arg, ptri2s_config->pMMAPRxBufPtr[ptri2s_config->rx_r_idx], I2S_PAGE_SIZE);
#endif
				ptri2s_config->rx_r_idx = (ptri2s_config->rx_r_idx+1)%MAX_I2S_PAGE;
				pi2s_status->rxbuffer_len--;
				spin_unlock(&ptri2s_config->lock);
				break;
			}
			else
			{
				/* Buffer Full */
				//printk("RBF rr=%d, rw=%d\n", ptri2s_config->rx_r_idx, ptri2s_config->rx_w_idx);
				pi2s_status->rxbuffer_ovrun++;
				spin_unlock(&ptri2s_config->lock);
				interruptible_sleep_on(&(ptri2s_config->i2s_rx_qh));
			}
		}while(1);
		break;
	case I2S_TX_STOP:
                spin_lock(&ptri2s_config->lock);
                i2s_mask_handler(GDMA_I2S_TX0);
                i2s_mask_handler(GDMA_I2S_TX1);
                spin_unlock(&ptri2s_config->lock);
                break;	
	case I2S_DEBUG_CODEC:
		for (i=0; i<10; i++)
		{
			printk("###### i=%d ######\n", i);
			i2s_clock_enable(ptri2s_config);
			i2s_clock_disable(ptri2s_config);
		}
	
	      	break;
#if defined(CONFIG_I2S_MS_CTRL)
	case I2S_MS_MODE_CTRL:
		spin_lock(&ptri2s_config->lock);
		if((int)arg == 1)
		{
			ptri2s_config->slave_en = 1;
			printk("I2S in slave mode.\n");
		}
		else 
		{
			ptri2s_config->slave_en = 0;
			printk("I2S in master mode.\n");
		}

		spin_unlock(&ptri2s_config->lock);
		break;
#endif
	case I2S_DEBUG_CLKGEN:
	case I2S_DEBUG_INLBK:
	case I2S_DEBUG_EXLBK:
	case I2S_DEBUG_CODECBYPASS:	
	case I2S_DEBUG_FMT:
	case I2S_DEBUG_RESET:
		i2s_debug_cmd(cmd, arg);
		break;							
	default :
		MSG("i2s_ioctl: command format error\n");
	}

	return 0;
}

EXPORT_SYMBOL(i2s_rx_disable);
EXPORT_SYMBOL(i2s_tx_disable);
EXPORT_SYMBOL(i2s_rx_enable);
EXPORT_SYMBOL(i2s_tx_enable);
EXPORT_SYMBOL(i2s_rx_config);
EXPORT_SYMBOL(i2s_tx_config);
EXPORT_SYMBOL(i2s_clock_disable);
EXPORT_SYMBOL(i2s_clock_enable);
EXPORT_SYMBOL(i2s_reset_rx_config);
EXPORT_SYMBOL(i2s_reset_tx_config);
EXPORT_SYMBOL(i2s_dma_rx_handler);
EXPORT_SYMBOL(i2s_dma_tx_handler);
EXPORT_SYMBOL(i2s_unmask_handler);
EXPORT_SYMBOL(i2s_open);
EXPORT_SYMBOL(pi2s_config);

module_init(i2s_mod_init);
module_exit(i2s_mod_exit);

MODULE_DESCRIPTION("Ralink SoC I2S Controller Module");
MODULE_AUTHOR("Qwert Chin <qwert.chin@ralinktech.com.tw>");
MODULE_SUPPORTED_DEVICE("I2S");
MODULE_VERSION(I2S_MOD_VERSION);
MODULE_LICENSE("GPL");
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,12)
MODULE_PARM (i2sdrv_major, "i");
#else
module_param (i2sdrv_major, int, 0);
#endif
