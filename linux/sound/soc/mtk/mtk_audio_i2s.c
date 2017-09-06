/*
 * mtk_audio_drv.c
 *
 *  Created on: 2013/8/20
 *      Author: MTK04880
 */
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
#include <linux/dma-mapping.h>
#include <sound/core.h>
#include <linux/pci.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/initval.h>
#include "drivers/char/ralink_gdma.h"
#include "mtk_audio_driver.h"

/****************************/
/*GLOBAL VARIABLE DEFINITION*/
/****************************/
#if 0
i2s_config_type* pAudio_config;
i2s_status_type* pi2s_status;

unsigned long i2sMaster_inclk_15p625Mhz[11] = {60<<8, 	43<<8, 		40<<8, 	 30<<8, 	21<<8, 		19<<8, 	 14<<8,    10<<8, 	9<<8, 	 7<<8, 	  4<<8};
unsigned long i2sMaster_exclk_12p288Mhz[11] = {47<<8, 	34<<8, 		31<<8,   23<<8, 	16<<8, 		15<<8, 	 11<<8,    8<<8, 	7<<8, 	 5<<8, 	  3<<8};
unsigned long i2sMaster_exclk_12Mhz[11]     = {46<<8, 	33<<8, 		30<<8,   22<<8, 	16<<8, 		15<<8, 	 11<<8,    8<<8,  	7<<8, 	 5<<8, 	  3<<8};

#if defined(CONFIG_RALINK_RT6855A)
unsigned long i2sMaster_inclk_int[11] = {97, 70, 65, 48, 35, 32, 24, 17, 16, 12, 8};
unsigned long i2sMaster_inclk_comp[11] = {336, 441, 53, 424, 220, 282, 212, 366, 141, 185, 70};
#elif defined (CONFIG_RALINK_MT7621)
#ifdef MT7621_ASIC_BOARD
				        /*  8K  11.025k 12k  16k  22.05k  24k  32k  44.1K  48k  88.2k  96k */
unsigned long i2sMaster_inclk_int[11] = {  576,   384,   0,  288,  192,   192, 144,   96,   96,   48,  48};
unsigned long i2sMaster_inclk_comp[11] = {  0,     0,    0,   0,   0,      0,   0,    0,    0,     0,   0};

#else
					/* 8K  11.025k 12k  16k  22.05k  24k   32k  44.1K  48k  88.2k  96k */
unsigned long i2sMaster_inclk_int[11] = { 529,   384,   0,  264,  192,   176,  132,   96,   88,   48,   44};
unsigned long i2sMaster_inclk_comp[11] = {102,    0,    0,  307,   0,    204,  153,    0,  102,    0,   51};
#endif
#else
unsigned long i2sMaster_inclk_int[11] = {78, 56, 52, 39, 28, 26, 19, 14, 13, 9, 6};
unsigned long i2sMaster_inclk_comp[11] = {64, 352, 42, 32, 176, 21, 272, 88, 10, 455, 261};
//unsigned long i2sMaster_inclk_int[11] = {78, 56, 52, 39, 28, 26, 19, 14, 13, 7, 6};
//unsigned long i2sMaster_inclk_comp[11] = {64, 352, 42, 32, 176, 21, 272, 88, 10, 44, 261};
#endif
#else
extern i2s_config_type* pi2s_config;
#endif

/****************************/
/*FUNCTION DECLRATION		*/
/****************************/
#if 0
static int mtk_audio_drv_pbVol_get(struct snd_kcontrol *kcontrol,\
	struct snd_ctl_elem_value *ucontrol);
static int mtk_audio_drv_pbVol_set(struct snd_kcontrol *kcontrol,\
	struct snd_ctl_elem_value *ucontrol);
static int mtk_audio_drv_recVol_get(struct snd_kcontrol *kcontrol,\
	struct snd_ctl_elem_value *ucontrol);
static int mtk_audio_drv_recVol_set(struct snd_kcontrol *kcontrol,\
	struct snd_ctl_elem_value *ucontrol);
#endif
static int mtk_audio_drv_set_fmt(struct snd_soc_dai *cpu_dai,\
		unsigned int fmt);

static int  mtk_audio_drv_shutdown(struct snd_pcm_substream *substream,
		       struct snd_soc_dai *dai);
static int  mtk_audio_drv_startup(struct snd_pcm_substream *substream,
		       struct snd_soc_dai *dai);
static int mtk_audio_hw_params(struct snd_pcm_substream *substream,\
				struct snd_pcm_hw_params *params,\
				struct snd_soc_dai *dai);
static int mtk_audio_drv_play_prepare(struct snd_pcm_substream *substream,struct snd_soc_dai *dai);
static int mtk_audio_drv_rec_prepare(struct snd_pcm_substream *substream,struct snd_soc_dai *dai);
static int mtk_audio_drv_hw_free(struct snd_pcm_substream *substream,struct snd_soc_dai *dai);
static int mtk_audio_drv_prepare(struct snd_pcm_substream *substream, struct snd_soc_dai *dai);


/****************************/
/*STRUCTURE DEFINITION		*/
/****************************/


static struct snd_soc_dai_ops mtk_audio_drv_dai_ops = {
	.startup = mtk_audio_drv_startup,
	.hw_params	= mtk_audio_hw_params,
	.hw_free = mtk_audio_drv_hw_free,
	//.shutdown = mtk_audio_drv_shutdown,
	.prepare = mtk_audio_drv_prepare,
	.set_fmt = mtk_audio_drv_set_fmt,
	//.set_sysclk = mtk_audio_drv_set_sysclk,
};

struct snd_soc_dai mtk_audio_drv_dai = {
	.name = "mtk-i2s",
	.playback = {
		.channels_min = 1,
		.channels_max = 2,
		.rates = (SNDRV_PCM_RATE_8000|SNDRV_PCM_RATE_11025|SNDRV_PCM_RATE_12000|\
		SNDRV_PCM_RATE_16000|SNDRV_PCM_RATE_22050|SNDRV_PCM_RATE_24000|SNDRV_PCM_RATE_32000|\
		SNDRV_PCM_RATE_44100|SNDRV_PCM_RATE_48000),

		.formats = (SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S20_3LE |\
				SNDRV_PCM_FMTBIT_S24_LE),
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 2,
		.rates = (SNDRV_PCM_RATE_8000|SNDRV_PCM_RATE_11025|SNDRV_PCM_RATE_12000|\
				SNDRV_PCM_RATE_16000|SNDRV_PCM_RATE_22050|SNDRV_PCM_RATE_24000|SNDRV_PCM_RATE_32000|\
				SNDRV_PCM_RATE_44100|SNDRV_PCM_RATE_48000),
		.formats = (SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S20_3LE |\
				SNDRV_PCM_FMTBIT_S24_LE),
	},
	.symmetric_rates = 1,
	.ops = &mtk_audio_drv_dai_ops,
};

/****************************/
/*FUNCTION BODY				*/
/****************************/
#if 0
int i2s_reset_tx_config(i2s_config_type* pAudio_config)
{
	pAudio_config->bTxDMAEnable = 0;
	pAudio_config->nTxDMAStopped = 0;
	pAudio_config->tx_isr_cnt = 0;
	pAudio_config->tx_w_idx = 0;
	pAudio_config->tx_r_idx = 0;
	pi2s_status->txbuffer_unrun = 0;
	pi2s_status->txbuffer_ovrun = 0;
	pi2s_status->txdmafault = 0;
	pi2s_status->txovrun = 0;
	pi2s_status->txunrun = 0;
	pi2s_status->txthres = 0;
	pi2s_status->txbuffer_len = 0;

	return 0;
}

int i2s_reset_rx_config(i2s_config_type* pAudio_config)
{
	pAudio_config->bRxDMAEnable = 0;
	pAudio_config->nRxDMAStopped = 0;
	pAudio_config->rx_isr_cnt = 0;
	pAudio_config->rx_w_idx = 0;
	pAudio_config->rx_r_idx = 0;
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
int i2s_xtal_enable(unsigned long index)
{
        unsigned long data;

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
#if defined(REF_CLK_40MHZ) || defined(REF_CLK_20MHZ)
        data |= REGBIT(0x1d, 8);
#else
        data |= REGBIT(0x17, 8);
#endif
#if defined(REF_CLK_40MHZ)
        data |= REGBIT(0x1, 6);
#endif
        i2s_outw(RALINK_ANA_CTRL_BASE+0x0014, data);

        data = i2s_inw(RALINK_ANA_CTRL_BASE+0x0018);
        data &= ~(0xf0773f00);
        data |= REGBIT(0x3, 28);
        data |= REGBIT(0x2, 20);
#if defined(REF_CLK_40MHZ) || defined(REF_CLK_20MHZ)
        data |= REGBIT(0x3, 16);
#else
        data |= REGBIT(0x2, 16);
#endif
        data |= REGBIT(0x3, 12);
#if defined(REF_CLK_40MHZ) || defined(REF_CLK_20MHZ)
        data |= REGBIT(0xd, 8);
#else
        data |= REGBIT(0x7, 8);
#endif
        i2s_outw(RALINK_ANA_CTRL_BASE+0x0018, data);

        if((index==1)|(index==4)|(index==7)|(index==9))// 270 MHz for 22.05K, 44.1K, 88.2K, 176.4K
        {
#if defined(REF_CLK_40MHZ) || defined(REF_CLK_20MHZ)
                i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x1a18548a);
#else
                i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x14ad106e);
#endif
        }
        else if ((index==0)|(index==3)|(index==5)|(index==6)|(index==8)|(index==10))// 294 MHZ for 24K, 48K, 96K, 192K
        {
#if defined(REF_CLK_40MHZ) || defined(REF_CLK_20MHZ)
                i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x1c7dbf48);
#else
                i2s_outw(RALINK_ANA_CTRL_BASE+0x0020, 0x1697cc39);
#endif
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
int i2s_clock_enable(i2s_config_type* pAudio_config)
{
	unsigned long data;
	unsigned long index;
	unsigned long* pTable;
	/* audio sampling rate decision */
	switch(pAudio_config->srate)
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
		default:
			index = 7;
	}
#ifdef MT7621_ASIC_BOARD
        /* Enable Xtal  */
        i2s_xtal_enable(index);
#endif

		/* enable internal MCLK */
#if defined(CONFIG_I2S_IN_MCLK)
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
#else
	#error "This SoC do not provide MCLK to audio codec\n");
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
#else
	#error "This SoC do not provide MCLK 12.288Mhz audio codec\n");
#endif
#endif /* MCLK_12P288MHZ */
#if defined(CONFIG_RALINK_RT6855A)
	i2s_outw(RALINK_SYSCTL_BASE+0x860, data);
#else
	i2s_outw(RALINK_SYSCTL_BASE+0x2c, data);
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
#elif defined (CONFIG_RALINK_MT7620) || (CONFIG_RALINK_MT7621)
	//FIXME:turn off REFCLK output
#endif
#if defined(CONFIG_RALINK_RT6855A)
	i2s_outw(RALINK_SYSCTL_BASE+0x860, data);
#else
	i2s_outw(RALINK_SYSCTL_BASE+0x2c, data);
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
//	data &= ~(0x03<<7);
//        data |= (1<<7);
        i2s_outw(RALINK_SYSCTL_BASE+0x60, data);
        //i2s_outw(RALINK_SYSCTL_BASE+0x60,0x003A1118);


        data = i2s_inw(RALINK_SYSCTL_BASE+0x2c);
        data &= ~(0x07<<9);
        data |= (1<<9);
        i2s_outw(RALINK_SYSCTL_BASE+0x2c, data);
#endif


	if(pAudio_config->slave_en==0)
	{
		/* Setup I2S_WS and I2S_CLK */

		#if defined(CONFIG_I2S_IN_CLK)
			/* REFCLK is 15.625Mhz or 40Mhz(fractional division) */
			#if defined(CONFIG_I2S_FRAC_DIV)
				MSG("Internal REFCLK with fractional division\n");
				pTable = i2sMaster_inclk_int;
				data = (unsigned long)(pTable[index]);
				i2s_outw(I2S_DIVINT_CFG, data);
				pTable = i2sMaster_inclk_comp;
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
			defined(CONFIG_RALINK_MT7621)
			data = i2s_inw(I2S_I2SCFG);
			data &= ~REGBIT(0x1, I2S_SLAVE_MODE);
			i2s_outw(I2S_I2SCFG, data);
		#else
		#error "a strange clock mode"
		#endif
		i2s_codec_enable(pAudio_config);
#if 0
#if defined(CONFIG_I2S_MCLK_12MHZ)
        pTable = i2sSlave_exclk_12Mhz;
        data = pTable[index];
#if defined(CONFIG_SND_SOC_WM8960)
	audiohw_set_frequency(data, pAudio_config->codec_pll_en);
#else
        audiohw_set_frequency(data|0x01);
#endif
#else
        pTable = i2sSlave_exclk_12p288Mhz;
        data = pTable[index];
        audiohw_set_frequency(data);
#endif
#endif

	}
	else
	{
		#if defined(CONFIG_RALINK_RT3052)
			data = i2s_inw(I2S_I2SCFG);
			data |= REGBIT(0x1, I2S_SLAVE_EN);
			data |= REGBIT(0x1, I2S_CLK_OUT_DIS);
			i2s_outw(I2S_I2SCFG, data);
		#elif defined(CONFIG_RALINK_RT3883)||defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350)||\
			defined(CONFIG_RALINK_RT6855)||defined(CONFIG_RALINK_MT7620)||defined(CONFIG_RALINK_RT6855A)||\
			defined(CONFIG_RALINK_MT7621)
			data = i2s_inw(I2S_I2SCFG);
			data |= REGBIT(0x1, I2S_SLAVE_MODE);
			i2s_outw(I2S_I2SCFG, data);
		#else
		#error "a strange clock mode "
		#endif

		i2s_codec_enable(pAudio_config);

#if 0
		#if defined(CONFIG_I2S_MCLK_12MHZ)
			pTable = i2sSlave_exclk_12Mhz;
			data = pTable[index];
			audiohw_set_frequency(data, 1);
		#else
			pTable = i2sSlave_exclk_12p288Mhz;
			data = pTable[index];
			audiohw_set_frequency(data);
		#endif
#endif
	}
	//audiohw_set_lineout_vol(1, 120, 120);
	return 0;

}

int i2s_clock_disable(i2s_config_type* pAudio_config)
{
#if defined(CONFIG_I2S_IN_MCLK)
	unsigned long data;
#endif
	i2s_codec_disable(pAudio_config);

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
#endif
	i2s_outw(RALINK_SYSCTL_BASE+0x2c, data);
#endif
	return 0;
}


int i2s_codec_enable(i2s_config_type* pAudio_config)
{
#if 0
	int AIn = 0, AOut = 0;
	/* Codec initialization */
	audiohw_preinit();

#if defined(CONFIG_I2S_TXRX)

	if(pAudio_config->bTxDMAEnable)
		AOut = 1;
	if(pAudio_config->bRxDMAEnable)
		AIn = 1;
	audiohw_postinit(!(pAudio_config->slave_en), AIn, AOut);

#else
#if defined(CONFIG_I2S_WM8750)
	audiohw_postinit(!(pAudio_config->slave_en), 0, 1);
#else
	if(pAudio_config->slave_en==0)
		audiohw_postinit(1,1);
	else
		audiohw_postinit(0,1);
#endif
#endif
#endif
	return 0;
}


int i2s_codec_disable(i2s_config_type* pAudio_config)
{
#if 0
	audiohw_close();
#endif
	return 0;
}

int i2s_tx_config(i2s_config_type* pAudio_config)
{
	unsigned long data;
	/* set I2S_I2SCFG */
	data = i2s_inw(I2S_I2SCFG);
	data &= 0xFFFFFF81;
	data |= REGBIT(pAudio_config->tx_ff_thres, I2S_TX_FF_THRES);
	data |= REGBIT(pAudio_config->tx_ch_swap, I2S_TX_CH_SWAP);
#if defined(CONFIG_RALINK_RT6855A)
	data |= REGBIT(1, I2S_BYTE_SWAP);
#endif
	data &= ~REGBIT(1, I2S_TX_CH0_OFF);
	data &= ~REGBIT(1, I2S_TX_CH1_OFF);
	i2s_outw(I2S_I2SCFG, data);

#if defined(CONFIG_I2S_EXTENDCFG)
	/* set I2S_I2SCFG1 */
	data = i2s_inw(I2S_I2SCFG1);
	data |= REGBIT(pAudio_config->lbk, I2S_LBK_EN);
	data |= REGBIT(pAudio_config->extlbk, I2S_EXT_LBK_EN);
	data &= 0xFFFFFFFC;
	data |= REGBIT(pAudio_config->fmt, I2S_DATA_FMT);
	i2s_outw(I2S_I2SCFG1, data);
#endif

	return 0;
}

int i2s_rx_config(i2s_config_type* pAudio_config)
{
	unsigned long data;
	/* set I2S_I2SCFG */
	data = i2s_inw(I2S_I2SCFG);
	data &= 0xFFFF81FF;
	data |= REGBIT(pAudio_config->rx_ff_thres, I2S_RX_FF_THRES);
	data |= REGBIT(pAudio_config->rx_ch_swap, I2S_RX_CH_SWAP);
	data &= ~REGBIT(1, I2S_RX_CH0_OFF);
	data &= ~REGBIT(1, I2S_RX_CH1_OFF);
	i2s_outw(I2S_I2SCFG, data);

#if defined(CONFIG_I2S_EXTENDCFG)
	/* set I2S_I2SCFG1 */
	data = i2s_inw(I2S_I2SCFG1);
	data |= REGBIT(pAudio_config->lbk, I2S_LBK_EN);
	data |= REGBIT(pAudio_config->extlbk, I2S_EXT_LBK_EN);
	data &= 0xFFFFFFFC;
	data |= REGBIT(pAudio_config->fmt, I2S_DATA_FMT);
	i2s_outw(I2S_I2SCFG1, data);
#endif
	return 0;
}

/* Turn On Tx DMA and INT */
int i2s_tx_enable(i2s_config_type* pAudio_config)
{
	unsigned long data;

	data = i2s_inw(I2S_INT_EN);
#if defined(I2S_FIFO_MODE)
	data = 0;
#else
	//data |= REGBIT(0x1, I2S_TX_INT3_EN);
	//data |= REGBIT(0x1, I2S_TX_INT2_EN);
	//data |= REGBIT(0x1, I2S_TX_INT1_EN);
	//data |= REGBIT(0x1, I2S_TX_INT0_EN);
#endif
	i2s_outw(I2S_INT_EN, data);

	data = i2s_inw(I2S_I2SCFG);
#if defined(CONFIG_I2S_TXRX)
	data |= REGBIT(0x1, I2S_TX_EN);
#else
	data |= REGBIT(0x1, I2S_EN);
#endif
#if defined(I2S_FIFO_MODE)
	data &= ~REGBIT(0x1, I2S_DMA_EN);
#else
	pAudio_config->bTxDMAEnable = 1;
	data |= REGBIT(0x1, I2S_DMA_EN);
#endif
	i2s_outw(I2S_I2SCFG, data);

	data = i2s_inw(I2S_I2SCFG);
	data |= REGBIT(0x1, I2S_EN);
#if defined(I2S_TX_BYTE_SWAP)
	data |= REGBIT(0x1, I2S_BYTE_SWAP);
#else
	data &= ~REGBIT(0x1, I2S_BYTE_SWAP);
#endif
	i2s_outw(I2S_I2SCFG, data);

	MSG("i2s_tx_enable done\n");
	return I2S_OK;
}

/* Turn On Rx DMA and INT */
int i2s_rx_enable(i2s_config_type* pAudio_config)
{
	unsigned long data;

	data = i2s_inw(I2S_INT_EN);
#if defined(I2S_FIFO_MODE)
	data = 0;
#else
	//data |= REGBIT(0x1, I2S_RX_INT3_EN);
	//data |= REGBIT(0x1, I2S_RX_INT2_EN);
	//data |= REGBIT(0x1, I2S_RX_INT1_EN);
	//data |= REGBIT(0x1, I2S_RX_INT0_EN);
#endif
	i2s_outw(I2S_INT_EN, data);

	data = i2s_inw(I2S_I2SCFG);
#if defined(CONFIG_I2S_TXRX)
	data |= REGBIT(0x1, I2S_RX_EN);
#else
	data |= REGBIT(0x1, I2S_EN);
#endif
#if defined(I2S_FIFO_MODE)
	data &= ~REGBIT(0x1, I2S_DMA_EN);
#else
	pAudio_config->bRxDMAEnable = 1;
	data |= REGBIT(0x1, I2S_DMA_EN);
#endif
	i2s_outw(I2S_I2SCFG, data);

	data = i2s_inw(I2S_I2SCFG);
	data |= REGBIT(0x1, I2S_EN);
#if defined(I2S_RX_BYTE_SWAP)
	data |= REGBIT(0x1, I2S_BYTE_SWAP);
#else
	data &= ~REGBIT(0x1, I2S_BYTE_SWAP);
#endif
	i2s_outw(I2S_I2SCFG, data);

	MSG("i2s_rx_enable done\n");
	return I2S_OK;
}
/* Turn Off Tx DMA and INT */
int i2s_tx_disable(i2s_config_type* pAudio_config)
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
	if(pAudio_config->bRxDMAEnable==0)
	{
		pAudio_config->bTxDMAEnable = 0;
		data &= ~REGBIT(0x1, I2S_DMA_EN);
                data &= ~REGBIT(0x1, I2S_EN);
	}
	i2s_outw(I2S_I2SCFG, data);

	return I2S_OK;
}
/* Turn Off Rx DMA and INT */
int i2s_rx_disable(i2s_config_type* pAudio_config)
{
	unsigned long data;

	data = i2s_inw(I2S_INT_EN);
	data &= ~REGBIT(0x1, I2S_RX_INT3_EN);
	data &= ~REGBIT(0x1, I2S_RX_INT2_EN);
	data &= ~REGBIT(0x1, I2S_RX_INT1_EN);
	//data &= ~REGBIT(0x1, I2S_RX_INT0_EN);
	i2s_outw(I2S_INT_EN, data);

	data = i2s_inw(I2S_I2SCFG);
#if defined(CONFIG_I2S_TXRX)
	data &= ~REGBIT(0x1, I2S_RX_EN);
#else
	data &= ~REGBIT(0x1, I2S_EN);
#endif
	if(pAudio_config->bTxDMAEnable==0)
	{
		pAudio_config->bRxDMAEnable = 0;
		data &= ~REGBIT(0x1, I2S_DMA_EN);
                data &= ~REGBIT(0x1, I2S_EN);
	}
	i2s_outw(I2S_I2SCFG, data);

	return I2S_OK;
}
void i2s_unmask_handler(u32 dma_ch)
{
	MSG("i2s_unmask_handler ch=%d\n",dma_ch);

	GdmaUnMaskChannel(dma_ch);

//	pi2s_config->dma_unmask_status = i2s_inw(RALINK_GDMA_UNMASKINT);
//	pi2s_config->dma_done_status = i2s_inw(RALINK_GDMA_DONEINT);

	return;
}
void i2s_dma_tx_handler(u32 dma_ch)
{
	if(pAudio_config->bTxDMAEnable==0)
	{
		MSG("TxDMA not enable dc=%d, i=%d\n", dma_ch, pAudio_config->tx_isr_cnt);
		pAudio_config->nTxDMAStopped ++;
		if(dma_ch==GDMA_I2S_TX0)
		{
			GdmaI2sTx((u32)pAudio_config->pPage0TxBuf8ptr, I2S_TX_FIFO_WREG, 0, 4, i2s_dma_tx_handler, i2s_unmask_handler);
		}
		else
		{
			GdmaI2sTx((u32)pAudio_config->pPage1TxBuf8ptr, I2S_TX_FIFO_WREG, 1, 4, i2s_dma_tx_handler, i2s_unmask_handler);
		}
		if (pAudio_config->nTxDMAStopped==3)
			wake_up_interruptible(&(pAudio_config->i2s_tx_qh));

		return;
	}

	pAudio_config->tx_isr_cnt++;

#ifdef 	I2S_STATISTIC
	if(pAudio_config->tx_isr_cnt%40==0)
		MSG("tisr i=%u,c=%u,o=%u,u=%d,s=%X [r=%d,w=%d]\n",pAudio_config->tx_isr_cnt,dma_ch,pi2s_status->txovrun,pi2s_status->txunrun,i2s_inw(I2S_INT_STATUS),pAudio_config->tx_r_idx,pAudio_config->tx_w_idx);

#endif

	if(pAudio_config->tx_r_idx==pAudio_config->tx_w_idx)
	{
		/* Buffer Empty */
		MSG("TXBE r=%d w=%d[i=%u,c=%u]\n",pAudio_config->tx_r_idx,pAudio_config->tx_w_idx,pAudio_config->tx_isr_cnt,dma_ch);
#ifdef I2S_STATISTIC
		pi2s_status->txbuffer_unrun++;
#endif
		if(dma_ch==GDMA_I2S_TX0)
		{
			memset(pAudio_config->pPage0TxBuf8ptr, 0, I2S_PAGE_SIZE);
			GdmaI2sTx((u32)pAudio_config->pPage0TxBuf8ptr, I2S_TX_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
		}
		else
		{
			memset(pAudio_config->pPage1TxBuf8ptr, 0, I2S_PAGE_SIZE);
			GdmaI2sTx((u32)pAudio_config->pPage1TxBuf8ptr, I2S_TX_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
		}

		goto EXIT;
	}

	if(pAudio_config->pMMAPTxBufPtr[pAudio_config->tx_r_idx]==NULL)
	{
		MSG("mmap buf NULL [%d]\n",pAudio_config->tx_r_idx);
		if(dma_ch==GDMA_I2S_TX0)
			GdmaI2sTx((u32)pAudio_config->pPage0TxBuf8ptr, I2S_TX_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
		else
			GdmaI2sTx((u32)pAudio_config->pPage1TxBuf8ptr, I2S_TX_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);

		goto EXIT;
	}
#ifdef I2S_STATISTIC
	pi2s_status->txbuffer_len--;
#endif
	if(dma_ch==GDMA_I2S_TX0)
	{
#if defined(CONFIG_I2S_MMAP)
		dma_sync_single_for_device(NULL,  i2s_mmap_addr[pAudio_config->tx_r_idx], I2S_PAGE_SIZE, DMA_TO_DEVICE);
		GdmaI2sTx((u32)(pAudio_config->pMMAPTxBufPtr[pAudio_config->tx_r_idx]), I2S_TX_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
#else
		memcpy(pAudio_config->pPage0TxBuf8ptr,  pAudio_config->pMMAPTxBufPtr[pAudio_config->tx_r_idx], I2S_PAGE_SIZE);
		GdmaI2sTx((u32)(pAudio_config->pPage0TxBuf8ptr), I2S_TX_FIFO_WREG, 0, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
#endif
		pAudio_config->dmach = GDMA_I2S_TX0;
		pAudio_config->tx_r_idx = (pAudio_config->tx_r_idx+1)%MAX_I2S_PAGE;
	}
	else
	{
#if defined(CONFIG_I2S_MMAP)
		dma_sync_single_for_device(NULL,  i2s_mmap_addr[pAudio_config->tx_r_idx], I2S_PAGE_SIZE, DMA_TO_DEVICE);
		GdmaI2sTx((u32)(pAudio_config->pMMAPTxBufPtr[pAudio_config->tx_r_idx]), I2S_TX_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
#else
		memcpy(pAudio_config->pPage1TxBuf8ptr,  pAudio_config->pMMAPTxBufPtr[pAudio_config->tx_r_idx], I2S_PAGE_SIZE);
		GdmaI2sTx((u32)(pAudio_config->pPage1TxBuf8ptr), I2S_TX_FIFO_WREG, 1, I2S_PAGE_SIZE, i2s_dma_tx_handler, i2s_unmask_handler);
#endif
		pAudio_config->dmach = GDMA_I2S_TX1;
		pAudio_config->tx_r_idx = (pAudio_config->tx_r_idx+1)%MAX_I2S_PAGE;

	}
EXIT:
#if 0
	if (pAudio_config->dma_unmask_status&((1<<GDMA_I2S_TX0)|(1<<GDMA_I2S_TX1)))
	{
		if (dma_ch==GDMA_I2S_TX0)
			GdmaUnMaskChannel(GDMA_I2S_TX0);
	    else
			GdmaUnMaskChannel(GDMA_I2S_TX1);

		pAudio_config->dma_unmask_status &= ~((1<<GDMA_I2S_TX0)|(1<<GDMA_I2S_TX1));
	}
#endif
	if(pAudio_config->pss)
		snd_pcm_period_elapsed(pAudio_config->pss);
	wake_up_interruptible(&(pAudio_config->i2s_tx_qh));
	return;
}

void i2s_dma_rx_handler(u32 dma_ch)
{
	u32 data;
	static int next_p0_idx, next_p1_idx;
	//MSG("%s :%d\n",__func__,pAudio_config->rx_w_idx);
#if defined(CONFIG_I2S_TXRX)
	if(pAudio_config->bRxDMAEnable==0) {
		MSG("RxDMA not enable dc=%d,i=%d\n",dma_ch,pAudio_config->rx_isr_cnt);
		pAudio_config->nRxDMAStopped ++;
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

		if (pAudio_config->nRxDMAStopped==2)
			wake_up_interruptible(&(pAudio_config->i2s_rx_qh));
		return;
	}
	if(pAudio_config->rx_isr_cnt==0)
	{
		next_p0_idx = 0;
		next_p1_idx = 1;
	}
	pAudio_config->rx_isr_cnt++;

#ifdef  I2S_STATISTIC
	if(pAudio_config->rx_isr_cnt%40==0)
		MSG("risr i=%u,c=%u,o=%u,u=%d,s=%X [r=%d,w=%d]\n",pAudio_config->rx_isr_cnt,dma_ch,\
				pi2s_status->rxovrun,pi2s_status->rxunrun,i2s_inw(I2S_INT_STATUS),pAudio_config->rx_r_idx,\
				pAudio_config->rx_w_idx);
#endif

	if(((pAudio_config->rx_w_idx+1)%MAX_I2S_PAGE)==pAudio_config->rx_r_idx)
	{
		/* Buffer Full */
		printk("RXBF r=%d w=%d[i=%u,c=%u]\n",pAudio_config->rx_r_idx,pAudio_config->rx_w_idx,
											pAudio_config->rx_isr_cnt,dma_ch);

#ifdef I2S_STATISTIC
		pi2s_status->rxbuffer_unrun++;
#endif
		if(dma_ch==GDMA_I2S_RX0)
		{
			GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)pAudio_config->pPage0RxBuf8ptr, 0, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
		}
		else
		{
			GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)pAudio_config->pPage1RxBuf8ptr, 1, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
		}

		goto EXIT;
	}

#ifdef I2S_STATISTIC
	pi2s_status->rxbuffer_len++;
#endif

	if(dma_ch==GDMA_I2S_RX0)
	{
		pAudio_config->rx_w_idx = (pAudio_config->rx_w_idx+1)%MAX_I2S_PAGE;
#ifdef CONFIG_I2S_MMAP
		dma_sync_single_for_cpu(NULL,  i2s_mmap_addr[next_p0_idx+(pAudio_config->mmap_index-MAX_I2S_PAGE)], I2S_PAGE_SIZE, DMA_FROM_DEVICE);
        next_p0_idx = (pAudio_config->rx_w_idx+1)%MAX_I2S_PAGE;
		dma_sync_single_for_device(NULL,  i2s_mmap_addr[next_p0_idx+(pAudio_config->mmap_index-MAX_I2S_PAGE)], I2S_PAGE_SIZE, DMA_FROM_DEVICE);
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)(pAudio_config->pMMAPRxBufPtr[next_p0_idx]), 0, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#else
		memcpy(pAudio_config->pMMAPRxBufPtr[pAudio_config->rx_w_idx], pAudio_config->pPage0RxBuf8ptr, I2S_PAGE_SIZE);
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)(pAudio_config->pPage0RxBuf8ptr), 0, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#endif
		pAudio_config->dmach = GDMA_I2S_RX0;

	}
	else
	{
		pAudio_config->rx_w_idx = (pAudio_config->rx_w_idx+1)%MAX_I2S_PAGE;
#ifdef CONFIG_I2S_MMAP
		dma_sync_single_for_cpu(NULL,  i2s_mmap_addr[next_p1_idx+(pAudio_config->mmap_index-MAX_I2S_PAGE)], I2S_PAGE_SIZE, DMA_FROM_DEVICE);
		next_p1_idx = (pAudio_config->rx_w_idx+1)%MAX_I2S_PAGE;
		dma_sync_single_for_device(NULL,  i2s_mmap_addr[next_p1_idx+(pAudio_config->mmap_index-MAX_I2S_PAGE)], I2S_PAGE_SIZE, DMA_FROM_DEVICE);
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)(pAudio_config->pMMAPRxBufPtr[next_p1_idx]), 1, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#else
		memcpy(pAudio_config->pMMAPRxBufPtr[pAudio_config->rx_w_idx], pAudio_config->pPage1RxBuf8ptr, I2S_PAGE_SIZE);
		GdmaI2sRx(I2S_RX_FIFO_RREG, (u32)(pAudio_config->pPage1RxBuf8ptr), 1, I2S_PAGE_SIZE, i2s_dma_rx_handler, i2s_unmask_handler);
#endif
		pAudio_config->dmach = GDMA_I2S_RX1;

	}
EXIT:
	//MSG("risr i=%u,d=%d [r=%d,w=%d][p0=%d,p1=%d]\n",pAudio_config->rx_isr_cnt,dma_ch,pAudio_config->rx_r_idx,pAudio_config->rx_w_idx,next_p0_idx,next_p1_idx);
#if 0
	if (pAudio_config->dma_unmask_status&((1<<GDMA_I2S_RX0)|(1<<GDMA_I2S_RX1)))
	{
		if (dma_ch==GDMA_I2S_RX0)
			GdmaUnMaskChannel(GDMA_I2S_RX0);
		else
			GdmaUnMaskChannel(GDMA_I2S_RX1);

		pAudio_config->dma_unmask_status &= ~((1<<GDMA_I2S_RX0)|(1<<GDMA_I2S_RX1));
	}
#endif

	if(pAudio_config->pss)
		snd_pcm_period_elapsed(pAudio_config->pss);
	wake_up_interruptible(&(pAudio_config->i2s_rx_qh));
#endif
	return;
}
#endif

#if 0
static int mtk_audio_drv_pbVol_get(struct snd_kcontrol *kcontrol,\
	struct snd_ctl_elem_value *ucontrol){
	ucontrol->value.integer.value[0] = pAudio_config->txvol;
	return 0;
}
static int mtk_audio_drv_pbVol_set(struct snd_kcontrol *kcontrol,\
	struct snd_ctl_elem_value *ucontrol){

	int tmpVol = ucontrol->value.integer.value[0];
	spin_lock(&pAudio_config->lock);
	if(tmpVol > 127)
	{
		pAudio_config->txvol = 127;
	}
	else if((int)tmpVol < 96)
	{
		pAudio_config->txvol = 96;
	}
	else
		pAudio_config->txvol = tmpVol;

	spin_unlock(&pAudio_config->lock);
	return 0;
}
static int mtk_audio_drv_recVol_get(struct snd_kcontrol *kcontrol,\
	struct snd_ctl_elem_value *ucontrol){
	ucontrol->value.integer.value[0] = pAudio_config->rxvol;
	return 0;
}
static int mtk_audio_drv_recVol_set(struct snd_kcontrol *kcontrol,\
	struct snd_ctl_elem_value *ucontrol){

	int tmpVol = ucontrol->value.integer.value[0];
	spin_lock(&pAudio_config->lock);
	if(tmpVol > 63)
	{
		pAudio_config->txvol = 63;
	}
	else if((int)tmpVol < 0)
	{
		pAudio_config->txvol = 0;
	}
	else
		pAudio_config->txvol = tmpVol;

	spin_unlock(&pAudio_config->lock);
	return 0;
}
#endif

static int mtk_audio_drv_set_fmt(struct snd_soc_dai *cpu_dai,
		unsigned int fmt)
{//TODO
#if 0
	unsigned long mask;
	unsigned long value;

	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_RIGHT_J:
		mask = KIRKWOOD_I2S_CTL_RJ;
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		mask = KIRKWOOD_I2S_CTL_LJ;
		break;
	case SND_SOC_DAIFMT_I2S:
		mask = KIRKWOOD_I2S_CTL_I2S;
		break;
	default:
		return -EINVAL;
	}

	/*
	 * Set same format for playback and record
	 * This avoids some troubles.
	 */
	value = readl(priv->io+KIRKWOOD_I2S_PLAYCTL);
	value &= ~KIRKWOOD_I2S_CTL_JUST_MASK;
	value |= mask;
	writel(value, priv->io+KIRKWOOD_I2S_PLAYCTL);

	value = readl(priv->io+KIRKWOOD_I2S_RECCTL);
	value &= ~KIRKWOOD_I2S_CTL_JUST_MASK;
	value |= mask;
	writel(value, priv->io+KIRKWOOD_I2S_RECCTL);
#endif
	return 0;
}

static int mtk_audio_drv_play_prepare(struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	i2s_config_type* rtd = (i2s_config_type*)substream->runtime->private_data;
	rtd->pss = substream;
	i2s_reset_tx_config( rtd);
	// rtd->bTxDMAEnable = 1;
	i2s_tx_config( rtd);

	if( rtd->bRxDMAEnable==0)
		i2s_clock_enable( rtd);
#if 0
	audiohw_set_lineout_vol(1,  rtd->txvol,  rtd->txvol);
#endif
	//data = i2s_inw(RALINK_REG_INTENA);
	//data |=0x0400;
	//i2s_outw(RALINK_REG_INTENA, data);
	i2s_tx_enable( rtd);
	//GdmaUnMaskChannel(GDMA_I2S_TX0);

	MSG("I2S_TXENABLE done\n");

	return 0;
}

static int mtk_audio_drv_rec_prepare(struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	i2s_config_type* rtd = (i2s_config_type*)substream->runtime->private_data;
	rtd->pss = substream;
	i2s_reset_rx_config(rtd);
	//rtd->bRxDMAEnable = 1;
	i2s_rx_config(rtd);

	if(rtd->bTxDMAEnable==0)
		i2s_clock_enable(rtd);

#if 0
#if defined(CONFIG_I2S_TXRX)
	audiohw_set_linein_vol(rtd->rxvol,  rtd->rxvol);
#endif
#endif
	i2s_rx_enable(rtd);

	//data = i2s_inw(RALINK_REG_INTENA);
	//data |=0x0400;
	//i2s_outw(RALINK_REG_INTENA, data);
	return 0;
}

static int  mtk_audio_drv_shutdown(struct snd_pcm_substream *substream,
		       struct snd_soc_dai *dai)
{
	//i2s_config_type* rtd = (i2s_config_type*)substream->runtime->private_data;
	MSG("%s :%d \n",__func__,__LINE__);
	return 0;
}

static int  mtk_audio_drv_startup(struct snd_pcm_substream *substream,
		       struct snd_soc_dai *dai)
{
#if 0
	/* set i2s_config */
	pAudio_config = (i2s_config_type*)kmalloc(sizeof(i2s_config_type), GFP_KERNEL);
	if(pAudio_config==NULL)
		return -1;
	memset(pAudio_config, 0, sizeof(i2s_config_type));

#ifdef I2S_STATISTIC
	pi2s_status = (i2s_status_type*)kmalloc(sizeof(i2s_status_type), GFP_KERNEL);
	if(pi2s_status==NULL)
		return -1;
	memset(pi2s_status, 0, sizeof(i2s_status_type));
#endif

	//i2s_config_type* rtd = (i2s_config_type*)substream->runtime->private_data;
	MSG("func: %s:LINE:%d \n",__func__,__LINE__);
	pAudio_config->flag = 0;
	pAudio_config->dmach = GDMA_I2S_TX0;
	pAudio_config->tx_ff_thres = CONFIG_I2S_TFF_THRES;
	pAudio_config->tx_ch_swap = CONFIG_I2S_CH_SWAP;
	pAudio_config->rx_ff_thres = CONFIG_I2S_TFF_THRES;
	pAudio_config->rx_ch_swap = CONFIG_I2S_CH_SWAP;
	pAudio_config->slave_en = CONFIG_I2S_SLAVE_EN;

	pAudio_config->srate = 44100;
	pAudio_config->txvol = 96;
	pAudio_config->rxvol = 60;
	pAudio_config->lbk = CONFIG_I2S_INLBK;
	pAudio_config->extlbk = CONFIG_I2S_EXLBK;
	pAudio_config->fmt = CONFIG_I2S_FMT;

    init_waitqueue_head(&(pAudio_config->i2s_tx_qh));
    init_waitqueue_head(&(pAudio_config->i2s_rx_qh));
#else
    i2s_open(NULL,NULL);
    if(!pi2s_config)
    	return -1;
#endif
	substream->runtime->private_data = pi2s_config;
	return 0;
}
static int mtk_audio_hw_params(struct snd_pcm_substream *substream,\
				struct snd_pcm_hw_params *params,\
				struct snd_soc_dai *dai){
	unsigned int srate = 0;
	unsigned long data;
	struct snd_pcm_runtime *runtime = substream->runtime;
	i2s_config_type* rtd = runtime->private_data;

	//printk("func: %s:LINE:%d \n",__func__,__LINE__);
	switch(params_rate(params)){
	case 8000:
		srate = 8000;
		break;
	case 16000:
		srate = 16000;
		break;
	case 32000:
		srate = 32000;
		break;
	case 44100:
		srate = 44100;
		break;
	case 48000:
		srate = 48000;
		break;
	default:
		srate = 44100;
		MSG("audio sampling rate %u should be %d ~ %d Hz\n", (u32)params_rate(params), MIN_SRATE_HZ, MAX_SRATE_HZ);
		break;
	}
	if(srate){
#if defined(CONFIG_RALINK_RT6855A)
		u32 reg_addr = RALINK_SYSCTL_BASE+0x834;
#else
		u32 reg_addr = RALINK_SYSCTL_BASE+0x34;
#endif
		data = *(unsigned long*)(reg_addr);
		data |=(1<<17);
		*(unsigned long*)(reg_addr) = data;
		data = *(unsigned long*)(reg_addr);
		data &=~(1<<17);
		*(unsigned long*)(reg_addr) = data;
		rtd->srate = srate;
		MSG("set audio sampling rate to %d Hz\n", rtd->srate);
	}

	return 0;
}
static int mtk_audio_drv_hw_free(struct snd_pcm_substream *substream,struct snd_soc_dai *dai){

	i2s_config_type* rtd = (i2s_config_type*)substream->runtime->private_data;
	MSG("%s %d \n",__func__,__LINE__);
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK){
		//if(rtd->bTxDMAEnable==1){
			MSG("I2S_TXDISABLE\n");
			i2s_reset_tx_config(rtd);

			//if (rtd->nTxDMAStopped<4)
			//	interruptible_sleep_on(&(rtd->i2s_tx_qh));
			i2s_tx_disable(rtd);
			if((rtd->bRxDMAEnable==0)&&(rtd->bTxDMAEnable==0))
				i2s_clock_disable(rtd);
		//}
	}
	else{
		//if(rtd->bRxDMAEnable==1){
			MSG("I2S_RXDISABLE\n");
			i2s_reset_rx_config(rtd);
			//spin_unlock(&rtd->lock);
			//if(rtd->nRxDMAStopped<2)
			//	interruptible_sleep_on(&(rtd->i2s_rx_qh));
			i2s_rx_disable(rtd);
			if((rtd->bRxDMAEnable==0)&&(rtd->bTxDMAEnable==0))
				i2s_clock_disable(rtd);
		//}
	}
	return 0;
}
static int mtk_audio_drv_prepare(struct snd_pcm_substream *substream,struct snd_soc_dai *dai)
{
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		return mtk_audio_drv_play_prepare(substream, dai);
	else
		return mtk_audio_drv_rec_prepare(substream, dai);

	return 0;
}
