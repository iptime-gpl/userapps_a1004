/*
 * mtk_audio_device.h
 *
 *  Created on: 2013/10/23
 *      Author: MTK04880
 */

#ifndef MTK_AUDIO_DEVICE_H_
#define MTK_AUDIO_DEVICE_H_
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>

#if defined(CONFIG_I2S_WM8750)
#undef CONFIG_I2S_WM8750
#elif defined(CONFIG_I2S_WM8751)
#undef CONFIG_I2S_WM8751
#elif defined(CONFIG_I2S_WM8960)
#undef CONFIG_I2S_WM8960
#else
#error "IIS with Unknown Codec?"
#endif

#ifdef CONFIG_I2S_MMAP
#undef CONFIG_I2S_MMAP
#endif

#if 0
void audiohw_preinit(void);
void audiohw_postinit(int bSlave, int Ain, int Aout);
void audiohw_close(void);
void audiohw_set_frequency(int fsel);
void audiohw_set_MCLK(unsigned int bUsb);
void audiohw_mute(bool mute);
#else
#define audiohw_preinit()
#define audiohw_postinit(a,b,c)
#define audiohw_close()
#define audiohw_set_frequency(a)
#define audiohw_set_MCLK(a);
#define audiohw_mute(a)
#define audiohw_set_frequency(a)
#define audiohw_set_lineout_vol(a,b,c);
#define audiohw_set_linein_vol(a,b)
unsigned long i2sSlave_exclk_12p288Mhz[11]  = {0x04,  	0x00,   	0x10,    0x14,  	0x38,	 	0x38,  	 0x18,     0x20,  	0x00,	 0x00, 	  0x1C};
unsigned long i2sSlave_exclk_12Mhz[11]      = {0x04,  	0x32,  		0x10,    0x14,  	0x37,  		0x38,  	 0x18,     0x22,  	0x00, 	 0x3E, 	  0x1C};
#endif
#endif /* MTK_AUDIO_DEVICE_H_ */
