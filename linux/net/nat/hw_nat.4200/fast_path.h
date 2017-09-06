
#ifndef _FASTPATH_WANTED
#define _FASTPATH_WANTED


#define PPTP_TCP_PORT           1723
#define PPTP_GRE_VERSION        0x1
#define PPTP_GRE_PROTOCOL       0x880B

#define PPP_ADDRESS_CONTROL     0xff03
#define PPP_PROTOCOL		0x0021

#define PPTP_GRE_FLAG_C		0x80
#define PPTP_GRE_FLAG_R		0x40
#define PPTP_GRE_FLAG_K		0x20
#define PPTP_GRE_FLAG_S		0x10
#define PPTP_GRE_FLAG_A		0x80

#define PPTP_GRE_IS_C(f)	((f)&PPTP_GRE_FLAG_C)
#define PPTP_GRE_IS_R(f)	((f)&PPTP_GRE_FLAG_R)
#define PPTP_GRE_IS_K(f)	((f)&PPTP_GRE_FLAG_K)
#define PPTP_GRE_IS_S(f)	((f)&PPTP_GRE_FLAG_S)
#define PPTP_GRE_IS_A(f)	((f)&PPTP_GRE_FLAG_A)


struct pptp_gre_hdr {
	unsigned char  flags;		/* bitfield */
	unsigned char  version;		/* should be PPTP_GRE_VER (enhanced GRE) */
	unsigned short protocol;		/* should be PPTP_GRE_PROTO (ppp-encaps) */
	unsigned short payload_len;	/* size of ppp payload, not inc. gre header */
	unsigned short call_id;		/* peer's call_id for this session */
	unsigned int seq;		/* sequence number.  Present if S==1 */
	unsigned int ack;		/* seq number of highest packet recieved by */
					/*  sender in this session */
};

#define PPTP_CONTROL_PACKET     1
#define PPTP_MGMT_PACKET        2

int	fast_pptp_to_lan(struct sk_buff **pskb);
int	fast_pptp_to_wan(struct sk_buff *pskb);
int	fast_l2tp_to_lan(struct sk_buff **pskb);
int	fast_l2tp_to_wan(struct sk_buff *pskb);
int32_t PktGenInitMod(void);
int32_t PptpToLanParseLayerInfo(struct sk_buff * skb);
int32_t PptpToWanParseLayerInfo(struct sk_buff * skb);
int32_t L2tpToWanParseLayerInfo(struct sk_buff * skb);
void	pptp_l2tp_fdb_update(unsigned char protocol, unsigned int addr, unsigned int foe_hash_index);
int32_t SendHashPkt(struct sk_buff *pskb);
int32_t SendL2TPHashPkt(struct sk_buff *pskb);
int	fast_pptp_init(void);
int	fast_pptp_clean(void);
#endif
