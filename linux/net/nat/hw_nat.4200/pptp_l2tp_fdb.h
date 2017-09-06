#ifndef __PPTP_L2TP_FDB_H_
#define __PPTP_L2TP_FDB_H_

/* -------------------- Macro Definitions ------------------------------ */


#define PPTP_L2TP_HASH_BITS 9
#define PPTP_L2TP_HASH_SIZE (1 << PPTP_L2TP_HASH_BITS)

//typedef unsigned int            u32;

/* -------------------- Structure Definitions -------------------------- */




struct pptp_l2tp_fdb_entry
{
    struct hlist_node			hlist;
    struct rcu_head			rcu;
    unsigned int			hash_index;
    unsigned int			addr;/*src port + dst port*/
    unsigned char			protocol;
    unsigned char			entry_type;  /*0: Invalid, 1: from ethernet, 2: from WLan, 3: remote??*/
};



extern struct FoeEntry         *PpeFoeBase;


/* -------------------- Address Definitions ---------------------------- */

/* -------------------- Function Declaration ---------------------------- */
void pptp_l2tp_fdb_update(unsigned char protocol, unsigned int addr, unsigned int foe_hash_index);
int is_pptp_l2tp_bind(unsigned char protocol, unsigned int addr);



#endif
