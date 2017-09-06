//#include <linux/kernel.h>

//#include <linux/init.h>
//#include <linux/spinlock.h>
//#include <linux/times.h>
#include <linux/netdevice.h>
//#include <linux/etherdevice.h>
#include <linux/jhash.h>

//#include <linux/list.h>
#include "pptp_l2tp_fdb.h"
#include "foe_fdb.h"


spinlock_t                      pptp_l2tp_hash_lock;
struct hlist_head               pptp_l2tp_hash[PPTP_L2TP_HASH_SIZE];

static u32 fdb_salt __read_mostly;

extern uint32_t         DebugLevel;



int pptp_l2tp_addr_hash(unsigned int key)
{
	/* use 1 byte of OUI cnd 3 bytes of NIC */
	//u32 key = get_unaligned((u32 *)(addr));
	return jhash_1word(key, fdb_salt) & (PPTP_L2TP_HASH_SIZE - 1);
}

void fdb_delete(struct pptp_l2tp_fdb_entry *f)
{
        //printk("fdb_delete %p\n\r", (void*)f);
	hlist_del_rcu(&f->hlist);
        kfree(f);
}


/* Completely flush all dynamic entries in forwarding database.*/
void pptp_l2tp_fdb_flush(void)
{
	int i;
	struct FoeEntry *foe_entry = NULL;

	spin_lock_bh(&pptp_l2tp_hash_lock);
	for (i = 0; i < PPTP_L2TP_HASH_SIZE; i++) {
		struct pptp_l2tp_fdb_entry *f;
		struct hlist_node *h, *n;
		hlist_for_each_entry_safe(f, h, n, &pptp_l2tp_hash[i], hlist) {
	
	    	    foe_entry = &PpeFoeBase[f->hash_index];
			if (foe_entry->bfib1.state != BIND){
				fdb_delete(f);
				//FoeDumpEntry(f->hash_index);
			}
		}
	}
	spin_unlock_bh(&pptp_l2tp_hash_lock);
}



struct pptp_l2tp_fdb_entry *pptp_l2tp_fdb_find(struct hlist_head *head,
						    unsigned int addr)
{
	struct hlist_node *h;
	struct pptp_l2tp_fdb_entry *fdb;

        //DBGPRINT_RAW(RT_DEBUG_INFO,("ucast_fdb_find called\n\r"));
	hlist_for_each_entry_rcu(fdb, h, head, hlist) {
		if (fdb->addr == addr){
			return fdb;
		}
	}
	return NULL;
}

struct pptp_l2tp_fdb_entry *pptp_l2tp_fdb_create(struct hlist_head *head,
					       unsigned int foe_hash,
					       unsigned int addr,
					       unsigned char protocol)
{
	struct pptp_l2tp_fdb_entry *fdb = NULL;


        fdb = kzalloc(sizeof(struct pptp_l2tp_fdb_entry), GFP_ATOMIC);
	if (DebugLevel >= 1) {
		printk("get a fdb space at %p\n", (void*)fdb);
	}
	if (fdb) {
		//memcpy(fdb->addr, addr, ETH_ALEN);
		hlist_add_head_rcu(&fdb->hlist, head);
		fdb->addr = addr;
		fdb->hash_index = foe_hash;
		fdb->protocol = protocol;
	}
	return fdb;
}


/*
 *
 *
 *
 *  upate mac address on tei
 *  protocol: UDP (0x11) or TCP (0x6)
 *
 *
 */
#if 1
void pptp_l2tp_fdb_update(unsigned char protocol, unsigned int addr, unsigned int foe_hash_index)
{
	struct hlist_head *head = &pptp_l2tp_hash[pptp_l2tp_addr_hash(addr)];
	struct pptp_l2tp_fdb_entry *fdb;

	fdb = pptp_l2tp_fdb_find(head, addr);
	if (likely(fdb)) {
	    
		if (DebugLevel >= 1) {
			printk("pptp l2tp entry already exist\n");  
		}
	} else {
		spin_lock(&pptp_l2tp_hash_lock);
		if (DebugLevel >= 1) {
			printk("create an entry #%d protocol=0x%2x addr=0x%4x\n",foe_hash_index, protocol, addr);
		}
		pptp_l2tp_fdb_create(head, foe_hash_index, addr, protocol);
		spin_unlock(&pptp_l2tp_hash_lock);
	  /* flush time out FDB */
		pptp_l2tp_fdb_flush();
	}
}

int is_pptp_l2tp_bind(unsigned char protocol, unsigned int addr)
{
	struct hlist_head *head = &pptp_l2tp_hash[pptp_l2tp_addr_hash(addr)];
	struct pptp_l2tp_fdb_entry *fdb = NULL;
	struct FoeEntry *foe_entry = NULL;
     
	//printk("is_pptp_l2tp_bind protocol=0x%2x addr=0x%4x\n", protocol, addr);
	fdb = pptp_l2tp_fdb_find(head, addr);
	if (fdb) {
		if(fdb->protocol == protocol){
			foe_entry = &PpeFoeBase[fdb->hash_index];
			//FoeDumpEntry(fdb->hash_index);
			if (foe_entry->bfib1.state == BIND)
				return 1;
		}
	} 
	else {
		return 0;
	}
	return 0;
}

#endif


/*
 * @brief: 
 *
 * @param: 
 *         
 * @return: 
 */
int pptp_l2tp_fdb_dump(void)
{
	int i, num = 0;
	struct hlist_node *h;
	struct pptp_l2tp_fdb_entry *f;
	struct FoeEntry *foe_entry = NULL;

	rcu_read_lock();
	for (i = 0; i < PPTP_L2TP_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(f, h, &pptp_l2tp_hash[i], hlist) {
		foe_entry = &PpeFoeBase[f->hash_index];
			if (foe_entry->bfib1.state != BIND)    
			{
				continue;
			}
			else{
			    printk("pptp l2tp bind entry address %x\n", f->addr);
			}

		}
	}

	rcu_read_unlock();
}



int pptp_l2tp_addr_delete(const unsigned char *addr)
{
	struct hlist_head *head = &pptp_l2tp_hash[pptp_l2tp_addr_hash(addr)];
	struct pptp_l2tp_fdb_entry *fdb;


	fdb = pptp_l2tp_fdb_find(head, addr);
	if (likely(fdb)) {
		//spin_lock(&ucast_hash_lock);
		fdb_delete(fdb);
		//spin_unlock(&ucast_hash_lock);
	        return 1;
	} else {
		printk("pptp_l2tp_addr_delete fdb no find \n\r");
	}
	return 0;
}




