/*   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   Copyright (C) 2014-2016 Sean Wang <sean.wang@mediatek.com>
 *   Copyright (C) 2016-2017 John Crispin <blogic@openwrt.org>
 */

#include <linux/netfilter_bridge.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <linux/netfilter_ipv6.h>
#include <linux/of.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <net/arp.h>
#include <net/neighbour.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#ifdef CONFIG_NF_HNAT_PACKET_ACCOUNTING
#include <net/netfilter/nf_hnat_packet_accounting.h>
#endif

#include "nf_hnat_mtk.h"
#include "hnat.h"

#include "../mtk_eth_soc.h"
#include "../mtk_eth_reset.h"
#include <linux/ppp_defs.h>
#include <linux/ppp_channel.h>
#include "../mtk_eth_soc.h"
#include "../mtk_eth_reset.h"
#include <linux/if_pppox.h>
#include <linux/if_ether.h>
#define do_ge2ext_fast(dev, skb)                                               \
	(skb_hnat_is_hashed(skb) && \
	  skb_hnat_reason(skb) == HIT_BIND_FORCE_TO_CPU)
#define do_ext2ge_fast_learn(dev, skb)                                         \
	((skb_hnat_sport(skb) == NR_PDMA_PORT ||                           \
	  skb_hnat_sport(skb) == NR_QDMA_PORT) &&                       \
	  ((get_dev_from_index(skb->vlan_tci & VLAN_VID_MASK)) ||   \
		 get_wandev_from_index(skb->vlan_tci & VLAN_VID_MASK)))
#define do_mape_w2l_fast(dev, skb)                                          \
		(mape_toggle && IS_WAN(dev) && (!is_from_mape(skb)))

extern struct net_device *ppd_dev;
static struct ipv6hdr mape_l2w_v6h;
static struct ipv6hdr mape_w2l_v6h;
static u16 ext_vlan=0;

enum hnat_tunnel_event {
	TNL_OUTER_SEEN,
	TNL_OUTER_IDENTITY_REJECT,
	TNL_OUTER_NEIGH_MISS,
	TNL_OUTER_PATH_REJECT,
	TNL_OUTER_TOPOLOGY_REJECT,
	TNL_SHADOW_MISS,
	TNL_INNER_IDENTITY_REJECT,
	TNL_SYNC_PENDING,
	TNL_SETUP_ERROR,
	TNL_LEASE_REJECT,
	TNL_PUBLISH_REJECT,
	TNL_ENCAP_BOUND,
	TNL_EVENT_MAX,
};

static atomic64_t hnat_tunnel_events[TNL_EVENT_MAX];

void hnat_tunnel_events_show(struct seq_file *s)
{
	static const char * const names[] = {
		"outer_seen", "outer_identity_reject", "outer_neigh_miss",
		"outer_path_reject", "outer_topology_reject", "shadow_miss",
		"inner_identity_reject", "sync_pending", "setup_error",
		"lease_reject", "publish_reject", "encap_bound",
	};
	unsigned int i;

	seq_puts(s, "unit=host_encap_learning_events; not_hardware_packet_counters\n");
	for (i = 0; i < ARRAY_SIZE(names); i++)
		seq_printf(s, "%s %lld\n", names[i],
			   atomic64_read(&hnat_tunnel_events[i]));
}

static void hnat_tunnel_event(enum hnat_tunnel_event event)
{
	atomic64_inc(&hnat_tunnel_events[event]);
}
static inline uint8_t get_wifi_hook_if_index_from_dev(const struct net_device *dev)
{
	int i;

	for (i = 1; i < MAX_IF_NUM; i++) {
		if (hnat_priv->wifi_hook_if[i] == dev)
			return i;
	}

	return 0;
}

static inline int get_ext_device_number(void)
{
	int i, number = 0;

	for (i = 0; i < MAX_EXT_DEVS && hnat_priv->ext_if[i]; i++)
		number += 1;
	return number;
}

static inline int find_extif_from_devname(const char *name)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS && hnat_priv->ext_if[i]; i++) {
		ext_entry = hnat_priv->ext_if[i];
		if (!strcmp(name, ext_entry->name))
			return 1;
	}
	return 0;
}
static inline int get_index_from_dev(const struct net_device *dev)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS && hnat_priv->ext_if[i]; i++) {
		ext_entry = hnat_priv->ext_if[i];
		if (dev == ext_entry->dev)
			return ext_entry->dev->ifindex;
	}
	return 0;
}

static inline struct net_device *get_dev_from_index(int index)
{
	int i;
	struct extdev_entry *ext_entry;
	struct net_device *dev = 0;

	for (i = 0; i < MAX_EXT_DEVS && hnat_priv->ext_if[i]; i++) {
		ext_entry = hnat_priv->ext_if[i];
		if (ext_entry->dev && index == ext_entry->dev->ifindex) {
			dev = ext_entry->dev;
			break;
		}
	}
		if (index == 1234)
			dev = ppd_dev;
	return dev;
}

static inline struct net_device *get_wandev_from_index(int index)
{
	if (!hnat_priv->g_wandev)
		hnat_priv->g_wandev = __dev_get_by_name(&init_net, hnat_priv->wan);

	if (hnat_priv->g_wandev && hnat_priv->g_wandev->ifindex == index)
		return hnat_priv->g_wandev;
	return NULL;
}

static inline int extif_match(const char *name)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS && hnat_priv->ext_if[i]; i++) {
		ext_entry = hnat_priv->ext_if[i];
		if (!strcmp(name, ext_entry->name) && !ext_entry->dev) {
			return i;
		}
	}

	return -1;
}

static inline bool extif_prefix_match(const char *name)
{
	int i;

	for (i = 0; i < MAX_EXT_PREFIX_NUM && hnat_priv->ext_if_prefix[i]; i++)
	{
		if (strlen(hnat_priv->ext_if_prefix[i]) && 
			!strncmp(name, hnat_priv->ext_if_prefix[i],
				strlen(hnat_priv->ext_if_prefix[i])))
			return true;
	}

	return false;
}

static inline int extif_set_dev(struct net_device *dev, int try_prefix)
{
	struct extdev_entry *ext_entry;
	int extif_index, number;

	extif_index = extif_match(dev->name);

	if (extif_index < 0) {
		/* try extif prefix match */
		if (try_prefix && extif_prefix_match(dev->name)) {
			number = get_ext_device_number();
			if (number >= MAX_EXT_DEVS) {
				pr_info("%s : extdev array is full. %s is not registered\n",
					__func__, dev->name);
				return -1;
			}

			ext_entry = kzalloc(sizeof(*ext_entry), GFP_KERNEL);
			if (!ext_entry)
				return -1;

			strncpy(ext_entry->name, dev->name, IFNAMSIZ - 1);
			dev_hold(dev);
			ext_entry->dev = dev;
			ext_vlan = 0;
			ext_if_add(ext_entry);

			pr_info("%s prefix match (%s)\n", __func__, dev->name);
			return dev->ifindex;
		}
	} else {
		dev_hold(dev);
		hnat_priv->ext_if[extif_index]->dev = dev;
		pr_info("%s(%s)\n", __func__, dev->name);
		return dev->ifindex;
	}

	return -1;
}

static inline int extif_put_dev(struct net_device *dev)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS && hnat_priv->ext_if[i]; i++) {
		ext_entry = hnat_priv->ext_if[i];
		if (ext_entry->dev == dev) {
			ext_entry->dev = NULL;
			dev_put(dev);
			pr_info("%s(%s)\n", __func__, dev->name);

			return 0;
		}
	}

	return -1;
}

int ext_if_add(struct extdev_entry *ext_entry)
{
	int len = get_ext_device_number();

	if (len < MAX_EXT_DEVS)
		hnat_priv->ext_if[len++] = ext_entry;

	return len;
}

static void foe_clear_ethdev_bind_entries(struct net_device *dev)
{
	struct net_device *master_dev = dev;
	const struct dsa_port *dp;
	struct foe_entry *entry, snapshot;
	u64 account_generation = 0;
	struct mtk_mac *mac;
	bool match_dev = false;
	int port_id, gmac;
	u32 i, hash_index;
	u32 dsa_tag;
	u32 total = 0;
	/* Get the master device if the device is slave device */
	port_id = hnat_dsa_get_port(&master_dev);
	mac = netdev_priv(master_dev);
	gmac = HNAT_GMAC_FP(mac->id);
	if (gmac < 0)
		return;
	if (port_id >= 0) {
		dp = dsa_port_from_netdev(dev);
		if (IS_ERR(dp))
			return;
		if (0)
			dsa_tag = port_id + BIT(11);
		else
			dsa_tag = BIT(port_id);
	}
	for (i = 0; i < CFG_PPE_NUM; i++) {
		for (hash_index = 0; hash_index < hnat_priv->foe_etry_num; hash_index++) {
			entry = hnat_priv->foe_table_cpu[i] + hash_index;
			if (hnat_account_enabled(hnat_priv)) {
				if (!hnat_account_clear_snapshot(hnat_priv, i, hash_index,
							 &snapshot, &account_generation))
					continue;
				entry = &snapshot;
			}
			if (!entry_hnat_is_bound(entry))
				continue;
			match_dev = (IS_IPV4_GRP(entry)) ? entry->ipv4_hnapt.iblk2.dp == gmac :
							   entry->ipv6_5t_route.iblk2.dp == gmac;
			if (match_dev && port_id >= 0) {
				if (0) {
					match_dev = (IS_IPV4_GRP(entry)) ?
						entry->ipv4_hnapt.vlan1 == dsa_tag :
						entry->ipv6_5t_route.vlan1 == dsa_tag;
				} else {
					match_dev = (IS_IPV4_GRP(entry)) ?
						!!(entry->ipv4_hnapt.etype & dsa_tag) :
						!!(entry->ipv6_5t_route.etype & dsa_tag);
				}
			}
			if (match_dev) {
				if (!hnat_account_clear_if_generation(hnat_priv, i, hash_index,
							 false, account_generation)) {
					entry->bfib1.state = INVALID;
					entry->bfib1.time_stamp =
					readl((hnat_priv->fe_base + 0x0010)) & 0xFF;
				}
				total++;
			}
		}
	}
	/* clear HWNAT cache */
	if (total > 0)
		hnat_cache_ebl(1);
}
int ext_if_del(struct extdev_entry *ext_entry)
{
	int i, j;

	for (i = 0; i < MAX_EXT_DEVS; i++) {
		if (hnat_priv->ext_if[i] == ext_entry) {
			for (j = i; hnat_priv->ext_if[j] && j < MAX_EXT_DEVS - 1; j++)
				hnat_priv->ext_if[j] = hnat_priv->ext_if[j + 1];
			hnat_priv->ext_if[j] = NULL;
			break;
		}
	}

	return i;
}

static void foe_clear_all_bind_entries_body(void)
{
	int i, hash_index;
	struct foe_entry *entry, snapshot;
	u64 account_generation = 0;

	for (i = 0; i < CFG_PPE_NUM; i++) {
		cr_set_field(hnat_priv->ppe_base[i] + PPE_TB_CFG,
			     SMA, SMA_ONLY_FWD_CPU);

		for (hash_index = 0; hash_index < hnat_priv->foe_etry_num; hash_index++) {
			entry = hnat_priv->foe_table_cpu[i] + hash_index;
			if (hnat_account_enabled(hnat_priv)) {
				if (!hnat_account_clear_snapshot(hnat_priv, i, hash_index,
							 &snapshot, &account_generation))
					continue;
				entry = &snapshot;
			}
			if (entry->bfib1.state == BIND) {
				if (!hnat_account_clear_if_generation(hnat_priv, i, hash_index,
							 false, account_generation)) {
					entry->ipv4_hnapt.udib1.state = INVALID;
					entry->ipv4_hnapt.udib1.time_stamp =
					readl((hnat_priv->fe_base + 0x0010)) & 0xFF;
				}
			}
		}
	}

	/* clear HWNAT cache */
	hnat_cache_ebl(1);

	mod_timer(&hnat_priv->hnat_sma_build_entry_timer, jiffies + 3 * HZ);
}

void foe_clear_all_bind_entries(void)
{
	if (!hnat_external_callback_enter())
		return;
	foe_clear_all_bind_entries_body();
	hnat_external_callback_exit();
}

static void gmac_ppe_fwd_enable(struct net_device *dev)
{
	struct net_device *master_dev = dev;
	struct mtk_mac *mac;

	if (netdev_uses_dsa(master_dev))
		hnat_dsa_get_port(&master_dev);

	mac = netdev_priv(master_dev);
 

	if (mac->id == MTK_GMAC1_ID)
		set_gmac_ppe_fwd(NR_GMAC1_PORT, 1);
	else if (mac->id == MTK_GMAC2_ID)
		set_gmac_ppe_fwd(NR_GMAC2_PORT, 1);
	else if (mac->id == MTK_GMAC3_ID)
		set_gmac_ppe_fwd(NR_GMAC3_PORT, 1);
}


void ppd_dev_setting(void)
{
	struct net_device *br_dev;
	br_dev = __dev_get_by_name(&init_net, "br-lan");
        if (br_dev) {
                struct net_device *dev;
                struct list_head *pos;
                netdev_for_each_lower_dev(br_dev, dev, pos) {
                        if (dev->flags & IFF_UP) {
                            if (netif_carrier_ok(dev)){
                                ppd_dev = __dev_get_by_name(&init_net, dev->name);
                                hnat_priv->g_ppdev = __dev_get_by_name(&init_net, dev->name);
                                break;
                                        }
                                }
                        }
                } 
       	br_dev = __dev_get_by_name(&init_net, "eth2");
        if (br_dev){
        if (br_dev->flags & IFF_UP){
		if (netif_carrier_ok(br_dev))
			hnat_priv->g_ppdev = __dev_get_by_name(&init_net, "eth2");
                }
		}
		br_dev = __dev_get_by_name(&init_net, "hnat");
        if (br_dev){
        if (br_dev->flags & IFF_UP){
		if (netif_carrier_ok(br_dev))
                hnat_priv->g_ppdev = __dev_get_by_name(&init_net, "hnat");
                }
		}
        br_dev = __dev_get_by_name(&init_net, "eth1");
        if (br_dev){
        if (br_dev->flags & IFF_UP){
		if (netif_carrier_ok(br_dev))
                hnat_priv->g_ppdev = __dev_get_by_name(&init_net, "eth1");
                }
		}
		br_dev = __dev_get_by_name(&init_net, "eth0");
        if (br_dev){
        if (br_dev->flags & IFF_UP){
		if (netif_carrier_ok(br_dev))
                hnat_priv->g_ppdev = __dev_get_by_name(&init_net, "eth0");
                }
		}
	pr_info("%s : now rx dev: %s, tx dev: %s\n", 
		__func__, hnat_priv->g_ppdev->name, ppd_dev->name);
}

static void hnat_flow_drop_dev(struct net_device *dev);

int nf_hnat_netdevice_event(struct notifier_block *unused, unsigned long event,
			    void *ptr)
{
	struct net_device *dev;

	dev = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_UP:
		ppd_dev_setting();		
		if (!hnat_priv->guest_en) {
			if (!strcmp(dev->name, "ra1") || !strcmp(dev->name, "rax1"))
				break;
		}
		
		gmac_ppe_fwd_enable(dev);

		extif_set_dev(dev,1);

		break;

	case NETDEV_CHANGE:
		/* Clear PPE entries if the slave of bond device physical link down */
		ppd_dev_setting();
		if (!netif_is_bond_slave(dev) ||
		    (!IS_LAN_GRP(dev) && !IS_WAN(dev)))
			break;
		if (netif_carrier_ok(dev))
			break;
		foe_clear_ethdev_bind_entries(dev);
		break;
		
	case NETDEV_GOING_DOWN:
		ppd_dev_setting();
		if (!get_wifi_hook_if_index_from_dev(dev))
			extif_put_dev(dev);

		if (!IS_LAN_GRP(dev) && !IS_WAN(dev) &&
		    !find_extif_from_devname(dev->name) &&
		    !dev->netdev_ops->ndo_flow_offload_check)
			break;

		foe_clear_all_bind_entries();

		break;
	case NETDEV_UNREGISTER:
		hnat_flow_drop_dev(dev);
		ppd_dev_setting();
		if (hnat_priv->g_ppdev == dev) {
			hnat_priv->g_ppdev = NULL;
		}
		if (hnat_priv->g_wandev == dev) {
			hnat_priv->g_wandev = NULL;
			dev_put(dev);
		}

		break;
	case NETDEV_REGISTER:
		ppd_dev_setting();
		if (IS_PPD(dev) && !hnat_priv->g_ppdev)
			hnat_priv->g_ppdev = __dev_get_by_name(&init_net, hnat_priv->ppd);
		if (IS_WAN(dev) && !hnat_priv->g_wandev)
			hnat_priv->g_wandev = __dev_get_by_name(&init_net, hnat_priv->wan);

		break;
	case MTK_FE_RESET_NAT_DONE:
		ppd_dev_setting();
		pr_info("[%s] HNAT driver starts to do warm init !\n", __func__);
		hnat_warm_init();
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

void foe_clear_entry(struct neighbour *neigh)
{
	u32 *daddr = (u32 *)neigh->primary_key;
	unsigned char h_dest[ETH_ALEN];
	struct foe_entry *entry, snapshot;
	u64 account_generation = 0;
	int i, hash_index;
	u32 dip;

	dip = (u32)(*daddr);

	for (i = 0; i < CFG_PPE_NUM; i++) {
		if (!hnat_priv->foe_table_cpu[i])
			continue;

		for (hash_index = 0; hash_index < hnat_priv->foe_etry_num; hash_index++) {
			entry = hnat_priv->foe_table_cpu[i] + hash_index;
			if (hnat_account_enabled(hnat_priv)) {
				if (!hnat_account_clear_snapshot(hnat_priv, i, hash_index,
							 &snapshot, &account_generation))
					continue;
				entry = &snapshot;
			}
			if (entry->bfib1.state == BIND &&
			    entry->ipv4_hnapt.new_dip == ntohl(dip) &&
			    IS_IPV4_HNAPT(entry)) {
				*((u32 *)h_dest) = swab32(entry->ipv4_hnapt.dmac_hi);
				*((u16 *)&h_dest[4]) =
					swab16(entry->ipv4_hnapt.dmac_lo);
				if (strncmp(h_dest, neigh->ha, ETH_ALEN) != 0) {
					cr_set_field(hnat_priv->ppe_base[i] + PPE_TB_CFG,
						     SMA, SMA_ONLY_FWD_CPU);

					if (!hnat_account_clear_if_generation(hnat_priv, i, hash_index,
							 false, account_generation)) {
						entry->ipv4_hnapt.udib1.state = INVALID;
						entry->ipv4_hnapt.udib1.time_stamp =
							readl((hnat_priv->fe_base + 0x0010)) & 0xFF;
					}

					/* clear HWNAT cache */
					hnat_cache_ebl(1);

					mod_timer(&hnat_priv->hnat_sma_build_entry_timer,
						  jiffies + 3 * HZ);

					if (debug_level >= 7 && net_ratelimit()) {
						pr_info("%s: state=%d\n", __func__,
							neigh->nud_state);
						pr_info("Delete old entry: dip =%pI4\n", &dip);
						pr_info("Old mac= %pM\n", h_dest);
						pr_info("New mac= %pM\n", neigh->ha);
					}
				}
			}
		}
	}
}

int nf_hnat_netevent_handler(struct notifier_block *unused, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = NULL;
	struct neighbour *neigh = NULL;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		neigh = ptr;
		dev = neigh->dev;
		if (dev)
			foe_clear_entry(neigh);
		break;
	}

	return NOTIFY_DONE;
}

unsigned int mape_add_ipv6_hdr(struct sk_buff *skb, struct ipv6hdr mape_ip6h)
{
	struct ethhdr *eth = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct iphdr *iph = NULL;

	if (skb_headroom(skb) < IPV6_HDR_LEN || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		return -1;
	}

	/* point to L3 */
	memcpy(skb->data - IPV6_HDR_LEN - ETH_HLEN, skb_push(skb, ETH_HLEN), ETH_HLEN);
	memcpy(skb_push(skb, IPV6_HDR_LEN - ETH_HLEN), &mape_ip6h, IPV6_HDR_LEN);

	eth = (struct ethhdr *)(skb->data - ETH_HLEN);
	eth->h_proto = htons(ETH_P_IPV6);
	skb->protocol = htons(ETH_P_IPV6);

	iph = (struct iphdr *)(skb->data + IPV6_HDR_LEN);
	ip6h = (struct ipv6hdr *)(skb->data);
	ip6h->payload_len = iph->tot_len; /* maybe different with ipv4 */

	skb_set_network_header(skb, 0);
	skb_set_transport_header(skb, iph->ihl * 4 + IPV6_HDR_LEN);
	return 0;
}

static void fix_skb_packet_type(struct sk_buff *skb, struct net_device *dev,
				struct ethhdr *eth)
{
	skb->pkt_type = PACKET_HOST;
	if (unlikely(is_multicast_ether_addr(eth->h_dest))) {
		if (ether_addr_equal_64bits(eth->h_dest, dev->broadcast))
			skb->pkt_type = PACKET_BROADCAST;
		else
			skb->pkt_type = PACKET_MULTICAST;
	}
}

unsigned int do_hnat_ext_to_ge(struct sk_buff *skb, const struct net_device *in,
			       const char *func)
{
	if (hnat_priv->g_ppdev && hnat_priv->g_ppdev->flags & IFF_UP) {
		u16 vlan_id = 0;
		skb_set_network_header(skb, 0);
		skb_push(skb, ETH_HLEN);
		set_to_ppe(skb);

		vlan_id = skb_vlan_tag_get_id(skb);
		if (unlikely(vlan_id)) {
			skb = vlan_insert_tag(skb, skb->vlan_proto, skb->vlan_tci);
			if (!skb)
				return -1;
		}
	
		/*set where we come from*/
		if (unlikely(skb_vlan_tag_present(skb))){
		 	ext_vlan = skb->vlan_tci;
		}
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), VLAN_CFI_MASK | (in->ifindex & VLAN_VID_MASK)); 
		skb->dev = hnat_priv->g_ppdev;
		dev_queue_xmit(skb);
		return 0;
	}

	pr_debug_ratelimited("%s: called from %s fail\n", __func__, func);
	return -1;
}

unsigned int do_hnat_ext_to_ge2(struct sk_buff *skb, const char *func)
{
	struct ethhdr *eth = eth_hdr(skb);
	struct net_device *dev;
	struct foe_entry *entry;
	
	pr_debug_ratelimited("%s: vlan_prot=0x%x, vlan_tci=%x\n", __func__,
		     ntohs(skb->vlan_proto), skb->vlan_tci);

	if (skb_hnat_entry(skb) >= hnat_priv->foe_etry_num ||
	    skb_hnat_ppe(skb) >= CFG_PPE_NUM)
		return -1;

	dev = get_dev_from_index(skb->vlan_tci & VLAN_VID_MASK);

	if (dev) {
		/*set where we to go*/
		skb->dev = dev;
		skb->vlan_proto = 0;
		skb->vlan_tci = 0;
		if (skb_vlan_tag_present(skb)){
		__vlan_hwaccel_clear_tag(skb);
		}
		if (ntohs(eth->h_proto) == ETH_P_8021Q) {
			skb = skb_vlan_untag(skb);
			if (unlikely(!skb))
				return -1;
		}
		 /*Restore original vlan */
                if (ext_vlan !=0)
                        __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), ext_vlan);

		if (IS_BOND(dev) &&
		    (((hnat_priv->data->version == MTK_HNAT_V2 ||
		       hnat_priv->data->version == MTK_HNAT_V3) &&
				(skb_hnat_entry(skb) != 0x7fff)) ||
		     ((hnat_priv->data->version != MTK_HNAT_V2 &&
		       hnat_priv->data->version != MTK_HNAT_V3) &&
				(skb_hnat_entry(skb) != 0x3fff))))
			skb_set_hash(skb, skb_hnat_entry(skb) >> 1, PKT_HASH_TYPE_L4);

		set_from_extge(skb);
		fix_skb_packet_type(skb, skb->dev, eth);
		netif_rx(skb);
		return 0;
	} else {
		/* MapE WAN --> LAN/WLAN PingPong. */
		dev = get_wandev_from_index(skb->vlan_tci & VLAN_VID_MASK);
		if (mape_toggle && dev) {
			if (!mape_add_ipv6_hdr(skb, mape_w2l_v6h)) {
				skb_set_mac_header(skb, -ETH_HLEN);
				skb->dev = dev;
				set_from_mape(skb);
				skb->vlan_proto = 0;
				skb->vlan_tci = 0;
				__vlan_hwaccel_clear_tag(skb);
				fix_skb_packet_type(skb, skb->dev, eth_hdr(skb));
				entry = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];
				entry->bfib1.pkt_type = IPV4_HNAPT;
				netif_rx(skb);
				return 0;
			}
		}
		pr_debug_ratelimited("%s: called from %s fail\n", __func__, func);
		return -1;
	}
}

unsigned int do_hnat_ge_to_ext(struct sk_buff *skb, const char *func)
{
	/*set where we to go*/
	u8 index;
	struct foe_entry *entry, snapshot;
	u64 account_generation = 0;
	struct net_device *dev;

	if (skb_hnat_entry(skb) >= hnat_priv->foe_etry_num ||
	    skb_hnat_ppe(skb) >= CFG_PPE_NUM)
		return -1;

	entry = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];
	if (hnat_account_enabled(hnat_priv)) {
		if (!hnat_account_clear_snapshot(hnat_priv, skb_hnat_ppe(skb),
					 skb_hnat_entry(skb), &snapshot, &account_generation))
			return -1;
		entry = &snapshot;
	}

	if (IS_IPV4_GRP(entry))
		index = entry->ipv4_hnapt.act_dp & UDF_PINGPONG_IFIDX;
	else
		index = entry->ipv6_5t_route.act_dp & UDF_PINGPONG_IFIDX;

	dev = get_dev_from_index(index);
	if (!dev) {
		pr_debug_ratelimited("%s: called from %s. Get wifi interface fail\n",
			     __func__, func);
		return 0;
	}

	skb->dev = dev;

	if (IS_HQOS_MODE && eth_hdr(skb)->h_proto == HQOS_MAGIC_TAG) {
		skb = skb_unshare(skb, GFP_ATOMIC);
		if (!skb)
			return NF_ACCEPT;

		if (unlikely(!pskb_may_pull(skb, VLAN_HLEN)))
			return NF_ACCEPT;

		skb_pull_rcsum(skb, VLAN_HLEN);

		memmove(skb->data - ETH_HLEN, skb->data - ETH_HLEN - VLAN_HLEN,
			2 * ETH_ALEN);
	}

	if (skb->dev) {
		skb_set_network_header(skb, 0);
		skb_push(skb, ETH_HLEN);
		dev_queue_xmit(skb);
		pr_debug_ratelimited("%s: called from %s successfully\n", __func__,
			     func);
		return 0;
	} else {
		if (mape_toggle) {
			/* Add ipv6 header mape for lan/wlan -->wan */
			dev = get_wandev_from_index(index);
			if (dev) {
				if (!mape_add_ipv6_hdr(skb, mape_l2w_v6h)) {
					skb_set_network_header(skb, 0);
					skb_push(skb, ETH_HLEN);
					skb_set_mac_header(skb, 0);
					skb->dev = dev;
					dev_queue_xmit(skb);
					return 0;
				}
				pr_debug_ratelimited("%s: called from %s fail[MapE]\n", __func__,
					     func);
				return -1;
			}
		}
	}
	/*if external devices is down, invalidate related ppe entry*/
	if (entry_hnat_is_bound(entry)) {
		if (!hnat_account_clear_if_generation(hnat_priv, skb_hnat_ppe(skb),
						      skb_hnat_entry(skb), false, account_generation)) {
			entry->bfib1.state = INVALID;
			if (IS_IPV4_GRP(entry))
				entry->ipv4_hnapt.act_dp &= ~UDF_PINGPONG_IFIDX;
			else
				entry->ipv6_5t_route.act_dp &= ~UDF_PINGPONG_IFIDX;
		}

		/* clear HWNAT cache */
		hnat_cache_ebl(1);
	}
	pr_debug_ratelimited("%s: called from %s fail, index=%x\n", __func__,
		     func, index);
	return -1;
}

static void pre_routing_print(struct sk_buff *skb, const struct net_device *in,
			      const struct net_device *out, const char *func)
{
	pr_debug_ratelimited(
		"[%s]: %s(iif=0x%x CB2=0x%x)-->%s (ppe_hash=0x%x) sport=0x%x reason=0x%x alg=0x%x from %s\n",
		__func__, in->name, skb_hnat_iface(skb),
		HNAT_SKB_CB2(skb)->magic, out->name, skb_hnat_entry(skb),
		skb_hnat_sport(skb), skb_hnat_reason(skb), skb_hnat_alg(skb),
		func);
}

static void post_routing_print(struct sk_buff *skb, const struct net_device *in,
			       const struct net_device *out, const char *func)
{
	pr_debug_ratelimited(
		"[%s]: %s(iif=0x%x, CB2=0x%x)-->%s (ppe_hash=0x%x) sport=0x%x reason=0x%x alg=0x%x from %s\n",
		__func__, in->name, skb_hnat_iface(skb),
		HNAT_SKB_CB2(skb)->magic, out->name, skb_hnat_entry(skb),
		skb_hnat_sport(skb), skb_hnat_reason(skb), skb_hnat_alg(skb),
		func);
}

static inline void hnat_set_iif(const struct nf_hook_state *state,
				struct sk_buff *skb, int val)
{
	if (IS_WHNAT(state->in) && FROM_WED(skb)) {
		return;
	} else if (IS_WHNAT(state->in)) {
                skb_hnat_iface(skb) = FOE_MAGIC_GE_LAN;
	} else if (IS_LAN(state->in)) {
		skb_hnat_iface(skb) = FOE_MAGIC_GE_LAN;
	} else if (IS_LAN2(state->in)) {
		skb_hnat_iface(skb) = FOE_MAGIC_GE_LAN2;
	} else if (IS_PPD(state->in)) {
		skb_hnat_iface(skb) = FOE_MAGIC_GE_PPD;
	} else if (IS_EXT(state->in)) {
		skb_hnat_iface(skb) = FOE_MAGIC_EXT;
	} else if (IS_WAN(state->in)) {
		skb_hnat_iface(skb) = FOE_MAGIC_GE_WAN;
	} else if (!IS_BR(state->in)) {
		if (state->in->netdev_ops->ndo_flow_offload_check) {
			skb_hnat_iface(skb) = FOE_MAGIC_GE_VIRTUAL;
		} else {
			skb_hnat_iface(skb) = FOE_INVALID;

			if (is_magic_tag_valid(skb) &&
			    IS_SPACE_AVAILABLE_HEAD(skb))
				memset(skb_hnat_info(skb), 0, FOE_INFO_LEN);
		}
	}
}

static inline void hnat_set_alg(const struct nf_hook_state *state,
				struct sk_buff *skb, int val)
{
	skb_hnat_alg(skb) = val;
}

static inline void hnat_set_head_frags(const struct nf_hook_state *state,
				       struct sk_buff *head_skb, int val,
				       void (*fn)(const struct nf_hook_state *state,
						  struct sk_buff *skb, int val))
{
	struct sk_buff *segs = skb_shinfo(head_skb)->frag_list;

	fn(state, head_skb, val);
	while (segs) {
		fn(state, segs, val);
		segs = segs->next;
	}
}

static void ppe_fill_flow_lbl(struct foe_entry *entry, struct ipv6hdr *ip6h)
{
	entry->ipv4_dslite.flow_lbl[0] = ip6h->flow_lbl[2];
	entry->ipv4_dslite.flow_lbl[1] = ip6h->flow_lbl[1];
	entry->ipv4_dslite.flow_lbl[2] = ip6h->flow_lbl[0];
}

unsigned int do_hnat_mape_w2l_fast(struct sk_buff *skb, const struct net_device *in,
				   const char *func)
{
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct iphdr _iphdr;
	struct iphdr *iph;
	struct ethhdr *eth;

	/* WAN -> LAN/WLAN MapE. */
	if (mape_toggle && (ip6h->nexthdr == NEXTHDR_IPIP)) {
		iph = skb_header_pointer(skb, IPV6_HDR_LEN, sizeof(_iphdr), &_iphdr);
		if (unlikely(!iph))
			return -1;

		switch (iph->protocol) {
		case IPPROTO_UDP:
		case IPPROTO_TCP:
			break;
		default:
			return -1;
		}
		mape_w2l_v6h = *ip6h;

		/* Remove ipv6 header. */
		memcpy(skb->data + IPV6_HDR_LEN - ETH_HLEN,
		       skb->data - ETH_HLEN, ETH_HLEN);
		skb_pull(skb, IPV6_HDR_LEN - ETH_HLEN);
		skb_set_mac_header(skb, 0);
		skb_set_network_header(skb, ETH_HLEN);
		skb_set_transport_header(skb, ETH_HLEN + sizeof(_iphdr));

		eth = eth_hdr(skb);
		eth->h_proto = htons(ETH_P_IP);
		set_to_ppe(skb);

		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), VLAN_CFI_MASK | (in->ifindex & VLAN_VID_MASK));
		if (!hnat_priv->g_ppdev)
			hnat_priv->g_ppdev = __dev_get_by_name(&init_net, hnat_priv->ppd);

		skb->dev = hnat_priv->g_ppdev;
		skb->protocol = htons(ETH_P_IP);

		dev_queue_xmit(skb);

		return 0;
	}
	return -1;
}

void mtk_464xlat_pre_process(struct sk_buff *skb)
{
	struct foe_entry *foe;

	if (skb_hnat_entry(skb) >= hnat_priv->foe_etry_num ||
	    skb_hnat_ppe(skb) >= CFG_PPE_NUM)
		return;

	foe = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];
	if (foe->bfib1.state != BIND &&
	    skb_hnat_reason(skb) == HIT_UNBIND_RATE_REACH)
		memcpy(&headroom[skb_hnat_entry(skb)], skb->head,
		       sizeof(struct hnat_desc));

	if (foe->bfib1.state == BIND)
		memset(&headroom[skb_hnat_entry(skb)], 0,
		       sizeof(struct hnat_desc));
}

static unsigned int is_ppe_support_type(struct sk_buff *skb)
{
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct iphdr _iphdr;
	struct net *net = skb->dev ? dev_net(skb->dev) : &init_net;

	eth = eth_hdr(skb);
	if (!is_magic_tag_valid(skb) || !IS_SPACE_AVAILABLE_HEAD(skb) ||
	    is_broadcast_ether_addr(eth->h_dest))
		return 0;

	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		iph = ip_hdr(skb);

		/* do not accelerate non tcp/udp traffic */
		if ((iph->protocol == IPPROTO_TCP) ||
		    (iph->protocol == IPPROTO_UDP) ||
		    (iph->protocol == IPPROTO_IPV6)) {
			/* Keep locally terminated traffic in software, including VRFs. */
			if ((skb->dev ? inet_addr_type_dev_table(net, skb->dev, iph->daddr) :
			     inet_addr_type(net, iph->daddr)) == RTN_LOCAL)
				return 0;

			return 1;
		}

		break;
	case ETH_P_IPV6:
		ip6h = ipv6_hdr(skb);

		if ((ip6h->nexthdr == NEXTHDR_TCP) ||
		    (ip6h->nexthdr == NEXTHDR_UDP)) {
			/* Same local-destination guard as IPv4 above. */
			if ((ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST) &&
			    ipv6_chk_addr(net, &ip6h->daddr, NULL, 0))
				return 0;

			return 1;
		} else if (ip6h->nexthdr == NEXTHDR_IPIP) {
			iph = skb_header_pointer(skb, IPV6_HDR_LEN,
						 sizeof(_iphdr), &_iphdr);
			if (unlikely(!iph))
				return 0;

			if ((iph->protocol == IPPROTO_TCP) ||
			    (iph->protocol == IPPROTO_UDP)) {
				return 1;
			}

		}

		break;
	case ETH_P_8021Q:
		return 1;
	}

	return 0;
}

static unsigned int do_hnat_cpu_to_ge(struct sk_buff *skb)
{
	if (unlikely(skb_shinfo(skb)->frag_list))
                return -1;
        if (unlikely(skb_headroom(skb) < (FOE_INFO_LEN + ETH_HLEN))) {
                if(unlikely(skb_cow(skb, FOE_INFO_LEN + ETH_HLEN)))
                return -1;
        }

	skb_hnat_alg(skb) = 0;
	skb_hnat_magic_tag(skb) = HNAT_MAGIC_TAG;
	skb_hnat_filled(skb) = 0;

	if (unlikely(!is_ppe_support_type(skb))) {
                skb_hnat_alg(skb) = 1;
                return -1;
        }
        if (hnat_priv->g_ppdev && hnat_priv->g_ppdev->flags & IFF_UP) {
                u16 vlan_id = 0;
                skb_set_network_header(skb, 0);
                skb_push(skb, ETH_HLEN);
		set_to_ppe(skb);
                vlan_id = skb_vlan_tag_get_id(skb);
                if (unlikely(vlan_id)) {
                        skb = vlan_insert_tag(skb, skb->vlan_proto, skb->vlan_tci);
                        if (!skb)
                                return -1;
                }

                /*set where we come from */
                __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), VLAN_CFI_MASK | (1234 & VLAN_VID_MASK));
                skb->dev = hnat_priv->g_ppdev;
                dev_queue_xmit(skb);
     		return 0;
        }
	return -1;
}

static void mtk_hnat_nf_update(struct sk_buff *skb)
{
	struct nf_conn *ct;
	struct nf_conn_acct *acct;
	struct nf_conn_counter *counter;
	enum ip_conntrack_info ctinfo;
	struct hnat_accounting diff;
	
	if (skb->protocol == htons(ETH_P_IPV6) && !hnat_priv->ipv6_en) {
		return ;
	}

	if (skb_hnat_alg(skb) || unlikely(!is_magic_tag_valid(skb) ||
					  !IS_SPACE_AVAILABLE_HEAD(skb)))
		return ;

	if (unlikely(!skb_mac_header_was_set(skb)))
		return ;

	if (unlikely(!skb_hnat_is_hashed(skb)))
		return ;
		
	if (unlikely(skb->mark == HNAT_EXCEPTION_TAG))
		return ;
 
	ct = nf_ct_get(skb, &ctinfo);
	if (ct) {
		if (hnat_account_enabled(hnat_priv)) {
			hnat_account_publish_delta(hnat_priv, skb_hnat_ppe(skb),
						   skb_hnat_entry(skb), skb);
			return;
		}
		if (!hnat_get_count(hnat_priv, skb_hnat_ppe(skb), skb_hnat_entry(skb), &diff))
			return;

		acct = nf_conn_acct_find(ct);
		
		if (acct) {
			counter = acct->counter;
			atomic64_add(diff.packets, &counter[CTINFO2DIR(ctinfo)].packets);
			atomic64_add(diff.bytes, &counter[CTINFO2DIR(ctinfo)].bytes);
			atomic64_set(&counter[CTINFO2DIR(ctinfo)].diff_packets, diff.packets);
			atomic64_set(&counter[CTINFO2DIR(ctinfo)].diff_bytes, diff.bytes);
		}
	}
}


/* Before conntrack/raw: verified keepalive metadata marks a synthetic packet
 * without allocation. Runtime-off packets retain the vendor counter contract.
 */
static void mtk_hnat_account_mark_keepalive(struct sk_buff *skb)
{
#ifdef CONFIG_NF_HNAT_PACKET_ACCOUNTING
	if (hnat_account_enabled(hnat_priv) && IS_SPACE_AVAILABLE_HEAD(skb) &&
	    is_magic_tag_valid(skb) &&
	    skb_hnat_reason(skb) == HIT_BIND_KEEPALIVE_DUP_OLD_HDR)
		nf_hnat_packet_accounting_mark(skb);
#endif
}

/* update hnat count to nf_conntrack and iptables by keepalive */
static unsigned int
mtk_hnat_nf_conntrack(void *priv, struct sk_buff *skb,
			     const struct nf_hook_state *state)
{
	if (!skb)
		goto drop;
	
	if (IS_SPACE_AVAILABLE_HEAD(skb) && is_magic_tag_valid(skb) &&
	    unlikely(skb_hnat_reason(skb) == HIT_BIND_KEEPALIVE_DUP_OLD_HDR))
		{
		if (hnat_priv->data->per_flow_accounting && hnat_priv->nf_stat_en)
			mtk_hnat_nf_update(skb);}
		
#ifdef CONFIG_NF_HNAT_PACKET_ACCOUNTING
	/* No CT, disabled statistics, or a rejected owner is still synthetic zero. */
	if (hnat_account_enabled(hnat_priv))
		nf_hnat_packet_accounting_finish_zero(skb);
#endif

	return NF_ACCEPT;
	
drop:
	
	return NF_DROP;	

}


static unsigned int
mtk_hnat_ipv6_nf_pre_routing(void *priv, struct sk_buff *skb,
			     const struct nf_hook_state *state)
{
	if (!skb)
		goto drop;
	mtk_hnat_account_mark_keepalive(skb);
	if (!IS_WHNAT(state->in) && IS_EXT(state->in)) {
		if (unlikely(skb_shinfo(skb)->frag_list))
        	return NF_ACCEPT;
        if (unlikely(skb_headroom(skb) < (FOE_INFO_LEN + ETH_HLEN))) {
        	if(unlikely(skb_cow(skb, FOE_INFO_LEN + ETH_HLEN)))
            	return NF_ACCEPT;
        }
		if (!is_magic_tag_valid(skb))
			hnat_tunnel_metadata_init(skb);
		skb_hnat_alg(skb) = 0;
		skb_hnat_magic_tag(skb) = HNAT_MAGIC_TAG;
	}
	
	if (!is_magic_tag_valid(skb))
		return NF_ACCEPT;

	if (!is_ppe_support_type(skb)) {
		hnat_set_head_frags(state, skb, 1, hnat_set_alg);
		return NF_ACCEPT;
	}

	hnat_set_head_frags(state, skb, -1, hnat_set_iif);

	pre_routing_print(skb, state->in, state->out, __func__);

	/* packets from external devices -> xxx ,step 1 , learning stage & bound stage*/
	if (do_ext2ge_fast_try(state->in, skb)) {
		if (!do_hnat_ext_to_ge(skb, state->in, __func__))
			return NF_STOLEN;
		return NF_ACCEPT;
	}

	/* packets form ge -> external device
	 * For standalone wan interface
	 */
	if (do_ge2ext_fast(state->in, skb)) {
		if (!do_hnat_ge_to_ext(skb, __func__))
			return NF_STOLEN;
		goto drop;
	}


#if !(defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3))
	/* MapE need remove ipv6 header and pingpong. */
	if (do_mape_w2l_fast(state->in, skb)) {
		if (!do_hnat_mape_w2l_fast(skb, state->in, __func__))
			return NF_STOLEN;
		else
			return NF_ACCEPT;
	}

	if (is_from_mape(skb))
		clr_from_extge(skb);
#endif
	if (xlat_toggle)
		mtk_464xlat_pre_process(skb);

	return NF_ACCEPT;
drop:
	if (skb)
		printk_ratelimited(KERN_WARNING
			"%s:drop (in_dev=%s, iif=0x%x, CB2=0x%x, ppe_hash=0x%x,\n"
			"sport=0x%x, reason=0x%x, alg=0x%x)\n",
			__func__, state->in->name, skb_hnat_iface(skb),
			HNAT_SKB_CB2(skb)->magic, skb_hnat_entry(skb),
			skb_hnat_sport(skb), skb_hnat_reason(skb),
			skb_hnat_alg(skb));

	return NF_DROP;
}

/* true means keep this software learning packet off the normal bind path. */
static bool hnat_tunnel_pre_route(struct sk_buff *skb)
{
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	struct flow_offload_hw_path path = { .dev = skb->dev, .virt_dev = skb->dev };

	if (!hnat_tunnel_available() || !IS_SPACE_AVAILABLE_HEAD(skb))
		return false;
	/* A failed COW must not modify a descriptor shared with another skb.
	 * Post-routing also refuses shared-head tunnel publication.
	 */
	if (skb_cow_head(skb, skb_headroom(skb)))
		return true;
	if (skb_hnat_tops(skb) && skb_hnat_is_decap(skb)) {
		if (skb->dev->netdev_ops->ndo_flow_offload_check &&
		    !skb->dev->netdev_ops->ndo_flow_offload_check(&path) &&
		    (path.flags & BIT(DEV_PATH_TNL)))
			hnat_tunnel_decap_offload(skb);
		/* This skb still carries the outer packet's hardware slot.  Even a
		 * successful decap setup must not bind its inner tuple into that slot.
		 */
		skb_hnat_alg(skb) = 1;
		return true;
	}
	if (!skb_hnat_is_decap(skb) && hnat_tunnel_decap_offloadable(skb)) {
		skb_hnat_is_decap(skb) = 1;
		return true;
	}
#endif
	return false;
}

static bool hnat_tunnel_rx_current(struct sk_buff *skb,
				   const struct net_device *dev)
{
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	const struct mtk_npu_rx_meta *rx = mtk_npu_rx_meta_find(skb);
	struct hnat_tunnel_token token = {};

	if (!rx || rx->tunnel_ifindex != (u32)dev->ifindex ||
	    !hnat_tunnel_rx_bind_lock(rx, &token))
		return false;
	hnat_tunnel_bind_unlock(&token);
	return true;
#else
	return false;
#endif
}

static unsigned int
mtk_hnat_ipv4_nf_pre_routing(void *priv, struct sk_buff *skb,
			     const struct nf_hook_state *state)
{
	struct flow_offload_hw_path hw_path = {};

	if (!skb)
		goto drop;
	mtk_hnat_account_mark_keepalive(skb);
		
	if (!IS_WHNAT(state->in) && IS_EXT(state->in)) {
		if (unlikely(skb_shinfo(skb)->frag_list))
        	return NF_ACCEPT;
        if (unlikely(skb_headroom(skb) < (FOE_INFO_LEN + ETH_HLEN))) {
        	if(unlikely(skb_cow(skb, FOE_INFO_LEN + ETH_HLEN)))
            	return NF_ACCEPT;
        }
		if (!is_magic_tag_valid(skb))
			hnat_tunnel_metadata_init(skb);
		skb_hnat_alg(skb) = 0;
		skb_hnat_magic_tag(skb) = HNAT_MAGIC_TAG;
	}

	if (!is_magic_tag_valid(skb))
		return NF_ACCEPT;

	if (hnat_tunnel_pre_route(skb))
		return NF_ACCEPT;

	if (!is_ppe_support_type(skb)) {
		hnat_set_head_frags(state, skb, 1, hnat_set_alg);
		return NF_ACCEPT;
	}

	hnat_set_head_frags(state, skb, -1, hnat_set_iif);

	hw_path.dev = skb->dev;
	hw_path.virt_dev = skb->dev;

	/*
	 * Avoid mistakenly binding of outer IP, ports in SW L2TP decap flow.
	 * A software-decapped packet still carries the outer flow's PPE slot.
	 * A validated TOPS DMA return instead has an inner hardware key and
	 * may learn HNAT/WHNAT; publication takes the tunnel lease again.
	 */
	if (skb_hnat_iface(skb) == FOE_MAGIC_GE_VIRTUAL
	    && skb->dev->netdev_ops->ndo_flow_offload_check) {
		if (skb->dev->netdev_ops->ndo_flow_offload_check(&hw_path) ||
		    ((hw_path.flags & BIT(DEV_PATH_TNL)) &&
		     !hnat_tunnel_rx_current(skb, state->in)))
			skb_hnat_alg(skb) = 1;
	}

	pre_routing_print(skb, state->in, state->out, __func__);

	/* packets from external devices -> xxx ,step 1 , learning stage & bound stage*/
	if (do_ext2ge_fast_try(state->in, skb)) {
		if (!do_hnat_ext_to_ge(skb, state->in, __func__))
			return NF_STOLEN;
		return NF_ACCEPT;
	}

	/* packets form ge -> external device
	 * For standalone wan interface
	 */
	if (do_ge2ext_fast(state->in, skb)) {
		if (!do_hnat_ge_to_ext(skb, __func__))
			return NF_STOLEN;
		goto drop;
	}
	if (xlat_toggle)
		mtk_464xlat_pre_process(skb);

	return NF_ACCEPT;
drop:
	if (skb)
		printk_ratelimited(KERN_WARNING
			"%s:drop (in_dev=%s, iif=0x%x, CB2=0x%x, ppe_hash=0x%x,\n"
			"sport=0x%x, reason=0x%x, alg=0x%x)\n",
			__func__, state->in->name, skb_hnat_iface(skb),
			HNAT_SKB_CB2(skb)->magic, skb_hnat_entry(skb),
			skb_hnat_sport(skb), skb_hnat_reason(skb),
			skb_hnat_alg(skb));

	return NF_DROP;
}

static unsigned int
mtk_hnat_br_nf_local_in(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct vlan_ethhdr *veth;

	if (!skb)
		goto drop;
	
	if (!IS_WHNAT(state->in) && IS_EXT(state->in)) {
		if (unlikely(skb_shinfo(skb)->frag_list))
        	return NF_ACCEPT;
        if (unlikely(skb_headroom(skb) < (FOE_INFO_LEN + ETH_HLEN))) {
        	if(unlikely(skb_cow(skb, FOE_INFO_LEN + ETH_HLEN)))
            	return NF_ACCEPT;
        }
		if (!is_magic_tag_valid(skb))
			hnat_tunnel_metadata_init(skb);
		skb_hnat_alg(skb) = 0;
		skb_hnat_magic_tag(skb) = HNAT_MAGIC_TAG;
	}

	if (!is_magic_tag_valid(skb))
		return NF_ACCEPT;

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	/* Software GRETAP/VXLAN decap can enter a bridge without another IPv4
	 * PRE_ROUTING pass. Only consume the outer packet's pending marker;
	 * ordinary bridge frames and hardware-decapped (tops=0) frames retain
	 * the original HNAT path. No bridge-netfilter sysctl is changed.
	 */
	if (IS_SPACE_AVAILABLE_HEAD(skb) && skb_hnat_tops(skb) &&
	    skb_hnat_is_decap(skb) && hnat_tunnel_pre_route(skb))
		return NF_ACCEPT;
#endif

	if (IS_HQOS_MODE && hnat_priv->data->whnat) {
		veth = (struct vlan_ethhdr *)skb_mac_header(skb);

		if (eth_hdr(skb)->h_proto == HQOS_MAGIC_TAG) {
			skb_hnat_entry(skb) = ntohs(veth->h_vlan_TCI) & 0x3fff;
			skb_hnat_reason(skb) = HIT_BIND_FORCE_TO_CPU;
		}
	}

	if (!HAS_HQOS_MAGIC_TAG(skb) && !is_ppe_support_type(skb)) {
		hnat_set_head_frags(state, skb, 1, hnat_set_alg);
		return NF_ACCEPT;
	}

	hnat_set_head_frags(state, skb, -1, hnat_set_iif);

	pre_routing_print(skb, state->in, state->out, __func__);

	if (unlikely(debug_level >= 7) && net_ratelimit()) {
		hnat_cpu_reason_cnt(skb);
		if (skb_hnat_reason(skb) == dbg_cpu_reason)
			foe_dump_pkt(skb);
	}

	/* packets from external devices -> xxx ,step 1 , learning stage & bound stage*/
	if ((skb_hnat_iface(skb) == FOE_MAGIC_EXT) && !is_from_extge(skb) &&
	    !is_multicast_ether_addr(eth_hdr(skb)->h_dest)) {
		if (!hnat_priv->g_ppdev)
			hnat_priv->g_ppdev = __dev_get_by_name(&init_net, hnat_priv->ppd);

		if (!do_hnat_ext_to_ge(skb, state->in, __func__))
			return NF_STOLEN;
		return NF_ACCEPT;
	}

	if (hnat_priv->data->whnat) {
		if (skb_hnat_iface(skb) == FOE_MAGIC_EXT)
			clr_from_extge(skb);

		/* packets from external devices -> xxx ,step 2, learning stage */
		if (do_ext2ge_fast_learn(state->in, skb) && (!qos_toggle ||
		    (qos_toggle && eth_hdr(skb)->h_proto != HQOS_MAGIC_TAG))) {
			if (!do_hnat_ext_to_ge2(skb, __func__))
				return NF_STOLEN;
			goto drop;
		}

		/* packets form ge -> external device */
		if (do_ge2ext_fast(state->in, skb)) {
			if (!do_hnat_ge_to_ext(skb, __func__))
				return NF_STOLEN;
			goto drop;
		}
	}

#if !(defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3))
	/* MapE need remove ipv6 header and pingpong. (bridge mode) */
	if (do_mape_w2l_fast(state->in, skb)) {
		if (!do_hnat_mape_w2l_fast(skb, state->in, __func__))
			return NF_STOLEN;
		else
			return NF_ACCEPT;
	}
#endif
	return NF_ACCEPT;
drop:
	if (skb)
		printk_ratelimited(KERN_WARNING
			"%s:drop (in_dev=%s, iif=0x%x, CB2=0x%x, ppe_hash=0x%x,\n"
			"sport=0x%x, reason=0x%x, alg=0x%x)\n",
			__func__, state->in->name, skb_hnat_iface(skb),
			HNAT_SKB_CB2(skb)->magic, skb_hnat_entry(skb),
			skb_hnat_sport(skb), skb_hnat_reason(skb),
			skb_hnat_alg(skb));

	return NF_DROP;
}

static unsigned int hnat_ipv6_get_nexthop(struct sk_buff *skb,
					  const struct net_device *out,
					  struct flow_offload_hw_path *hw_path)
{
	const struct in6_addr *ipv6_nexthop;
	struct neighbour *neigh = NULL;
	struct dst_entry *dst = skb_dst(skb);
	struct ethhdr *eth;
	u16 eth_pppoe_hlen = ETH_HLEN + PPPOE_SES_HLEN;

	if (hw_path->flags & BIT(DEV_PATH_PPPOE)) {
		if (ipv6_hdr(skb)->nexthdr == NEXTHDR_IPIP) {
			eth = (struct ethhdr *)(skb->data - eth_pppoe_hlen);
			eth->h_proto = skb->protocol;
			ether_addr_copy(eth->h_dest, hw_path->eth_dest);
			ether_addr_copy(eth->h_source,  hw_path->eth_src);
		} else {
			eth = eth_hdr(skb);
			memcpy(eth->h_source, hw_path->eth_src, ETH_ALEN);
			memcpy(eth->h_dest, hw_path->eth_dest, ETH_ALEN);
		}

		return 0;
	}

	rcu_read_lock_bh();
	ipv6_nexthop =
		rt6_nexthop((struct rt6_info *)dst, &ipv6_hdr(skb)->daddr);
	neigh = __ipv6_neigh_lookup_noref(dst->dev, ipv6_nexthop);
	if (unlikely(!neigh)) {
		dev_notice(hnat_priv->dev, "%s:No neigh (daddr=%pI6)\n", __func__,
			   &ipv6_hdr(skb)->daddr);
		rcu_read_unlock_bh();
		return -1;
	}

	/* why do we get all zero ethernet address ? */
	if (!is_valid_ether_addr(neigh->ha)) {
		rcu_read_unlock_bh();
		return -1;
	}

	if (ipv6_hdr(skb)->nexthdr == NEXTHDR_IPIP) {
		/*copy ether type for DS-Lite and MapE */
		eth = (struct ethhdr *)(skb->data - ETH_HLEN);
		eth->h_proto = skb->protocol;
	} else {
		eth = eth_hdr(skb);
	}

	ether_addr_copy(eth->h_dest, neigh->ha);
	ether_addr_copy(eth->h_source, out->dev_addr);

	rcu_read_unlock_bh();

	return 0;
}

static unsigned int hnat_ipv4_get_nexthop(struct sk_buff *skb,
					  const struct net_device *out,
					  struct flow_offload_hw_path *hw_path)
{
	u32 nexthop;
	struct neighbour *neigh;
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = (__force struct net_device *)out;

	if (hw_path->flags & BIT(DEV_PATH_PPPOE)) {
		memcpy(eth_hdr(skb)->h_source, hw_path->eth_src, ETH_ALEN);
		memcpy(eth_hdr(skb)->h_dest, hw_path->eth_dest, ETH_ALEN);
		return 0;
	}

	rcu_read_lock_bh();
	nexthop = (__force u32)rt_nexthop(rt, ip_hdr(skb)->daddr);
	neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
	if (unlikely(!neigh)) {
		dev_notice(hnat_priv->dev, "%s:No neigh (daddr=%pI4)\n", __func__,
			   &ip_hdr(skb)->daddr);
		rcu_read_unlock_bh();
		return -1;
	}

	/* why do we get all zero ethernet address ? */
	if (!is_valid_ether_addr(neigh->ha)) {
		rcu_read_unlock_bh();
		return -1;
	}

	memcpy(eth_hdr(skb)->h_dest, neigh->ha, ETH_ALEN);
	memcpy(eth_hdr(skb)->h_source, out->dev_addr, ETH_ALEN);

	rcu_read_unlock_bh();

	return 0;
}

static u16 ppe_get_chkbase(struct iphdr *iph)
{
	u16 org_chksum = ntohs(iph->check);
	u16 org_tot_len = ntohs(iph->tot_len);
	u16 org_id = ntohs(iph->id);
	u16 chksum_tmp, tot_len_tmp, id_tmp;
	u32 tmp = 0;
	u16 chksum_base = 0;

	chksum_tmp = ~(org_chksum);
	tot_len_tmp = ~(org_tot_len);
	id_tmp = ~(org_id);
	tmp = chksum_tmp + tot_len_tmp + id_tmp;
	tmp = ((tmp >> 16) & 0x7) + (tmp & 0xFFFF);
	tmp = ((tmp >> 16) & 0x7) + (tmp & 0xFFFF);
	chksum_base = tmp & 0xFFFF;

	return chksum_base;
}

struct foe_entry ppe_fill_L2_info(struct ethhdr *eth, struct foe_entry entry,
				  struct flow_offload_hw_path *hw_path)
{
	switch ((int)entry.bfib1.pkt_type) {
	case IPV4_HNAPT:
	case IPV4_HNAT:
		entry.ipv4_hnapt.dmac_hi = swab32(*((u32 *)eth->h_dest));
		entry.ipv4_hnapt.dmac_lo = swab16(*((u16 *)&eth->h_dest[4]));
		entry.ipv4_hnapt.smac_hi = swab32(*((u32 *)eth->h_source));
		entry.ipv4_hnapt.smac_lo = swab16(*((u16 *)&eth->h_source[4]));
		entry.ipv4_hnapt.pppoe_id = hw_path->pppoe_sid;
		break;
	case IPV4_DSLITE:
	case IPV4_MAP_E:
	case IPV6_6RD:
	case IPV6_5T_ROUTE:
	case IPV6_3T_ROUTE:
	case IPV6_HNAPT:
	case IPV6_HNAT:
		entry.ipv6_5t_route.dmac_hi = swab32(*((u32 *)eth->h_dest));
		entry.ipv6_5t_route.dmac_lo = swab16(*((u16 *)&eth->h_dest[4]));
		entry.ipv6_5t_route.smac_hi = swab32(*((u32 *)eth->h_source));
		entry.ipv6_5t_route.smac_lo =
			swab16(*((u16 *)&eth->h_source[4]));
		entry.ipv6_5t_route.pppoe_id = hw_path->pppoe_sid;
		break;
	}
	return entry;
}

struct foe_entry ppe_fill_info_blk(struct ethhdr *eth, struct foe_entry entry,
				   struct flow_offload_hw_path *hw_path)
{
	entry.bfib1.psn = (hw_path->flags & BIT(DEV_PATH_PPPOE)) ? 1 : 0;
	entry.bfib1.vlan_layer += (hw_path->flags & BIT(DEV_PATH_VLAN)) ? 1 : 0;
	entry.bfib1.vpm = (entry.bfib1.vlan_layer) ? 1 : 0;
	entry.bfib1.cah = 1;
	entry.bfib1.time_stamp = (hnat_priv->data->version == MTK_HNAT_V2 ||
				  hnat_priv->data->version == MTK_HNAT_V3) ?
		readl(hnat_priv->fe_base + 0x0010) & (0xFF) :
		readl(hnat_priv->fe_base + 0x0010) & (0x7FFF);

	switch ((int)entry.bfib1.pkt_type) {
	case IPV4_HNAPT:
	case IPV4_HNAT:
		if (hnat_priv->data->mcast &&
		    is_multicast_ether_addr(&eth->h_dest[0])) {
			entry.ipv4_hnapt.iblk2.mcast = 1;
			if (hnat_priv->data->version == MTK_HNAT_V1_3) {
				entry.bfib1.sta = 1;
				entry.ipv4_hnapt.m_timestamp = foe_timestamp(hnat_priv);
			}
		} else {
			entry.ipv4_hnapt.iblk2.mcast = 0;
		}

		entry.ipv4_hnapt.iblk2.port_ag =
			(hnat_priv->data->version == MTK_HNAT_V2 ||
			 hnat_priv->data->version == MTK_HNAT_V3) ? 0xf : 0x3f;
		break;
	case IPV4_DSLITE:
	case IPV4_MAP_E:
	case IPV6_6RD:
	case IPV6_5T_ROUTE:
	case IPV6_3T_ROUTE:
	case IPV6_HNAPT:
	case IPV6_HNAT:
		if (hnat_priv->data->mcast &&
		    is_multicast_ether_addr(&eth->h_dest[0])) {
			entry.ipv6_5t_route.iblk2.mcast = 1;
			if (hnat_priv->data->version == MTK_HNAT_V1_3) {
				entry.bfib1.sta = 1;
				entry.ipv4_hnapt.m_timestamp = foe_timestamp(hnat_priv);
			}
		} else {
			entry.ipv6_5t_route.iblk2.mcast = 0;
		}

		entry.ipv6_5t_route.iblk2.port_ag =
			(hnat_priv->data->version == MTK_HNAT_V2 ||
			 hnat_priv->data->version == MTK_HNAT_V3) ? 0xf : 0x3f;
		break;
	}
	return entry;
}

static struct ethhdr *get_ipv6_ipip_ethhdr(struct sk_buff *skb,
					   struct flow_offload_hw_path *hw_path)
{
	struct ethhdr *eth;
	u16 eth_pppoe_hlen = ETH_HLEN + PPPOE_SES_HLEN;

	if (hw_path->flags & BIT(DEV_PATH_PPPOE))
		eth = (struct ethhdr *)(skb->data - eth_pppoe_hlen);
	else
		eth = (struct ethhdr *)(skb->data - ETH_HLEN);

	return eth;
}

static atomic64_t hnat_flow_entry_sequence = ATOMIC64_INIT(0);

static bool hnat_flow_entry_format_compatible(const struct foe_entry *entry,
					     const struct foe_entry *data)
{
	u8 entry_type = entry->udib1.pkt_type;
	u8 data_type = data->udib1.pkt_type;

	return entry->udib1.udp == data->udib1.udp &&
	       (entry_type == data_type ||
		((entry_type == IPV6_HNAPT || entry_type == IPV6_HNAT) &&
		 data_type == IPV6_5T_ROUTE));
}

bool hnat_flow_entry_match(const struct foe_entry *entry,
			   const struct foe_entry *data)
{
	size_t offset, len;

	if (!hnat_flow_entry_format_compatible(entry, data))
		return false;

	switch (entry->udib1.pkt_type) {
	case IPV4_HNAPT:
	case IPV4_HNAT:
	case IPV4_DSLITE:
	case IPV4_MAP_T:
	case IPV4_MAP_E:
		offset = offsetof(struct hnat_ipv4_hnapt, sip);
		len = offsetof(struct hnat_ipv4_hnapt, info_blk2) - offset;
		break;
	case IPV6_3T_ROUTE:
		offset = offsetof(struct hnat_ipv6_3t_route, ipv6_sip0);
		len = offsetof(struct hnat_ipv6_3t_route, resv1) - offset;
		break;
	case IPV6_5T_ROUTE:
	case IPV6_6RD:
	case IPV6_HNAPT:
	case IPV6_HNAT:
		offset = offsetof(struct hnat_ipv6_5t_route, ipv6_sip0);
		len = offsetof(struct hnat_ipv6_5t_route, resv1) - offset;
		break;
	default:
		return false;
	}

	return !memcmp((const u8 *)entry + offset,
		       (const u8 *)data + offset, len);
}

static void hnat_flow_entry_free_rcu(struct rcu_head *head)
{
	struct hnat_flow_entry *flow = container_of(head, struct hnat_flow_entry, rcu);

	if (flow->tunnel_ct)
		nf_ct_put(flow->tunnel_ct);
	if (flow->tunnel_dev)
		dev_put(flow->tunnel_dev);
	kfree(flow);
}

void hnat_flow_entry_delete(struct hnat_flow_entry *flow_entry)
{
	hlist_del_init(&flow_entry->list);
	call_rcu(&flow_entry->rcu, hnat_flow_entry_free_rcu);
}

/* Caller holds flow_entry_lock. Buckets follow the official PPE/slot hash
 * chain; the saved key, rather than a hardware PRE_FILLED bit, is identity.
 */
static struct hnat_flow_entry *hnat_flow_entry_search(
		const struct foe_entry *data, u16 ppe_index, u16 hash, bool live_key)
{
	struct hnat_flow_entry *flow_entry;
	struct hlist_head *head;

	if (ppe_index >= MAX_PPE_NUM || ppe_index >= CFG_PPE_NUM ||
	    hash >= hnat_priv->foe_etry_num || !hnat_priv->foe_flow[ppe_index])
		return NULL;

	head = &hnat_priv->foe_flow[ppe_index][hash / 4];
	hlist_for_each_entry(flow_entry, head, list) {
		if (flow_entry->ppe_index == ppe_index &&
		    flow_entry->hash == hash &&
		    (live_key ? hnat_flow_entry_unbind_match(&flow_entry->data, data) :
		     hnat_flow_entry_match(&flow_entry->data, data)))
			return flow_entry;
	}

	return NULL;
}

/* A tunnel is invalidated before its firmware table index can be reused.
 * Keep descriptor mutation and retirement within HNAT's existing lock order.
 * Callbacks into NPU are never made while entry_lock is held.
 */
int hnat_tunnel_flush(u32 tops_entry)
{
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	struct hnat_flow_entry *flow;
	struct hlist_node *next;
	struct foe_entry *entry;
	u32 ppe, slot, code, count = 0;

	if (tops_entry && (tops_entry < 32 || tops_entry >= 64))
		return -EINVAL;
	if (!hnat_external_callback_enter())
		return -ENODEV;
	for (ppe = 0; ppe < hnat_priv->ppe_num && ppe < CFG_PPE_NUM &&
	     ppe < MAX_PPE_NUM; ppe++) {
		if (!hnat_priv->foe_table_cpu[ppe])
			continue;
		for (slot = 0; slot < hnat_priv->foe_etry_num; slot++) {
			spin_lock_bh(&hnat_priv->entry_lock);
			entry = &hnat_priv->foe_table_cpu[ppe][slot];
			if (entry->bfib1.state != BIND ||
			    !(IS_IPV4_GRP(entry) || IS_IPV6_GRP(entry)))
				goto next;
			if (IS_IPV4_GRP(entry)) {
				code = entry->ipv4_hnapt.tops_entry;
			} else {
				code = entry->ipv6_5t_route.tops_entry;
			}
			if (code < 32 || (tops_entry && code != tops_entry))
				goto next;
			if (!hnat_account_tunnel_invalidate(hnat_priv, ppe, slot)) {
				u32 info1 = READ_ONCE(entry->ipv4_hnapt.info_blk1);

				WRITE_ONCE(entry->ipv4_hnapt.info_blk1,
					   info1 & ~GENMASK(29, 28));
				dma_wmb();
			}
			spin_lock_bh(&hnat_priv->flow_entry_lock);
			if (hnat_priv->foe_flow[ppe])
				hlist_for_each_entry_safe(flow, next,
					&hnat_priv->foe_flow[ppe][slot / 4], list)
					if (flow->hash == slot)
						hnat_flow_entry_delete(flow);
			spin_unlock_bh(&hnat_priv->flow_entry_lock);
			count++;
		next:
			spin_unlock_bh(&hnat_priv->entry_lock);
		}
	}
	if (count)
		hnat_cache_ebl(1);
	hnat_external_callback_exit();
	return count;
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL_GPL(hnat_tunnel_flush);

/* pkt_type zero is IPv4 HNAPT, not an empty-slot marker. Only a zero
 * four-tuple in a dynamic UNBIND IPv4 slot is an unlearned identity. Its
 * prepared key must come from a live CT and be checked against the skb.
 */
static bool hnat_flow_entry_unbind_empty(const struct foe_entry *live)
{
	return live->udib1.pkt_type == IPV4_HNAPT && !live->udib1.sta &&
	       !READ_ONCE(live->ipv4_hnapt.sip) &&
	       !READ_ONCE(live->ipv4_hnapt.dip) &&
	       !READ_ONCE(live->ipv4_hnapt.sport) &&
	       !READ_ONCE(live->ipv4_hnapt.dport);
}

/* Software locks cannot prevent a concurrent PPE rewrite. Keep the live
 * state/key gate at every prefill and publication, including empty slots.
 */
bool hnat_flow_entry_unbind_match(const struct foe_entry *entry,
				  const struct foe_entry *live)
{
	u32 info_blk1 = READ_ONCE(live->ipv4_hnapt.info_blk1);
	bool match;
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
	const u32 identity_mask = GENMASK(31, 23);
#else
	const u32 identity_mask = GENMASK(31, 25);
#endif

	if (((info_blk1 >> 28) & 0x3) != UNBIND || (info_blk1 & BIT(31)))
		return false;
	dma_rmb();
	if (hnat_flow_entry_unbind_empty(live))
		match = entry->udib1.pkt_type == IPV4_HNAPT &&
			entry->ipv4_hnapt.sip && entry->ipv4_hnapt.dip;
	else
		match = hnat_flow_entry_match(entry, live);
	/* Ignore timestamps/counts; reject a state, format or protocol change. */
	return match && !((info_blk1 ^ READ_ONCE(live->ipv4_hnapt.info_blk1)) &
			 identity_mask);
}

static bool hnat_flow_entry_store(const struct foe_entry *entry, u32 ppe,
				  u32 slot, u64 generation, struct net_device *tunnel_dev,
				  struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	struct hnat_flow_entry *flow, *new_flow, *found = NULL;
	struct hlist_head *head;
	struct hlist_node *next;
	struct foe_entry *live;
	u64 seq;

	if (ppe >= MAX_PPE_NUM || ppe >= CFG_PPE_NUM ||
	    slot >= hnat_priv->foe_etry_num || !hnat_priv->foe_flow[ppe])
		return false;

	new_flow = kzalloc(sizeof(*new_flow), GFP_ATOMIC);
	if (!new_flow)
		return false;
	INIT_HLIST_NODE(&new_flow->list);
	if (tunnel_dev) {
		dev_hold(tunnel_dev);
		new_flow->tunnel_dev = tunnel_dev;
		if (ct) {
			nf_conntrack_get(&ct->ct_general);
			new_flow->tunnel_ct = ct;
			new_flow->tunnel_ctinfo = ctinfo;
		}
	}
	memcpy(&new_flow->data, entry, sizeof(*entry));
	new_flow->ppe_index = ppe;
	new_flow->hash = slot;
	new_flow->generation = generation;
	new_flow->last_update = jiffies;
	seq = atomic64_inc_return(&hnat_flow_entry_sequence);
	if (!seq)
		seq = atomic64_inc_return(&hnat_flow_entry_sequence);
	new_flow->sequence = seq;

	live = &hnat_priv->foe_table_cpu[ppe][slot];
	head = &hnat_priv->foe_flow[ppe][slot / 4];
	spin_lock_bh(&hnat_priv->flow_entry_lock);
	if (!hnat_flow_entry_unbind_match(entry, live)) {
		spin_unlock_bh(&hnat_priv->flow_entry_lock);
		hnat_flow_entry_delete(new_flow);
		return false;
	}

	/* A PPE slot has one current key. Retire any old identity for this
	 * slot before adding the new one, while preserving the bucket chain.
	 */
	hlist_for_each_entry_safe(flow, next, head, list) {
		if (flow->ppe_index != ppe || flow->hash != slot)
			continue;
		if (hnat_flow_entry_match(&flow->data, entry) && !found) {
			found = flow;
			continue;
		}
		hnat_flow_entry_delete(flow);
	}
	if (found) {
		memcpy(&found->data, entry, sizeof(*entry));
		found->generation = generation;
		found->last_update = jiffies;
		found->sequence = seq;
		{
			struct net_device *old_dev = found->tunnel_dev;
			struct nf_conn *old_ct = found->tunnel_ct;

			found->tunnel_dev = new_flow->tunnel_dev;
			found->tunnel_ct = new_flow->tunnel_ct;
			found->tunnel_ctinfo = new_flow->tunnel_ctinfo;
			new_flow->tunnel_dev = old_dev;
			new_flow->tunnel_ct = old_ct;
		}
		hnat_flow_entry_delete(new_flow);
	} else {
		hlist_add_head(&new_flow->list, head);
	}
	spin_unlock_bh(&hnat_priv->flow_entry_lock);
	return true;
}

static void hnat_flow_sweep(struct net_device *dev)
{
	struct hnat_flow_entry *flow;
	struct hlist_node *next;
	u32 ppe, bucket;

	for (ppe = 0; ppe < CFG_PPE_NUM && ppe < MAX_PPE_NUM; ppe++) {
		if (!hnat_priv->foe_flow[ppe])
			continue;
		for (bucket = 0; bucket < DIV_ROUND_UP(hnat_priv->foe_etry_num, 4); bucket++) {
			spin_lock_bh(&hnat_priv->flow_entry_lock);
			hlist_for_each_entry_safe(flow, next,
					&hnat_priv->foe_flow[ppe][bucket], list) {
				if (dev ? flow->tunnel_dev == dev :
				    time_after_eq(jiffies, flow->last_update + 3 * HZ))
					hnat_flow_entry_delete(flow);
			}
			spin_unlock_bh(&hnat_priv->flow_entry_lock);
		}
	}
}

static void hnat_flow_drop_dev(struct net_device *dev)
{
	hnat_flow_sweep(dev);
}

static void hnat_flow_gc_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(hnat_flow_gc, hnat_flow_gc_work);
static void hnat_flow_gc_work(struct work_struct *work)
{
	hnat_flow_sweep(NULL);
	schedule_delayed_work(&hnat_flow_gc, 5 * HZ);
}

void hnat_flow_gc_start(void)
{
	schedule_delayed_work(&hnat_flow_gc, 5 * HZ);
}

void hnat_flow_gc_stop(void)
{
	cancel_delayed_work_sync(&hnat_flow_gc);
}

/* Caller holds entry_lock; success returns with flow_entry_lock held. */
static bool hnat_flow_entry_lock_current(const struct foe_entry *key,
					 u32 ppe, u32 slot,
					 u64 generation, u64 sequence,
					 struct hnat_flow_entry **result)
{
	struct hnat_flow_entry *flow;

	spin_lock_bh(&hnat_priv->flow_entry_lock);
	flow = hnat_flow_entry_search(key, ppe, slot, false);
	if (!flow ||
	    time_after_eq(jiffies, flow->last_update + 3 * HZ) ||
	    flow->generation != generation || flow->sequence != sequence) {
		if (flow && time_after_eq(jiffies, flow->last_update + 3 * HZ))
			hnat_flow_entry_delete(flow);
		spin_unlock_bh(&hnat_priv->flow_entry_lock);
		return false;
	}
	*result = flow;
	return true;
}

void hnat_flow_entry_clear(u32 ppe_id)
{
	struct hnat_flow_entry *flow_entry;
	struct hlist_head *head;
	struct hlist_node *n;
	u32 index;

	if (!hnat_priv || ppe_id >= MAX_PPE_NUM ||
	    ppe_id >= CFG_PPE_NUM || !hnat_priv->foe_flow[ppe_id])
		return;

	spin_lock_bh(&hnat_priv->flow_entry_lock);
	for (index = 0; index < hnat_priv->foe_etry_num / 4; index++) {
		head = &hnat_priv->foe_flow[ppe_id][index];
		hlist_for_each_entry_safe(flow_entry, n, head, list)
			hnat_flow_entry_delete(flow_entry);
	}
	spin_unlock_bh(&hnat_priv->flow_entry_lock);
}

/* Only inspect unambiguously ordinary IPv4 packets. skb_header_pointer()
 * safely handles non-linear data. Reject the generic encapsulation marker,
 * fragments, malformed headers and unsupported protocols. This path does
 * not infer proprietary TOPS tunnel metadata that this skb API does not expose.
 */
static bool hnat_flow_ipv4_tuple_match(const struct sk_buff *skb,
				       const struct foe_entry *entry)
{
	struct iphdr iph_buf, *iph;
	struct tcpudphdr ports_buf, *ports;
	int offset = skb_network_offset(skb);
	unsigned int ihl;
	u16 total_len;

	if (entry->udib1.pkt_type != IPV4_HNAPT &&
	    entry->udib1.pkt_type != IPV4_HNAT)
		return true;
	if (skb->protocol != htons(ETH_P_IP) || offset < 0 ||
	    (unsigned int)offset > skb->len || skb->encapsulation)
		return false;

	iph = skb_header_pointer(skb, offset, sizeof(iph_buf), &iph_buf);
	if (!iph || iph->version != 4 || iph->ihl < 5 || ip_is_fragment(iph))
		return false;
	ihl = iph->ihl * 4;
	total_len = ntohs(iph->tot_len);
	if (total_len < ihl + sizeof(ports_buf) ||
	    total_len > skb->len - (unsigned int)offset)
		return false;
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return false;
	if ((iph->protocol == IPPROTO_UDP) != !!entry->udib1.udp)
		return false;

	ports = skb_header_pointer(skb, offset + ihl, sizeof(ports_buf),
				   &ports_buf);
	if (!ports)
		return false;

	return ntohl(iph->saddr) == entry->ipv4_hnapt.new_sip &&
	       ntohl(iph->daddr) == entry->ipv4_hnapt.new_dip &&
	       ntohs(ports->src) == entry->ipv4_hnapt.new_sport &&
	       ntohs(ports->dst) == entry->ipv4_hnapt.new_dport;
}

/*
 * WHNAT prefill starts with a hardware key and fills the translated side from
 * the current skb.  For ordinary IPv4 TCP/UDP, require those two views to be
 * one conntrack direction: key == tuple[dir], and current/post-NAT tuple ==
 * reverse(tuple[!dir]).  Without a usable CT, only identity tuples are
 * provable.  Encapsulated and other FOE formats remain outside this check.
 */
static bool hnat_flow_ipv4_ct_match(const struct sk_buff *skb,
				    const struct foe_entry *entry,
				    const struct nf_conn *ct,
				    enum ip_conntrack_info ctinfo)
{
	const struct nf_conntrack_tuple *key, *translated;
	u8 proto;
	unsigned int dir;

	if (entry->udib1.pkt_type != IPV4_HNAPT &&
	    entry->udib1.pkt_type != IPV4_HNAT)
		return true;

	if (skb && !hnat_flow_ipv4_tuple_match(skb, entry))
		return false;
	if (!ct || nf_ct_is_template(ct) || nf_ct_is_dying(ct))
		return entry->ipv4_hnapt.sip == entry->ipv4_hnapt.new_sip &&
		       entry->ipv4_hnapt.dip == entry->ipv4_hnapt.new_dip &&
		       entry->ipv4_hnapt.sport == entry->ipv4_hnapt.new_sport &&
		       entry->ipv4_hnapt.dport == entry->ipv4_hnapt.new_dport;

	proto = entry->udib1.udp ? IPPROTO_UDP : IPPROTO_TCP;
	dir = CTINFO2DIR(ctinfo);
	key = nf_ct_tuple(ct, dir);
	translated = nf_ct_tuple(ct, !dir);
	if (key->src.l3num != NFPROTO_IPV4 ||
	    translated->src.l3num != NFPROTO_IPV4 ||
	    key->dst.protonum != proto || translated->dst.protonum != proto)
		return false;

	return ntohl(key->src.u3.ip) == entry->ipv4_hnapt.sip &&
	       ntohl(key->dst.u3.ip) == entry->ipv4_hnapt.dip &&
	       ntohs(key->src.u.all) == entry->ipv4_hnapt.sport &&
	       ntohs(key->dst.u.all) == entry->ipv4_hnapt.dport &&
	       ntohl(translated->dst.u3.ip) == entry->ipv4_hnapt.new_sip &&
	       ntohl(translated->src.u3.ip) == entry->ipv4_hnapt.new_dip &&
	       ntohs(translated->dst.u.all) == entry->ipv4_hnapt.new_sport &&
	       ntohs(translated->src.u.all) == entry->ipv4_hnapt.new_dport;
}

/* Classify only a header-only TCP packet whose complete headers are readable.
 * Do not change skb header offsets: later consumers still own those offsets.
 */
static bool hnat_tcp_no_payload(const struct sk_buff *skb, u16 h_proto)
{
	struct iphdr iph_buf, *iph;
	struct ipv6hdr ip6h_buf, *ip6h;
	struct tcphdr tcp_buf, *tcp;
	int offset = skb_network_offset(skb);
	u32 len, l3_len, l4_len;

	if (offset < 0 || (unsigned int)offset > skb->len || skb->encapsulation)
		return false;
	if (h_proto == ETH_P_IP) {
		iph = skb_header_pointer(skb, offset, sizeof(iph_buf), &iph_buf);
		if (!iph || iph->version != 4 || iph->ihl < 5 ||
		    iph->protocol != IPPROTO_TCP || ip_is_fragment(iph))
			return false;
		l3_len = iph->ihl * 4;
		len = ntohs(iph->tot_len);
	} else if (h_proto == ETH_P_IPV6) {
		ip6h = skb_header_pointer(skb, offset, sizeof(ip6h_buf), &ip6h_buf);
		if (!ip6h || ip6h->version != 6 || ip6h->nexthdr != IPPROTO_TCP)
			return false;
		l3_len = sizeof(ip6h_buf);
		len = l3_len + ntohs(ip6h->payload_len);
	} else {
		return false;
	}
	if (len > skb->len - (unsigned int)offset ||
	    len < l3_len + sizeof(tcp_buf))
		return false;
	tcp = skb_header_pointer(skb, offset + l3_len, sizeof(tcp_buf), &tcp_buf);
	if (!tcp || tcp->doff < 5)
		return false;
	l4_len = tcp->doff * 4;
	return len == l3_len + l4_len;
}

static u32 hnat_select_qid(const struct sk_buff *skb,
			   const struct net_device *dev, int port_id,
			   u8 dscp, u16 h_proto)
{
	u32 mark = skb->mark & MTK_QDMA_TX_MASK;
	u32 qid;

	/* A selected queue (including a routing mark's low bits) is already a
	 * complete QID, never a per-port offset. Adding a PSE destination to it
	 * can exceed MTK_QDMA_TX_MASK, e.g. 0x50535731 + GMAC3 selects QID 64.
	 */
	if (IS_HQOS_MODE)
		return dscp && hnat_priv->dscp_en ? (dscp >> 2) & MTK_QDMA_TX_MASK : mark;
	/* PPPQ uses the Ethernet driver's queue map, not the wider manual
	 * HNAT/HQoS namespace. Keep unrelated high routing-mark bits out of it.
	 */
	if (IS_PPPQ_MODE)
		mark &= MTK_QDMA_NUM_QUEUES - 1;
	if (mark >= MAX_PPPQ_PORT_NUM)
		return mark;
	if (!IS_PPPQ_MODE || !IS_PPPQ_PATH(dev, skb) ||
	    port_id < 0 || port_id >= MAX_PPPQ_PORT_NUM)
		return 0;

	/* PPPQ data queues 0..5 and TCP ACK queues 6..11. A PSE destination
	 * such as GMAC3 (15) is not a QDMA queue offset.
	 */
	qid = port_id;
	if (hnat_tcp_no_payload(skb, h_proto))
		qid += MAX_PPPQ_PORT_NUM;
	return qid & MTK_QDMA_TX_MASK;
}

static unsigned int skb_to_hnat_info(struct sk_buff *skb,
				     const struct net_device *dev,
				     struct foe_entry *foe,
				     struct flow_offload_hw_path *hw_path)
{
	struct net_device *master_dev = (struct net_device *)dev;
	struct foe_entry entry = { 0 };
	struct mtk_mac *mac;
	int whnat = IS_WHNAT(dev);
	bool tunnel_prefill = false;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	tunnel_prefill = skb_hnat_tops(skb) &&
		(hw_path->flags & BIT(DEV_PATH_TNL));
#endif
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcpudphdr _ports;
	const struct tcpudphdr *pptr;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	int gmac = NR_DISCARD;
	int udp = 0;
	bool account_handled, accepted = false;
	bool empty_key = hnat_flow_entry_unbind_empty(foe);
	u64 account_generation = 0;
	u32 qid = 0;
	int port_id = 0;
	int mape = 0;
	u8  dscp = 0;


	ct = nf_ct_get(skb, &ctinfo);

	if (ipv6_hdr(skb)->nexthdr == NEXTHDR_IPIP)
		/* point to ethernet header for DS-Lite and MapE */
		eth = get_ipv6_ipip_ethhdr(skb, hw_path);
	else
		eth = eth_hdr(skb);

	/*do not bind multicast if PPE mcast not enable*/
	if (!hnat_priv->data->mcast && !hnat_npu_mcast_active() &&
	    is_multicast_ether_addr(eth->h_dest))
		return 0;

	if (whnat && is_hnat_info_filled(skb))
		return 0;

	entry.bfib1.pkt_type = foe->udib1.pkt_type; /* Get packte type state*/
	entry.bfib1.state = foe->udib1.state;

	if (unlikely(entry.bfib1.state != UNBIND))
		return 0;

#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
	entry.bfib1.sp = foe->udib1.sp;
#endif

	switch (ntohs(eth->h_proto)) {
	case ETH_P_IP:
		iph = ip_hdr(skb);
		/* Do not bind if pkt is fragmented */
		if (ip_is_fragment(iph))
			return 0;

		switch (iph->protocol) {
		case IPPROTO_UDP:
			udp = 1;
			fallthrough;
			/* fallthrough */
		case IPPROTO_TCP:
			entry.ipv4_hnapt.etype = htons(ETH_P_IP);

			/* DS-Lite WAN->LAN */
			if (entry.ipv4_hnapt.bfib1.pkt_type == IPV4_DSLITE ||
			    entry.ipv4_hnapt.bfib1.pkt_type == IPV4_MAP_E) {
				entry.ipv4_dslite.sip = foe->ipv4_dslite.sip;
				entry.ipv4_dslite.dip = foe->ipv4_dslite.dip;
				entry.ipv4_dslite.sport =
					foe->ipv4_dslite.sport;
				entry.ipv4_dslite.dport =
					foe->ipv4_dslite.dport;

#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
				if (entry.bfib1.pkt_type == IPV4_MAP_E) {
					pptr = skb_header_pointer(skb,
								  iph->ihl * 4,
								  sizeof(_ports),
								  &_ports);
					if (unlikely(!pptr))
						return -1;

					entry.ipv4_mape.new_sip =
							ntohl(iph->saddr);
					entry.ipv4_mape.new_dip =
							ntohl(iph->daddr);
					entry.ipv4_mape.new_sport =
							ntohs(pptr->src);
					entry.ipv4_mape.new_dport =
							ntohs(pptr->dst);
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
					entry.ipv4_mape.eg_keep_ecn = 1;
					entry.ipv4_mape.eg_keep_dscp = 1;
#endif
				}
#endif

				entry.ipv4_dslite.tunnel_sipv6_0 =
					foe->ipv4_dslite.tunnel_sipv6_0;
				entry.ipv4_dslite.tunnel_sipv6_1 =
					foe->ipv4_dslite.tunnel_sipv6_1;
				entry.ipv4_dslite.tunnel_sipv6_2 =
					foe->ipv4_dslite.tunnel_sipv6_2;
				entry.ipv4_dslite.tunnel_sipv6_3 =
					foe->ipv4_dslite.tunnel_sipv6_3;

				entry.ipv4_dslite.tunnel_dipv6_0 =
					foe->ipv4_dslite.tunnel_dipv6_0;
				entry.ipv4_dslite.tunnel_dipv6_1 =
					foe->ipv4_dslite.tunnel_dipv6_1;
				entry.ipv4_dslite.tunnel_dipv6_2 =
					foe->ipv4_dslite.tunnel_dipv6_2;
				entry.ipv4_dslite.tunnel_dipv6_3 =
					foe->ipv4_dslite.tunnel_dipv6_3;

				entry.ipv4_dslite.bfib1.rmt = 1;
				entry.ipv4_dslite.iblk2.dscp = iph->tos;
				entry.ipv4_dslite.vlan1 = hw_path->vlan_id;
				if (hnat_priv->data->per_flow_accounting)
					entry.ipv4_dslite.iblk2.mibf = 1;

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.ipv4_dslite.eg_keep_ecn = 1;
				entry.ipv4_dslite.eg_keep_cls = 1;
#endif

			} else {
				entry.ipv4_hnapt.iblk2.dscp = iph->tos;
				dscp = iph->tos;
				if (hnat_priv->data->per_flow_accounting)
					entry.ipv4_hnapt.iblk2.mibf = 1;

				entry.ipv4_hnapt.vlan1 = hw_path->vlan_id;

				if (skb_vlan_tagged(skb)) {
					entry.bfib1.vlan_layer += 1;

					if (entry.ipv4_hnapt.vlan1)
						entry.ipv4_hnapt.vlan2 =
							skb->vlan_tci;
					else
						entry.ipv4_hnapt.vlan1 =
							skb->vlan_tci;
			}

				entry.ipv4_hnapt.sip = foe->ipv4_hnapt.sip;
				entry.ipv4_hnapt.dip = foe->ipv4_hnapt.dip;
				entry.ipv4_hnapt.sport = foe->ipv4_hnapt.sport;
				entry.ipv4_hnapt.dport = foe->ipv4_hnapt.dport;
				if (empty_key) {
					const struct nf_conntrack_tuple *key;

					if (!ct || !nf_ct_is_confirmed(ct) || nf_ct_is_template(ct) || nf_ct_is_dying(ct))
						return 0;
					key = nf_ct_tuple(ct, CTINFO2DIR(ctinfo));
					if (key->src.l3num != NFPROTO_IPV4 ||
					    key->dst.protonum != iph->protocol)
						return 0;
					entry.ipv4_hnapt.sip = ntohl(key->src.u3.ip);
					entry.ipv4_hnapt.dip = ntohl(key->dst.u3.ip);
					entry.ipv4_hnapt.sport = ntohs(key->src.u.all);
					entry.ipv4_hnapt.dport = ntohs(key->dst.u.all);
				}

				entry.ipv4_hnapt.new_sip = ntohl(iph->saddr);
				entry.ipv4_hnapt.new_dip = ntohl(iph->daddr);
			}

			entry.ipv4_hnapt.bfib1.udp = udp;
			if (IS_IPV4_HNAPT(foe) || IS_IPV4_HNAT(foe)) {
				pptr = skb_header_pointer(skb, iph->ihl * 4,
							  sizeof(_ports),
							  &_ports);
				if (unlikely(!pptr))
					return -1;

				entry.ipv4_hnapt.new_sport = ntohs(pptr->src);
				entry.ipv4_hnapt.new_dport = ntohs(pptr->dst);
			}

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
			entry.ipv4_hnapt.eg_keep_ecn = 1;
			entry.ipv4_hnapt.eg_keep_dscp = 1;
#endif

			break;

		default:
			return -1;
		}
		pr_debug_ratelimited(
			"[%s]skb->head=%p, skb->data=%p,ip_hdr=%p, skb->len=%d, skb->data_len=%d\n",
			__func__, skb->head, skb->data, iph, skb->len,
			skb->data_len);
		break;

	case ETH_P_IPV6:
		ip6h = ipv6_hdr(skb);
		switch (ip6h->nexthdr) {
		case NEXTHDR_UDP:
			udp = 1;
			fallthrough;
			/* fallthrough */
		case NEXTHDR_TCP: /* IPv6-5T or IPv6-3T */
			entry.ipv6_5t_route.etype = htons(ETH_P_IPV6);

			entry.ipv6_5t_route.vlan1 = hw_path->vlan_id;

			if (skb_vlan_tagged(skb)) {
				entry.bfib1.vlan_layer += 1;

				if (entry.ipv6_5t_route.vlan1)
					entry.ipv6_5t_route.vlan2 =
						skb->vlan_tci;
				else
					entry.ipv6_5t_route.vlan1 =
						skb->vlan_tci;
			}

			if (hnat_priv->data->per_flow_accounting)
				entry.ipv6_5t_route.iblk2.mibf = 1;
			entry.ipv6_5t_route.bfib1.udp = udp;

			if (IS_IPV6_6RD(foe)) {
				entry.ipv6_5t_route.bfib1.rmt = 1;
				entry.ipv6_6rd.tunnel_sipv4 =
					foe->ipv6_6rd.tunnel_sipv4;
				entry.ipv6_6rd.tunnel_dipv4 =
					foe->ipv6_6rd.tunnel_dipv4;

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.ipv6_6rd.eg_keep_ecn = 1;
				entry.ipv6_6rd.eg_keep_cls = 1;
#endif
			}

			entry.ipv6_3t_route.ipv6_sip0 =
				foe->ipv6_3t_route.ipv6_sip0;
			entry.ipv6_3t_route.ipv6_sip1 =
				foe->ipv6_3t_route.ipv6_sip1;
			entry.ipv6_3t_route.ipv6_sip2 =
				foe->ipv6_3t_route.ipv6_sip2;
			entry.ipv6_3t_route.ipv6_sip3 =
				foe->ipv6_3t_route.ipv6_sip3;

			entry.ipv6_3t_route.ipv6_dip0 =
				foe->ipv6_3t_route.ipv6_dip0;
			entry.ipv6_3t_route.ipv6_dip1 =
				foe->ipv6_3t_route.ipv6_dip1;
			entry.ipv6_3t_route.ipv6_dip2 =
				foe->ipv6_3t_route.ipv6_dip2;
			entry.ipv6_3t_route.ipv6_dip3 =
				foe->ipv6_3t_route.ipv6_dip3;

			if (IS_IPV6_3T_ROUTE(foe)) {
				entry.ipv6_3t_route.prot =
					foe->ipv6_3t_route.prot;
				entry.ipv6_3t_route.hph =
					foe->ipv6_3t_route.hph;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.ipv6_3t_route.eg_keep_ecn = 1;
				entry.ipv6_3t_route.eg_keep_cls = 1;
#endif
			}

			if (IS_IPV6_5T_ROUTE(foe) || IS_IPV6_6RD(foe)) {
				entry.ipv6_5t_route.sport =
					foe->ipv6_5t_route.sport;
				entry.ipv6_5t_route.dport =
					foe->ipv6_5t_route.dport;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.ipv6_5t_route.eg_keep_ecn = 1;
				entry.ipv6_5t_route.eg_keep_cls = 1;
#endif
			}

			if (ct && (ct->status & IPS_SRC_NAT)) {
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.bfib1.pkt_type = IPV6_HNAPT;

				if (IS_WAN(dev) || IS_DSA_WAN(dev)) {
					entry.ipv6_hnapt.eg_ipv6_dir =
						IPV6_SNAT;
					entry.ipv6_hnapt.new_ipv6_ip0 =
						ntohl(ip6h->saddr.s6_addr32[0]);
					entry.ipv6_hnapt.new_ipv6_ip1 =
						ntohl(ip6h->saddr.s6_addr32[1]);
					entry.ipv6_hnapt.new_ipv6_ip2 =
						ntohl(ip6h->saddr.s6_addr32[2]);
					entry.ipv6_hnapt.new_ipv6_ip3 =
						ntohl(ip6h->saddr.s6_addr32[3]);
				} else {
					entry.ipv6_hnapt.eg_ipv6_dir =
						IPV6_DNAT;
					entry.ipv6_hnapt.new_ipv6_ip0 =
						ntohl(ip6h->daddr.s6_addr32[0]);
					entry.ipv6_hnapt.new_ipv6_ip1 =
						ntohl(ip6h->daddr.s6_addr32[1]);
					entry.ipv6_hnapt.new_ipv6_ip2 =
						ntohl(ip6h->daddr.s6_addr32[2]);
					entry.ipv6_hnapt.new_ipv6_ip3 =
						ntohl(ip6h->daddr.s6_addr32[3]);
				}

				pptr = skb_header_pointer(skb, IPV6_HDR_LEN,
							  sizeof(_ports),
							  &_ports);
				if (unlikely(!pptr))
					return -1;

				entry.ipv6_hnapt.new_sport = ntohs(pptr->src);
				entry.ipv6_hnapt.new_dport = ntohs(pptr->dst);
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.ipv6_hnapt.eg_keep_ecn = 1;
				entry.ipv6_hnapt.eg_keep_cls = 1;
#endif
#else
				return -1;
#endif
			}

			entry.ipv6_5t_route.iblk2.dscp =
				(ip6h->priority << 4 |
				 (ip6h->flow_lbl[0] >> 4));
			break;

		case NEXTHDR_IPIP:
			iph = (struct iphdr *)skb_inner_network_header(skb);
			/* don't process inner fragment packets */
			if (ip_is_fragment(iph))
				return 0;

			if ((!mape_toggle &&
			     entry.bfib1.pkt_type == IPV4_DSLITE) ||
			    (mape_toggle &&
			     entry.bfib1.pkt_type == IPV4_MAP_E)) {
				/* DS-Lite LAN->WAN */
				entry.ipv4_dslite.bfib1.udp =
					foe->ipv4_dslite.bfib1.udp;
				entry.ipv4_dslite.sip = foe->ipv4_dslite.sip;
				entry.ipv4_dslite.dip = foe->ipv4_dslite.dip;
				entry.ipv4_dslite.sport =
					foe->ipv4_dslite.sport;
				entry.ipv4_dslite.dport =
					foe->ipv4_dslite.dport;

				entry.ipv4_dslite.tunnel_sipv6_0 =
					ntohl(ip6h->saddr.s6_addr32[0]);
				entry.ipv4_dslite.tunnel_sipv6_1 =
					ntohl(ip6h->saddr.s6_addr32[1]);
				entry.ipv4_dslite.tunnel_sipv6_2 =
					ntohl(ip6h->saddr.s6_addr32[2]);
				entry.ipv4_dslite.tunnel_sipv6_3 =
					ntohl(ip6h->saddr.s6_addr32[3]);

				entry.ipv4_dslite.tunnel_dipv6_0 =
					ntohl(ip6h->daddr.s6_addr32[0]);
				entry.ipv4_dslite.tunnel_dipv6_1 =
					ntohl(ip6h->daddr.s6_addr32[1]);
				entry.ipv4_dslite.tunnel_dipv6_2 =
					ntohl(ip6h->daddr.s6_addr32[2]);
				entry.ipv4_dslite.tunnel_dipv6_3 =
					ntohl(ip6h->daddr.s6_addr32[3]);

				ppe_fill_flow_lbl(&entry, ip6h);

				entry.ipv4_dslite.priority = ip6h->priority;
				entry.ipv4_dslite.hop_limit = ip6h->hop_limit;
				entry.ipv4_dslite.vlan1 = hw_path->vlan_id;
				if (hnat_priv->data->per_flow_accounting)
					entry.ipv4_dslite.iblk2.mibf = 1;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.ipv4_dslite.eg_keep_ecn = 1;
				entry.ipv4_dslite.eg_keep_cls = 1;
#endif
				/* Map-E LAN->WAN record inner IPv4 header info. */
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
				if (mape_toggle) {
					entry.ipv4_dslite.iblk2.dscp = foe->ipv4_dslite.iblk2.dscp;
					entry.ipv4_mape.new_sip = foe->ipv4_mape.new_sip;
					entry.ipv4_mape.new_dip = foe->ipv4_mape.new_dip;
					entry.ipv4_mape.new_sport = foe->ipv4_mape.new_sport;
					entry.ipv4_mape.new_dport = foe->ipv4_mape.new_dport;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
					entry.ipv4_mape.eg_keep_ecn = 1;
					entry.ipv4_mape.eg_keep_dscp = 1;
#endif
				}
#endif
			} else if (mape_toggle &&
				   entry.bfib1.pkt_type == IPV4_HNAPT) {
				/* MapE LAN -> WAN */
				mape = 1;
				entry.ipv4_hnapt.iblk2.dscp =
					foe->ipv4_hnapt.iblk2.dscp;
				dscp = foe->ipv4_hnapt.iblk2.dscp;
				if (hnat_priv->data->per_flow_accounting)
					entry.ipv4_hnapt.iblk2.mibf = 1;

				if (IS_GMAC1_MODE)
					entry.ipv4_hnapt.vlan1 = 1;
				else
					entry.ipv4_hnapt.vlan1 = hw_path->vlan_id;

				entry.ipv4_hnapt.sip = foe->ipv4_hnapt.sip;
				entry.ipv4_hnapt.dip = foe->ipv4_hnapt.dip;
				entry.ipv4_hnapt.sport = foe->ipv4_hnapt.sport;
				entry.ipv4_hnapt.dport = foe->ipv4_hnapt.dport;

				entry.ipv4_hnapt.new_sip =
					foe->ipv4_hnapt.new_sip;
				entry.ipv4_hnapt.new_dip =
					foe->ipv4_hnapt.new_dip;
				entry.ipv4_hnapt.etype = htons(ETH_P_IP);

				if (IS_HQOS_MODE) {
					entry.ipv4_hnapt.iblk2.qid =
						(hnat_priv->data->version ==
						 MTK_HNAT_V2 ||
						 hnat_priv->data->version ==
						 MTK_HNAT_V3) ?
						 skb->mark & 0x7f : skb->mark & 0xf;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
					if ((IS_HQOS_UL_MODE && IS_WAN(dev)) ||
					    (IS_HQOS_DL_MODE &&
					     IS_LAN_GRP(dev)) ||
					    (IS_PPPQ_MODE &&
					     IS_PPPQ_PATH(dev, skb)))
						entry.ipv4_hnapt.tport_id = 1;
					else
						entry.ipv4_hnapt.tport_id = 0;
#endif
					entry.ipv4_hnapt.iblk2.fqos = 1;
				}

				entry.ipv4_hnapt.bfib1.udp =
					foe->ipv4_hnapt.bfib1.udp;

				entry.ipv4_hnapt.new_sport =
					foe->ipv4_hnapt.new_sport;
				entry.ipv4_hnapt.new_dport =
					foe->ipv4_hnapt.new_dport;
				mape_l2w_v6h = *ip6h;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.ipv4_hnapt.eg_keep_ecn = 1;
				entry.ipv4_hnapt.eg_keep_dscp = 1;
#endif
			}
			break;

		default:
			return -1;
		}

		pr_debug_ratelimited(
			"[%s]skb->head=%p, skb->data=%p,ipv6_hdr=%p, skb->len=%d, skb->data_len=%d\n",
			__func__, skb->head, skb->data, ip6h, skb->len,
			skb->data_len);
		break;

	default:
		iph = ip_hdr(skb);
		switch (entry.bfib1.pkt_type) {
		case IPV6_6RD: /* 6RD LAN->WAN */
			entry.ipv6_6rd.ipv6_sip0 = foe->ipv6_6rd.ipv6_sip0;
			entry.ipv6_6rd.ipv6_sip1 = foe->ipv6_6rd.ipv6_sip1;
			entry.ipv6_6rd.ipv6_sip2 = foe->ipv6_6rd.ipv6_sip2;
			entry.ipv6_6rd.ipv6_sip3 = foe->ipv6_6rd.ipv6_sip3;

			entry.ipv6_6rd.ipv6_dip0 = foe->ipv6_6rd.ipv6_dip0;
			entry.ipv6_6rd.ipv6_dip1 = foe->ipv6_6rd.ipv6_dip1;
			entry.ipv6_6rd.ipv6_dip2 = foe->ipv6_6rd.ipv6_dip2;
			entry.ipv6_6rd.ipv6_dip3 = foe->ipv6_6rd.ipv6_dip3;

			entry.ipv6_6rd.sport = foe->ipv6_6rd.sport;
			entry.ipv6_6rd.dport = foe->ipv6_6rd.dport;
			entry.ipv6_6rd.tunnel_sipv4 = ntohl(iph->saddr);
			entry.ipv6_6rd.tunnel_dipv4 = ntohl(iph->daddr);
			entry.ipv6_6rd.hdr_chksum = ppe_get_chkbase(iph);
			entry.ipv6_6rd.flag = (ntohs(iph->frag_off) >> 13);
			entry.ipv6_6rd.ttl = iph->ttl;
			entry.ipv6_6rd.dscp = iph->tos;
			entry.ipv6_6rd.per_flow_6rd_id = 1;
			entry.ipv6_6rd.vlan1 = hw_path->vlan_id;
			if (hnat_priv->data->per_flow_accounting)
				entry.ipv6_6rd.iblk2.mibf = 1;

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
			entry.ipv6_6rd.eg_keep_ecn = 1;
			entry.ipv6_6rd.eg_keep_cls = 1;
#endif
			break;

		default:
			return -1;
		}
	}

	/* Fill Layer2 Info.*/
	entry = ppe_fill_L2_info(eth, entry, hw_path);

	/* Fill Info Blk*/
	entry = ppe_fill_info_blk(eth, entry, hw_path);

	if (tunnel_prefill) {
		/* Software-only prepared entry; final physical egress is filled later. */
		gmac = NR_PDMA_PORT;
	} else if (IS_LAN_GRP(dev) || IS_WAN(dev)) { /* Forward to GMAC Ports */
		port_id = hnat_dsa_get_port(&master_dev);
		if (port_id >= 0) {
			if (hnat_dsa_fill_stag(dev, &entry, hw_path,
					       ntohs(eth->h_proto), mape) < 0)
				return 0;
		}
		mac = netdev_priv(master_dev);
		gmac = HNAT_GMAC_FP(mac->id);
		if (IS_WAN(dev) && mape_toggle && mape == 1) {
			gmac = NR_PDMA_PORT;
			/* Set act_dp = wan_dev */
			entry.ipv4_hnapt.act_dp &= ~UDF_PINGPONG_IFIDX;
			entry.ipv4_hnapt.act_dp |= dev->ifindex & UDF_PINGPONG_IFIDX;
		}
	} else if (IS_EXT(dev)) {
		if (!hnat_priv->data->whnat && IS_GMAC1_MODE) {
			entry.bfib1.vpm = 1;
			entry.bfib1.vlan_layer = 1;

			if (FROM_GE_LAN(skb))
				entry.ipv4_hnapt.vlan1 = 1;
			else if (FROM_GE_WAN(skb) || FROM_GE_VIRTUAL(skb))
				entry.ipv4_hnapt.vlan1 = 2;
		}

		pr_debug_ratelimited("learn of lan or wan(iif=%x) --> %s(ext)\n",
			     skb_hnat_iface(skb), dev->name);
		/* To CPU then stolen by pre-routing hant hook of LAN/WAN
		 * Current setting is PDMA RX.
		 */
		gmac = NR_PDMA_PORT;
		if (IS_IPV4_GRP(foe)) {
			entry.ipv4_hnapt.act_dp &= ~UDF_PINGPONG_IFIDX;
			entry.ipv4_hnapt.act_dp |= dev->ifindex & UDF_PINGPONG_IFIDX;
		} else {
			entry.ipv6_5t_route.act_dp &= ~UDF_PINGPONG_IFIDX;
			entry.ipv6_5t_route.act_dp |= dev->ifindex & UDF_PINGPONG_IFIDX;
		}
	} else {
		gmac = -EINVAL;
	}

	if (gmac < 0) {
		printk_ratelimited(KERN_WARNING
				   "Unknown case of dp, iif=%x --> %s\n",
				   skb_hnat_iface(skb), dev->name);
 		return 0;
 	}
	qid = hnat_select_qid(skb, dev, port_id, dscp, ntohs(eth->h_proto));

	if (IS_IPV4_GRP(foe)) {
		entry.ipv4_hnapt.iblk2.dp = gmac;
		entry.ipv4_hnapt.iblk2.port_mg =
			(hnat_priv->data->version == MTK_HNAT_V1_1) ? 0x3f : 0;

		if (qos_toggle) {
			if (hnat_priv->data->version == MTK_HNAT_V2 ||
			    hnat_priv->data->version == MTK_HNAT_V3) {
				entry.ipv4_hnapt.iblk2.qid = qid & 0x7f;
			} else {
				/* qid[5:0]= port_mg[1:0]+ qid[3:0] */
				entry.ipv4_hnapt.iblk2.qid = qid & 0xf;
				if (hnat_priv->data->version != MTK_HNAT_V1_1)
					entry.ipv4_hnapt.iblk2.port_mg |=
						((qid >> 4) & 0x3);

				if (((IS_EXT(dev) && (FROM_GE_LAN_GRP(skb) ||
				      FROM_GE_WAN(skb) || FROM_GE_VIRTUAL(skb))) ||
				      ((mape_toggle && mape == 1) && !FROM_EXT(skb))) &&
				      (!whnat)) {
					entry.ipv4_hnapt.etype = htons(HQOS_MAGIC_TAG);
					entry.ipv4_hnapt.vlan1 = skb_hnat_entry(skb);
					entry.bfib1.vlan_layer = 1;
				}
			}

			if (FROM_EXT(skb) || skb_hnat_sport(skb) == NR_QDMA_PORT)
				entry.ipv4_hnapt.iblk2.fqos = 0;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry.ipv4_hnapt.tport_id = HQOS_FLAG(dev, skb, qid) ? 1 : 0;
#endif
				entry.ipv4_hnapt.iblk2.fqos = HQOS_FLAG(dev, skb, qid) ? 1 : 0;
		} else {
			entry.ipv4_hnapt.iblk2.fqos = 0;
		}
	} else {
		entry.ipv6_5t_route.iblk2.dp = gmac;
		entry.ipv6_5t_route.iblk2.port_mg =
			(hnat_priv->data->version == MTK_HNAT_V1_1) ? 0x3f : 0;

		if (qos_toggle) {
			if (hnat_priv->data->version == MTK_HNAT_V2 ||
			    hnat_priv->data->version == MTK_HNAT_V3) {
				entry.ipv6_5t_route.iblk2.qid = qid & 0x7f;
			} else {
				/* qid[5:0]= port_mg[1:0]+ qid[3:0] */
				entry.ipv6_5t_route.iblk2.qid = qid & 0xf;
				if (hnat_priv->data->version != MTK_HNAT_V1_1)
					entry.ipv6_5t_route.iblk2.port_mg |=
								((qid >> 4) & 0x3);

				if (IS_EXT(dev) && (FROM_GE_LAN_GRP(skb) ||
				    FROM_GE_WAN(skb) || FROM_GE_VIRTUAL(skb)) &&
				    (!whnat)) {
					entry.ipv6_5t_route.etype = htons(HQOS_MAGIC_TAG);
					entry.ipv6_5t_route.vlan1 = skb_hnat_entry(skb);
					entry.bfib1.vlan_layer = 1;
				}
			}

			if (FROM_EXT(skb) || skb_hnat_sport(skb) == NR_QDMA_PORT)
				entry.ipv6_5t_route.iblk2.fqos = 0;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				switch (entry.bfib1.pkt_type) {
				case IPV4_MAP_E:
				case IPV4_MAP_T:
					entry.ipv4_mape.tport_id =
						HQOS_FLAG(dev, skb, qid) ? 1 : 0;
					break;
				case IPV6_HNAPT:
				case IPV6_HNAT:
					entry.ipv6_hnapt.tport_id =
						HQOS_FLAG(dev, skb, qid) ? 1 : 0;
					break;
				default:
					entry.ipv6_5t_route.tport_id =
						HQOS_FLAG(dev, skb, qid) ? 1 : 0;
					break;
				}
				entry.ipv6_5t_route.iblk2.fqos = HQOS_FLAG(dev, skb, qid) ? 1 : 0;
#endif
		} else {
			entry.ipv6_5t_route.iblk2.fqos = 0;
		}
	}

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	{
		const struct mtk_npu_rx_meta *rx = mtk_npu_rx_meta_find(skb);

		if (rx) {
			if (tunnel_prefill || is_multicast_ether_addr(eth->h_dest))
				return 0;
			if (IS_IPV4_HNAPT(&entry) || IS_IPV4_HNAT(&entry))
				entry.ipv4_hnapt.tops_entry = rx->entry;
			else if (entry.bfib1.pkt_type == IPV6_5T_ROUTE)
				entry.ipv6_5t_route.tops_entry = rx->entry;
			else
				return 0;
		}
	}
#endif

	/* WHNAT keeps the complete prepared entry in software.  The hardware slot
	 * remains UNBIND until TX confirms this skb's flow identity.
	 */
	/* WED RX -> GMAC binds here, without the WHNAT TX shadow confirmation.
	 * For ordinary IPv4, also prove that the PPE key and post-NAT skb belong
	 * to the same CT direction.  Encapsulation needs its own identity parser;
	 * this check does not infer an inner tuple or change those existing paths.
	 */
	if ((empty_key || FROM_WED(skb)) && skb->protocol == htons(ETH_P_IP) &&
	    !skb->encapsulation &&
	    !hnat_flow_ipv4_ct_match(skb, &entry, ct, ctinfo))
		return 0;

	/* NETSYSv3 replication is owned by the NPU MDB provider. Cache
	 * validation and descriptor publication share entry_lock, so leave
	 * and reset cannot race a fresh BIND. No MCU call runs in this path.
	 */
	if (!hnat_priv->data->mcast && is_multicast_ether_addr(eth->h_dest)) {
		if (whnat || tunnel_prefill)
			return 0;
		lockdep_assert_held(&hnat_priv->entry_lock);
		if (!hnat_npu_mcast_prepare(skb, dev, &entry, skb_hnat_ppe(skb),
					    skb_hnat_entry(skb))) {
			entry.bfib1.ttl = 1;
			entry.bfib1.state = BIND;
			hnat_account_commit(hnat_priv, skb_hnat_ppe(skb),
					    skb_hnat_entry(skb), skb, &entry,
					    false, false, 0, &accepted);
		}
		return 0;
	}

	if (whnat || tunnel_prefill) {
		if (!hnat_flow_entry_unbind_match(&entry, foe) ||
		    !hnat_flow_ipv4_ct_match(skb, &entry, ct, ctinfo))
			return 0;
		account_handled = hnat_account_commit(hnat_priv, skb_hnat_ppe(skb),
						      skb_hnat_entry(skb), skb,
						      &entry, true, false, 0,
						      &accepted);
		if ((account_handled && !accepted) ||
		    (!account_handled && hnat_priv->data->per_flow_accounting))
			return 0;
		if (account_handled &&
		    !hnat_account_generation_snapshot(hnat_priv,
						     skb_hnat_ppe(skb),
						     skb_hnat_entry(skb),
						     &account_generation)) {
			hnat_account_invalidate(hnat_priv, skb_hnat_ppe(skb),
						skb_hnat_entry(skb));
			return 0;
		}
		if (!hnat_flow_entry_store(&entry, skb_hnat_ppe(skb),
					   skb_hnat_entry(skb), account_generation,
					   tunnel_prefill ? (struct net_device *)dev : NULL,
					   ct, ctinfo)) {
			if (account_handled)
				hnat_account_invalidate(hnat_priv, skb_hnat_ppe(skb),
							skb_hnat_entry(skb));
			return 0;
		}
		skb_hnat_filled(skb) = HNAT_INFO_FILLED;
		return 0;
	}

	entry.bfib1.ttl = 1;
	entry.bfib1.state = BIND;
	account_handled = hnat_account_commit(hnat_priv, skb_hnat_ppe(skb),
						      skb_hnat_entry(skb), skb,
						      &entry, false, false, 0,
						      &accepted);
	if (!account_handled) {
		if (!hnat_priv->data->per_flow_accounting &&
		    hnat_flow_entry_unbind_match(&entry, foe)) {
			hnat_copy_foe_info(foe, &entry);
			wmb();
			memcpy(&foe->bfib1, &entry.bfib1, sizeof(entry.bfib1));
			dma_wmb();
		}
	} else if (!accepted) {
		return 0;
	}
	return 0;
}

int mtk_sw_nat_hook_tx(struct sk_buff *skb, int gmac_no)
{
	struct foe_entry *hw_entry, entry;
	struct hnat_flow_entry *flow;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	u64 account_generation = 0, shadow_sequence;
	bool account_handled, accepted = false;
	struct ethhdr *eth;
	struct hnat_tunnel_token rx_token = {};
	const struct mtk_npu_rx_meta *rx = mtk_npu_rx_meta_find(skb);

	if (skb_hnat_alg(skb) || !is_hnat_info_filled(skb) ||
	    !is_magic_tag_valid(skb) || !IS_SPACE_AVAILABLE_HEAD(skb))
		return NF_ACCEPT;

	pr_debug_ratelimited(
		"[%s]entry=%x reason=%x gmac_no=%x wdmaid=%x rxid=%x wcid=%x bssid=%x\n",
		__func__, skb_hnat_entry(skb), skb_hnat_reason(skb), gmac_no,
		skb_hnat_wdma_id(skb), skb_hnat_rx_id(skb), skb_hnat_wc_id(skb),
		skb_hnat_bss_id(skb));

	if ((gmac_no != NR_WDMA0_PORT) && (gmac_no != NR_WDMA1_PORT) &&
	    (gmac_no != NR_WDMA2_PORT) && (gmac_no != NR_WHNAT_WDMA_PORT))
		return NF_ACCEPT;
	if (unlikely(!skb_mac_header_was_set(skb)) ||
	    !skb_hnat_is_hashed(skb) ||
	    skb_hnat_entry(skb) >= hnat_priv->foe_etry_num ||
	    skb_hnat_ppe(skb) >= CFG_PPE_NUM ||
	    skb_hnat_reason(skb) != HIT_UNBIND_RATE_REACH)
		return NF_ACCEPT;

	hw_entry = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];
	if (hnat_priv->data->per_flow_accounting &&
	    !hnat_account_generation_snapshot(hnat_priv, skb_hnat_ppe(skb),
					      skb_hnat_entry(skb),
					      &account_generation))
		return NF_ACCEPT;

	/* Follow the official flow-key chain. Only the skb marked by the
	 * matching software prefill may consume the saved full entry.
	 */
	spin_lock_bh(&hnat_priv->flow_entry_lock);
	flow = hnat_flow_entry_search(hw_entry, skb_hnat_ppe(skb),
				      skb_hnat_entry(skb), true);
	if (!flow || flow->tunnel_dev ||
	    time_after_eq(jiffies, flow->last_update + 3 * HZ) ||
	    flow->generation != account_generation ||
	    !hnat_flow_entry_unbind_match(&flow->data, hw_entry)) {
		if (flow && time_after_eq(jiffies, flow->last_update + 3 * HZ))
			hnat_flow_entry_delete(flow);
		spin_unlock_bh(&hnat_priv->flow_entry_lock);
		return NF_ACCEPT;
	}
	memcpy(&entry, &flow->data, sizeof(entry));
	shadow_sequence = flow->sequence;
	spin_unlock_bh(&hnat_priv->flow_entry_lock);

	ct = nf_ct_get(skb, &ctinfo);
	if (ct ? !hnat_flow_ipv4_ct_match(skb, &entry, ct, ctinfo) :
		 !hnat_flow_ipv4_tuple_match(skb, &entry))
		return NF_ACCEPT;

	eth = eth_hdr(skb);

	/*not bind multicast if PPE mcast not enable*/
	if (!hnat_priv->data->mcast) {
		if (is_multicast_ether_addr(eth->h_dest))
			return NF_ACCEPT;

		if (IS_IPV4_GRP(&entry))
			entry.ipv4_hnapt.iblk2.mcast = 0;
		else
			entry.ipv6_5t_route.iblk2.mcast = 0;
	}

	/* Some mt_wifi virtual interfaces, such as apcli,
	 * will change the smac for specail purpose.
	 */
	switch ((int)entry.bfib1.pkt_type) {
	case IPV4_HNAPT:
	case IPV4_HNAT:
		entry.ipv4_hnapt.smac_hi = swab32(*((u32 *)eth->h_source));
		entry.ipv4_hnapt.smac_lo = swab16(*((u16 *)&eth->h_source[4]));
		break;
	case IPV4_DSLITE:
	case IPV4_MAP_E:
	case IPV6_6RD:
	case IPV6_5T_ROUTE:
	case IPV6_3T_ROUTE:
	case IPV6_HNAPT:
	case IPV6_HNAT:
		entry.ipv6_5t_route.smac_hi = swab32(*((u32 *)eth->h_source));
		entry.ipv6_5t_route.smac_lo = swab16(*((u16 *)&eth->h_source[4]));
		break;
	}

	if (skb_vlan_tagged(skb)) {
		entry.bfib1.vlan_layer = 1;
		entry.bfib1.vpm = 1;
		if (IS_IPV4_GRP(&entry)) {
			entry.ipv4_hnapt.etype = htons(ETH_P_8021Q);
			entry.ipv4_hnapt.vlan1 = skb->vlan_tci;
		} else if (IS_IPV6_GRP(&entry)) {
			entry.ipv6_5t_route.etype = htons(ETH_P_8021Q);
			entry.ipv6_5t_route.vlan1 = skb->vlan_tci;
		}
	} else {
		entry.bfib1.vpm = 0;
		entry.bfib1.vlan_layer = 0;
	}

	/* MT7622 wifi hw_nat not support QoS */
	if (IS_IPV4_GRP(&entry)) {
		entry.ipv4_hnapt.iblk2.fqos = 0;
		if ((hnat_priv->data->version == MTK_HNAT_V1_2 &&
		     gmac_no == NR_WHNAT_WDMA_PORT) ||
		    ((hnat_priv->data->version == MTK_HNAT_V2 ||
		      hnat_priv->data->version == MTK_HNAT_V3) &&
		     (gmac_no == NR_WDMA0_PORT || gmac_no == NR_WDMA1_PORT ||
		      gmac_no == NR_WDMA2_PORT))) {
			entry.ipv4_hnapt.winfo.bssid = skb_hnat_bss_id(skb);
			entry.ipv4_hnapt.winfo.wcid = skb_hnat_wc_id(skb);
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
			entry.ipv4_hnapt.tport_id = IS_HQOS_DL_MODE ? 1 : 0;
			entry.ipv4_hnapt.iblk2.fqos = IS_HQOS_DL_MODE ? 1 : 0;
			entry.ipv4_hnapt.iblk2.rxid = skb_hnat_rx_id(skb);
			entry.ipv4_hnapt.iblk2.winfoi = 1;
			entry.ipv4_hnapt.winfo_pao.usr_info =
				skb_hnat_usr_info(skb);
			entry.ipv4_hnapt.winfo_pao.tid = skb_hnat_tid(skb);
			entry.ipv4_hnapt.winfo_pao.is_fixedrate =
				skb_hnat_is_fixedrate(skb);
			entry.ipv4_hnapt.winfo_pao.is_prior =
				skb_hnat_is_prior(skb);
			entry.ipv4_hnapt.winfo_pao.is_sp = skb_hnat_is_sp(skb);
			entry.ipv4_hnapt.winfo_pao.hf = skb_hnat_hf(skb);
			entry.ipv4_hnapt.winfo_pao.amsdu = skb_hnat_amsdu(skb);
#elif defined(CONFIG_MEDIATEK_NETSYS_V2)
			entry.ipv4_hnapt.iblk2.rxid = skb_hnat_rx_id(skb);
			entry.ipv4_hnapt.iblk2.winfoi = 1;
#else
			entry.ipv4_hnapt.winfo.rxid = skb_hnat_rx_id(skb);
			entry.ipv4_hnapt.iblk2w.winfoi = 1;
			entry.ipv4_hnapt.iblk2w.wdmaid = skb_hnat_wdma_id(skb);
#endif
		} else {
			if (IS_GMAC1_MODE && !hnat_dsa_is_enable(hnat_priv)) {
				entry.bfib1.vpm = 1;
				entry.bfib1.vlan_layer = 1;

				if (FROM_GE_LAN_GRP(skb))
					entry.ipv4_hnapt.vlan1 = 1;
				else if (FROM_GE_WAN(skb) || FROM_GE_VIRTUAL(skb))
					entry.ipv4_hnapt.vlan1 = 2;
			}

			if (IS_HQOS_MODE &&
			    (FROM_GE_LAN_GRP(skb) || FROM_GE_WAN(skb) || FROM_GE_VIRTUAL(skb))) {
				entry.bfib1.vpm = 0;
				entry.bfib1.vlan_layer = 1;
				entry.ipv4_hnapt.etype = htons(HQOS_MAGIC_TAG);
				entry.ipv4_hnapt.vlan1 = skb_hnat_entry(skb);
				entry.ipv4_hnapt.iblk2.fqos = 1;
			}
		}
		entry.ipv4_hnapt.iblk2.dp = gmac_no;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	} else if (IS_IPV6_HNAPT(&entry) || IS_IPV6_HNAT(&entry)) {
		entry.ipv6_hnapt.iblk2.dp = gmac_no;
		entry.ipv6_hnapt.iblk2.rxid = skb_hnat_rx_id(skb);
		entry.ipv6_hnapt.iblk2.winfoi = 1;

		entry.ipv6_hnapt.winfo.bssid = skb_hnat_bss_id(skb);
		entry.ipv6_hnapt.winfo.wcid = skb_hnat_wc_id(skb);
		entry.ipv6_hnapt.winfo_pao.usr_info = skb_hnat_usr_info(skb);
		entry.ipv6_hnapt.winfo_pao.tid = skb_hnat_tid(skb);
		entry.ipv6_hnapt.winfo_pao.is_fixedrate =
			skb_hnat_is_fixedrate(skb);
		entry.ipv6_hnapt.winfo_pao.is_prior = skb_hnat_is_prior(skb);
		entry.ipv6_hnapt.winfo_pao.is_sp = skb_hnat_is_sp(skb);
		entry.ipv6_hnapt.winfo_pao.hf = skb_hnat_hf(skb);
		entry.ipv6_hnapt.winfo_pao.amsdu = skb_hnat_amsdu(skb);
		entry.ipv6_hnapt.tport_id = IS_HQOS_DL_MODE ? 1 : 0;
		entry.ipv6_hnapt.iblk2.fqos = IS_HQOS_DL_MODE ? 1 : 0;
#endif
	} else {
		entry.ipv6_5t_route.iblk2.fqos = 0;
		if ((hnat_priv->data->version == MTK_HNAT_V1_2 &&
		     gmac_no == NR_WHNAT_WDMA_PORT) ||
		    ((hnat_priv->data->version == MTK_HNAT_V2 ||
		      hnat_priv->data->version == MTK_HNAT_V3) &&
		     (gmac_no == NR_WDMA0_PORT || gmac_no == NR_WDMA1_PORT ||
		      gmac_no == NR_WDMA2_PORT))) {
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
			switch (entry.bfib1.pkt_type) {
			case IPV4_MAP_E:
			case IPV4_MAP_T:
				entry.ipv4_mape.winfo.bssid = skb_hnat_bss_id(skb);
				entry.ipv4_mape.winfo.wcid = skb_hnat_wc_id(skb);
				entry.ipv4_mape.tport_id = IS_HQOS_DL_MODE ? 1 : 0;
				entry.ipv4_mape.iblk2.fqos = IS_HQOS_DL_MODE ? 1 : 0;
				entry.ipv4_mape.iblk2.rxid = skb_hnat_rx_id(skb);
				entry.ipv4_mape.iblk2.winfoi = 1;
				entry.ipv4_mape.winfo_pao.usr_info =
					skb_hnat_usr_info(skb);
				entry.ipv4_mape.winfo_pao.tid =
					skb_hnat_tid(skb);
				entry.ipv4_mape.winfo_pao.is_fixedrate =
					skb_hnat_is_fixedrate(skb);
				entry.ipv4_mape.winfo_pao.is_prior =
					skb_hnat_is_prior(skb);
				entry.ipv4_mape.winfo_pao.is_sp =
					skb_hnat_is_sp(skb);
				entry.ipv4_mape.winfo_pao.hf =
					skb_hnat_hf(skb);
				entry.ipv4_mape.winfo_pao.amsdu =
					skb_hnat_amsdu(skb);
				break;
			default:
				entry.ipv6_5t_route.winfo.bssid = skb_hnat_bss_id(skb);
				entry.ipv6_5t_route.winfo.wcid = skb_hnat_wc_id(skb);
				entry.ipv6_5t_route.tport_id = IS_HQOS_DL_MODE ? 1 : 0;
				entry.ipv6_5t_route.iblk2.fqos = IS_HQOS_DL_MODE ? 1 : 0;
				entry.ipv6_5t_route.iblk2.rxid = skb_hnat_rx_id(skb);
				entry.ipv6_5t_route.iblk2.winfoi = 1;
				entry.ipv6_5t_route.winfo_pao.usr_info =
					skb_hnat_usr_info(skb);
				entry.ipv6_5t_route.winfo_pao.tid =
					skb_hnat_tid(skb);
				entry.ipv6_5t_route.winfo_pao.is_fixedrate =
					skb_hnat_is_fixedrate(skb);
				entry.ipv6_5t_route.winfo_pao.is_prior =
					skb_hnat_is_prior(skb);
				entry.ipv6_5t_route.winfo_pao.is_sp =
					skb_hnat_is_sp(skb);
				entry.ipv6_5t_route.winfo_pao.hf =
					skb_hnat_hf(skb);
				entry.ipv6_5t_route.winfo_pao.amsdu =
					skb_hnat_amsdu(skb);
				break;
			}
#elif defined(CONFIG_MEDIATEK_NETSYS_V2)
			entry.ipv6_5t_route.winfo.bssid = skb_hnat_bss_id(skb);
			entry.ipv6_5t_route.winfo.wcid = skb_hnat_wc_id(skb);
			entry.ipv6_5t_route.iblk2.rxid = skb_hnat_rx_id(skb);
			entry.ipv6_5t_route.iblk2.winfoi = 1;
#else
			entry.ipv6_5t_route.winfo.bssid = skb_hnat_bss_id(skb);
			entry.ipv6_5t_route.winfo.wcid = skb_hnat_wc_id(skb);
			entry.ipv6_5t_route.winfo.rxid = skb_hnat_rx_id(skb);
			entry.ipv6_5t_route.iblk2w.winfoi = 1;
			entry.ipv6_5t_route.iblk2w.wdmaid = skb_hnat_wdma_id(skb);
#endif
		} else {
			if (IS_GMAC1_MODE && !hnat_dsa_is_enable(hnat_priv)) {
				entry.bfib1.vpm = 1;
				entry.bfib1.vlan_layer = 1;

				if (FROM_GE_LAN_GRP(skb))
					entry.ipv6_5t_route.vlan1 = 1;
				else if (FROM_GE_WAN(skb) || FROM_GE_VIRTUAL(skb))
					entry.ipv6_5t_route.vlan1 = 2;
			}

			if (IS_HQOS_MODE &&
			    (FROM_GE_LAN_GRP(skb) || FROM_GE_WAN(skb) || FROM_GE_VIRTUAL(skb))) {
				entry.bfib1.vpm = 0;
				entry.bfib1.vlan_layer = 1;
				entry.ipv6_5t_route.etype = htons(HQOS_MAGIC_TAG);
				entry.ipv6_5t_route.vlan1 = skb_hnat_entry(skb);
				entry.ipv6_5t_route.iblk2.fqos = 1;
			}
		}
		entry.ipv6_5t_route.iblk2.dp = gmac_no;
	}

	entry.bfib1.time_stamp =
		(hnat_priv->data->version == MTK_HNAT_V2 ||
		 hnat_priv->data->version == MTK_HNAT_V3) ?
		(readl(hnat_priv->fe_base + 0x0010) & 0xFF) :
		(readl(hnat_priv->fe_base + 0x0010) & 0x7FFF);
	entry.bfib1.ttl = 1;
	entry.bfib1.state = BIND;
	if (IS_IPV4_GRP(&entry))
		entry.ipv4_hnapt.act_dp &= ~UDF_HNAT_PRE_FILLED;
	else
		entry.ipv6_5t_route.act_dp &= ~UDF_HNAT_PRE_FILLED;

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	if (rx) {
		if ((IS_IPV4_GRP(&entry) ? entry.ipv4_hnapt.tops_entry :
			 entry.ipv6_5t_route.tops_entry) != rx->entry ||
		    !hnat_tunnel_rx_bind_lock(rx, &rx_token))
			return NF_ACCEPT;
	} else if ((IS_IPV4_GRP(&entry) ? entry.ipv4_hnapt.tops_entry :
		    entry.ipv6_5t_route.tops_entry) >= 32) {
		return NF_ACCEPT;
	}
#else
	if (rx)
		return NF_ACCEPT;
#endif
	spin_lock_bh(&hnat_priv->entry_lock);
	if (!hnat_flow_entry_lock_current(&entry, skb_hnat_ppe(skb),
					  skb_hnat_entry(skb),
					  account_generation, shadow_sequence,
					  &flow)) {
		spin_unlock_bh(&hnat_priv->entry_lock);
		goto rx_unlock;
	}
	if (!hnat_flow_entry_unbind_match(&flow->data, hw_entry) ||
	    !hnat_flow_entry_unbind_match(&entry, hw_entry)) {
		hnat_flow_entry_delete(flow);
		spin_unlock_bh(&hnat_priv->flow_entry_lock);
		spin_unlock_bh(&hnat_priv->entry_lock);
		goto rx_unlock;
	}

	account_handled = hnat_account_commit(hnat_priv, skb_hnat_ppe(skb),
					      skb_hnat_entry(skb), skb, &entry,
					      false, true, account_generation,
					      &accepted);
	if (account_handled && !accepted) {
		hnat_flow_entry_delete(flow);
		spin_unlock_bh(&hnat_priv->flow_entry_lock);
		spin_unlock_bh(&hnat_priv->entry_lock);
		goto rx_unlock;
	}
	if (!account_handled) {
		/* Missing accounting is a legal path only when accounting is
		 * disabled. Never turn a failed accounting gate into fallback.
		 */
		if (hnat_priv->data->per_flow_accounting ||
		    !hnat_flow_entry_unbind_match(&entry, hw_entry)) {
			hnat_flow_entry_delete(flow);
			spin_unlock_bh(&hnat_priv->flow_entry_lock);
			spin_unlock_bh(&hnat_priv->entry_lock);
			goto rx_unlock;
		}
		hnat_copy_foe_info(hw_entry, &entry);
		wmb();
		memcpy(&hw_entry->bfib1, &entry.bfib1,
		       sizeof(entry.bfib1));
		dma_wmb();
	}
	hnat_flow_entry_delete(flow);
	spin_unlock_bh(&hnat_priv->flow_entry_lock);

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	if (debug_level >= 7 && net_ratelimit()) {
		pr_info("%s %d dp:%d rxid:%d tid:%d usr_info:%d bssid:%d wcid:%d hsh-idx:%d sp:%d\n",
			__func__, __LINE__,
			gmac_no, skb_hnat_rx_id(skb), skb_hnat_tid(skb),
			skb_hnat_usr_info(skb), skb_hnat_bss_id(skb),
			skb_hnat_wc_id(skb), skb_hnat_entry(skb),
			skb_hnat_sport(skb));

		if (IS_IPV4_GRP(&entry)) {
			pr_info("%s %d dp:%d rxid:%d tid:%d uinfo:%d bssid:%d wcid:%d hsh-idx:%d sp:%d\n",
				__func__, __LINE__,
				(hw_entry->ipv4_hnapt.iblk2.dp),
				(hw_entry->ipv4_hnapt.iblk2.rxid),
				(hw_entry->ipv4_hnapt.winfo_pao.tid),
				(hw_entry->ipv4_hnapt.winfo_pao.usr_info),
				(hw_entry->ipv4_hnapt.winfo.bssid),
				(hw_entry->ipv4_hnapt.winfo.wcid),
				skb_hnat_entry(skb), skb_hnat_sport(skb));
			pr_info("%s %d dip:%x sip:%x dp:%x sp:%x hsh-idx:%d\n",
				__func__, __LINE__,
				hw_entry->ipv4_hnapt.dip, hw_entry->ipv4_hnapt.sip,
				hw_entry->ipv4_hnapt.dport, hw_entry->ipv4_hnapt.sport,
				skb_hnat_entry(skb));
			pr_info("%s %d new_dip:%x new_sip:%x new_dp:%x new_sp:%x hsh-idx:%d\n",
				__func__, __LINE__,
				hw_entry->ipv4_hnapt.new_dip, hw_entry->ipv4_hnapt.new_sip,
				hw_entry->ipv4_hnapt.new_dport,
				hw_entry->ipv4_hnapt.new_sport, skb_hnat_entry(skb));
		} else {
			pr_info("%s %d dp:%d rxid:%d tid:%d uinfo:%d bssid:%d wcid:%d hidx:%d sp:%d\n",
				__func__, __LINE__,
				(hw_entry->ipv6_5t_route.iblk2.dp),
				(hw_entry->ipv6_5t_route.iblk2.rxid),
				(hw_entry->ipv6_5t_route.winfo_pao.tid),
				(hw_entry->ipv6_5t_route.winfo_pao.usr_info),
				(hw_entry->ipv6_5t_route.winfo.bssid),
				(hw_entry->ipv6_5t_route.winfo.wcid),
				skb_hnat_entry(skb), skb_hnat_sport(skb));
			pr_info("sip:%x-:%x-:%x-:%x dip0:%x-:%x-:%x-:%x dport:%x sport:%x\n",
				hw_entry->ipv6_5t_route.ipv6_sip0,
				hw_entry->ipv6_5t_route.ipv6_sip1,
				hw_entry->ipv6_5t_route.ipv6_sip2,
				hw_entry->ipv6_5t_route.ipv6_sip3,
				hw_entry->ipv6_5t_route.ipv6_dip0,
				hw_entry->ipv6_5t_route.ipv6_dip1,
				hw_entry->ipv6_5t_route.ipv6_dip2,
				hw_entry->ipv6_5t_route.ipv6_dip3,
				hw_entry->ipv6_5t_route.dport,
				hw_entry->ipv6_5t_route.sport);
		}
	}
#endif
	spin_unlock_bh(&hnat_priv->entry_lock);
rx_unlock:
	if (rx)
		hnat_tunnel_bind_unlock(&rx_token);
	return NF_ACCEPT;
}

int mtk_sw_nat_hook_rx(struct sk_buff *skb)
{
	/* Private metadata must never overwrite packet bytes on a short skb. */
	if (!IS_SPACE_AVAILABLE_HEAD(skb))
		return NF_ACCEPT;
	if (!FROM_WED(skb)) {
		skb_hnat_magic_tag(skb) = 0;
		return NF_ACCEPT;
	}

	hnat_tunnel_metadata_init(skb);
	skb_hnat_alg(skb) = 0;
	/* This is a new RX packet, never a software-prefilled TX confirmation. */
	skb_hnat_filled(skb) = 0;
	skb_hnat_magic_tag(skb) = HNAT_MAGIC_TAG;

	if (skb_hnat_iface(skb) == FOE_MAGIC_WED0)
		skb_hnat_sport(skb) = NR_WDMA0_PORT;
	else if (skb_hnat_iface(skb) == FOE_MAGIC_WED1)
		skb_hnat_sport(skb) = NR_WDMA1_PORT;
	else if (skb_hnat_iface(skb) == FOE_MAGIC_WED2)
		skb_hnat_sport(skb) = NR_WDMA2_PORT;

	return NF_ACCEPT;
}

static void mtk_ppe_dev_register_hook_body(struct net_device *dev)
{
	int i, number = 0;
	struct extdev_entry *ext_entry;


	if (!hnat_priv->guest_en ) {
		if (!strcmp(dev->name, "ra1") || !strcmp(dev->name, "rax1"))
			return;
	}
	for (i = 1; i < MAX_IF_NUM; i++) {
		if (hnat_priv->wifi_hook_if[i] == dev) {
			pr_info("%s : %s has been registered in wifi_hook_if table[%d]\n",
				__func__, dev->name, i);
			return;
		}
	}

	for (i = 1; i < MAX_IF_NUM; i++) {
		if (!hnat_priv->wifi_hook_if[i]) {
			if (find_extif_from_devname(dev->name)) {
				extif_set_dev(dev, 0);
				goto add_wifi_hook_if;
			}

			number = get_ext_device_number();
			if (number >= MAX_EXT_DEVS) {
				pr_info("%s : extdev array is full. %s is not registered\n",
					__func__, dev->name);
				return;
			}

			ext_entry = kzalloc(sizeof(*ext_entry), GFP_KERNEL);
			if (!ext_entry)
				return;

			strncpy(ext_entry->name, dev->name, IFNAMSIZ - 1);
			dev_hold(dev);
			ext_entry->dev = dev;
			ext_if_add(ext_entry);

add_wifi_hook_if:
			dev_hold(dev);
			hnat_priv->wifi_hook_if[i] = dev;

			break;
		}
	}
	pr_info("%s : ineterface %s register (%d)\n", __func__, dev->name, i);
}

void mtk_ppe_dev_register_hook(struct net_device *dev)
{
	if (!hnat_external_callback_enter())
		return;
	if (hnat_priv->data->whnat)
		mtk_ppe_dev_register_hook_body(dev);
	hnat_external_callback_exit();
}

static void mtk_ppe_dev_unregister_hook_body(struct net_device *dev)
{
	int i;

	for (i = 1; i < MAX_IF_NUM; i++) {
		if (hnat_priv->wifi_hook_if[i] == dev) {
			hnat_priv->wifi_hook_if[i] = NULL;
			dev_put(dev);

			break;
		}
	}

	extif_put_dev(dev);
	pr_info("%s : ineterface %s set null (%d)\n", __func__, dev->name, i);
}

void mtk_ppe_dev_unregister_hook(struct net_device *dev)
{
	if (!hnat_external_callback_enter())
		return;
	if (hnat_priv->data->whnat)
		mtk_ppe_dev_unregister_hook_body(dev);
	hnat_external_callback_exit();
}

static unsigned int mtk_hnat_accel_type(struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	const struct nf_conn_help *help;

	/* Do not accelerate 1st round of xfrm flow, and 2nd round of xfrm flow
	 * is from local_out which is also filtered in sanity check.
	 */
	dst = skb_dst(skb);
	if (dst && dst_xfrm(dst))
		return 0;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return 1;

	/* rcu_read_lock()ed by nf_hook_slow */
	help = nfct_help(ct);
	if (help && rcu_dereference(help->helper))
		return 0;

	return 1;
}

static void mtk_hnat_dscp_update(struct sk_buff *skb, struct foe_entry *entry)
{
	struct iphdr *iph;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	bool flag = false;

	eth = eth_hdr(skb);
	switch (ntohs(eth->h_proto)) {
	case ETH_P_IP:
		iph = ip_hdr(skb);
		if (IS_IPV4_GRP(entry) && entry->ipv4_hnapt.iblk2.dscp != iph->tos) {
			entry->ipv4_hnapt.iblk2.dscp = iph->tos;
			flag = true;
		}
		break;
	case ETH_P_IPV6:
		ip6h = ipv6_hdr(skb);
		if ((IS_IPV6_3T_ROUTE(entry) || IS_IPV6_5T_ROUTE(entry)) &&
			(entry->ipv6_5t_route.iblk2.dscp !=
			(ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4)))) {
			entry->ipv6_5t_route.iblk2.dscp =
				(ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4));
			flag = true;
		}
		break;
	default:
		return;
	}

	if (flag) {
		if (debug_level >= 7 && net_ratelimit())
			pr_info("%s %d update entry idx=%d\n", __func__, __LINE__,
			skb_hnat_entry(skb));
		hnat_cache_ebl(1);
	}
}



int mtk_464xlat_fill_mac(struct foe_entry *entry, struct sk_buff *skb,
			 const struct net_device *out, bool l2w)
{
	const struct in6_addr *ipv6_nexthop;
	struct dst_entry *dst = skb_dst(skb);
	struct neighbour *neigh = NULL;
	struct rtable *rt = (struct rtable *)dst;
	u32 nexthop;

	rcu_read_lock_bh();
	if (l2w) {
		ipv6_nexthop = rt6_nexthop((struct rt6_info *)dst,
					   &ipv6_hdr(skb)->daddr);
		neigh = __ipv6_neigh_lookup_noref(dst->dev, ipv6_nexthop);
		if (unlikely(!neigh)) {
			dev_notice(hnat_priv->dev, "%s:No neigh (daddr=%pI6)\n",
				   __func__, &ipv6_hdr(skb)->daddr);
			rcu_read_unlock_bh();
			return -1;
		}
	} else {
		nexthop = (__force u32)rt_nexthop(rt, ip_hdr(skb)->daddr);
		neigh = __ipv4_neigh_lookup_noref(dst->dev, nexthop);
		if (unlikely(!neigh)) {
			dev_notice(hnat_priv->dev, "%s:No neigh (daddr=%pI4)\n",
				   __func__, &ip_hdr(skb)->daddr);
			rcu_read_unlock_bh();
			return -1;
		}
	}
	rcu_read_unlock_bh();

	entry->ipv4_dslite.dmac_hi = swab32(*((u32 *)neigh->ha));
	entry->ipv4_dslite.dmac_lo = swab16(*((u16 *)&neigh->ha[4]));
	entry->ipv4_dslite.smac_hi = swab32(*((u32 *)out->dev_addr));
	entry->ipv4_dslite.smac_lo = swab16(*((u16 *)&out->dev_addr[4]));

	return 0;
}

int mtk_464xlat_get_hash(struct sk_buff *skb, u32 *hash, bool l2w)
{
	struct in6_addr addr_v6, prefix;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	struct tcpudphdr *pptr, _ports;
	struct foe_entry tmp;
	u32 addr, protoff;

	if (l2w) {
		ip6h = ipv6_hdr(skb);
		if (mtk_ppe_get_xlat_v4_by_v6(&ip6h->daddr, &addr))
			return -1;
		protoff = IPV6_HDR_LEN;

		tmp.bfib1.pkt_type = IPV4_HNAPT;
		tmp.ipv4_hnapt.sip = ntohl(ip6h->saddr.s6_addr32[3]);
		tmp.ipv4_hnapt.dip = ntohl(addr);
	} else {
		iph = ip_hdr(skb);
		if (mtk_ppe_get_xlat_v6_by_v4(&iph->saddr, &addr_v6, &prefix))
			return -1;

		protoff = iph->ihl * 4;

		tmp.bfib1.pkt_type = IPV6_5T_ROUTE;
		tmp.ipv6_5t_route.ipv6_sip0 = ntohl(addr_v6.s6_addr32[0]);
		tmp.ipv6_5t_route.ipv6_sip1 = ntohl(addr_v6.s6_addr32[1]);
		tmp.ipv6_5t_route.ipv6_sip2 = ntohl(addr_v6.s6_addr32[2]);
		tmp.ipv6_5t_route.ipv6_sip3 = ntohl(addr_v6.s6_addr32[3]);
		tmp.ipv6_5t_route.ipv6_dip0 = ntohl(prefix.s6_addr32[0]);
		tmp.ipv6_5t_route.ipv6_dip1 = ntohl(prefix.s6_addr32[1]);
		tmp.ipv6_5t_route.ipv6_dip2 = ntohl(prefix.s6_addr32[2]);
		tmp.ipv6_5t_route.ipv6_dip3 = ntohl(iph->daddr);
	}

	pptr = skb_header_pointer(skb, protoff,
				  sizeof(_ports), &_ports);
	if (unlikely(!pptr))
		return -1;

	if (l2w) {
		tmp.ipv4_hnapt.sport = ntohs(pptr->src);
		tmp.ipv4_hnapt.dport = ntohs(pptr->dst);
	} else {
		tmp.ipv6_5t_route.sport = ntohs(pptr->src);
		tmp.ipv6_5t_route.dport = ntohs(pptr->dst);
	}

	*hash = hnat_get_ppe_hash(&tmp);

	return 0;
}

void mtk_464xlat_fill_info1(struct foe_entry *entry,
			    struct sk_buff *skb, bool l2w)
{
	entry->bfib1.cah = 1;
	entry->bfib1.ttl = 1;
	entry->bfib1.state = BIND;
	entry->bfib1.time_stamp = readl(hnat_priv->fe_base + 0x0010) & (0xFF);
	if (l2w) {
		entry->bfib1.pkt_type = IPV4_DSLITE;
		entry->bfib1.udp = ipv6_hdr(skb)->nexthdr ==
				   IPPROTO_UDP ? 1 : 0;
	} else {
		entry->bfib1.pkt_type = IPV6_6RD;
		entry->bfib1.udp = ip_hdr(skb)->protocol ==
				   IPPROTO_UDP ? 1 : 0;
	}
}

void mtk_464xlat_fill_info2(struct foe_entry *entry, bool l2w)
{
	entry->ipv4_dslite.iblk2.mibf = 1;
	entry->ipv4_dslite.iblk2.port_ag = 0xF;

	if (l2w)
		entry->ipv4_dslite.iblk2.dp = NR_GMAC2_PORT;
	else
		entry->ipv6_6rd.iblk2.dp = NR_GMAC1_PORT;
}

void mtk_464xlat_fill_ipv4(struct foe_entry *entry, struct sk_buff *skb,
			   struct foe_entry *foe, bool l2w)
{
	struct iphdr *iph;

	if (l2w) {
		entry->ipv4_dslite.sip = foe->ipv4_dslite.sip;
		entry->ipv4_dslite.dip = foe->ipv4_dslite.dip;
		entry->ipv4_dslite.sport = foe->ipv4_dslite.sport;
		entry->ipv4_dslite.dport = foe->ipv4_dslite.dport;
	} else {
		iph = ip_hdr(skb);
		entry->ipv6_6rd.tunnel_sipv4 = ntohl(iph->saddr);
		entry->ipv6_6rd.tunnel_dipv4 = ntohl(iph->daddr);
		entry->ipv6_6rd.sport = foe->ipv6_6rd.sport;
		entry->ipv6_6rd.dport = foe->ipv6_6rd.dport;
		entry->ipv6_6rd.hdr_chksum = ppe_get_chkbase(iph);
		entry->ipv6_6rd.ttl = iph->ttl;
		entry->ipv6_6rd.dscp = iph->tos;
		entry->ipv6_6rd.flag = (ntohs(iph->frag_off) >> 13);
	}
}

int mtk_464xlat_fill_ipv6(struct foe_entry *entry, struct sk_buff *skb,
			  struct foe_entry *foe, bool l2w)
{
	struct ipv6hdr *ip6h;
	struct in6_addr addr_v6, prefix;
	u32 addr;

	if (l2w) {
		ip6h = ipv6_hdr(skb);

		if (mtk_ppe_get_xlat_v4_by_v6(&ip6h->daddr, &addr))
			return -1;

		if (mtk_ppe_get_xlat_v6_by_v4(&addr, &addr_v6, &prefix))
			return -1;

		entry->ipv4_dslite.tunnel_sipv6_0 =
			ntohl(prefix.s6_addr32[0]);
		entry->ipv4_dslite.tunnel_sipv6_1 =
			ntohl(ip6h->saddr.s6_addr32[1]);
		entry->ipv4_dslite.tunnel_sipv6_2 =
			ntohl(ip6h->saddr.s6_addr32[2]);
		entry->ipv4_dslite.tunnel_sipv6_3 =
			ntohl(ip6h->saddr.s6_addr32[3]);
		entry->ipv4_dslite.tunnel_dipv6_0 =
			ntohl(ip6h->daddr.s6_addr32[0]);
		entry->ipv4_dslite.tunnel_dipv6_1 =
			ntohl(ip6h->daddr.s6_addr32[1]);
		entry->ipv4_dslite.tunnel_dipv6_2 =
			ntohl(ip6h->daddr.s6_addr32[2]);
		entry->ipv4_dslite.tunnel_dipv6_3 =
			ntohl(ip6h->daddr.s6_addr32[3]);

		ppe_fill_flow_lbl(entry, ip6h);
		entry->ipv4_dslite.priority = ip6h->priority;
		entry->ipv4_dslite.hop_limit = ip6h->hop_limit;

	} else {
		entry->ipv6_6rd.ipv6_sip0 = foe->ipv6_6rd.ipv6_sip0;
		entry->ipv6_6rd.ipv6_sip1 = foe->ipv6_6rd.ipv6_sip1;
		entry->ipv6_6rd.ipv6_sip2 = foe->ipv6_6rd.ipv6_sip2;
		entry->ipv6_6rd.ipv6_sip3 = foe->ipv6_6rd.ipv6_sip3;
		entry->ipv6_6rd.ipv6_dip0 = foe->ipv6_6rd.ipv6_dip0;
		entry->ipv6_6rd.ipv6_dip1 = foe->ipv6_6rd.ipv6_dip1;
		entry->ipv6_6rd.ipv6_dip2 = foe->ipv6_6rd.ipv6_dip2;
		entry->ipv6_6rd.ipv6_dip3 = foe->ipv6_6rd.ipv6_dip3;
	}

	return 0;
}

int mtk_464xlat_fill_l2(struct foe_entry *entry, struct sk_buff *skb,
			const struct net_device *dev, bool l2w)
{
	const unsigned int *port_reg;
	int port_index;
	u16 sp_tag;

	if (l2w)
		entry->ipv4_dslite.etype = ETH_P_IP;
	else {
		if (IS_DSA_LAN(dev)) {
			port_reg = of_get_property(dev->dev.of_node,
						   "reg", NULL);
			if (unlikely(!port_reg))
				return -1;

			port_index = be32_to_cpup(port_reg);
			sp_tag = BIT(port_index);

			entry->bfib1.vlan_layer = 1;
			entry->bfib1.vpm = 0;
			entry->ipv6_6rd.etype = sp_tag;
		} else
			entry->ipv6_6rd.etype = ETH_P_IPV6;
	}

	if (mtk_464xlat_fill_mac(entry, skb, dev, l2w))
		return -1;

	return 0;
}


int mtk_464xlat_fill_l3(struct foe_entry *entry, struct sk_buff *skb,
			struct foe_entry *foe, bool l2w)
{
	mtk_464xlat_fill_ipv4(entry, skb, foe, l2w);

	if (mtk_464xlat_fill_ipv6(entry, skb, foe, l2w))
		return -1;

	return 0;
}

int mtk_464xlat_post_process(struct sk_buff *skb, const struct net_device *out)
{
	struct foe_entry *foe, entry = {};
	u32 hash;
	bool l2w;

	if (skb->protocol == htons(ETH_P_IPV6))
		l2w = true;
	else if (skb->protocol == htons(ETH_P_IP))
		l2w = false;
	else
		return -1;

	if (mtk_464xlat_get_hash(skb, &hash, l2w))
		return -1;

	if (hash >= hnat_priv->foe_etry_num)
		return -1;

	if (headroom[hash].crsn != HIT_UNBIND_RATE_REACH)
		return -1;

	if (headroom_ppe(headroom[hash]) >= CFG_PPE_NUM ||
	    headroom_ppe(headroom[hash]) >= MAX_PPE_NUM ||
	    !hnat_priv->foe_table_cpu[headroom_ppe(headroom[hash])])
		return -1;
	foe = &hnat_priv->foe_table_cpu[headroom_ppe(headroom[hash])][hash];

	mtk_464xlat_fill_info1(&entry, skb, l2w);

	if (mtk_464xlat_fill_l3(&entry, skb, foe, l2w))
		return -1;

	mtk_464xlat_fill_info2(&entry, l2w);

	if (mtk_464xlat_fill_l2(&entry, skb, out, l2w))
		return -1;

	/* We must ensure all info has been updated before set to hw */
	wmb();
	if (!hnat_account_commit(hnat_priv, headroom_ppe(headroom[hash]),
				 hash, NULL, &entry, false, false, 0, NULL))
		memcpy(foe, &entry, sizeof(struct foe_entry));

	return 0;
}

static inline void hnat_mark_unbindable(struct sk_buff *skb)
{
	/* A clone may share this descriptor with a different packet. */
	if (skb_cow_head(skb, 0))
		return; /* Existing downstream bounds checks still prevent binding. */

	/* Invalidate only HNAT eligibility, preserving headroom and skb->cb. */
	skb_hnat_alg(skb) = 1;
	skb_hnat_magic_tag(skb) = 0;
}

static bool hnat_invalid_index_fallback(struct sk_buff *skb)
{
	bool invalid_foe = skb_hnat_entry(skb) >= hnat_priv->foe_etry_num;
	bool invalid_ppe = skb_hnat_ppe(skb) >= CFG_PPE_NUM;

	if (likely(!invalid_foe && !invalid_ppe))
		return false;

	if (invalid_foe)
		atomic64_inc(&hnat_priv->invalid_foe);
	if (invalid_ppe)
		atomic64_inc(&hnat_priv->invalid_ppe);
	atomic64_inc(&hnat_priv->software_fallback);
	hnat_mark_unbindable(skb);

	return true;
}

/* The existing firmware encapsulates the outer tunnel; PPE handles the inner
 * TCP/UDP translation. Validate a complete non-GSO IPv4 transport header before
 * either prefill or confirmation. This is not an outer-IPv6 capability claim.
 */
static bool hnat_tunnel_ipv4_payload_valid(const struct sk_buff *skb, int offset,
					  const struct iphdr *ip)
{
	struct tcphdr tcp_copy;
	struct udphdr udp_copy;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	u32 l4_len;

	if (!ip || offset < 0 || (unsigned int)offset > skb->len ||
	    ip->version != 4 || ip->ihl != 5 || ip_is_fragment(ip) || skb_is_gso(skb) ||
	    ntohs(ip->tot_len) < sizeof(*ip) ||
	    ntohs(ip->tot_len) > skb->len - (unsigned int)offset)
		return false;
	l4_len = ntohs(ip->tot_len) - sizeof(*ip);
	if (ip->protocol == IPPROTO_TCP) {
		if (l4_len < sizeof(tcp_copy))
			return false;
		tcp = skb_header_pointer(skb, offset + sizeof(*ip),
					 sizeof(tcp_copy), &tcp_copy);
		return tcp && tcp->doff >= 5 && tcp->doff * 4 <= l4_len;
	}
	if (ip->protocol == IPPROTO_UDP) {
		if (l4_len < sizeof(udp_copy))
			return false;
		udp = skb_header_pointer(skb, offset + sizeof(*ip),
					 sizeof(udp_copy), &udp_copy);
		/* IPv4 permits a zero UDP checksum. Length still has to describe
		 * the complete datagram; no truncated/padded header is inferred.
		 */
		return udp && ntohs(udp->len) == l4_len;
	}
	return false;
}

/* Confirm the inner packet using an explicit kernel inner-header marker.
 * Unknown encapsulations/offsets remain on the software forwarding path.
 */
static bool hnat_tunnel_inner_match(const struct sk_buff *skb,
				  const struct foe_entry *entry)
{
	struct iphdr ip_copy;
	struct tcpudphdr ports_copy;
	const struct iphdr *ip;
	const struct tcpudphdr *ports;
	int offset;

	if (!skb->encapsulation || skb_is_gso(skb) ||
	    entry->bfib1.pkt_type != IPV4_HNAPT)
		return false;
	offset = skb_inner_network_header(skb) - skb->data;
	if (offset < 0 || offset > skb->len || skb->len - offset < sizeof(ip_copy))
		return false;
	ip = skb_header_pointer(skb, offset, sizeof(ip_copy), &ip_copy);
	if (!hnat_tunnel_ipv4_payload_valid(skb, offset, ip))
		return false;
	ports = skb_header_pointer(skb, offset + ip->ihl * 4,
				   sizeof(ports_copy), &ports_copy);
	return ports && (ip->protocol == IPPROTO_UDP) == !!entry->bfib1.udp &&
	       ntohl(ip->saddr) == entry->ipv4_hnapt.new_sip &&
	       ntohl(ip->daddr) == entry->ipv4_hnapt.new_dip &&
	       ntohs(ports->src) == entry->ipv4_hnapt.new_sport &&
	       ntohs(ports->dst) == entry->ipv4_hnapt.new_dport;
}

/* Match a real MT7988 MAC by its driver's registered netdev array. Names
 * such as eth1.10/bond0 are not proof that netdev_priv contains mtk_mac.
 */
static struct mtk_mac *hnat_tunnel_eth_mac(const struct net_device *dev)
{
	struct mtk_eth *eth;
	unsigned int i;

	if (!dev->dev.parent || !dev->dev.parent->of_node ||
	    !of_device_is_compatible(dev->dev.parent->of_node, "mediatek,mt7988-eth"))
		return NULL;
	eth = dev_get_drvdata(dev->dev.parent);
	if (!eth)
		return NULL;
	for (i = 0; i < MTK_MAX_DEVS; i++)
		if (eth->netdev[i] == dev)
			return eth->mac[i];
	return NULL;
}

/* Only a verified saved INNER flow may retain offload eligibility across
 * the kernel's LOCAL_OUT traversal of the newly encapsulated outer skb.
 * This is not a publication: post-routing repeats identity checks after NAT.
 */
static bool hnat_tunnel_pending_outer(struct sk_buff *skb)
{
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	struct hnat_flow_entry *flow;
	struct foe_entry *live;
	struct iphdr copy;
	const struct iphdr *ip;
	u64 generation = 0;
	u32 ppe, slot, type;
	bool valid = false;

	if (!hnat_tunnel_available() || !IS_SPACE_AVAILABLE_HEAD(skb) ||
	    skb_header_cloned(skb) || !is_magic_tag_valid(skb) ||
	    !is_hnat_info_filled(skb) || skb_hnat_is_decap(skb) ||
	    skb_hnat_reason(skb) != HIT_UNBIND_RATE_REACH)
		return false;
	type = skb_hnat_tops(skb);
	if (type != FLOW_OFFLOAD_TNL_GRETAP + 1 &&
	    type != FLOW_OFFLOAD_TNL_PPTP + 1 &&
	    type != FLOW_OFFLOAD_TNL_VXLAN + 1 &&
	    type != FLOW_OFFLOAD_TNL_L2TP_V2 + 1)
		return false;
	ip = skb_header_pointer(skb, skb_network_offset(skb), sizeof(copy), &copy);
	if (skb->protocol != htons(ETH_P_IP) || !ip || ip->version != 4 ||
	    ip->ihl != 5 || ip_is_fragment(ip))
		return false;
	ppe = skb_hnat_ppe(skb);
	slot = skb_hnat_entry(skb);
	if (ppe >= CFG_PPE_NUM || ppe >= MAX_PPE_NUM ||
	    slot >= hnat_priv->foe_etry_num || !hnat_priv->foe_table_cpu[ppe])
		return false;
	if (hnat_priv->data->per_flow_accounting &&
	    !hnat_account_generation_snapshot(hnat_priv, ppe, slot, &generation))
		return false;
	live = &hnat_priv->foe_table_cpu[ppe][slot];
	spin_lock_bh(&hnat_priv->flow_entry_lock);
	flow = hnat_flow_entry_search(live, ppe, slot, true);
	if (flow && flow->tunnel_dev && netif_running(flow->tunnel_dev) &&
	    flow->generation == generation &&
	    time_before(jiffies, flow->last_update + 3 * HZ) &&
	    hnat_flow_entry_unbind_match(&flow->data, live) &&
	    hnat_tunnel_inner_match(skb, &flow->data) &&
	    hnat_flow_ipv4_ct_match(NULL, &flow->data, flow->tunnel_ct, flow->tunnel_ctinfo))
		valid = true;
	spin_unlock_bh(&hnat_priv->flow_entry_lock);
	return valid;
#else
	return false;
#endif
}

/* Resolve outer Ethernet parameters into a software copy. eth_hdr(skb) can
 * still point at GRETAP/VXLAN's INNER Ethernet frame here; never rewrite it.
 * Neighbour resolution continues normally in the software path on a miss.
 */
static bool hnat_tunnel_outer_neighbour(struct sk_buff *skb,
					const struct net_device *out,
					struct flow_offload_hw_path *path)
{
	struct dst_entry *dst = skb_dst(skb);
	struct neighbour *neigh;
	bool valid;

	if (!dst || dst->dev != out || dst_xfrm(dst) ||
	    skb->protocol != htons(ETH_P_IP))
		return false;
	/* PPPoE's live channel supplies the peer MAC and session under the
	 * native PPP unit/channel locks. A PPP netdev has no ARP neighbour.
	 */
	if (path->flags & BIT(DEV_PATH_PPPOE))
		return path->pppoe_sid &&
		       is_valid_ether_addr(path->eth_dest) &&
		       is_valid_ether_addr(path->eth_src);
	neigh = dst_neigh_lookup_skb(dst, skb);
	if (!neigh)
		return false;
	neigh_ha_snapshot(path->eth_dest, neigh, out);
	valid = (READ_ONCE(neigh->nud_state) & NUD_VALID) &&
		is_valid_ether_addr(path->eth_dest) && is_valid_ether_addr(out->dev_addr);
	if (valid)
		ether_addr_copy(path->eth_src, out->dev_addr);
	neigh_release(neigh);
	return valid;
}

/* A bridge used as a WAN L3 endpoint is supported only with one direct,
 * forwarding MAC port and no VLAN filtering. Native ndo resolution supplies
 * that port from the real neighbour MAC/FDB; never guess it from an ifname.
 * Multiport bridges need FDB-move retirement before they can be cached.
 */
static bool hnat_tunnel_bridge_path(const struct net_device *underlay,
				    const struct flow_offload_hw_path *path)
{
	struct net_device *bridge = (struct net_device *)underlay;
	struct net_device *lower;
	struct list_head *iter;
	unsigned int ports = 0;
	bool valid = true;

	if (!netif_is_bridge_master(underlay))
		return true;
	if (br_vlan_enabled(underlay) ||
	    path->flags != BIT(DEV_PATH_ETHERNET) ||
	    path->virt_dev != underlay)
		return false;
	rcu_read_lock();
	iter = &bridge->adj_list.lower;
	while ((lower = netdev_next_lower_dev_rcu(bridge, &iter))) {
		ports++;
		if (lower != path->dev ||
		    br_port_get_stp_state(lower) != BR_STATE_FORWARDING)
			valid = false;
	}
	rcu_read_unlock();
	return valid && ports == 1;
}

/* One 802.1Q tag and/or a connected PPPoE channel, or the bridge above,
 * resolved by native ndo callbacks to an actual MT7988 MAC. Do not cast
 * virtual netdev private storage to mtk_mac or flatten QinQ/DSA paths.
 */
static bool hnat_tunnel_outer_path(const struct sk_buff *skb,
				   const struct net_device *underlay,
				   const struct flow_offload_hw_path *path,
				   struct hnat_tunnel_token *token)
{
	u32 flags = BIT(DEV_PATH_ETHERNET) | BIT(DEV_PATH_VLAN) | BIT(DEV_PATH_PPPOE);
	u16 tci = 0;

	if (!path->dev || path->flags & ~flags ||
	    !hnat_tunnel_eth_mac(path->dev) || netdev_uses_dsa(path->dev) ||
	    !netif_running(underlay) || !netif_running(path->dev) ||
	    dev_net(underlay) != &init_net || dev_net(path->dev) != &init_net ||
	    !hnat_tunnel_bridge_path(underlay, path))
		return false;
	if (path->flags & BIT(DEV_PATH_VLAN)) {
		if (path->vlan_proto != htons(ETH_P_8021Q) ||
		    path->vlan_id >= VLAN_VID_MASK || !path->virt_dev ||
		    !is_vlan_dev(path->virt_dev) ||
		    vlan_dev_real_dev(path->virt_dev) != path->dev ||
		    vlan_dev_vlan_id(path->virt_dev) != path->vlan_id)
			return false;
		tci = path->vlan_id | vlan_dev_get_egress_qos_mask(path->virt_dev, skb->priority);
	}
	if ((path->flags & BIT(DEV_PATH_PPPOE)) && !path->pppoe_sid)
		return false;
	token->underlay = (struct net_device *)underlay;
	token->egress = path->dev;
	token->egress_flags = path->flags;
	token->vlan_proto = path->flags & BIT(DEV_PATH_VLAN) ? path->vlan_proto : 0;
	token->vlan_tci = tci;
	token->pppoe_sid = path->flags & BIT(DEV_PATH_PPPOE) ? path->pppoe_sid : 0;
	return true;
}

static void hnat_tunnel_outer_l2(struct foe_entry *entry,
				 const struct hnat_tunnel_token *token)
{
	/* Native PPE actions insert PPPoE/VLAN; the TOPS firmware ABI remains
	 * Ethernet plus IP/tunnel parameters, exactly as in the vendor path.
	 */
	entry->bfib1.psn = !!(token->egress_flags & BIT(DEV_PATH_PPPOE));
	entry->bfib1.vlan_layer = !!(token->egress_flags & BIT(DEV_PATH_VLAN));
	entry->bfib1.vpm = entry->bfib1.vlan_layer != 0;
	entry->ipv4_hnapt.vlan1 = token->vlan_tci;
	entry->ipv4_hnapt.vlan2 = 0;
	entry->ipv4_hnapt.pppoe_id = token->pppoe_sid;
}

static void hnat_tunnel_confirm(struct sk_buff *skb, const struct net_device *out,
				const struct flow_offload_hw_path *path)
{
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	struct hnat_tunnel_token token = { 0 };
	struct hnat_flow_entry *flow;
	struct foe_entry entry, *live;
	struct net_device *tunnel_dev = NULL;
	struct nf_conn *ct = NULL;
	struct mtk_mac *mac;
	struct ethhdr eth = { .h_proto = htons(ETH_P_IP) };
	u64 generation = 0, sequence;
	u32 ppe = skb_hnat_ppe(skb), slot = skb_hnat_entry(skb);
	u8 ctinfo = 0;
	bool handled, accepted = false;
	int ret;

	if (!hnat_tunnel_outer_path(skb, out, path, &token)) {
		hnat_tunnel_event(TNL_OUTER_TOPOLOGY_REJECT);
		goto reject;
	}
	if (!is_hnat_info_filled(skb) || ppe >= CFG_PPE_NUM || ppe >= MAX_PPE_NUM ||
	    slot >= hnat_priv->foe_etry_num || !hnat_priv->foe_table_cpu[ppe] ||
	    skb_hnat_reason(skb) != HIT_UNBIND_RATE_REACH) {
		hnat_tunnel_event(TNL_OUTER_IDENTITY_REJECT);
		goto reject;
	}
	mac = hnat_tunnel_eth_mac(path->dev);
	if (hnat_priv->data->per_flow_accounting &&
	    !hnat_account_generation_snapshot(hnat_priv, ppe, slot, &generation))
		goto reject;
	live = &hnat_priv->foe_table_cpu[ppe][slot];
	spin_lock_bh(&hnat_priv->flow_entry_lock);
	flow = hnat_flow_entry_search(live, ppe, slot, true);
	if (!flow || !flow->tunnel_dev || flow->generation != generation ||
	    time_after_eq(jiffies, flow->last_update + 3 * HZ) ||
	    !hnat_flow_entry_unbind_match(&flow->data, live)) {
		spin_unlock_bh(&hnat_priv->flow_entry_lock);
		hnat_tunnel_event(TNL_SHADOW_MISS);
		goto reject;
	}
	entry = flow->data;
	sequence = flow->sequence;
	tunnel_dev = flow->tunnel_dev;
	dev_hold(tunnel_dev);
	ct = flow->tunnel_ct;
	ctinfo = flow->tunnel_ctinfo;
	if (ct)
		nf_conntrack_get(&ct->ct_general);
	spin_unlock_bh(&hnat_priv->flow_entry_lock);
	if (!hnat_tunnel_inner_match(skb, &entry) ||
	    !hnat_flow_ipv4_ct_match(NULL, &entry, ct, ctinfo)) {
		hnat_tunnel_event(TNL_INNER_IDENTITY_REJECT);
		goto put;
	}
	ether_addr_copy(eth.h_dest, path->eth_dest);
	ether_addr_copy(eth.h_source, path->eth_src);
	ret = hnat_tunnel_encap_offload(skb, &eth, tunnel_dev, &token);
	if (ret) {
		hnat_tunnel_event(ret == -EAGAIN ? TNL_SYNC_PENDING : TNL_SETUP_ERROR);
		goto put;
	}
	if (skb_hnat_tops(skb) != token.index + 32 ||
	    !hnat_tunnel_bind_lock(tunnel_dev, &token)) {
		hnat_tunnel_event(TNL_LEASE_REJECT);
		goto put;
	}
	/* No NPU callback/lock is acquired inside entry_lock. Keep the tunnel
	 * lease held until the actual descriptor publication has finished.
	 */
	spin_lock_bh(&hnat_priv->entry_lock);
	if (!hnat_flow_entry_lock_current(&entry, ppe, slot, generation, sequence, &flow))
		goto entry_unlock;
	if (flow->tunnel_dev != tunnel_dev || flow->tunnel_ct != ct ||
	    !hnat_flow_entry_unbind_match(&entry, live) ||
	    !hnat_tunnel_inner_match(skb, &entry) ||
	    !hnat_flow_ipv4_ct_match(NULL, &entry, ct, ctinfo))
		goto flow_unlock;
	entry.ipv4_hnapt.iblk2.dp = HNAT_GMAC_FP(mac->id);
	entry.ipv4_hnapt.tops_entry = token.index + 32;
	entry.ipv4_hnapt.tport_id = 5; /* official NR_TDMA_QDMA_TPORT */
	entry.ipv4_hnapt.iblk2.qid = 14;
	entry.ipv4_hnapt.iblk2.fqos = 1;
	hnat_tunnel_outer_l2(&entry, &token);
	entry.bfib1.state = BIND;
	entry.bfib1.ttl = 1;
	entry.bfib1.time_stamp = foe_timestamp(hnat_priv);
	handled = hnat_account_tunnel_commit(hnat_priv, ppe, slot, ct, ctinfo,
					     &entry, generation, &accepted);
	if (!handled && !hnat_priv->data->per_flow_accounting &&
	    (!ct || !nf_ct_is_dying(ct)) && hnat_flow_entry_unbind_match(&entry, live)) {
		hnat_copy_foe_info(live, &entry);
		wmb();
		memcpy(&live->bfib1, &entry.bfib1, sizeof(entry.bfib1));
		dma_wmb();
		accepted = true;
	}
	if (accepted) {
		hnat_tunnel_event(TNL_ENCAP_BOUND);
		hnat_flow_entry_delete(flow);
	} else {
		hnat_tunnel_event(TNL_PUBLISH_REJECT);
	}
flow_unlock:
	spin_unlock_bh(&hnat_priv->flow_entry_lock);
entry_unlock:
	spin_unlock_bh(&hnat_priv->entry_lock);
	hnat_tunnel_bind_unlock(&token);
put:
	if (ct)
		nf_ct_put(ct);
	if (tunnel_dev)
		dev_put(tunnel_dev);
reject:
	/* A failed hardware bind must never fall into ordinary outer-tuple
	 * publication. The already software-encapsulated skb keeps forwarding.
	 */
	skb_hnat_alg(skb) = 1;
	skb_hnat_filled(skb) = 0;
	skb_hnat_tops(skb) = 0;
#endif
}

static int hnat_mcast_unshare(struct sk_buff *skb)
{
	/* Bridge multicast replicates cloned skbs. The ordinary HNAT parser
	 * needs a private header before modifying its metadata. Zero extra
	 * headroom preserves the descriptor stored at skb->head.
	 */
	if (skb_header_cloned(skb) && hnat_npu_mcast_active() &&
	    IS_SPACE_AVAILABLE_HEAD(skb) && is_magic_tag_valid(skb) &&
	    skb_mac_header_was_set(skb) &&
	    is_multicast_ether_addr(eth_hdr(skb)->h_dest))
		return skb_cow_head(skb, 0);
	return 0;
}

static unsigned int mtk_hnat_nf_post_routing(
	struct sk_buff *skb, const struct net_device *out,
	unsigned int (*fn)(struct sk_buff *, const struct net_device *,
			   struct flow_offload_hw_path *),
	const char *func)
{
	struct foe_entry *entry;
	struct flow_offload_hw_path hw_path = { .dev = (struct net_device*)out,
						.virt_dev = (struct net_device*)out,
						.skb_hash = skb_hnat_entry(skb) };
	const struct net_device *arp_dev = out;
	const struct net_device *route_out = out;
	int path_err = 0;
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	bool tunnel_outer = false;
#endif

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	if (hnat_mcast_unshare(skb))
		return 0;
	if (skb_header_cloned(skb) &&
	    (hnat_tunnel_available() ||
	     (IS_SPACE_AVAILABLE_HEAD(skb) && is_magic_tag_valid(skb) && skb_hnat_tops(skb))))
		return 0;
	if (is_magic_tag_valid(skb) && IS_SPACE_AVAILABLE_HEAD(skb) &&
	    skb_hnat_tops(skb) && skb_hnat_is_decap(skb)) {
		skb_hnat_alg(skb) = 1;
		return 0;
	}
#endif

	if (xlat_toggle && !mtk_464xlat_post_process(skb, out))
		return 0;

	if (skb_hnat_alg(skb) || unlikely(!is_magic_tag_valid(skb) ||
					  !IS_SPACE_AVAILABLE_HEAD(skb)))
		return 0;

	/* Check before is_hashed(), which itself filters invalid FOE indices. */
	if (unlikely(hnat_invalid_index_fallback(skb)))
		return 0;

	if (unlikely(!skb_mac_header_was_set(skb)))
		return 0;
		
	if (!IS_WHNAT(out) && IS_EXT(out) && FROM_WED(skb))
		return 0;

	if (unlikely(!skb_hnat_is_hashed(skb)))
		return 0;

	if (unlikely(skb->mark == HNAT_EXCEPTION_TAG))
		return 0;

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	tunnel_outer = skb_hnat_tops(skb) && is_hnat_info_filled(skb);
	if (tunnel_outer) {
		hnat_tunnel_event(TNL_OUTER_SEEN);
		if (!hnat_tunnel_pending_outer(skb)) {
			hnat_tunnel_event(TNL_OUTER_IDENTITY_REJECT);
			return 0;
		}
		/* br_flow_offload_check needs ETH + the OUTER destination MAC
		 * before it can resolve a physical port through the bridge FDB.
		 * The skb MAC header can still describe the inner VXLAN frame.
		 */
		if (netif_is_bridge_master(route_out)) {
			if (!hnat_tunnel_outer_neighbour(skb, route_out, &hw_path)) {
				hnat_tunnel_event(TNL_OUTER_NEIGH_MISS);
				return 0;
			}
			hw_path.flags |= BIT(DEV_PATH_ETHERNET);
		}
	}
#endif
	if (out->netdev_ops->ndo_flow_offload_check) {
		path_err = out->netdev_ops->ndo_flow_offload_check(&hw_path);
		/* A failed/partial resolution cannot supply a device or hardware
		 * action for publication. Leave this packet on its software path.
		 */
		if (path_err || !hw_path.dev || !hw_path.virt_dev) {
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
			if (tunnel_outer)
				hnat_tunnel_event(TNL_OUTER_PATH_REJECT);
#endif
			return 0;
		}
		out = (IS_GMAC1_MODE) ? hw_path.virt_dev : hw_path.dev;
	}

#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	if ((hw_path.flags & BIT(DEV_PATH_TNL)) && mtk_npu_rx_meta_find(skb)) {
		skb_hnat_alg(skb) = 1;
		return 0;
	}
	if ((hw_path.flags & BIT(DEV_PATH_TNL)) && hnat_tunnel_available()) {
		struct iphdr copy;
		const struct iphdr *ip = skb_header_pointer(skb, skb_network_offset(skb),
							 sizeof(copy), &copy);

		if (skb->protocol != htons(ETH_P_IP) ||
		    !hnat_tunnel_ipv4_payload_valid(skb, skb_network_offset(skb), ip) ||
		    dev_net(out) != &init_net ||
		    (hw_path.tnl_type != FLOW_OFFLOAD_TNL_GRETAP &&
		     hw_path.tnl_type != FLOW_OFFLOAD_TNL_PPTP &&
		     hw_path.tnl_type != FLOW_OFFLOAD_TNL_VXLAN &&
		     hw_path.tnl_type != FLOW_OFFLOAD_TNL_L2TP_V2)) {
			skb_hnat_alg(skb) = 1;
			return 0;
		}
		skb_hnat_tops(skb) = hw_path.tnl_type + 1;
		skb_hnat_is_decap(skb) = 0;
	} else if (tunnel_outer) {
		if (!hnat_tunnel_outer_neighbour(skb, route_out, &hw_path)) {
			hnat_tunnel_event(TNL_OUTER_NEIGH_MISS);
			return 0;
		}
		hnat_tunnel_confirm(skb, route_out, &hw_path);
		return 0;
	}
	if (!skb_hnat_tops(skb) && !IS_LAN_GRP(out) && !IS_WAN(out) && !IS_EXT(out))
		return 0;
#else
	if (!IS_LAN_GRP(out) && !IS_WAN(out) && !IS_EXT(out))
		return 0;
#endif
	
	if (!IS_WHNAT(out) && IS_EXT(out))
		return 0;

	pr_debug_ratelimited("[%s] case hit, %x-->%s, reason=%x\n", __func__,
		     skb_hnat_iface(skb), out->name, skb_hnat_reason(skb));

	entry = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];

	switch (skb_hnat_reason(skb)) {
	case HIT_UNBIND_RATE_REACH:
		if (entry_hnat_is_bound(entry))
			break;

		if (fn && !mtk_hnat_accel_type(skb))
			break;

		if (fn && !(hw_path.flags & BIT(DEV_PATH_TNL)) && fn(skb, arp_dev, &hw_path))
			break;

		{
			struct hnat_tunnel_token rx_token = {};
			const struct mtk_npu_rx_meta *rx = mtk_npu_rx_meta_find(skb);

			if (rx && !hnat_tunnel_rx_bind_lock(rx, &rx_token))
				break;
			spin_lock_bh(&hnat_priv->entry_lock);
			skb_to_hnat_info(skb, out, entry, &hw_path);
			spin_unlock_bh(&hnat_priv->entry_lock);
			if (rx)
				hnat_tunnel_bind_unlock(&rx_token);
		}
		break;
	case HIT_BIND_KEEPALIVE_DUP_OLD_HDR:
		/* update hnat count to nf_conntrack by keepalive */
		if (hnat_priv->data->per_flow_accounting && hnat_priv->nf_stat_en)
			mtk_hnat_nf_update(skb);

		if (fn && !mtk_hnat_accel_type(skb))
			break;

		/* update dscp for qos */
		mtk_hnat_dscp_update(skb, entry);

		/* update mcast timestamp*/
		if (hnat_priv->data->version == MTK_HNAT_V1_3 &&
		    hnat_priv->data->mcast && entry->bfib1.sta == 1)
			entry->ipv4_hnapt.m_timestamp = foe_timestamp(hnat_priv);

		if (entry_hnat_is_bound(entry)) {
			memset(skb_hnat_info(skb), 0, sizeof(struct hnat_desc));

			return -1;
		}
		break;
	case HIT_BIND_MULTICAST_TO_CPU:
	case HIT_BIND_MULTICAST_TO_GMAC_CPU:
		/*do not forward to gdma again,if ppe already done it*/
		if (IS_LAN_GRP(out) || IS_WAN(out))
			return -1;
		break;
	}

	return 0;
}

static unsigned int
mtk_hnat_ipv6_nf_local_out(void *priv, struct sk_buff *skb,
			   const struct nf_hook_state *state)
{
	struct foe_entry *entry;
	struct ipv6hdr *ip6h;
	struct iphdr _iphdr;
	const struct iphdr *iph;
	struct tcpudphdr _ports;
	const struct tcpudphdr *pptr;
	int udp = 0;

	if (!is_magic_tag_valid(skb))
		return NF_ACCEPT;

	if (unlikely(!skb_hnat_is_hashed(skb)))
		return NF_ACCEPT;
		
	ip6h = ipv6_hdr(skb);
	if (ip6h->nexthdr != NEXTHDR_IPIP) {
		hnat_set_head_frags(state, skb, 1, hnat_set_alg);
		return NF_ACCEPT;
	}

	if (skb_hnat_entry(skb) >= hnat_priv->foe_etry_num ||
	    skb_hnat_ppe(skb) >= CFG_PPE_NUM)
		return NF_ACCEPT;

	entry = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];
	if (skb_hnat_reason(skb) == HIT_UNBIND_RATE_REACH) {
		if (ip6h->nexthdr == NEXTHDR_IPIP) {
			/* Map-E LAN->WAN: need to record orig info before fn. */
			if (mape_toggle) {
				iph = skb_header_pointer(skb, IPV6_HDR_LEN,
							 sizeof(_iphdr), &_iphdr);
				if (unlikely(!iph))
					return NF_ACCEPT;

				switch (iph->protocol) {
				case IPPROTO_UDP:
					udp = 1;
				case IPPROTO_TCP:
				break;

				default:
					return NF_ACCEPT;
				}

				pptr = skb_header_pointer(skb, IPV6_HDR_LEN + iph->ihl * 4,
							  sizeof(_ports), &_ports);
				if (unlikely(!pptr))
                                        return NF_ACCEPT;
				/* don't process inner fragment packets */
				if (ip_is_fragment(iph))
					return NF_ACCEPT;

				entry->bfib1.udp = udp;

				/* Map-E LAN->WAN record inner IPv4 header info. */
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
				entry->bfib1.pkt_type = IPV4_MAP_E;
				entry->ipv4_dslite.iblk2.dscp = iph->tos;
				entry->ipv4_mape.new_sip = ntohl(iph->saddr);
				entry->ipv4_mape.new_dip = ntohl(iph->daddr);
				entry->ipv4_mape.new_sport = ntohs(pptr->src);
				entry->ipv4_mape.new_dport = ntohs(pptr->dst);
#else
				entry->ipv4_hnapt.iblk2.dscp = iph->tos;
				entry->ipv4_hnapt.new_sip = ntohl(iph->saddr);
				entry->ipv4_hnapt.new_dip = ntohl(iph->daddr);
				entry->ipv4_hnapt.new_sport = ntohs(pptr->src);
				entry->ipv4_hnapt.new_dport = ntohs(pptr->dst);
#endif
			} else {
				entry->bfib1.pkt_type = IPV4_DSLITE;
			}
		}
	}
	return NF_ACCEPT;
}

static unsigned int
mtk_hnat_ipv6_nf_post_routing(void *priv, struct sk_buff *skb,
			      const struct nf_hook_state *state)
{
	if (!skb)
		goto drop;

	post_routing_print(skb, state->in, state->out, __func__);

	if (!mtk_hnat_nf_post_routing(skb, state->out, hnat_ipv6_get_nexthop,
				      __func__))
		return NF_ACCEPT;

drop:
	if (skb)
		pr_debug_ratelimited(
			"%s:drop (iif=0x%x, out_dev=%s, CB2=0x%x, ppe_hash=0x%x,\n"
			"sport=0x%x, reason=0x%x, alg=0x%x)\n",
			__func__, skb_hnat_iface(skb), state->out->name,
			HNAT_SKB_CB2(skb)->magic, skb_hnat_entry(skb),
			skb_hnat_sport(skb), skb_hnat_reason(skb),
			skb_hnat_alg(skb));

	return NF_DROP;
}

static unsigned int
mtk_hnat_ipv4_nf_post_routing(void *priv, struct sk_buff *skb,
			      const struct nf_hook_state *state)
{
	if (!skb)
		goto drop;

	post_routing_print(skb, state->in, state->out, __func__);

	if (!mtk_hnat_nf_post_routing(skb, state->out, hnat_ipv4_get_nexthop,
				      __func__))
		return NF_ACCEPT;

drop:
	if (skb)
		pr_debug_ratelimited(
			"%s:drop (iif=0x%x, out_dev=%s, CB2=0x%x, ppe_hash=0x%x,\n"
			"sport=0x%x, reason=0x%x, alg=0x%x)\n",
			__func__, skb_hnat_iface(skb), state->out->name,
			HNAT_SKB_CB2(skb)->magic, skb_hnat_entry(skb),
			skb_hnat_sport(skb), skb_hnat_reason(skb),
			skb_hnat_alg(skb));

	return NF_DROP;
}

static unsigned int
mtk_pong_hqos_handler(void *priv, struct sk_buff *skb,
		      const struct nf_hook_state *state)
{
	struct vlan_ethhdr *veth;

	if (!skb)
		goto drop;

	if (!is_magic_tag_valid(skb))
		return NF_ACCEPT;

	veth = (struct vlan_ethhdr *)skb_mac_header(skb);

	if (IS_HQOS_MODE && eth_hdr(skb)->h_proto == HQOS_MAGIC_TAG) {
		skb_hnat_entry(skb) = ntohs(veth->h_vlan_TCI) & 0x3fff;
		skb_hnat_reason(skb) = HIT_BIND_FORCE_TO_CPU;
	}

	if (skb_hnat_iface(skb) == FOE_MAGIC_EXT)
		clr_from_extge(skb);

	/* packets from external devices -> xxx ,step 2, learning stage */
	if (do_ext2ge_fast_learn(state->in, skb) && (!qos_toggle ||
	    (qos_toggle && eth_hdr(skb)->h_proto != HQOS_MAGIC_TAG))) {
		if (!do_hnat_ext_to_ge2(skb, __func__))
			return NF_STOLEN;
		goto drop;
	}

	/* packets form ge -> external device */
	if (do_ge2ext_fast(state->in, skb)) {
		if (!do_hnat_ge_to_ext(skb, __func__))
			return NF_STOLEN;
		goto drop;
	}

	return NF_ACCEPT;

drop:
	if (skb)
		printk_ratelimited(KERN_WARNING
			"%s:drop (in_dev=%s, iif=0x%x, CB2=0x%x, ppe_hash=0x%x,\n"
			"sport=0x%x, reason=0x%x, alg=0x%x)\n",
			__func__, state->in->name, skb_hnat_iface(skb),
			HNAT_SKB_CB2(skb)->magic, skb_hnat_entry(skb),
			skb_hnat_sport(skb), skb_hnat_reason(skb),
			skb_hnat_alg(skb));

	return NF_DROP;
}

static unsigned int
mtk_hnat_br_nf_local_out(void *priv, struct sk_buff *skb,
			 const struct nf_hook_state *state)
{
	if (!skb)
		goto drop;
	
	if ((!strncmp(state->out->name, "ra",2)) && !is_from_extge(skb) && !( FROM_GE_PPD(skb) || FROM_GE_LAN(skb) ||
		   FROM_GE_WAN(skb) || FROM_WED(skb) || FROM_EXT(skb) ||FROM_GE_VIRTUAL(skb))){
                if (!do_hnat_cpu_to_ge(skb))
                        return NF_STOLEN; 
        }

	if (!is_magic_tag_valid(skb))
		return NF_ACCEPT;

	post_routing_print(skb, state->in, state->out, __func__);

	if (!mtk_hnat_nf_post_routing(skb, state->out, 0, __func__))
		return NF_ACCEPT;

drop:
	if (skb)
		pr_debug_ratelimited(
			"%s:drop (iif=0x%x, out_dev=%s, CB2=0x%x, ppe_hash=0x%x,\n"
			"sport=0x%x, reason=0x%x, alg=0x%x)\n",
			__func__, skb_hnat_iface(skb), state->out->name,
			HNAT_SKB_CB2(skb)->magic, skb_hnat_entry(skb),
			skb_hnat_sport(skb), skb_hnat_reason(skb),
			skb_hnat_alg(skb));

	return NF_DROP;
}

static unsigned int
mtk_hnat_ipv4_nf_local_out(void *priv, struct sk_buff *skb,
			   const struct nf_hook_state *state)
{
	struct foe_entry *entry;
	struct iphdr *iph;

	if (!is_magic_tag_valid(skb))
		return NF_ACCEPT;

	if (unlikely(skb_headroom(skb) < FOE_INFO_LEN))
		return NF_ACCEPT;

	if (!skb_hnat_is_hashed(skb))
		return NF_ACCEPT;

	if (skb_hnat_entry(skb) >= hnat_priv->foe_etry_num ||
	    skb_hnat_ppe(skb) >= CFG_PPE_NUM)
		return NF_ACCEPT;

	if (hnat_tunnel_pending_outer(skb))
		return NF_ACCEPT;

	entry = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];

	/* Make the flow from local not be bound. */
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_IPV6) {
		entry->udib1.pkt_type = IPV6_6RD;
		hnat_set_head_frags(state, skb, 0, hnat_set_alg);
	} else {
		hnat_set_head_frags(state, skb, 1, hnat_set_alg);
	}

	return NF_ACCEPT;
}

static unsigned int mtk_hnat_br_nf_forward(void *priv,
					   struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	if ((hnat_priv->data->version == MTK_HNAT_V1_2) &&
	    unlikely(IS_EXT(state->in) && IS_EXT(state->out)))
		hnat_set_head_frags(state, skb, 1, hnat_set_alg);

	return NF_ACCEPT;
}

/* Learn bridge multicast even when the optional WiFi driver has not adjusted
 * the ordinary HNAT bridge hooks. Only UNBIND rate notifications enter this
 * path; replicated traffic and keepalive handling retain their normal hooks.
 */
static unsigned int
mtk_hnat_br_mcast_post_routing(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	if (state->out && hnat_npu_mcast_active() &&
	    IS_SPACE_AVAILABLE_HEAD(skb) && is_magic_tag_valid(skb) &&
	    skb_mac_header_was_set(skb) &&
	    is_multicast_ether_addr(eth_hdr(skb)->h_dest) &&
	    skb_hnat_reason(skb) == HIT_UNBIND_RATE_REACH)
		mtk_hnat_nf_post_routing(skb, state->out, NULL, __func__);
	return NF_ACCEPT;
}

static struct nf_hook_ops mtk_hnat_nf_ops[] __read_mostly = {
	{
		.hook = mtk_hnat_br_mcast_post_routing,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_POST_ROUTING,
		.priority = NF_BR_PRI_LAST,
	},
	{
		.hook = mtk_hnat_nf_conntrack,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE-1,
	},
	{
		.hook = mtk_hnat_nf_conntrack,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE-1,
	},
	{
		.hook = mtk_hnat_ipv4_nf_pre_routing,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST + 1,
	},
	{
		.hook = mtk_hnat_ipv6_nf_pre_routing,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST + 1,
	},
	{
		.hook = mtk_hnat_ipv6_nf_post_routing,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_hnat_ipv6_nf_local_out,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_hnat_ipv4_nf_post_routing,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_hnat_ipv4_nf_local_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_hnat_br_nf_local_in,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_LOCAL_IN,
		.priority = NF_BR_PRI_FIRST,
	},
	{
		.hook = mtk_hnat_br_nf_local_out,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_LOCAL_OUT,
		.priority = NF_BR_PRI_LAST - 1,
	},
	{
		.hook = mtk_pong_hqos_handler,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_PRE_ROUTING,
		.priority = NF_BR_PRI_FIRST + 1,
	},
};

int hnat_register_nf_hooks(void)
{
	return nf_register_net_hooks(&init_net, mtk_hnat_nf_ops, ARRAY_SIZE(mtk_hnat_nf_ops));
}

void hnat_unregister_nf_hooks(void)
{
	nf_unregister_net_hooks(&init_net, mtk_hnat_nf_ops, ARRAY_SIZE(mtk_hnat_nf_ops));
}

int whnat_adjust_nf_hooks(void)
{
	struct nf_hook_ops *hook = mtk_hnat_nf_ops;
	unsigned int n = ARRAY_SIZE(mtk_hnat_nf_ops);

	while (n-- > 0) {
		if (hook[n].hook == mtk_hnat_br_nf_local_in) {
			hook[n].hooknum = NF_BR_PRE_ROUTING;
			hook[n].priority = NF_BR_PRI_FIRST + 1;
		} else if (hook[n].hook == mtk_hnat_br_nf_local_out) {
			hook[n].hooknum = NF_BR_POST_ROUTING;
		} else if (hook[n].hook == mtk_pong_hqos_handler) {
			hook[n].hook = mtk_hnat_br_nf_forward;
			hook[n].hooknum = NF_BR_FORWARD;
			hook[n].priority = NF_BR_PRI_LAST - 1;
		}
	}

	return 0;
}

int mtk_hqos_ptype_cb(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *unused)
{
	struct vlan_ethhdr *veth = (struct vlan_ethhdr *)skb_mac_header(skb);

	skb_hnat_entry(skb) = ntohs(veth->h_vlan_TCI) & 0x3fff;
	skb_hnat_reason(skb) = HIT_BIND_FORCE_TO_CPU;

	if (do_hnat_ge_to_ext(skb, __func__) == -1)
		return 1;

	return 0;
}
