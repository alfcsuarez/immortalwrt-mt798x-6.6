// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 MediaTek Inc. All Rights Reserved.
 *
 * Author: Ren-Ting Wang <ren-ting.wang@mediatek.com>
 */

#include <linux/err.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/ppp_channel.h>

#include <net/flow_offload.h>
#include <net/ip.h>
#include <net/netfilter/nf_flow_table.h>

#include <mtk_eth_soc.h>
#include <mtk_hnat/hnat.h>
#include <mtk_hnat/nf_hnat_mtk.h>

#include <pce/cls.h>
#include <pce/netsys.h>
#include <pce/pce.h>

#include "npu/mcu.h"
#include "npu/misc.h"
#include "npu/netsys.h"

#include "npu/protocol/tunnel/gre/gretap.h"
#include "npu/protocol/tunnel/l2tp/l2tpv2.h"
#include "npu/protocol/tunnel/pptp/pptp.h"
#include "npu/protocol/tunnel/vxlan/vxlan.h"

#include "npu-nf_hnat/internal.h"
#include "npu-nf_hnat/tnl-offload.h"

static int mtk_npu_nf_hnat_tnl_info_cls_setup(struct npu_tnl_info *tnl_info);
static void mtk_npu_nf_hnat_tnl_info_cls_destroy(struct npu_tnl_info *tnl_info);

static void hnat_flush_index(u32 index)
{
	hnat_tunnel_flush(index + __NPU_TUNNEL_TYPE_MAX);
}

static struct npu_tnl_info_ops hnat_tnl_info_ops = {
	.flush = mtk_npu_tnl_info_flush_one_ppe_tnl,
	.flush_index = hnat_flush_index,
	.cls_setup = mtk_npu_nf_hnat_tnl_info_cls_setup,
	.cls_destroy = mtk_npu_nf_hnat_tnl_info_cls_destroy,
};
static struct npu_nf_hnat_statistic hnat_ts;

static inline void inc_tnl_hnat_decap_offloadable_statistic_success(void)
{
	atomic64_inc(&hnat_ts.decap_offloadable.success);
}

static inline void inc_tnl_hnat_decap_offloadable_statistic_fail(void)
{
	atomic64_inc(&hnat_ts.decap_offloadable.fail);
}

static inline void inc_tnl_hnat_decap_offload_statistic_fail(void)
{
	atomic64_inc(&hnat_ts.decap_offload.fail);
}

static inline void inc_tnl_hnat_encap_offload_statistic_fail(void)
{
	atomic64_inc(&hnat_ts.encap_offload.fail);
}

static void mtk_npu_hnat_setup_result(struct npu_nf_hnat_statistic_counter *counter,
				    int ret)
{
	/* Learning queues a firmware update before any PPE publication. Those
	 * packets intentionally fall back until the ACK; this is not a FW error.
	 */
	if (ret == -EAGAIN)
		atomic64_inc(&counter->pending_sync);
	else if (ret)
		atomic64_inc(&counter->fail);
	else
		atomic64_inc(&counter->success);
}

static inline void skb_set_npu_tnl_idx(struct sk_buff *skb, u32 tnl_idx)
{
	skb_hnat_tops(skb) = tnl_idx + __NPU_TUNNEL_TYPE_MAX;
}

static inline bool skb_npu_valid(struct sk_buff *skb)
{
	return (skb && skb_hnat_tops(skb) < __NPU_TUNNEL_TYPE_MAX);
}

static inline struct npu_tnl_type *skb_to_tnl_type(struct sk_buff *skb)
{
	enum npu_tunnel_type tnl_proto_type = skb_hnat_tops(skb);

	if (unlikely(!tnl_proto_type || tnl_proto_type >= __NPU_TUNNEL_TYPE_MAX))
		return ERR_PTR(-EINVAL);

	return mtk_npu_tnl_type_get_by_idx(tnl_proto_type);
}

static inline struct npu_tnl_info *skb_to_tnl_info(struct sk_buff *skb)
{
	u32 tnl_idx = skb_hnat_tops(skb) - __NPU_TUNNEL_TYPE_MAX;

	return mtk_npu_tnl_info_get_by_idx(tnl_idx);
}

static inline void skb_mark_unbind(struct sk_buff *skb)
{
	skb_hnat_tops(skb) = 0;
	skb_hnat_is_decap(skb) = 0;
	skb_hnat_alg(skb) = 1;
}

/*
 * check cls entry is updated for tunnel protocols that only use 1 CLS HW entry
 *
 * since only tunnel sync task will operate on tcls linked list,
 * it is safe to access without lock
 *
 * return true on updated
 * return false on need update
 */
static bool mtk_npu_nf_hnat_tnl_info_cls_is_updated(struct npu_tnl_info *tnl_info,
						    struct npu_tnl_type *tnl_type)
{
	struct npu_cls_entry *found = NULL;
	struct npu_cls_entry *tcls;

	/*
	 * check tnl_type has already allocate a npu_cls_entry
	 * if not, return false to prepare to allocate a new one
	 */
	if (list_empty(&tnl_type->tcls_head))
		return false;

	/*
	 * if tnl_info is not associate to tnl_type's cls entry,
	 * make a reference to npu_cls_entry
	 */
	if (!tnl_info->tcls) {
		list_for_each_entry(tcls, &tnl_type->tcls_head, node) {
			if (tcls->cls->cdesc.cdrt_idx == tnl_info->tnl_params.cdrt_idx) {
				found = tcls;
				break;
			}
		}

		if (!found)
			return false;

		mtk_npu_tnl_info_cls_link(tnl_info, found);
	}

	return tnl_info->tcls->updated;
}

static int mtk_npu_nf_hnat_tnl_info_cls_setup(struct npu_tnl_info *tnl_info)
{
	struct npu_tnl_params *tnl_params = &tnl_info->tnl_params;
	struct npu_tnl_type *tnl_type = tnl_info->tnl_type;
	struct npu_cls_entry *tcls;
	int ret;

	if (mtk_npu_nf_hnat_tnl_info_cls_is_updated(tnl_info, tnl_type))
		return 0;

	if (tnl_info->tcls)
		goto cls_entry_write;

	tcls = mtk_npu_tnl_info_cls_entry_alloc(tnl_info, tnl_params);
	if (IS_ERR(tcls))
		return PTR_ERR(tcls);

	/* Crypto/EIP197 is outside this 24.10 tunnel port. No guessed TPORT. */
	if (tnl_params->cdrt_idx) {
		ret = -EOPNOTSUPP;
		goto cls_entry_unprepare;
	}
	ret = tnl_type->cls_entry_setup(tnl_info, &tcls->cls->cdesc);
	if (ret) {
		NPU_NOTICE("npu cls entry setup failed: %d\n", ret);
		goto cls_entry_unprepare;
	}

cls_entry_write:
	ret = mtk_npu_tnl_info_cls_entry_write(tnl_info);

cls_entry_unprepare:
	if (ret)
		mtk_npu_tnl_info_cls_entry_free(tnl_info, tnl_params);

	return ret;
}

static void mtk_npu_nf_hnat_tnl_info_cls_destroy(struct npu_tnl_info *tnl_info)
{
	struct npu_tnl_params *tnl_params = &tnl_info->tnl_params;
	struct npu_cls_entry *tcls = tnl_info->tcls;

	if (!tcls)
		return;

	if (!tnl_params->cdrt_idx)
		memset(&tcls->cls->cdesc, 0, sizeof(tcls->cls->cdesc));
	else
		/*
		 * recover tport_ix to let matched-packets to
		 * go through EIP197 only
		 */
		CLS_DESC_DATA(&tcls->cls->cdesc, tport_idx, 2);
}

/* HNAT owns FOE locking, MIB retirement and software shadow lifetime. */
void mtk_npu_tnl_info_flush_one_ppe_tnl_no_lock(struct npu_tnl_info *tnl_info)
{
	if (!tnl_info)
		return;
	lockdep_assert_held(&tnl_info->lock);
	hnat_tunnel_flush(tnl_info->tnl_idx + __NPU_TUNNEL_TYPE_MAX);
}

void mtk_npu_tnl_info_flush_one_ppe_tnl(struct npu_tnl_info *tnl_info)
{
	if (!tnl_info)
		return;
	/* HNAT nests BH locks while draining its ledger. Keep IRQs enabled. */
	spin_lock_bh(&tnl_info->lock);
	mtk_npu_tnl_info_flush_one_ppe_tnl_no_lock(tnl_info);
	spin_unlock_bh(&tnl_info->lock);
}

void mtk_npu_tnl_info_flush_all_ppe_tnl(void)
{
	hnat_tunnel_flush(0);
}

static inline void mtk_npu_nf_hnat_tnl_info_preserve(struct npu_tnl_type *tnl_type,
						     struct npu_tnl_params *old,
						     struct npu_tnl_params *new)
{
	new->flag |= old->flag;
	new->cls_entry = old->cls_entry;
	if (old->cdrt_idx)
		new->cdrt_idx = old->cdrt_idx;

	/* restore mtu if old parameter already setup */
	if (old->params.mtu && old->params.mtu != tnl_type->max_mtu)
		new->params.mtu = old->params.mtu;
	else
		new->params.mtu = tnl_type->max_mtu;

	/* we can only get ttl from encapsulation */
	if (new->params.network.ip.ttl == 128 && old->params.network.ip.ttl != 0)
		new->params.network.ip.ttl = old->params.network.ip.ttl;

	/* call tunnel specific restore callback */
	if (tnl_type->tnl_param_restore)
		tnl_type->tnl_param_restore(&old->params, &new->params);
}

static bool mtk_npu_egress_matches(const struct npu_tnl_info *info,
				 const struct hnat_tunnel_token *token)
{
	return token && info->underlay == token->underlay &&
	       info->egress == token->egress &&
	       info->egress_flags == token->egress_flags &&
	       info->vlan_proto == token->vlan_proto &&
	       info->vlan_tci == token->vlan_tci &&
	       info->pppoe_sid == token->pppoe_sid;
}

static void mtk_npu_egress_replace(struct npu_tnl_info *info,
				   const struct hnat_tunnel_token *token)
{
	/* Caller owns the tunnel lock; no borrowed session/socket escapes. */
	dev_hold(token->underlay);
	dev_hold(token->egress);
	if (info->underlay)
		dev_put(info->underlay);
	if (info->egress)
		dev_put(info->egress);
	info->underlay = token->underlay;
	info->egress = token->egress;
	info->egress_flags = token->egress_flags;
	info->vlan_proto = token->vlan_proto;
	info->vlan_tci = token->vlan_tci;
	info->pppoe_sid = token->pppoe_sid;
}

/* Caller holds tbl_lock with BH disabled and IRQs enabled. This function
 * takes info->lock and may nest HNAT's BH locks during egress retirement.
 */
static int mtk_npu_nf_hnat_tnl_info_setup(struct npu_tnl_input *tnl_input,
					  struct npu_tnl_type *tnl_type,
					  struct npu_tnl_info *tnl_info,
					  struct npu_tnl_params *tnl_params)
{
	struct sk_buff *skb = tnl_input->hnat.skb;
	struct net_device *dev = tnl_input->hnat.dev;
	const struct hnat_tunnel_token *token = tnl_input->hnat.token;
	bool has_diff = false;
	bool egress_diff = false;
	int ret = 0;

	if (unlikely(!skb || !dev || !tnl_info || !tnl_params ||
		     dev_net(dev) != &init_net))
		return -EPERM;

	spin_lock(&tnl_info->lock);
	if (dev->type == ARPHRD_PPP && !ppp_netdev_tunnel_offload_allowed(dev)) {
		spin_unlock(&tnl_info->lock);
		return -EOPNOTSUPP;
	}
	if ((tnl_info->status & (TNL_STA_DELETING | TNL_STA_DELETING_SKIP_PCE)) ||
	    (tnl_info->dev && tnl_info->dev != dev)) {
		spin_unlock(&tnl_info->lock);
		return -EBUSY;
	}
	if (skb_hnat_is_encap(skb)) {
		if (!token || !token->underlay || !token->egress ||
		    !netif_running(token->underlay) || !netif_running(token->egress)) {
			spin_unlock(&tnl_info->lock);
			return -ENODEV;
		}
		egress_diff = !mtk_npu_egress_matches(tnl_info, token);
		if (egress_diff) {
			/* Session/VID changes are not in firmware's ABI. Retire PPE
			 * actions before allowing another host-side egress epoch.
			 */
			if (tnl_info->egress)
				mtk_npu_tnl_info_flush_one_ppe_tnl_no_lock(tnl_info);
			mtk_npu_egress_replace(tnl_info, token);
		}
	}
	if (!tnl_info->dev) {
		dev_hold(dev);
		tnl_info->dev = dev;
	}
	tnl_info->ops = &hnat_tnl_info_ops;

	mtk_npu_nf_hnat_tnl_info_preserve(tnl_type, &tnl_info->cache, tnl_params);

	has_diff = egress_diff || memcmp(&tnl_info->cache, tnl_params, sizeof(*tnl_params));
	if (has_diff) {
		if (!++tnl_info->generation)
			tnl_info->generation++;
		memcpy(&tnl_info->cache, tnl_params, sizeof(*tnl_params));
		mtk_npu_tnl_info_hash_no_lock(tnl_info);
	}

	if (skb_hnat_is_decap(skb)) {
		/* the net_device is used to forward pkt to decap'ed inf when Rx */
		tnl_info->cache.params.mtu = READ_ONCE(skb->dev->mtu);
		if (!tnl_info_decap_is_enable(tnl_info)) {
			has_diff = true;
			tnl_info_decap_enable(tnl_info);
		}
	} else if (skb_hnat_is_encap(skb)) {
		/* set skb_hnat_tops(skb) to tunnel index for ppe binding */
		skb_set_npu_tnl_idx(skb, tnl_info->tnl_idx);
		if (!tnl_info_encap_is_enable(tnl_info)) {
			has_diff = true;
			tnl_info_encap_enable(tnl_info);
		}
	}

	if (has_diff)
		mtk_npu_tnl_info_submit_no_tnl_lock(tnl_info);
	/* Do not publish a PPE binding while firmware synchronization is pending. */
	if (!(tnl_info->status & TNL_STA_UPDATED) ||
	    (tnl_info->status & (TNL_STA_UPDATING | TNL_STA_QUEUED)) ||
	    memcmp(&tnl_info->cache, &tnl_info->tnl_params, sizeof(tnl_info->cache)))
		ret = -EAGAIN;
	else if (tnl_input->hnat.generation) {
		*tnl_input->hnat.generation = tnl_info->generation;
		if (tnl_input->hnat.token)
			tnl_input->hnat.token->allocation = tnl_info->allocation_cookie;
	}
	spin_unlock(&tnl_info->lock);
	return ret;
}

static bool mtk_npu_tnl_decap_offloadable(struct sk_buff *skb)
{
	struct flow_offload_hw_path hw_path = { 0 };
	struct npu_tnl_type *tnl_type;
	struct iphdr copy, *iph;
	u32 offload_tnl_type_num;
	u32 cnt;
	u32 i;

	if (!mtk_npu_is_ready() || dev_net(skb->dev) != &init_net ||
	    skb_hnat_cdrt(skb) || secpath_exists(skb))
		return false;

	if (unlikely(!mtk_npu_mcu_alive())) {
		skb_mark_unbind(skb);
		inc_tnl_hnat_decap_offloadable_statistic_fail();
		return false;
	}

	/* skb should not carry npu here */
	if (skb_hnat_tops(skb)) {
		inc_tnl_hnat_decap_offloadable_statistic_fail();
		return false;
	}

	iph = skb_header_pointer(skb, skb_network_offset(skb), sizeof(copy), &copy);
	/* Only a complete, unfragmented IPv4 outer header is supported. */
	if (!iph || iph->version != 4 || iph->ihl != 5 || ip_is_fragment(iph) ||
	    !pskb_may_pull(skb, skb_network_offset(skb) + iph->ihl * 4))
		return false;

	hw_path.dev = skb->dev;
	hw_path.virt_dev = skb->dev;

	if (skb->dev->netdev_ops->ndo_flow_offload_check) {
		skb->dev->netdev_ops->ndo_flow_offload_check(&hw_path);
		if (hw_path.flags & BIT(DEV_PATH_PPPOE))
			skb_hnat_set_is_pppoe(skb, 1);
	}

	offload_tnl_type_num = mtk_npu_tnl_type_get_offload_num();
	/* TODO: may can be optimized */
	for (i = NPU_TUNNEL_GRETAP, cnt = 0;
	     i < __NPU_TUNNEL_TYPE_MAX && cnt < offload_tnl_type_num;
	     i++) {
		tnl_type = mtk_npu_tnl_type_get_by_idx(i);
		if (IS_ERR(tnl_type))
			continue;

		cnt++;
		if (tnl_type->tnl_decap_offloadable
		    && tnl_type->tnl_decap_offloadable(skb)) {
			skb_hnat_tops(skb) = tnl_type->tnl_proto_type;
			inc_tnl_hnat_decap_offloadable_statistic_success();
			return true;
		}
	}

	inc_tnl_hnat_decap_offloadable_statistic_fail();

	return false;
}

static int mtk_npu_tnl_decap_offload(struct sk_buff *skb)
{
	struct npu_tnl_params tnl_params;
	struct npu_tnl_input tnl_input;
	struct npu_tnl_type *tnl_type;
	int ret;

	if (unlikely(!mtk_npu_mcu_alive())) {
		skb_mark_unbind(skb);
		inc_tnl_hnat_decap_offload_statistic_fail();
		return -EAGAIN;
	}

	if (unlikely(!skb_npu_valid(skb) || !skb_hnat_is_decap(skb))) {
		skb_mark_unbind(skb);
		inc_tnl_hnat_decap_offload_statistic_fail();
		return -EINVAL;
	}

	tnl_type = skb_to_tnl_type(skb);
	if (IS_ERR(tnl_type)) {
		skb_mark_unbind(skb);
		inc_tnl_hnat_decap_offload_statistic_fail();
		return PTR_ERR(tnl_type);
	}

	if (unlikely(!tnl_type->tnl_decap_param_setup || !tnl_type->tnl_param_match)) {
		skb_mark_unbind(skb);
		inc_tnl_hnat_decap_offload_statistic_fail();
		return -ENODEV;
	}

	/* Every parser below restores known, removed headers in headroom.
	 * Keep those reads above the 16-byte descriptor, and reject unknown
	 * inner/outer formats before any push operation.
	 */
	if (skb->protocol != htons(ETH_P_IP) ||
	    !pskb_may_pull(skb, sizeof(struct iphdr)) ||
	    ip_hdr(skb)->version != 4 ||
	    skb_headroom(skb) < 16 + 64 + (skb_hnat_is_pppoe(skb) ? 8 : 0))
		return -EOPNOTSUPP;

	memset(&tnl_params, 0, sizeof(struct npu_tnl_params));
	memset(&tnl_input, 0, sizeof(struct npu_tnl_input));
	tnl_input.hnat.skb = skb;
	tnl_input.hnat.dev = skb->dev;

	/* push removed ethernet header back first */
	if (tnl_type->has_inner_eth)
		skb_push(skb, sizeof(struct ethhdr));

	ret = mtk_npu_decap_param_setup(skb,
					 &tnl_params.params,
					 tnl_type->tnl_decap_param_setup);

	/* pull ethernet header to restore skb->data to ip start */
	if (tnl_type->has_inner_eth)
		skb_pull(skb, sizeof(struct ethhdr));

	/*
	 * We don't need to mark unbind here
	 * Since we may learn the tunnel info in next pre-routing
	 */
	if (unlikely(ret))
		return ret;

	tnl_params.npu_entry_proto = tnl_type->tnl_proto_type;
	tnl_params.cdrt_idx = skb_hnat_cdrt(skb);

	ret = mtk_npu_tnl_offload(&tnl_input,
				  tnl_type,
				  &tnl_params,
				  mtk_npu_nf_hnat_tnl_info_setup);

	/*
	 * whether success or fail to offload a decapsulation tunnel
	 * skb_hnat_tops(skb) must be cleared to avoid mtk_tnl_decap_offload() get
	 * called again
	 */
	skb_hnat_tops(skb) = 0;
	skb_hnat_is_decap(skb) = 0;

	mtk_npu_hnat_setup_result(&hnat_ts.decap_offload, ret);

	return ret;
}

static int mtk_npu_tnl_l2_update(struct sk_buff *skb, struct ethhdr *eth)
{
	struct npu_tnl_info *tnl_info = skb_to_tnl_info(skb);
	struct npu_tnl_type *tnl_type;
	unsigned long flag;
	int ret;

	if (IS_ERR(tnl_info))
		return PTR_ERR(tnl_info);

	tnl_type = tnl_info->tnl_type;
	if (!tnl_type->tnl_l2_param_update)
		return -ENODEV;

	spin_lock_irqsave(&tnl_info->lock, flag);

	ret = tnl_type->tnl_l2_param_update(&tnl_info->cache.params, eth);
	/* tnl params need to be updated */
	if (ret == 1) {
		mtk_npu_tnl_info_submit_no_tnl_lock(tnl_info);
		ret = 0;
	}

	spin_unlock_irqrestore(&tnl_info->lock, flag);

	return ret;
}

static int __mtk_npu_tnl_encap_offload(struct sk_buff *skb, struct ethhdr *eth,
				      struct net_device *dev, struct hnat_tunnel_token *token)
{
	struct npu_tnl_params tnl_params;
	struct npu_tnl_input tnl_input;
	struct npu_tnl_type *tnl_type;
	int ret;

	tnl_type = skb_to_tnl_type(skb);
	if (IS_ERR(tnl_type))
		return PTR_ERR(tnl_type);

	if (unlikely(!tnl_type->tnl_encap_param_setup || !tnl_type->tnl_param_match))
		return -ENODEV;

	memset(&tnl_params, 0, sizeof(struct npu_tnl_params));
	memset(&tnl_input, 0, sizeof(struct npu_tnl_input));

	/* Protocol parsers move only known outer headers. Make that bounded
	 * prefix linear before any pull/push; payload fragments stay untouched.
	 */
	if (!pskb_may_pull(skb, min_t(unsigned int, skb->len, 128)))
		return -ENOMEM;
	ret = mtk_npu_encap_param_setup(skb,
					eth,
					&tnl_params.params,
					tnl_type->tnl_encap_param_setup);
	if (unlikely(ret))
		return ret;

	tnl_params.npu_entry_proto = tnl_type->tnl_proto_type;
	tnl_params.cdrt_idx = skb_hnat_cdrt(skb);
	tnl_input.hnat.skb = skb;
	tnl_input.hnat.dev = dev;
	tnl_input.hnat.generation = &token->generation;
	tnl_input.hnat.token = token;

	return mtk_npu_tnl_offload(&tnl_input,
				   tnl_type,
				   &tnl_params,
				   mtk_npu_nf_hnat_tnl_info_setup);
}

static int mtk_npu_tnl_encap_offload(struct sk_buff *skb, struct ethhdr *eth,
				  struct net_device *dev, struct hnat_tunnel_token *token)
{
	int ret;

	if (unlikely(!skb || !eth || !dev || !token ||
		     !mtk_npu_is_ready() || skb_hnat_cdrt(skb) ||
		     dev_net(dev) != &init_net)) {
		inc_tnl_hnat_encap_offload_statistic_fail();
		return -EINVAL;
	}

	if (unlikely(!mtk_npu_mcu_alive())) {
		skb_mark_unbind(skb);
		inc_tnl_hnat_encap_offload_statistic_fail();
		return -EAGAIN;
	}

	if (!skb_hnat_is_encap(skb)) {
		inc_tnl_hnat_encap_offload_statistic_fail();
		return -EPERM;
	}

	if (skb_hnat_cdrt(skb))
		ret = mtk_npu_tnl_l2_update(skb, eth);
	else
		ret = __mtk_npu_tnl_encap_offload(skb, eth, dev, token);
	if (!ret)
		token->index = skb_hnat_tops(skb) - __NPU_TUNNEL_TYPE_MAX;

	mtk_npu_hnat_setup_result(&hnat_ts.encap_offload, ret);

	return ret;
}

static bool mtk_npu_nf_hnat_tnl_is_encrypted_offloadable(struct sk_buff *skb)
{
	return skb && !skb_hnat_cdrt(skb) && skb_dst(skb) && dst_xfrm(skb_dst(skb));
}

static struct net_device *mtk_npu_get_tnl_dev(u8 reason, struct mtk_npu_rx_meta *meta)
{
	struct npu_tnl_info *info;
	struct net_device *dev = NULL;
	unsigned long flags;

	if (!mtk_npu_is_ready() || !mtk_npu_mcu_alive() ||
	    reason < NPU_CRSN_TNL_ID_START || reason > NPU_CRSN_TNL_ID_END)
		return NULL;
	info = mtk_npu_tnl_info_get_by_idx(reason - NPU_CRSN_TNL_ID_START);
	if (IS_ERR(info))
		return NULL;
	spin_lock_irqsave(&info->lock, flags);
	if (mtk_npu_tnl_offload_ready() &&
	    info->dev && (info->status & TNL_STA_UPDATED) &&
	    !(info->status & (TNL_STA_UPDATING | TNL_STA_QUEUED |
			      TNL_STA_DELETING | TNL_STA_DELETING_SKIP_PCE)) &&
	    info->synced_generation == info->generation &&
	    (info->dev->type != ARPHRD_PPP ||
	     ppp_netdev_tunnel_offload_allowed(info->dev)) &&
	    tnl_info_decap_is_enable(info) && netif_running(info->dev)) {
		dev = info->dev;
		meta->entry = info->tnl_idx + __NPU_TUNNEL_TYPE_MAX;
		meta->tunnel_ifindex = dev->ifindex;
		meta->generation = info->generation;
		meta->allocation = info->allocation_cookie;
		npu_tnl_record_rx_no_lock(info, meta->rx_frame_len);
		dev_hold(dev);
	}
	spin_unlock_irqrestore(&info->lock, flags);
	return dev;
}

static int mcu_netstop_pre_enter(struct mcu_state_notifier *notifier)
{
	mtk_npu_tnl_info_backup_all();
	mtk_npu_tnl_info_flush_all_ppe_tnl();

	return 0;
}

static int mcu_init_pre_leave(struct mcu_state_notifier *notifier)
{
	int ret;

	ret = mtk_npu_misc_set_ppe_num();
	if (ret)
		return ret;
	/* Firmware may relocate the table on every boot/recovery. */
	ret = mtk_npu_tnl_offload_post_init(NULL);
	if (ret)
		return ret;

	mtk_npu_tnl_info_restore_all();

	return 0;
}

static int mcu_freerun_pre_enter(struct mcu_state_notifier *notifier)
{
	/* Some reset events return from NETSTOP without a cold INIT. */
	if (!mtk_npu_tnl_offload_ready())
		return mcu_init_pre_leave(notifier);
	return 0;
}

static struct mcu_state_notifier mcu_netstop_notifier = {
	.pre_enter = mcu_netstop_pre_enter,
};

static struct mcu_state_notifier mcu_init_notifier = {
	.pre_leave = mcu_init_pre_leave,
};

static struct mcu_state_notifier mcu_freerun_notifier = {
	.pre_enter = mcu_freerun_pre_enter,
};

static struct npu_tnl_offload_ops nf_hnat_tnl_ops = {
	.tnl_is_encrypted_offloadable = mtk_npu_nf_hnat_tnl_is_encrypted_offloadable,
};

static bool mtk_npu_bind_lock(struct net_device *dev, struct hnat_tunnel_token *token)
{
	struct npu_tnl_info *info;

	if (!mtk_npu_is_ready() || !mtk_npu_mcu_alive())
		return false;
	info = mtk_npu_tnl_info_get_by_idx(token->index);
	if (IS_ERR(info))
		return false;
	spin_lock_bh(&info->lock);
	if (!mtk_npu_tnl_offload_ready() ||
	    info->dev != dev || !netif_running(dev) ||
	    (dev->type == ARPHRD_PPP && !ppp_netdev_tunnel_offload_allowed(dev)) ||
	    !mtk_npu_egress_matches(info, token) ||
	    !netif_running(token->underlay) || !netif_running(token->egress) ||
	    info->generation != token->generation ||
	    info->allocation_cookie != token->allocation ||
	    info->synced_generation != info->generation ||
	    !(info->status & TNL_STA_UPDATED) ||
	    (info->status & (TNL_STA_UPDATING | TNL_STA_QUEUED |
			    TNL_STA_DELETING | TNL_STA_DELETING_SKIP_PCE)) ||
	    !tnl_info_encap_is_enable(info) ||
	    memcmp(&info->cache, &info->tnl_params, sizeof(info->cache))) {
		spin_unlock_bh(&info->lock);
		return false;
	}
	token->private = info;
	return true;
}

static bool mtk_npu_rx_bind_lock(const struct mtk_npu_rx_meta *meta,
				 struct hnat_tunnel_token *token)
{
	struct npu_tnl_info *info;

	if (!mtk_tnl_rx_meta_current(meta) || meta->entry < 32 || meta->entry >= 64 ||
	    !mtk_npu_is_ready() || !mtk_npu_mcu_alive())
		return false;
	info = mtk_npu_tnl_info_get_by_idx(meta->entry - 32);
	if (IS_ERR(info))
		return false;
	spin_lock_bh(&info->lock);
	if (!mtk_npu_tnl_offload_ready() || !info->dev ||
	    (u32)info->dev->ifindex != meta->tunnel_ifindex || !netif_running(info->dev) ||
	    info->generation != meta->generation ||
	    info->allocation_cookie != meta->allocation ||
	    info->synced_generation != info->generation ||
	    !(info->status & TNL_STA_UPDATED) ||
	    (info->status & (TNL_STA_UPDATING | TNL_STA_QUEUED |
			    TNL_STA_DELETING | TNL_STA_DELETING_SKIP_PCE)) ||
	    !tnl_info_decap_is_enable(info) ||
	    (info->dev->type == ARPHRD_PPP &&
	     !ppp_netdev_tunnel_offload_allowed(info->dev))) {
		spin_unlock_bh(&info->lock);
		return false;
	}
	token->index = meta->entry - 32;
	token->private = info;
	return true;
}

static void mtk_npu_bind_unlock(struct hnat_tunnel_token *token)
{
	struct npu_tnl_info *info = token->private;

	spin_unlock_bh(&info->lock);
}

static const struct hnat_tunnel_ops packet_ops = {
	.decap_offloadable = mtk_npu_tnl_decap_offloadable,
	.decap_offload = mtk_npu_tnl_decap_offload,
	.encap_offload = mtk_npu_tnl_encap_offload,
	.bind_lock = mtk_npu_bind_lock,
	.rx_bind_lock = mtk_npu_rx_bind_lock,
	.bind_unlock = mtk_npu_bind_unlock,
};
static const struct mtk_tnl_rx_ops rx_ops = { .get_dev = mtk_npu_get_tnl_dev };
static const struct ppp_tunnel_offload_ops ppp_ops = {
	.quiesce = mtk_npu_tnl_info_quiesce_ppp,
	.invalidate = mtk_npu_tnl_info_invalidate_ppp,
};

int mtk_npu_nf_hnat_tnl_offload_start(void)
{
	int ret;

	ret = ppp_tunnel_offload_register(&ppp_ops);
	if (ret)
		return ret;
	ret = mtk_tnl_rx_register(&rx_ops);
	if (ret)
		goto ppp_remove;
	ret = hnat_tunnel_register(&packet_ops);
	if (ret)
		mtk_tnl_rx_unregister(&rx_ops);
	if (!ret)
		return 0;
ppp_remove:
	ppp_tunnel_offload_unregister(&ppp_ops);
	return ret;
}

void mtk_npu_nf_hnat_tnl_offload_stop(void)
{
	ppp_tunnel_offload_unregister(&ppp_ops);
	hnat_tunnel_unregister(&packet_ops);
	mtk_tnl_rx_unregister(&rx_ops);
	mtk_npu_tnl_info_flush_all_ppe_tnl();
}

int mtk_npu_nf_hnat_tnl_offload_init(void)
{
	int ret;

	ret = mtk_npu_tnl_offload_ops_register(&nf_hnat_tnl_ops);
	if (ret)
		return ret;
	ret = mtk_npu_mcu_state_notifier_register(MCU_STATE_TYPE_NETSTOP, &mcu_netstop_notifier);
	if (ret)
		goto ops_remove;
	ret = mtk_npu_mcu_state_notifier_register(MCU_STATE_TYPE_INIT, &mcu_init_notifier);
	if (ret)
		goto netstop_remove;
	ret = mtk_npu_mcu_state_notifier_register(MCU_STATE_TYPE_FREERUN,
						&mcu_freerun_notifier);
	if (ret)
		goto init_remove;
	ret = mtk_npu_gretap_init();
	if (ret)
		goto freerun_remove;
	ret = mtk_npu_l2tpv2_init();
	if (ret)
		goto gre_remove;
	ret = mtk_npu_vxlan_init();
	if (ret)
		goto l2tp_remove;
	ret = mtk_npu_pptp_init();
	if (ret)
		goto vxlan_remove;
	ret = mtk_npu_misc_set_ppe_num();
	if (!ret)
		return 0;
	mtk_npu_pptp_deinit();
vxlan_remove:
	mtk_npu_vxlan_deinit();
l2tp_remove:
	mtk_npu_l2tpv2_deinit();
gre_remove:
	mtk_npu_gretap_deinit();
freerun_remove:
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_FREERUN, &mcu_freerun_notifier);
init_remove:
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_INIT, &mcu_init_notifier);
netstop_remove:
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_NETSTOP, &mcu_netstop_notifier);
ops_remove:
	mtk_npu_tnl_offload_ops_unregister(&nf_hnat_tnl_ops);
	return ret;
}

void mtk_npu_nf_hnat_tnl_offload_deinit(void)
{
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_FREERUN, &mcu_freerun_notifier);
	mtk_npu_pptp_deinit();
	mtk_npu_vxlan_deinit();
	mtk_npu_l2tpv2_deinit();
	mtk_npu_gretap_deinit();
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_INIT, &mcu_init_notifier);
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_NETSTOP, &mcu_netstop_notifier);
	mtk_npu_tnl_offload_ops_unregister(&nf_hnat_tnl_ops);
}

void mtk_npu_nf_hnat_statistic_show(struct seq_file *s)
{
	seq_puts(s, "unit=host_eligibility_and_setup_events; not_hardware_bytes_or_forwarding_proof\n");
	seq_printf(s, "decap offloadable|success: %lld|fail: %lld|\n",
		   atomic64_read(&hnat_ts.decap_offloadable.success),
		   atomic64_read(&hnat_ts.decap_offloadable.fail));
	seq_printf(s, "decap offload    |success: %lld|fail: %lld|pending_sync: %lld|\n",
		   atomic64_read(&hnat_ts.decap_offload.success),
		   atomic64_read(&hnat_ts.decap_offload.fail),
		   atomic64_read(&hnat_ts.decap_offload.pending_sync));
	seq_printf(s, "encap offload    |success: %lld|fail: %lld|pending_sync: %lld|\n",
		   atomic64_read(&hnat_ts.encap_offload.success),
		   atomic64_read(&hnat_ts.encap_offload.fail),
		   atomic64_read(&hnat_ts.encap_offload.pending_sync));
}

void mtk_npu_nf_hnat_statistic_clear(void)
{
	struct npu_nf_hnat_statistic_counter *counters[] = {
		&hnat_ts.decap_offloadable, &hnat_ts.decap_offload,
		&hnat_ts.encap_offload,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(counters); i++) {
		atomic64_set(&counters[i]->success, 0);
		atomic64_set(&counters[i]->fail, 0);
		atomic64_set(&counters[i]->pending_sync, 0);
	}
}

void mtk_npu_nf_hnat_statistic_enable(bool en)
{
	hnat_ts.en = en;
}

bool mtk_npu_nf_hnat_statistic_is_enabled(void)
{
	return mtk_npu_tnl_statistic_is_enabled() && hnat_ts.en;
}
