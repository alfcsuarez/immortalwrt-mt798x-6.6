// SPDX-License-Identifier: GPL-2.0-or-later
/* Native flowtable backend. The core owns power, workers and mappings. */
#include <linux/etherdevice.h>
#include <linux/ppp_channel.h>
#include <net/mtk_npu_flow.h>
#include <mtk_eth_soc.h>
#include <mtk_ppe.h>
#include <pce/cls.h>
#include <pce/netsys.h>
#include <pce/pce.h>
#include "npu/mcu.h"
#include "npu/misc.h"
#include "npu/netsys.h"
#include "npu/tunnel.h"
#include "npu/protocol/tunnel/l2tp/l2tpv2.h"
#include "npu/protocol/tunnel/pptp/pptp.h"
#include "npu-flow/internal.h"
#include "npu-flow/tnl-offload.h"

static bool mtk_npu_flow_tnl_info_cls_is_updated(struct npu_tnl_info *tnl_info,
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

static int mtk_npu_flow_tnl_info_cls_setup(struct npu_tnl_info *tnl_info)
{
	struct npu_tnl_params *tnl_params = &tnl_info->tnl_params;
	struct npu_tnl_type *tnl_type = tnl_info->tnl_type;
	struct npu_cls_entry *tcls;
	int ret;

	if (mtk_npu_flow_tnl_info_cls_is_updated(tnl_info, tnl_type))
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

static void mtk_npu_flow_tnl_info_cls_destroy(struct npu_tnl_info *tnl_info)
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

static void flow_flush_index(u32 index)
{
	mtk_npu_flow_flush_ppe(mtk_npu_netsys_get_eth(),
			       index + __NPU_TUNNEL_TYPE_MAX);
}

static void flow_flush(struct npu_tnl_info *info)
{
	mtk_npu_flow_flush_ppe(mtk_npu_netsys_get_eth(),
			       info->tnl_idx + __NPU_TUNNEL_TYPE_MAX);
}

void mtk_npu_tnl_info_flush_all_ppe_tnl(void)
{
	mtk_npu_flow_flush_ppe(mtk_npu_netsys_get_eth(), 0);
}

static struct npu_tnl_info_ops flow_tnl_info_ops = {
	.flush = flow_flush,
	.flush_index = flow_flush_index,
	.cls_setup = mtk_npu_flow_tnl_info_cls_setup,
	.cls_destroy = mtk_npu_flow_tnl_info_cls_destroy,
};

static bool flow_underlay(struct net_device *dev)
{
	struct mtk_eth *eth = mtk_npu_netsys_get_eth();

	/* Native backend: the plain Ethernet GMAC2/GMAC3 paths. Vendor HNAT
	 * retains the separate bridge/VLAN/PPPoE/DSA adaptation path.
	 */
	return dev && eth && (dev == eth->netdev[1] || dev == eth->netdev[2]) &&
	       dev_net(dev) == &init_net && netif_running(dev) && netif_carrier_ok(dev);
}

static int flow_setup(struct npu_tnl_input *input, struct npu_tnl_type *type,
		      struct npu_tnl_info *info, struct npu_tnl_params *params)
{
	const struct net_device_path *path = input->flow.path;
	struct net_device *dev = (struct net_device *)path->dev;
	struct net_device *underlay;
	struct mtk_npu_flow_token *token = input->flow.token;
	bool changed;
	int ret = -EAGAIN;

	underlay = dev_get_by_index_rcu(&init_net, path->tunnel.underlay_ifindex);
	if (!flow_underlay(underlay) || !ppp_netdev_tunnel_offload_allowed(dev))
		return -EOPNOTSUPP;
	spin_lock(&info->lock);
	if ((info->status & (TNL_STA_DELETING | TNL_STA_DELETING_SKIP_PCE)) ||
	    (info->dev && info->dev != dev)) {
		ret = -ESTALE;
		goto out;
	}
	if (info->underlay && info->underlay != underlay) {
		mtk_npu_tnl_info_delete_no_lock(info);
		goto out;
	}
	if (!info->dev) {
		dev_hold(dev);
		info->dev = dev;
		dev_hold(underlay);
		info->underlay = underlay;
		dev_hold(underlay);
		info->egress = underlay;
	}
	info->ops = &flow_tnl_info_ops;
	params->flag |= info->cache.flag;
	params->cls_entry = info->cache.cls_entry;
	params->params.mtu = min_t(unsigned int, READ_ONCE(dev->mtu), type->max_mtu);
	if (type->tnl_param_restore)
		type->tnl_param_restore(&info->cache.params, &params->params);
	changed = memcmp(&info->cache, params, sizeof(*params));
	if (changed) {
		if (!++info->generation)
			info->generation++;
		info->cache = *params;
		mtk_npu_tnl_info_hash_no_lock(info);
	}
	if (!tnl_info_decap_is_enable(info) || !tnl_info_encap_is_enable(info)) {
		tnl_info_decap_enable(info);
		tnl_info_encap_enable(info);
		changed = true;
	}
	if (changed)
		mtk_npu_tnl_info_submit_no_tnl_lock(info);
	if (!(info->status & TNL_STA_UPDATED) ||
	    (info->status & (TNL_STA_QUEUED | TNL_STA_UPDATING)) ||
	    info->synced_generation != info->generation ||
	    memcmp(&info->cache, &info->tnl_params, sizeof(info->cache)))
		goto out;
	token->entry = info->tnl_idx + __NPU_TUNNEL_TYPE_MAX;
	token->generation = info->generation;
	token->allocation = info->allocation_cookie;
	token->tunnel_ifindex = dev->ifindex;
	token->egress_ifindex = underlay->ifindex;
	ret = 0;
out:
	spin_unlock(&info->lock);
	return ret;
}

static bool flow_supported(enum net_device_path_type type)
{
	struct npu_tnl_type *protocol;

	if (!mtk_npu_is_ready() || !mtk_npu_mcu_alive() ||
	    !mtk_npu_tnl_offload_ready() ||
	    (type != DEV_PATH_L2TP && type != DEV_PATH_PPTP))
		return false;
	protocol = mtk_npu_tnl_type_get_by_path_type(type);
	return !IS_ERR(protocol) && protocol->tnl_flow_param_setup;
}

static int flow_prepare(const struct net_device_path *path,
			struct mtk_npu_flow_token *token)
{
	struct npu_tnl_input input = { .kind = NPU_TNL_INPUT_FLOW };
	struct npu_tnl_params params = {};
	struct npu_tnl_type *type;

	if (!path || !path->dev || dev_net(path->dev) != &init_net ||
	    !netif_running(path->dev) || !flow_supported(path->type) ||
	    !path->tunnel.sip.ip || !path->tunnel.dip.ip || !path->tunnel.ttl ||
	    (path->type == DEV_PATH_L2TP && path->tunnel.sport != htons(1701)))
		return -EOPNOTSUPP;
	type = mtk_npu_tnl_type_get_by_path_type(path->type);
	if (IS_ERR(type))
		return PTR_ERR(type);
	type->tnl_flow_param_setup(path, &params.params);
	params.npu_entry_proto = type->tnl_proto_type;
	input.flow.path = path;
	input.flow.token = token;
	return mtk_npu_tnl_offload(&input, type, &params, flow_setup);
}

static bool flow_bind(const struct mtk_npu_flow_token *token, void **owner)
{
	struct npu_tnl_info *info;

	if (!mtk_npu_is_ready() || !mtk_npu_mcu_alive() ||
	    token->entry < __NPU_TUNNEL_TYPE_MAX ||
	    token->entry >= __NPU_TUNNEL_TYPE_MAX + CONFIG_NPU_TNL_NUM)
		return false;
	info = mtk_npu_tnl_info_get_by_idx(token->entry - __NPU_TUNNEL_TYPE_MAX);
	if (IS_ERR(info))
		return false;
	spin_lock(&info->lock);
	if (!mtk_npu_tnl_offload_ready() || !info->dev ||
	    (u32)info->dev->ifindex != token->tunnel_ifindex ||
	    !netif_running(info->dev) || !ppp_netdev_tunnel_offload_allowed(info->dev) ||
	    !flow_underlay(info->egress) ||
	    (u32)info->egress->ifindex != token->egress_ifindex ||
	    info->generation != token->generation ||
	    info->allocation_cookie != token->allocation ||
	    info->synced_generation != info->generation ||
	    !(info->status & TNL_STA_UPDATED) ||
	    (info->status & (TNL_STA_UPDATING | TNL_STA_QUEUED |
			    TNL_STA_DELETING | TNL_STA_DELETING_SKIP_PCE)) ||
	    memcmp(&info->cache, &info->tnl_params, sizeof(info->cache))) {
		spin_unlock(&info->lock);
		return false;
	}
	*owner = info;
	return true;
}

static void flow_unbind(void *owner)
{
	struct npu_tnl_info *info = owner;

	spin_unlock(&info->lock);
}

static const struct mtk_npu_flow_ops flow_ops = {
	.supported = flow_supported,
	.prepare = flow_prepare,
	.bind = flow_bind,
	.unbind = flow_unbind,
};

static struct net_device *flow_rx_dev(u8 reason, struct mtk_npu_rx_meta *meta)
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
	if (mtk_npu_tnl_offload_ready() && info->dev && netif_running(info->dev) &&
	    ppp_netdev_tunnel_offload_allowed(info->dev) &&
	    (info->status & TNL_STA_UPDATED) &&
	    !(info->status & (TNL_STA_UPDATING | TNL_STA_QUEUED |
			      TNL_STA_DELETING | TNL_STA_DELETING_SKIP_PCE)) &&
	    info->synced_generation == info->generation && tnl_info_decap_is_enable(info)) {
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

static const struct mtk_tnl_rx_ops rx_ops = { .get_dev = flow_rx_dev };
static const struct ppp_tunnel_offload_ops ppp_ops = {
	.quiesce = mtk_npu_tnl_info_quiesce_ppp,
	.invalidate = mtk_npu_tnl_info_invalidate_ppp,
};

int mtk_npu_flow_tnl_start(void)
{
	int ret;

	ret = ppp_tunnel_offload_register(&ppp_ops);
	if (ret)
		return ret;
	ret = mtk_tnl_rx_register(&rx_ops);
	if (ret)
		goto ppp_remove;
	ret = mtk_npu_flow_register(&flow_ops);
	if (!ret)
		return 0;
	mtk_tnl_rx_unregister(&rx_ops);
ppp_remove:
	ppp_tunnel_offload_unregister(&ppp_ops);
	return ret;
}

void mtk_npu_flow_tnl_stop(void)
{
	mtk_npu_flow_unregister(&flow_ops);
	ppp_tunnel_offload_unregister(&ppp_ops);
	mtk_tnl_rx_unregister(&rx_ops);
	mtk_npu_tnl_info_flush_all_ppe_tnl();
}

static int flow_netstop(struct mcu_state_notifier *notifier)
{
	mtk_npu_tnl_info_backup_all();
	mtk_npu_tnl_info_flush_all_ppe_tnl();
	return 0;
}

static int flow_init_leave(struct mcu_state_notifier *notifier)
{
	int ret;

	ret = mtk_npu_misc_set_ppe_num();
	if (ret)
		return ret;
	ret = mtk_npu_tnl_offload_post_init(NULL);
	if (ret)
		return ret;
	mtk_npu_tnl_info_restore_all();
	return 0;
}

static int flow_freerun(struct mcu_state_notifier *notifier)
{
	return mtk_npu_tnl_offload_ready() ? 0 : flow_init_leave(notifier);
}

static struct mcu_state_notifier netstop_notifier = { .pre_enter = flow_netstop };
static struct mcu_state_notifier init_notifier = { .pre_leave = flow_init_leave };
static struct mcu_state_notifier freerun_notifier = { .pre_enter = flow_freerun };

int mtk_npu_flow_tnl_offload_init(void)
{
	int ret;

	ret = mtk_npu_mcu_state_notifier_register(MCU_STATE_TYPE_NETSTOP, &netstop_notifier);
	if (ret)
		return ret;
	ret = mtk_npu_mcu_state_notifier_register(MCU_STATE_TYPE_INIT, &init_notifier);
	if (ret)
		goto netstop_remove;
	ret = mtk_npu_mcu_state_notifier_register(MCU_STATE_TYPE_FREERUN, &freerun_notifier);
	if (ret)
		goto init_remove;
	ret = mtk_npu_l2tpv2_init();
	if (ret)
		goto freerun_remove;
	ret = mtk_npu_pptp_init();
	if (ret)
		goto l2tp_remove;
	ret = mtk_npu_misc_set_ppe_num();
	if (!ret)
		return 0;
	mtk_npu_pptp_deinit();
l2tp_remove:
	mtk_npu_l2tpv2_deinit();
freerun_remove:
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_FREERUN, &freerun_notifier);
init_remove:
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_INIT, &init_notifier);
netstop_remove:
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_NETSTOP, &netstop_notifier);
	return ret;
}

void mtk_npu_flow_tnl_offload_deinit(void)
{
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_FREERUN, &freerun_notifier);
	mtk_npu_pptp_deinit();
	mtk_npu_l2tpv2_deinit();
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_INIT, &init_notifier);
	mtk_npu_mcu_state_notifier_unregister(MCU_STATE_TYPE_NETSTOP, &netstop_notifier);
}
