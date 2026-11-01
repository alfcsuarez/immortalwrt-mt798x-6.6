// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 MediaTek Inc. All Rights Reserved.
 *
 * Author: Ren-Ting Wang <ren-ting.wang@mediatek.com>
 */

#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#include "npu/internal.h"
#include "npu/procfs.h"
#include "npu/tunnel.h"

struct proc_dir_entry *npu_proc_root;
EXPORT_SYMBOL(npu_proc_root);

/* Software capability marker. Legacy utilization reads can otherwise enter
 * an unbounded mailbox wait; userspace must opt in only with this driver.
 */
static int telemetry_capabilities_show(struct seq_file *s, void *unused)
{
	seq_puts(s, "schema=1 mailbox_bounded=1 utilization_cores=5\n");
	return 0;
}

static int telemetry_capabilities_open(struct inode *inode, struct file *file)
{
	return single_open(file, telemetry_capabilities_show, NULL);
}

static const struct proc_ops telemetry_capabilities_ops = {
	.proc_open = telemetry_capabilities_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int tnl_show(struct seq_file *s, void *private)
{
	struct npu_tnl_info *tnl_info;
	struct npu_tnl_params *tnl_params;
	u32 i;

	for (i = 0; i < CONFIG_NPU_TNL_NUM; i++) {
		tnl_info = mtk_npu_tnl_info_get_by_idx(i);
		if (IS_ERR(tnl_info))
			/* tunnel not enabled */
			continue;

		tnl_params = &tnl_info->tnl_params;
		if (!tnl_info->tnl_type || !tnl_info->tnl_type->tnl_param_dump)
			continue;

		seq_printf(s, "Tunnel Index: %02u\n", i);

		mtk_npu_mac_param_dump(s, &tnl_params->params);

		mtk_npu_network_param_dump(s, &tnl_params->params);

		mtk_npu_transport_param_dump(s, &tnl_params->params);

		tnl_info->tnl_type->tnl_param_dump(s, &tnl_params->params);
		seq_printf(s, "\tNPU Entry: %02u CLS Entry: %02u CDRT: %02u Decap Enable: %u Encap Enable: %u MTU: %4u\n",
				tnl_params->npu_entry_proto,
				tnl_params->cls_entry,
				tnl_params->cdrt_idx,
				!!(tnl_params->flag & TNL_DECAP_ENABLE),
				!!(tnl_params->flag & TNL_ENCAP_ENABLE),
				tnl_params->params.mtu);
	}

	return 0;
}

/* Bounded software snapshot, one lock per slot. No FW/MMIO/MIB access.
 * Rows are independently consistent, not a global atomic hardware snapshot.
 */
static int tunnels_show(struct seq_file *s, void *unused)
{
	struct npu_tnl_info *info;
	struct npu_tnl_params params;
	unsigned long flags;
	u64 generation, sync_attempts, sync_failures, synced_generation;
	int sync_error;
	u8 sync_stage;
	u32 i, status, ifindex;
	bool synced;

	seq_puts(s, "# schema=1 max_tunnels=32 snapshot=per_entry unit=metadata\n");
	seq_puts(s, "# index generation ifindex type ipproto sip sport dip dport encap decap synchronized\n");
	for (i = 0; i < CONFIG_NPU_TNL_NUM; i++) {
		info = mtk_npu_tnl_info_get_by_idx(i);
		if (IS_ERR(info))
			continue;
		spin_lock_irqsave(&info->lock, flags);
		status = info->status;
		if (!info->dev || (status & (TNL_STA_UNINIT | TNL_STA_DELETING |
					    TNL_STA_DELETING_SKIP_PCE))) {
			spin_unlock_irqrestore(&info->lock, flags);
			continue;
		}
		params = info->cache;
		generation = info->generation;
		sync_attempts = info->sync_attempts;
		sync_failures = info->sync_failures;
		synced_generation = info->synced_generation;
		sync_error = info->last_sync_error;
		sync_stage = info->sync_stage;
		ifindex = info->dev->ifindex;
		synced = (status & TNL_STA_UPDATED) &&
			 !(status & (TNL_STA_UPDATING | TNL_STA_QUEUED)) &&
			 !memcmp(&info->tnl_params, &params, sizeof(params));
		spin_unlock_irqrestore(&info->lock, flags);
		if (params.params.network.type != NPU_NETWORK_IP)
			continue;
		/* Optional comment records preserve the schema-1 data-row format.
		 * Counters describe host setup/ACKs, never forwarded bytes/packets.
		 */
		seq_printf(s, "# sync %u %llu %llu %llu %u %d %llu\n",
			i, generation, sync_attempts, sync_failures,
			sync_stage, sync_error, synced_generation);
		seq_printf(s, "# crypto %u %llu %u\n",
			i, generation, params.cdrt_idx);
		seq_printf(s, "%u %llu %u %u %u %pI4 %u %pI4 %u %u %u %u\n",
			i, generation, ifindex, params.params.tunnel.type,
			params.params.network.ip.proto, &params.params.network.ip.sip,
			params.params.transport.type == NPU_TRANSPORT_UDP ?
				ntohs(params.params.transport.udp.sport) : 0,
			&params.params.network.ip.dip,
			params.params.transport.type == NPU_TRANSPORT_UDP ?
				ntohs(params.params.transport.udp.dport) : 0,
			!!(params.flag & TNL_ENCAP_ENABLE),
			!!(params.flag & TNL_DECAP_ENABLE), synced);
	}
	return 0;
}

static int tunnels_open(struct inode *inode, struct file *file)
{
	return single_open(file, tunnels_show, NULL);
}

static const struct proc_ops tunnels_proc_ops = {
	.proc_open = tunnels_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/* The RX descriptor's TOPS tunnel reason is validated against the live
 * generation before recording. Packets that stay in the hardware forwarding
 * path never reach this counter. No firmware/MMIO counter layout is assumed.
 */
static int dataplane_show(struct seq_file *s, void *unused)
{
	struct npu_tnl_info *info;
	unsigned long flags;
	u64 generation, packets, bytes;
	u32 i, ifindex;

	seq_puts(s, "# schema=1 source=rx_dma_tunnel_reason coverage=cpu_returns unit=inner_frame_bytes\n");
	seq_puts(s, "# index generation ifindex rx_packets rx_bytes\n");
	for (i = 0; i < CONFIG_NPU_TNL_NUM; i++) {
		info = mtk_npu_tnl_info_get_by_idx(i);
		if (IS_ERR(info))
			continue;
		spin_lock_irqsave(&info->lock, flags);
		if (!info->dev || (info->status & (TNL_STA_UNINIT | TNL_STA_DELETING |
						 TNL_STA_DELETING_SKIP_PCE))) {
			spin_unlock_irqrestore(&info->lock, flags);
			continue;
		}
		generation = info->generation;
		ifindex = info->dev->ifindex;
		packets = info->rx_generation == generation ? info->rx_packets : 0;
		bytes = info->rx_generation == generation ? info->rx_frame_bytes : 0;
		spin_unlock_irqrestore(&info->lock, flags);
		seq_printf(s, "%u %llu %u %llu %llu\n",
			   i, generation, ifindex, packets, bytes);
	}
	return 0;
}

static int dataplane_open(struct inode *inode, struct file *file)
{
	return single_open(file, dataplane_show, NULL);
}

static const struct proc_ops dataplane_proc_ops = {
	.proc_open = dataplane_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int tnl_open(struct inode *inode, struct file *file)
{
	return single_open(file, tnl_show, file->private_data);
}

#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
static const struct file_operations tnl_proc_ops = {
	.owner = THIS_MODULE,
	.open = tnl_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#else /* KERNEL_VERSION(5, 6, 0) <= LINUX_VERSION_CODE */
static const struct proc_ops tnl_proc_ops = {
	.proc_open = tnl_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#endif /* KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE */

int mtk_npu_procfs_init(struct platform_device *pdev)
{
	npu_proc_root = proc_mkdir("npu", NULL);
	if (!npu_proc_root)
		return -ENOMEM;

	if (!proc_create("tnl", S_IFREG | 0444, npu_proc_root, &tnl_proc_ops))
		goto err_out;

	if (!proc_create("tunnels", 0400, npu_proc_root, &tunnels_proc_ops)) {
		remove_proc_entry("tnl", npu_proc_root);
		goto err_out;
	}
	if (!proc_create("dataplane", 0400, npu_proc_root, &dataplane_proc_ops)) {
		remove_proc_entry("tunnels", npu_proc_root);
		remove_proc_entry("tnl", npu_proc_root);
		goto err_out;
	}
	if (!proc_create("telemetry-capabilities", 0400, npu_proc_root,
			 &telemetry_capabilities_ops)) {
		remove_proc_entry("dataplane", npu_proc_root);
		remove_proc_entry("tunnels", npu_proc_root);
		remove_proc_entry("tnl", npu_proc_root);
		goto err_out;
	}
	return 0;

err_out:
	remove_proc_entry("npu", NULL);

	return -ENOMEM;
}

void mtk_npu_procfs_deinit(struct platform_device *pdev)
{
	remove_proc_entry("dataplane", npu_proc_root);
	remove_proc_entry("telemetry-capabilities", npu_proc_root);
	remove_proc_entry("tunnels", npu_proc_root);
	remove_proc_entry("tnl", npu_proc_root);
	remove_proc_entry("npu", NULL);
}
