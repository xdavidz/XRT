// SPDX-License-Identifier: GPL-2.0
/*
 * Xilinx Kernel Driver XCLBIN parser
 *
 * Copyright (C) 2020 Xilinx, Inc.
 *
 * Authors: David Zhang <davidzha@xilinx.com>
 */

#include "xrt_xclbin.h"
#include "xocl_drv.h"

struct xclbin_arg {
	xdev_handle_t 		xdev;
	struct axlf 		*xclbin;
	struct xocl_subdev 	*urpdevs;
	int 			num_dev;
};

struct xocl_xclbin_ops {
	int (*xclbin_pre_download)(xdev_handle_t xdev, struct xclbin_arg *arg);
	int (*xclbin_download)(xdev_handle_t xdev, struct xclbin_arg *arg);
	int (*xclbin_post_download)(xdev_handle_t xdev, struct xclbin_arg *arg);
};

int xocl_xclbin_wr_lock(xdev_handle_t xdev)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	pid_t pid = pid_nr(task_tgid(current));
	int ret = 0;

	mutex_lock(&xxb->xclbin_lock);
	if (xxb->xclbin_busy) {
		ret = -EBUSY;
	} else {
		xxb->xclbin_busy = (u64)pid;
	}
	mutex_unlock(&xxb->xclbin_lock);
	if (ret)
		goto done;

	ret = wait_event_interruptible(xxb->xclbin_reader_wq,
	    xxb->xclbin_reader_ref == 0);
	if (ret)
		goto done;

	BUG_ON(xxb->xclbin_reader_ref != 0);

done:
	xocl_xdev_info(xdev, "pid: %d ret: %d", pid, ret);
	return ret;
}

void xocl_xclbin_wr_unlock(xdev_handle_t xdev)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	pid_t pid = pid_nr(task_tgid(current));

	BUG_ON(xxb->xclbin_busy != (u64)pid);

	mutex_lock(&xxb->xclbin_lock);
	xxb->xclbin_busy = 0;
	mutex_unlock(&xxb->xclbin_lock);
	xocl_xdev_info(xdev, "pid: %d", pid);
}

int xocl_xclbin_rd_lock(xdev_handle_t xdev)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	pid_t pid = pid_nr(task_tgid(current));
	int ret = 0;

	mutex_lock(&xxb->xclbin_lock);

	if (xxb->xclbin_busy) {
		ret = -EBUSY;
		goto done;
	}

	xxb->xclbin_reader_ref++;

done:
	mutex_unlock(&xxb->xclbin_lock);
	xocl_xdev_info(xdev, "pid: %d ret: %d", pid, ret);
	return ret;
}

void xocl_xclbin_rd_unlock(xdev_handle_t xdev)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	pid_t pid = pid_nr(task_tgid(current));
	bool wake = false;

	mutex_lock(&xxb->xclbin_lock);

	BUG_ON(xxb->xclbin_reader_ref == 0);

	wake = (--xxb->xclbin_reader_ref == 0);

	mutex_unlock(&xxb->xclbin_lock);
	if (wake)
		wake_up_interruptible(&xxb->xclbin_reader_wq);

	xocl_xdev_info(xdev, "pid: %d", pid);
}

bool xocl_xclbin_in_use(xdev_handle_t xdev)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	BUG_ON(xxb->xclbin_refcnt < 0);
	return xxb->xclbin_refcnt != 0;
}

static int xclbin_probe_urpdev(xdev_handle_t xdev, struct xclbin_arg *arg)
{
	struct axlf *xclbin = arg->xclbin;
	void *metadata = NULL;	
	uint64_t size;
	int ret;

	ret = xrt_xclbin_get_section(xclbin, PARTITION_METADATA, &metadata, &size);
	if (ret)
		return 0;

	if (metadata) {
		arg->num_dev = xocl_fdt_parse_blob(xdev, metadata,
		    size, &(arg->urpdevs));
		vfree(metadata);
	}
	xocl_subdev_destroy_by_level(xdev, XOCL_SUBDEV_LEVEL_URP);

	return 0;
}

static int xclbin_create_urpdev(xdev_handle_t xdev, struct xclbin_arg *arg)
{
	struct xclbin_arg *arg = (struct xclbin_arg *)args;
	int i, ret = 0;

	if (arg->num_dev) {
		for (i = 0; i < arg->num_dev; i++)
			(void) xocl_subdev_create(xdev, &(arg->urpdevs[i].info));
		xocl_subdev_create_by_level(xdev, XOCL_SUBDEV_LEVEL_URP);
	}

	return ret;
}

static int xclbin_create_and_config_clock(xdev_handle_t xdev, struct xclbin_arg *arg)
{
	struct xclbin_arg *arg = (struct xclbin_arg *)args;
	int i, ret = 0;

	if (arg->num_dev) {
		for (i = 0; i < arg->num_dev; i++) {
			if (arg->urpdevs[i].info.id != XOCL_SUBDEV_CLOCK)
				continue;

			ret = xocl_subdev_create(xdev, &(arg->urpdevs[i].info));
			if (ret)
				goto done;
			ret = xclbin_mgmt_setup_clock_freq_topology(xdev, arg->xclbin);
		}
	}
done:
	return ret;
}

static int versal_xclbin_pre_download(xdev_handle_t xdev, struct xclbin_arg *arg)
{
	return xclbin_probe_urpdev(xdev, arg);
}

static int versal_xclbin_download(xdev_handle_t xdev, void *args)
{
	struct xclbin_arg *arg = (struct xclbin_arg *)args;
	int ret = 0;

	BUG_ON(!arg->xclbin);

	xocl_axigate_freeze(xdev, XOCL_SUBDEV_LEVEL_PRP);

	/* download bitstream */
	ret = xocl_xfer_versal_download_axlf(xdev, arg->xclbin);

	xocl_axigate_free(xdev, XOCL_SUBDEV_LEVEL_PRP);

	return ret;
}

static int versal_xclbin_post_download(xdev_handle_t xdev, void *args)
{
	return xclbin_create_urpdev(xdev, arg);
}

static uint64_t xclbin_get_section_size(xdev_handle_t xdev, enum axlf_section_kind kind)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	uint64_t size = 0;

	switch (kind) {
	case IP_LAYOUT:
		size = sizeof_sect(xxb->xclbin_ip_layout, m_ip_data);
		break;
	case MEM_TOPOLOGY:
		size = sizeof_sect(xxb->xclbin_mem_topology, m_mem_data);
		break;
	case DEBUG_IP_LAYOUT:
		size = sizeof_sect(xxb->xclbin_debug_layout, m_debug_ip_data);
		break;
	case CONNECTIVITY:
		size = sizeof_sect(xxb->xclbin_connectivity, m_connection);
		break;
	case CLOCK_FREQ_TOPOLOGY:
		size = sizeof_sect(xxb->xclbin_clock_freq_topology, m_clock_freq);
		break;
	case PARTITION_METADATA:
		size = fdt_totalsize(xxb->xclbin_partition_metadata);
		break;
	default:
		break;
	}

	return size;
}

static int xclbin_cache_section(xdev_handle_t xdev,
	const struct axlf *xclbin, enum axlf_section_kind kind)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	long err = 0;
	uint64_t section_size = 0, sect_sz = 0;
	void **target = NULL;

	if (memcmp(xclbin->m_magic, ICAP_XCLBIN_V2, sizeof(ICAP_XCLBIN_V2)))
		return -EINVAL;

	switch (kind) {
	case IP_LAYOUT:
		target = (void **)&xxb->xclbin_ip_layout;
		break;
	case MEM_TOPOLOGY:
		target = (void **)&xxb->xclbin_mem_topology;
		break;
	case DEBUG_IP_LAYOUT:
		target = (void **)&xxb->xclbin_debug_layout;
		break;
	case CONNECTIVITY:
		target = (void **)&xxb->xclbin_connectivity;
		break;
	case CLOCK_FREQ_TOPOLOGY:
		target = (void **)&xxb->xclbin_clock_freq_topology;
		break;
	case PARTITION_METADATA:
		target = (void **)&xxb->xclbin_partition_metadata;
		break;
	default:
		return -EINVAL;
	}
	if (target && *target) {
		vfree(*target);
		*target = NULL;
	}

	err = xrt_xclbin_get_section(xclbin, kind, target, &section_size);
	if (err != 0) {
		ICAP_ERR(icap, "get section err: %ld", err);
		goto done;
	}
	sect_sz = xocl_xclbin_get_section_size(kind);
	if (sect_sz > section_size) {
		err = -EINVAL;
		goto done;
	}

done:
	if (err) {
		if (target && *target) {
			vfree(*target);
			*target = NULL;
		}
		ICAP_INFO(icap, "skip kind %d, return code %ld", kind, err);
	} else
		ICAP_INFO(icap, "found kind %d", kind);
	return err;
}

static void xclbin_free_clock_freq_topology(xdev_handle_t xdev)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	vfree(xxb->xclbin_clock_freq_topology);
	xxb->xclbin_clock_freq_topology = NULL;
	xxb->xclbin_clock_freq_topology_length = 0;
}

static void xclbin_write_clock_freq(struct clock_freq *dst, struct clock_freq *src)
{
	dst->m_freq_Mhz = src->m_freq_Mhz;
	dst->m_type = src->m_type;
	memcpy(&dst->m_name, &src->m_name, sizeof(src->m_name));
}

static int xclbin_setup_clock_freq_topology(xdev_handle_t xdev,
	const struct axlf *xclbin)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	int i;
	struct clock_freq_topology *topology;
	struct clock_freq *clk_freq = NULL;
	const struct axlf_section_header *hdr =
		xrt_xclbin_get_section_hdr(xclbin, CLOCK_FREQ_TOPOLOGY);

	/* Can't find CLOCK_FREQ_TOPOLOGY, just return*/
	if (!hdr)
		return 0;

	xclbin_free_clock_freq_topology(xdev);

	xxb->xclbin_clock_freq_topology = vzalloc(hdr->m_sectionSize);
	if (!xxb->xclbin_clock_freq_topology)
		return -ENOMEM;

	topology = (struct clock_freq_topology *)(((char *)xclbin) + hdr->m_sectionOffset);

	/*
	 *  icap->xclbin_clock_freq_topology->m_clock_freq
	 *  must follow the order
	 *
	 *	0: DATA_CLK
	 *	1: KERNEL_CLK
	 *	2: SYSTEM_CLK
	 *
	 */
	xxb->xclbin_clock_freq_topology->m_count = topology->m_count;
	for (i = 0; i < topology->m_count; ++i) {
		if (topology->m_clock_freq[i].m_type == CT_SYSTEM)
			clk_freq = &xxb->xclbin_clock_freq_topology->m_clock_freq[SYSTEM_CLK];
		else if (topology->m_clock_freq[i].m_type == CT_DATA)
			clk_freq = &xxb->xclbin_clock_freq_topology->m_clock_freq[DATA_CLK];
		else if (topology->m_clock_freq[i].m_type == CT_KERNEL)
			clk_freq = &xxb->xclbin_clock_freq_topology->m_clock_freq[KERNEL_CLK];
		else
			break;

		xclbin_write_clock_freq(clk_freq, &topology->m_clock_freq[i]);
	}

	return 0;
}

static int xclbin_mgmt_setup_clock_freq_topology(xdev_handle_t xdev,
	const struct axlf *xclbin)
{
	if (!XOCL_DSA_IS_SMARTN(xdev))
		return xclbin_setup_clock_freq_topology(xdev, xclbin);

	return 0;
}

static int xclbin_create_srsr_subdev(xdev_handle_t xdev, struct axlf *xclbin)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	int err = 0, i = 0;
	struct ip_layout *ip_layout = xxb->xclbin_ip_layout;
	struct mem_topology *mem_topo = xxb->xclbin_mem_topology;
	uint32_t memidx = 0;

	if (!ip_layout) {
		err = -ENODEV;
		goto done;
	}

	if (!mem_topo) {
		err = -ENODEV;
		goto done;
	}

	for (i = 0; i < ip_layout->m_count; ++i) {
		struct ip_data *ip = &ip_layout->m_ip_data[i];

		if (ip->m_type == IP_KERNEL)
			continue;

		if (ip->m_type == IP_DDR4_CONTROLLER && !strncasecmp(ip->m_name, "SRSR", 4)) {
			struct xocl_subdev_info subdev_info = XOCL_DEVINFO_SRSR;
			uint32_t idx = 0;

			if (sscanf(ip->m_name, "SRSR-BANK%x", &idx) != 1) {
				err = -EINVAL;
				goto done;
			}

			/* hardcoded, to find a global*/
			memidx = icap_get_memidx(mem_topo, ip->m_type, idx);
			if (memidx == INVALID_MEM_IDX) {
				ICAP_ERR(icap, "INVALID_MEM_IDX: %u",
					ip->properties);
				continue;
			}

			subdev_info.res[0].start += ip->m_base_address;
			subdev_info.res[0].end += ip->m_base_address;
			subdev_info.override_idx = memidx;

			/* no way to be here */
			if (!ICAP_PRIVILEGED(icap))
				subdev_info.num_res = 0;

			err = xocl_subdev_create(xdev, &subdev_info);
			if (err) {
				ICAP_ERR(icap, "can't create SRSR subdev");
				goto done;
			}
		}
	}
done:
	if (err)
		xocl_subdev_destroy_by_id(xdev, XOCL_SUBDEV_SRSR);
	return err;
}

static int xclbin_create_subdev(xdev_handle_t xdev, struct axlf *xclbin)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	struct axlf *xclbin = arg->xclbin;
	int err = 0, i = 0;
	struct ip_layout *ip_layout = xxb->xclbin_ip_layout;
	struct mem_topology *mem_topo = xxb->xclbin_mem_topo;

	if (XOCL_DSA_IS_VERSAL(xdev))
		return 0;

	if (!ip_layout) {
		err = -ENODEV;
		goto done;
	}

	if (!mem_topo) {
		err = -ENODEV;
		goto done;
	}

	for (i = 0; i < ip_layout->m_count; ++i) {
		struct ip_data *ip = &ip_layout->m_ip_data[i];
		struct xocl_mig_label mig_label = { {0} };
		uint32_t memidx = 0;

		if (ip->m_type == IP_KERNEL)
			continue;

		if (ip->m_type == IP_DDR4_CONTROLLER || ip->m_type == IP_MEM_DDR4) {
			struct xocl_subdev_info subdev_info = XOCL_DEVINFO_MIG;

			if (!strncasecmp(ip->m_name, "SRSR", 4))
				continue;

			memidx = icap_get_memidx(mem_topo, ip->m_type, ip->properties);

			if (memidx == INVALID_MEM_IDX) {
				ICAP_ERR(icap, "INVALID_MEM_IDX: %u",
					ip->properties);
				continue;
			}

			if (!mem_topo || memidx >= mem_topo->m_count) {
				ICAP_ERR(icap, "bad ECC controller index: %u",
					ip->properties);
				continue;
			}
			if (!mem_topo->m_mem_data[memidx].m_used) {
				ICAP_INFO(icap,
					"ignore ECC controller for: %s",
					mem_topo->m_mem_data[memidx].m_tag);
				continue;
			}

			memcpy(&mig_label.tag, mem_topo->m_mem_data[memidx].m_tag, 16);
			mig_label.mem_idx = memidx;

			subdev_info.res[0].start += ip->m_base_address;
			subdev_info.res[0].end += ip->m_base_address;
			subdev_info.priv_data = &mig_label;
			subdev_info.data_len =
				sizeof(struct xocl_mig_label);

			if (!ICAP_PRIVILEGED(icap))
				subdev_info.num_res = 0;

			err = xocl_subdev_create(xdev, &subdev_info);
			if (err) {
				ICAP_ERR(icap, "can't create MIG subdev");
				goto done;
			}

		} else if (ip->m_type == IP_MEM_HBM) {
			struct xocl_subdev_info subdev_info = XOCL_DEVINFO_MIG_HBM;
			uint16_t memidx = icap_get_memidx(mem_topo, IP_MEM_HBM, ip->indices.m_index);

			if (memidx == INVALID_MEM_IDX)
				continue;

			if (!mem_topo || memidx >= mem_topo->m_count) {
				ICAP_ERR(icap, "bad ECC controller index: %u",
					ip->properties);
				continue;
			}

			if (!mem_topo->m_mem_data[memidx].m_used) {
				ICAP_INFO(icap,
					"ignore ECC controller for: %s",
					mem_topo->m_mem_data[memidx].m_tag);
				continue;
			}

			memcpy(&mig_label.tag, mem_topo->m_mem_data[memidx].m_tag, 16);
			mig_label.mem_idx = memidx;

			subdev_info.res[0].start += ip->m_base_address;
			subdev_info.res[0].end += ip->m_base_address;
			subdev_info.priv_data = &mig_label;
			subdev_info.data_len =
				sizeof(struct xocl_mig_label);

			if (!ICAP_PRIVILEGED(icap))
				subdev_info.num_res = 0;

			err = xocl_subdev_create(xdev, &subdev_info);
			if (err) {
				ICAP_ERR(icap, "can't create MIG_HBM subdev");
				goto done;
			}

		} else if (ip->m_type == IP_DNASC) {
			struct xocl_subdev_info subdev_info = XOCL_DEVINFO_DNA;

			subdev_info.res[0].start += ip->m_base_address;
			subdev_info.res[0].end += ip->m_base_address;

			if (!ICAP_PRIVILEGED(icap))
				subdev_info.num_res = 0;

			err = xocl_subdev_create(xdev, &subdev_info);
			if (err) {
				ICAP_ERR(icap, "can't create DNA subdev");
				goto done;
			}
		}
	}

	if (!ICAP_PRIVILEGED(icap))
		err = icap_create_cu(pdev);

	if (!ICAP_PRIVILEGED(icap))
		err = icap_create_subdev_debugip(pdev);
done:
	return err;
}

static int xclbin_setup_capability(xdev_handle_t xdev, struct axlf *xclbin)
{

	/* capability BIT8 as DRM IP enable, BIT0 as AXI mode
	 * We only check if anyone of them is set.
	 */
	capability = ((xocl_dna_capability(xdev) & 0x101) != 0);

	if (capability) {
		uint32_t *cert = NULL;

		if (0x1 & xocl_dna_status(xdev))
			goto done;
		/*
		 * Any error occurs here should return -EACCES for app to
		 * know that DNA has failed.
		 */
		err = -EACCES;

		ICAP_INFO(icap, "DNA version: %s", (capability & 0x1) ? "AXI" : "BRAM");

		if (xrt_xclbin_get_section(xclbin, DNA_CERTIFICATE,
			(void **)&cert, &section_size) != 0) {

			/* We keep dna sub device if IP_DNASC presents */
			ICAP_ERR(icap, "Can't get certificate section");
			goto done;
		}

		ICAP_INFO(icap, "DNA Certificate Size 0x%llx", section_size);
		if (section_size % 64 || section_size < 576)
			ICAP_ERR(icap, "Invalid certificate size");
		else
			xocl_dna_write_cert(xdev, cert, section_size);

		vfree(cert);


		/* Check DNA validation result. */
		if (0x1 & xocl_dna_status(xdev))
			err = 0; /* xclbin is valid */
		else {
			ICAP_ERR(icap, "DNA inside xclbin is invalid");
			goto done;
		}
	}

}

static int xclbin_setup_subdev(xdev_handle_t xdev, struct axlf *xclbin)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	int err = 0;
	uint64_t section_size = 0;
	u32 capability;

	if (XOCL_DSA_IS_VERSAL(xdev))
		return 0;

	/*
	 * Add sub device dynamically.
	 * restrict any dynamically added sub-device and 1 base address,
	 * Has pre-defined length
	 *  Ex:    "ip_data": {
	 *         "m_type": "IP_DNASC",
	 *         "properties": "0x0",
	 *         "m_base_address": "0x1100000", <--  base address
	 *         "m_name": "slr0\/dna_self_check_0"
	 */

	err = xclbin_create_subdev(pdev);
	if (err)
		goto done;

	/* Skip dna validation in userpf*/
	if (!ICAP_PRIVILEGED(icap))
		goto done;
	err = xclbin_setup_capability(xdev);	

done:
	return err;
}

static void xclbin_cache_max_host_mem_aperture(xdev_handle_t xdev)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	int i = 0;
	struct mem_topology *mem_topo = xxb->xclbin_mem_topo;

	xxb->xclbin_max_host_mem_aperture = 0;

	if (!mem_topo)
		return;

	for ( i=0; i< mem_topo->m_count; ++i) {
		if (!mem_topo->m_mem_data[i].m_used)
			continue;
		if (IS_HOST_MEM(mem_topo->m_mem_data[i].m_tag))
			xxb->max_host_mem_aperture =
			    mem_topo->m_mem_data[i].m_size << 10;
	}

	return;
}

static int xclbin_user_download(xdev_handle_t xdev, struct axlf *xclbin)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);

	xocl_xdev_info(xdev, "incoming xclbin: %pUb\non device xclbin: %pUb",
		&xclbin->m_header.uuid, &xxb->xclbin_uuid);

	/*
	 * NOTE: no xmc, no memcalib on user side.
	 *       why cache sections separately? let's refactor it later.
	 */

	/* has to create mem topology even with failure case
	 * please refer the comment in xocl_ioctl.c
	 * without creating mem topo, memory corruption could happen
	 */
	xclbin_cache_section(xdev, xclbin, MEM_TOPOLOGY);

	err = xclbin_peer_download(xdev, xclbin);

	/* TODO: Remove this after new KDS replace the legacy one */
	/*
	 * xclbin download changes PR region, make sure next
	 * ERT configure cmd will go through
	 */
	if (!kds_mode)
		(void) xocl_exec_reconfig(xdev);
	if (err)
		goto done;

	xclbin_cache_section(xdev, xclbin, IP_LAYOUT);
	xclbin_cache_section(xdev, xclbin, CONNECTIVITY);
	xclbin_cache_section(xdev, xclbin, DEBUG_IP_LAYOUT);
	xclbin_setup_clock_freq_topology(icap, xclbin);

	xclbin_create_subdev(xdev, xclbin);

	xclbin_cache_max_host_mem_aperture(xdev, xclbin);

	return err;
}

static int xclbin_validate(xdev_handle_t xdev, struct axlf *xclbin)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	int err = 0;
	const struct axlf_section_header *header = NULL;

	//err = xocl_xclbin_wr_lock(xdev);
	//if (err)
	//return err;

	/* Sanity check xclbin. */
	if (memcmp(xclbin->m_magic, ICAP_XCLBIN_V2, sizeof(ICAP_XCLBIN_V2))) {
		ICAP_ERR(icap, "invalid xclbin magic string");
		err = -EINVAL;
		goto done;
	}

	header = xrt_xclbin_get_section_hdr(xclbin, PARTITION_METADATA);
	if (header) {
		ICAP_INFO(icap, "check interface uuid");
		if (!XDEV(xdev)->fdt_blob) {
			ICAP_ERR(icap, "did not find platform dtb");
			err = -EINVAL;
			goto done;
		}
		err = xocl_fdt_check_uuids(xdev,
				(const void *)XDEV(xdev)->fdt_blob,
				(const void *)((char *)xclbin +
				header->m_sectionOffset));
		if (err) {
			ICAP_ERR(icap, "interface uuids do not match");
			err = -EINVAL;
			goto done;
		}
	}

	/*
	 * If the previous frequency was very high and we load an incompatible
	 * bitstream it may damage the hardware!
	 * If no clock freq, must return without touching the hardware.
	 */
	header = xrt_xclbin_get_section_hdr(xclbin, CLOCK_FREQ_TOPOLOGY);
	if (!header) {
		err = -EINVAL;
		goto done;
	}

	if (xocl_xrt_version_check(xdev, xclbin, true)) {
		ICAP_ERR(icap, "xclbin isn't supported by current XRT");
		err = -EINVAL;
		goto done;
	}
	if (!xocl_verify_timestamp(xdev,
		xclbin->m_header.m_featureRomTimeStamp)) {
		ICAP_ERR(icap, "TimeStamp of ROM did not match Xclbin");
		err = -EOPNOTSUPP;
		goto done;
	}
	if (xocl_xclbin_in_use(xdev)) {
		ICAP_ERR(icap, "bitstream is in-use, can't change");
		err = -EBUSY;
		goto done;
	}

	/*
	mutex_lock(&icap->icap_lock);
	err = __icap_download_bitstream_axlf(pdev, xclbin);
	mutex_unlock(&icap->icap_lock);
	*/
done:
	ICAP_INFO(icap, "%s err: %d", __func__, err);
	return err;
}

static int xclbin_peer_download(xdev_handle_t xdev, struct axlf *xclbin)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);

	/* Utilize existing icap infra to download xclbin */
	return xocl_icap_peer_download(xdev, xclbin);
}

static uint32_t convert_mem_type(const char *name)
{
	/* Don't trust m_type in xclbin, convert name to m_type instead.
	 * m_tag[i] = "HBM[0]" -> m_type = MEM_HBM
	 * m_tag[i] = "DDR[1]" -> m_type = MEM_DRAM
	 *
	 * Use MEM_DDR3 as a invalid memory type. */
	enum MEM_TYPE mem_type = MEM_DDR3;

	if (!strncasecmp(name, "DDR", 3))
		mem_type = MEM_DRAM;
	else if (!strncasecmp(name, "HBM", 3))
		mem_type = MEM_HBM;
	else if (!strncasecmp(name, "bank", 4))
		mem_type = MEM_DRAM;

	return mem_type;
}

static void xclbin_save_calib(xdev_handle_t xdev)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	struct mem_topology *mem_topo = xxb->xclbin_mem_topo;
	int err = 0, i = 0, ddr_idx = -1;

	if (!mem_topo)
		return;

	for (; i < mem_topo->m_count; ++i) {
		if (convert_mem_type(mem_topo->m_mem_data[i].m_tag) != MEM_DRAM)
			continue;
		else
			ddr_idx++;

		if (!mem_topo->m_mem_data[i].m_used)
			continue;

		err = xocl_srsr_save_calib(xdev, ddr_idx);
		if (err)
			xocl_xdev_dbg(xdev, "Not able to save mem %d calibration data.", i);

	}
	err = xocl_calib_storage_save(xdev);
}

static int icap_xclbin_pre_download(xdev_handle_t xdev, void *args)
{
	return  xclbin_validate(xdev, arg->xclbin);
}

static bool check_mem_topo_and_data_retention(xdev_handle_t xdev,
	struct axlf *xclbin)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	struct mem_topology *mem_topo = xxb->xclbin_mem_topology;
	const struct axlf_section_header *hdr =
		xrt_xclbin_get_section_hdr(xclbin, MEM_TOPOLOGY);
	uint64_t size = 0, offset = 0;

	if (!hdr || !mem_topo || !icap->data_retention)
		return false;

	size = hdr->m_sectionSize;
	offset = hdr->m_sectionOffset;

	/* Data retention feature ONLY works if the xclbins have identical mem_topology 
	 * or it will lead to hardware failure.
	 * If the incoming xclbin has different mem_topology, disable data retention feature
	 */

	if ((size != sizeof_sect(mem_topo, m_mem_data)) ||
		    memcmp(((char *)xclbin)+offset, mem_topo, size)) {
		ICAP_WARN(icap, "Incoming mem_topology doesn't match, disable data retention");
		return false;
	}

	return true;
}

static int xclbin_reset_ddr_gate_pin(xdev_handle_t xdev)
{
	int err = 0;

	err = xocl_iores_write32(xdev, XOCL_SUBDEV_LEVEL_PRP,
		IORES_DDR4_RESET_GATE, 0, 1);

	ICAP_INFO(icap, "%s ret %d", __func__, err);
	return err;
}

static int xclbin_release_ddr_gate_pin(xdev_handle_t xdev)
{
	int err = 0;

	err = xocl_iores_write32(xdev, XOCL_SUBDEV_LEVEL_PRP,
		IORES_DDR4_RESET_GATE, 0, 0);

	ICAP_INFO(icap, "%s ret %d", __func__, err);
	return err;
}

static void xclbin_calib(xdev_handle_t xdev, bool retain)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	int err = 0, i = 0, ddr_idx = -1;
	struct mem_topology *mem_topo = xxb->xclbin_mem_topology;

	BUG_ON(!mem_topo);

	err = xocl_calib_storage_restore(xdev);

	for (; i < mem_topo->m_count; ++i) {
		if (convert_mem_type(mem_topo->m_mem_data[i].m_tag) != MEM_DRAM)
			continue;
		else
			ddr_idx++;

		if (!mem_topo->m_mem_data[i].m_used)
			continue;

		err = xocl_srsr_calib(xdev, ddr_idx, retain);
		if (err)
			xocl_xdev_dbg(xdev, "Not able to calibrate mem %d.", i);

	}

}

static int icap_xclbin_mgmt_download(xdev_handle_t xdev, struct axlf *xclbin, bool sref)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	int i = 0, err = 0, num_dev = 0;
	bool retention = ((xxb->xclbin_data_retention & 0x1) == 0x1) && sref;
	struct xocl_subdev *subdevs = NULL;

	//again?
	//icap_probe_urpdev(icap->icap_pdev, xclbin, &num_dev, &subdevs);

	/* convert this to an api, xocl_icap_sign */
	/* err = xocl_icap_signature(xdev, xclbin); */

	err = xclbin_mgmt_setup_clock_freq_topology(icap, xclbin);
	if (err)
		goto out;

	if (retention) {
		err = xclbin_reset_ddr_gate_pin(icap);
		if (err == -ENODEV)
			ICAP_INFO(icap, "No ddr gate pin");
		else if (err) {
			ICAP_ERR(icap, "not able to reset ddr gate pin");
			goto out;
		}
	}

	/*
	 * xclbin generated for the flat shell contains MCS files which
	 * includes the accelerator these MCS files should have been already
	 * flashed into the device using xbmgmt tool we don't need to reprogram
	 * the xclbin for the FLAT shells.
	 * TODO Currently , There is no way to check whether the programmed
	 * xclbin matches with this xclbin or not
	 */
	if (xclbin->m_header.m_mode != XCLBIN_FLAT) {
		err = xocl_icap_download_bitstream(xdev, xclbin);
		if (err)
			goto out;
	} else {
		uuid_copy(&xxb->xclbin_uuid, &xclbin->m_header.uuid);
		ICAP_INFO(icap, "xclbin is generated for flat shell, dont need to program the bitstream ");
	}

	/* calibrate hbm and ddr should be performed when resources are ready */
	err = xclbin_create_srsr_subdev(xdev, xclbin);
	if (err)
		goto out;

	/* For 2RP, the majority of ULP IP can only be touched after ucs
	 * control bit set to 0x1 which is done in icap_refresh_clock_freq.
	 * Move so logics(create clock devices and set ucs control bit)
	 * to xclbin download function as workaround to solve interleaving issue.
	 * DDR SRSR IP and MIG need to wait until ucs control bit set to 0x1, 
	 * and icap mig calibration needs to wait until DDR SRSR calibration finish
	 */
	err = xclbin_create_and_config_clock(xdev, xclbin);
	if (err)
		goto out;

	xclbin_calib(xdev, retention);

	if (retention) {
		err = xclbin_release_ddr_gate_pin(icap);
		if (err == -ENODEV)
			ICAP_INFO(icap, "No ddr gate pin");
		else if (err)
			ICAP_ERR(icap, "not able to release ddr gate pin");
	}

	err = icap_calibrate_mig(icap->icap_pdev);

out:
	if (err && retention)
		icap_release_ddr_gate_pin(icap);
	if (subdevs)
		vfree(subdevs);
	ICAP_INFO(icap, "ret: %d", (int)err);
	return err;
}

static int icap_xclbin_download(xdev_handle_t xdev, struct xclbin_arg *args)
{
	int ret = 0;
	bool sref = false;

	ret = xocl_xmc_freeze(xdev);
	if (ret && ret != -ENODEV)
		return ret;

	xclbin_save_calib(xdev);

	xocl_subdev_destroy_by_level(xdev, XOCL_SUBDEV_LEVEL_URP);
	/* NOTE: memclaib resource can be changed, should be refreshed */

	/* Check the incoming mem topoloy with the current one before overwrite */
	sref = check_mem_topo_and_data_retention(xdev, xclbin);

	xclbin_cache_section(xdev, xclbin, MEM_TOPOLOGY);
	xclbin_cache_section(xdev, xclbin, IP_LAYOUT);

	err = icap_xclbin_mgmt_download(xdev, xclbin, sref);
	if (err)
		goto done;

	xclbin_probe_urpdev(xdev, arg);
	/* reconfig mig and dna after calibrate_mig */
	err = icap_verify_bitstream_axlf(pdev, xclbin);
	if (err)
		goto done;

}

static int icap_xclbin_post_download(xdev_handle_t xdev, void *args)
{
	return 0;
}

static int user_pre_download(xdev_handle_t xdev, struct xclbin_arg *arg)
{
	return  xclbin_validate(xdev, arg->xclbin);
}

static int user_download(xdev_handle_t xdev, struct xclbin_arg *arg)
{
	struct xocl_xclbin *xxb = XDEV_XCLBIN(xdev);
	struct axlf *xclbin = arg->xclbin;
	int ret = 0;

	xocl_subdev_destroy_by_level(xdev, XOCL_SUBDEV_LEVEL_URP);
	xclbin_probe_urpdev(xdev, arg);

	ret = xclbin_user_download(xdev, xclbin);

	xclbin_create_urpdev(xdev, arg);
done:
	if (ret) {
		uuid_copy(&xxb->xclbin_uuid, &uuid_null);
	} else {
		/* Remember "this" bitstream, so avoid redownload next time. */
		uuid_copy(&xxb->xclbin_uuid, &xclbin->m_header.uuid);
	}
}

static int user_post_download(xdev_handle_t xdev, struct xclbin_arg *arg)
{
	return 0;
}

static struct xocl_xclbin_ops versal_ops = {
	.xclbin_pre_download 	= versal_xclbin_pre_download,
	.xclbin_download 	= versal_xclbin_download,
	.xclbin_post_download 	= versal_xclbin_post_download,
};

static struct xocl_xclbin_ops icap_ops = {
	.xclbin_pre_download 	= icap_xclbin_pre_download,
	.xclbin_download 	= icap_xclbin_download,
	.xclbin_post_download 	= icap_xclbin_post_download,
};

static struct xocl_xclbin_ops xclbin_ops = {
	.xclbin_pre_download 	= user_pre_download,
	.xclbin_download 	= user_download,
	.xclbin_post_download 	= user_post_download,
};

#if 0
/*
 *Future enhancement for binding info table to of_device_id with
 *device-tree compatible
 */
static const struct xocl_xclbin_info icap_info = {
	.ops = &icap_ops;
};

static const struct xocl_xclbin_info versal_info = {
	.ops = &versal_ops;
};
#endif

static int xocl_xclbin_download_impl(xdev_handle_t xdev, const void *xclbin,
	struct xocl_xclbin_ops *ops)
{
	/* args are simular, thus using the same pattern among all ops*/
	struct xclbin_arg args = {
		.xdev = xdev,
		.xclbin = (struct axlf *)xclbin,
		.num_dev = 0,
	};
	int ret = 0;	

	ret = xocl_xclbin_wr_lock(xdev);
	if (ret)
		goto done;

	/* Step1: call pre download callback */
	if (ops->xclbin_pre_download) {
		ret = ops->xclbin_pre_download(xdev, &args);
		if (ret)
			goto done;
	}

	/* Step2: there must be a download callback */
	if (!ops->xclbin_download) {
		ret = -EINVAL;
		goto done;
	}
	ret = ops->xclbin_download(xdev, &args);
	if (ret)
		goto done;

	/* Step3: call post download callback */
	if (ops->xclbin_post_download) {
		ret = ops->xclbin_post_download(xdev, &args);
	}

done:	
	xocl_xclbin_wr_unlock(xdev);
	return ret;
}

/*
 * xdev(xocl_dev_core) has cached xcol_xclbin as xdev_xclbin, we can parse
 * incoming xclbin and store info into xdev_xclbin.
 */
int xocl_xclbin_mgmt_download(xdev_handle_t xdev, const void *xclbin)
{
	if (XOCL_DSA_IS_VERSAL(xdev))
		return xocl_xclbin_download_impl(xdev, xclbin, &versal_ops);
	else
		//return xocl_icap_download_axlf(xdev, xclbin);
		return xocl_xclbin_download_impl(xdev, xclbin, &icap_ops);
}

/*
 * On user side, all xclbin download is the almost the same procedure
 */
int xocl_xclbin_user_download(xdev_handle_t xdev, const void *xclbin)
{
	return xocl_xclbin_download_impl(xdev, xclbin, &user_ops);
}
