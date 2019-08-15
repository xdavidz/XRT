/*
 * A GEM style (optionally CMA backed) device manager for ZynQ based
 * OpenCL accelerators.
 *
 * Copyright (C) 2019 Xilinx, Inc. All rights reserved.
 *
 * Authors:
 *    Larry Liu       <yliu@xilinx.com>
 *    David Zhang     <davidzha@xilinx.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ert.h"
#include "zocl_drv.h"
#include "zocl_mailbox.h"

static inline const char *
reg2name(struct mailbox *mbx, u32 *reg)
{
	const char *reg_names[] = {
		"wrdata",
		"reserved1",
		"rddata",
		"reserved2",
		"status",
		"error",
		"sit",
		"rit",
		"is",
		"ie",
		"ip",
		"ctrl"
	};

	return reg_names[((uintptr_t)reg -
		(uintptr_t)mbx->mbx_regs) / sizeof(u32)];
}

static inline u32
mailbox_reg_read(struct mailbox *mbx, u32 *reg)
{
	u32 val = ioread32(reg);
	DZ_DEBUG("name %s, val 0x%x", reg2name(mbx, reg), val);
	return val;
}

static inline void
mailbox_reg_write(struct mailbox *mbx, u32 *reg, u32 val)
{
	DZ_DEBUG("name %s, val 0x%x", reg2name(mbx, reg), val);
	iowrite32(val, reg);
}

u32
zocl_mailbox_status(struct mailbox *mbx)
{
	return mailbox_reg_read(mbx, &mbx->mbx_regs->mbr_status);
}

/* get from mbx->mbx_regs->mbr_rddata */
u32
zocl_mailbox_get(struct mailbox *mbx)
{
	return mailbox_reg_read(mbx, &mbx->mbx_regs->mbr_rddata);
}

/* set to mbx->mbx_regs->mbr_wrdata */
void
zocl_mailbox_set(struct mailbox *mbx, u32 val)
{
	mailbox_reg_write(mbx, &mbx->mbx_regs->mbr_wrdata, val);
}

int
zocl_init_mailbox(struct drm_device *drm)
{
        struct drm_zocl_dev *zdev = drm->dev_private;
        struct mailbox *mbx;
	DZ_DEBUG("in mailbox");
	/* memory will be freed automatically when device detached */
	mbx = devm_kzalloc(drm->dev, sizeof (*mbx), GFP_KERNEL);
	if (!mbx)
		return -ENOMEM;

	mbx->mbx_regs = zdev->ert->mb_ioremap;
	zdev->zdev_mailbox = mbx;

	return 0;
}
