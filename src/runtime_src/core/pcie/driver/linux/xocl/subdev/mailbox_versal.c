/*
 * A GEM style device manager for PCIe based OpenCL accelerators.
 *
 * Copyright (C) 2019 Xilinx, Inc. All rights reserved.
 *
 * Authors: Larry Liu <yliu@xilinx.com>
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

#include "../xocl_drv.h"

#define	MBV_ERR(mbv, fmt, arg...)    \
    xocl_err(&mbv->mbv_pdev->dev, fmt "\n", ##arg)

/*
 * Mailbox IP register layout
 */
struct mailbox_reg {
	u32			mbr_wrdata;
	u32			mbr_resv1;
	u32			mbr_rddata;
	u32			mbr_resv2;
	u32			mbr_status;
	u32			mbr_error;
	u32			mbr_sit;
	u32			mbr_rit;
	u32			mbr_is;
	u32			mbr_ie;
	u32			mbr_ip;
	u32			mbr_ctrl;
} __attribute__((packed));

struct mailbox_versal {
	struct platform_device *mbv_pdev;
	struct mailbox_reg *mbv_regs;
};

static int mailbox_versal_set(struct platform_device *pdev, u32 data)
{
	printk("__larry_xocl__: enter %s\n", __func__);

	return 0;
}

static int mailbox_versal_get(struct platform_device *pdev, u32 *data)
{
	struct mailbox_versal *mbv = platform_get_drvdata(pdev);

	printk("__larry_xocl__: enter %s, reg base is %p\n", __func__,
	    mbv);

	return 0;
}

static struct xocl_mailbox_versal_funcs mailbox_versal_ops = {
	.set		= mailbox_versal_set,
	.get		= mailbox_versal_get,
};

static int mailbox_versal_remove(struct platform_device *pdev)
{
	struct mailbox_versal *mbv = platform_get_drvdata(pdev);

	printk("__larry_mailbox__: enter %s\n", __func__);

	platform_set_drvdata(pdev, NULL);
	xocl_drvinst_free(mbv);

	return 0;
}

static int mailbox_versal_probe(struct platform_device *pdev)
{
	struct mailbox_versal *mbv = NULL;
	struct resource *res;
	int ret;

	printk("__larry_mailbox__: enter %s\n", __func__);

	mbv = xocl_drvinst_alloc(&pdev->dev, sizeof(struct mailbox_versal));
	if (!mbv)
		return -ENOMEM;
	platform_set_drvdata(pdev, mbv);
	mbv->mbv_pdev = pdev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	printk("__larry_mailbox__: start is %llx, end is %llx\n",
	    res->start, res->end);

	mbv->mbv_regs = ioremap_nocache(res->start, res->end - res->start + 1);
	if (!mbv->mbv_regs) {
		MBV_ERR(mbv, "failed to map in registers");
		ret = -EIO;
		goto failed;
	}

	return 0;

failed:
	mailbox_versal_remove(pdev);
	return ret;
}

struct xocl_drv_private mailbox_versal_priv = {
	.ops = &mailbox_versal_ops,
	.dev = -1,
};

struct platform_device_id mailbox_versal_id_table[] = {
	{ XOCL_DEVNAME(XOCL_MAILBOX_VERSAL),
	    (kernel_ulong_t)&mailbox_versal_priv },
	{ },
};

static struct platform_driver	mailbox_versal_driver = {
	.probe		= mailbox_versal_probe,
	.remove		= mailbox_versal_remove,
	.driver		= {
		.name = XOCL_DEVNAME(XOCL_MAILBOX_VERSAL),
	},
	.id_table = mailbox_versal_id_table,
};

int __init xocl_init_mailbox_versal(void)
{
	printk("__larry_xocl__: enter %s\n", __func__);
	return platform_driver_register(&mailbox_versal_driver);
}

void xocl_fini_mailbox_versal(void)
{
	printk("__larry_xocl__: enter %s\n", __func__);
	platform_driver_unregister(&mailbox_versal_driver);
}
