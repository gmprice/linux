// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. All rights reserved. */
#include <linux/acpi.h>
#include <linux/fw_table.h>
#include "cxlpci.h"
#include "cxl.h"

static int cdat_dsmas_handler(union acpi_subtable_headers *header, void *arg,
			      const unsigned long end)
{
	struct acpi_cdat_header *hdr = &header->cdat;
	struct acpi_cdat_dsmas *dsmas;
	int size = sizeof(*hdr) + sizeof(*dsmas);
	struct list_head *dsmas_list = arg;
	struct dsmas_entry *dent;
	u16 len;

	len = le16_to_cpu((__force __le16)hdr->length);
	if (len != size || (unsigned long)hdr + len > end) {
		pr_warn("Malformed DSMAS table length: (%u:%u)\n", size, len);
		return -EINVAL;
	}

	/* Skip common header */
	dsmas = (struct acpi_cdat_dsmas *)(hdr + 1);

	dent = kzalloc(sizeof(*dent), GFP_KERNEL);
	if (!dent)
		return -ENOMEM;

	dent->handle = dsmas->dsmad_handle;
	dent->dpa_range.start = le64_to_cpu((__force __le64)dsmas->dpa_base_address);
	dent->dpa_range.end = le64_to_cpu((__force __le64)dsmas->dpa_base_address) +
			      le64_to_cpu((__force __le64)dsmas->dpa_length) - 1;
	list_add_tail(&dent->list, dsmas_list);

	return 0;
}

int cxl_cdat_endpoint_process(struct cxl_port *port, struct list_head *list)
{
	return cdat_table_parse(ACPI_CDAT_TYPE_DSMAS, cdat_dsmas_handler,
				list, port->cdat.table);
}
EXPORT_SYMBOL_NS_GPL(cxl_cdat_endpoint_process, CXL);

void cxl_cdat_dsmas_list_destroy(struct list_head *dsmas_list)
{
	struct dsmas_entry *dentry, *n;

	list_for_each_entry_safe(dentry, n, dsmas_list, list) {
		list_del(&dentry->list);
		kfree(dentry);
	}
}
EXPORT_SYMBOL_NS_GPL(cxl_cdat_dsmas_list_destroy, CXL);

MODULE_IMPORT_NS(CXL);
