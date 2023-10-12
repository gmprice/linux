// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. All rights reserved. */
#include <linux/acpi.h>
#include <linux/fw_table.h>
#include <linux/overflow.h>
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

static void cxl_access_coordinate_set(struct access_coordinate *coord,
				      int access, unsigned int val)
{
	switch (access) {
	case ACPI_HMAT_ACCESS_LATENCY:
		coord->read_latency = val;
		coord->write_latency = val;
		break;
	case ACPI_HMAT_READ_LATENCY:
		coord->read_latency = val;
		break;
	case ACPI_HMAT_WRITE_LATENCY:
		coord->write_latency = val;
		break;
	case ACPI_HMAT_ACCESS_BANDWIDTH:
		coord->read_bandwidth = val;
		coord->write_bandwidth = val;
		break;
	case ACPI_HMAT_READ_BANDWIDTH:
		coord->read_bandwidth = val;
		break;
	case ACPI_HMAT_WRITE_BANDWIDTH:
		coord->write_bandwidth = val;
		break;
	}
}

static int cdat_dslbis_handler(union acpi_subtable_headers *header, void *arg,
			       const unsigned long end)
{
	struct acpi_cdat_header *hdr = &header->cdat;
	struct acpi_cdat_dslbis *dslbis;
	int size = sizeof(*hdr) + sizeof(*dslbis);
	struct list_head *dsmas_list = arg;
	struct dsmas_entry *dent;
	u16 len;

	len = le16_to_cpu((__force __le16)hdr->length);
	if (len != size || (unsigned long)hdr + len > end) {
		pr_warn("Malformed DSLBIS table length: (%u:%u)\n", size, len);
		return -EINVAL;
	}

	/* Skip common header */
	dslbis = (struct acpi_cdat_dslbis *)(hdr + 1);

	/* Skip unrecognized data type */
	if (dslbis->data_type > ACPI_HMAT_WRITE_BANDWIDTH)
		return 0;

	list_for_each_entry(dent, dsmas_list, list) {
		__le64 le_base;
		__le16 le_val;
		u64 val;
		int rc;

		if (dslbis->handle != dent->handle)
			continue;

		/* Not a memory type, skip */
		if ((dslbis->flags & ACPI_HMAT_MEMORY_HIERARCHY) !=
		    ACPI_HMAT_MEMORY)
			return 0;

		le_base = (__force __le64)dslbis->entry_base_unit;
		le_val = (__force __le16)dslbis->entry[0];
		rc = check_mul_overflow(le64_to_cpu(le_base),
					le16_to_cpu(le_val), &val);
		if (rc)
			pr_warn("DSLBIS value overflowed.\n");

		cxl_access_coordinate_set(&dent->coord, dslbis->data_type, val);
		break;
	}

	return 0;
}

static int cdat_table_parse_output(int rc)
{
	if (rc < 0)
		return rc;
	if (rc == 0)
		return -ENOENT;

	return 0;
}

int cxl_cdat_endpoint_process(struct cxl_port *port, struct list_head *list)
{
	int rc;

	rc = cdat_table_parse(ACPI_CDAT_TYPE_DSMAS, cdat_dsmas_handler,
			      list, port->cdat.table);
	rc = cdat_table_parse_output(rc);
	if (rc)
		return rc;

	rc = cdat_table_parse(ACPI_CDAT_TYPE_DSLBIS, cdat_dslbis_handler,
			      list, port->cdat.table);
	return cdat_table_parse_output(rc);
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

static int cdat_sslbis_handler(union acpi_subtable_headers *header, void *arg,
			       const unsigned long end)
{
	struct acpi_cdat_sslbis *sslbis;
	int size = sizeof(header->cdat) + sizeof(*sslbis);
	struct cxl_port *port = arg;
	struct device *dev = &port->dev;
	struct acpi_cdat_sslbe *entry;
	int remain, entries, i;
	u16 len;

	len = le16_to_cpu((__force __le16)header->cdat.length);
	remain = len - size;
	if (!remain || remain % sizeof(*entry) ||
	    (unsigned long)header + len > end) {
		dev_warn(dev, "Malformed SSLBIS table length: (%u)\n", len);
		return -EINVAL;
	}

	/* Skip common header */
	sslbis = (struct acpi_cdat_sslbis *)((unsigned long)header +
					     sizeof(header->cdat));

	/* Unrecognized data type, we can skip */
	if (sslbis->data_type > ACPI_HMAT_WRITE_BANDWIDTH)
		return 0;

	entries = remain / sizeof(*entry);
	entry = (struct acpi_cdat_sslbe *)((unsigned long)header + sizeof(*sslbis));

	for (i = 0; i < entries; i++) {
		u16 x = le16_to_cpu((__force __le16)entry->portx_id);
		u16 y = le16_to_cpu((__force __le16)entry->porty_id);
		__le64 le_base;
		__le16 le_val;
		struct cxl_dport *dport;
		unsigned long index;
		u16 dsp_id;
		u64 val;

		switch (x) {
		case ACPI_CDAT_SSLBIS_US_PORT:
			dsp_id = y;
			break;
		case ACPI_CDAT_SSLBIS_ANY_PORT:
			switch (y) {
			case ACPI_CDAT_SSLBIS_US_PORT:
				dsp_id = x;
				break;
			case ACPI_CDAT_SSLBIS_ANY_PORT:
				dsp_id = ACPI_CDAT_SSLBIS_ANY_PORT;
				break;
			default:
				dsp_id = y;
				break;
			}
			break;
		default:
			dsp_id = x;
			break;
		}

		le_base = (__force __le64)sslbis->entry_base_unit;
		le_val = (__force __le16)entry->latency_or_bandwidth;

		if (check_mul_overflow(le64_to_cpu(le_base),
				       le16_to_cpu(le_val), &val))
			dev_warn(dev, "SSLBIS value overflowed!\n");

		xa_for_each(&port->dports, index, dport) {
			if (dsp_id == ACPI_CDAT_SSLBIS_ANY_PORT ||
			    dsp_id == dport->port_id)
				cxl_access_coordinate_set(&dport->coord,
							  sslbis->data_type,
							  val);
		}

		entry++;
	}

	return 0;
}

int cxl_cdat_switch_process(struct cxl_port *port)
{
	int rc;

	rc = cdat_table_parse(ACPI_CDAT_TYPE_SSLBIS, cdat_sslbis_handler,
			      port, port->cdat.table);
	return cdat_table_parse_output(rc);
}
EXPORT_SYMBOL_NS_GPL(cxl_cdat_switch_process, CXL);

MODULE_IMPORT_NS(CXL);
