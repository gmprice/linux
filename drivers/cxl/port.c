// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Intel Corporation. All rights reserved. */
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "cxlmem.h"
#include "cxlpci.h"

/**
 * DOC: cxl port
 *
 * The port driver enumerates dport via PCI and scans for HDM
 * (Host-managed-Device-Memory) decoder resources via the
 * @component_reg_phys value passed in by the agent that registered the
 * port. All descendant ports of a CXL root port (described by platform
 * firmware) are managed in this drivers context. Each driver instance
 * is responsible for tearing down the driver context of immediate
 * descendant ports. The locking for this is validated by
 * CONFIG_PROVE_CXL_LOCKING.
 *
 * The primary service this driver provides is presenting APIs to other
 * drivers to utilize the decoders, and indicating to userspace (via bind
 * status) the connectivity of the CXL.mem protocol throughout the
 * PCIe topology.
 */

static void schedule_detach(void *cxlmd)
{
	schedule_cxl_memdev_detach(cxlmd);
}

static int discover_region(struct device *dev, void *root)
{
	struct cxl_endpoint_decoder *cxled;
	int rc;

	if (!is_endpoint_decoder(dev))
		return 0;

	cxled = to_cxl_endpoint_decoder(dev);
	if ((cxled->cxld.flags & CXL_DECODER_F_ENABLE) == 0)
		return 0;

	if (cxled->state != CXL_DECODER_STATE_AUTO)
		return 0;

	/*
	 * Region enumeration is opportunistic, if this add-event fails,
	 * continue to the next endpoint decoder.
	 */
	rc = cxl_add_to_region(root, cxled);
	if (rc)
		dev_dbg(dev, "failed to add to region: %#llx-%#llx\n",
			cxled->cxld.hpa_range.start, cxled->cxld.hpa_range.end);

	return 0;
}

static int cxl_port_perf_data_calculate(struct cxl_port *port,
					struct list_head *dsmas_list)
{
	struct access_coordinate c;
	struct cxl_port *root_port;
	struct cxl_root *cxl_root;
	struct dsmas_entry *dent;
	int valid_entries = 0;
	int rc;

	rc = cxl_endpoint_get_perf_coordinates(port, &c);
	if (rc) {
		dev_dbg(&port->dev, "Failed to retrieve perf coordinates.\n");
		return rc;
	}

	root_port = find_cxl_root(port);
	cxl_root = to_cxl_root(root_port);
	if (!cxl_root->ops || !cxl_root->ops->get_qos_class)
		return -EOPNOTSUPP;

	list_for_each_entry(dent, dsmas_list, list) {
		int qos_class;

		dent->coord.read_latency = dent->coord.read_latency +
					   c.read_latency;
		dent->coord.write_latency = dent->coord.write_latency +
					    c.write_latency;
		dent->coord.read_bandwidth = min_t(int, c.read_bandwidth,
						   dent->coord.read_bandwidth);
		dent->coord.write_bandwidth = min_t(int, c.write_bandwidth,
						    dent->coord.write_bandwidth);

		dent->entries = 1;
		rc = cxl_root->ops->get_qos_class(root_port, &dent->coord, 1, &qos_class);
		if (rc != 1)
			continue;

		valid_entries++;
		dent->qos_class = qos_class;
	}

	if (!valid_entries)
		return -ENOENT;

	return 0;
}

static void cxl_memdev_set_qos_class(struct cxl_dev_state *cxlds,
				     struct list_head *dsmas_list)
{
	struct cxl_memdev_state *mds = to_cxl_memdev_state(cxlds);
	struct range pmem_range = {
		.start = cxlds->pmem_res.start,
		.end = cxlds->pmem_res.end,
	};
	struct range ram_range = {
		.start = cxlds->ram_res.start,
		.end = cxlds->ram_res.end,
	};
	struct perf_prop_entry *perf;
	struct dsmas_entry *dent;

	list_for_each_entry(dent, dsmas_list, list) {
		perf = devm_kzalloc(cxlds->dev, sizeof(*perf), GFP_KERNEL);
		if (!perf)
			return;

		perf->dpa_range = dent->dpa_range;
		perf->coord = dent->coord;
		perf->qos_class = dent->qos_class;
		list_add_tail(&perf->list, &mds->perf_list);

		if (resource_size(&cxlds->ram_res) &&
		    range_contains(&ram_range, &dent->dpa_range)) {
			if (mds->ram_qos_class == CXL_QOS_CLASS_INVALID)
				mds->ram_qos_class = perf->qos_class;
			else
				dev_dbg(cxlds->dev,
					"Multiple DSMAS entries for ram region.\n");
		} else if (resource_size(&cxlds->pmem_res) &&
			 range_contains(&pmem_range, &dent->dpa_range)) {
			if (mds->pmem_qos_class == CXL_QOS_CLASS_INVALID)
				mds->pmem_qos_class = perf->qos_class;
			else
				dev_dbg(cxlds->dev,
					"Multiple DSMAS entries for pmem region.\n");
		}
	}
}

static int cxl_switch_port_probe(struct cxl_port *port)
{
	struct cxl_hdm *cxlhdm;
	int rc;

	/* Cache the data early to ensure is_visible() works */
	read_cdat_data(port);

	rc = devm_cxl_port_enumerate_dports(port);
	if (rc < 0)
		return rc;

	cxlhdm = devm_cxl_setup_hdm(port, NULL);
	if (!IS_ERR(cxlhdm))
		return devm_cxl_enumerate_decoders(cxlhdm, NULL);

	if (PTR_ERR(cxlhdm) != -ENODEV) {
		dev_err(&port->dev, "Failed to map HDM decoder capability\n");
		return PTR_ERR(cxlhdm);
	}

	if (port->cdat.table) {
		rc = cxl_cdat_switch_process(port);
		if (rc < 0)
			dev_warn(&port->dev, "Failed to parse SSLBIS: %d\n", rc);
	}

	if (rc == 1) {
		dev_dbg(&port->dev, "Fallback to passthrough decoder\n");
		return devm_cxl_add_passthrough_decoder(port);
	}

	dev_err(&port->dev, "HDM decoder capability not found\n");
	return -ENXIO;
}

static int cxl_endpoint_port_probe(struct cxl_port *port)
{
	struct cxl_endpoint_dvsec_info info = { .port = port };
	struct cxl_memdev *cxlmd = to_cxl_memdev(port->uport_dev);
	struct cxl_dev_state *cxlds = cxlmd->cxlds;
	struct cxl_hdm *cxlhdm;
	struct cxl_port *root;
	int rc;

	rc = cxl_dvsec_rr_decode(cxlds->dev, cxlds->cxl_dvsec, &info);
	if (rc < 0)
		return rc;

	cxlhdm = devm_cxl_setup_hdm(port, &info);
	if (IS_ERR(cxlhdm)) {
		if (PTR_ERR(cxlhdm) == -ENODEV)
			dev_err(&port->dev, "HDM decoder registers not found\n");
		return PTR_ERR(cxlhdm);
	}

	/* Cache the data early to ensure is_visible() works */
	read_cdat_data(port);

	get_device(&cxlmd->dev);
	rc = devm_add_action_or_reset(&port->dev, schedule_detach, cxlmd);
	if (rc)
		return rc;

	rc = cxl_hdm_decode_init(cxlds, cxlhdm, &info);
	if (rc)
		return rc;

	rc = devm_cxl_enumerate_decoders(cxlhdm, &info);
	if (rc)
		return rc;

	/*
	 * This can't fail in practice as CXL root exit unregisters all
	 * descendant ports and that in turn synchronizes with cxl_port_probe()
	 */
	root = find_cxl_root(port);

	/*
	 * Now that all endpoint decoders are successfully enumerated, try to
	 * assemble regions from committed decoders
	 */
	device_for_each_child(&port->dev, root, discover_region);
	put_device(&root->dev);

	if (port->cdat.table) {
		LIST_HEAD(dsmas_list);

		rc = cxl_cdat_endpoint_process(port, &dsmas_list);
		if (rc < 0) {
			dev_dbg(&port->dev, "Failed to parse CDAT: %d\n", rc);
			goto out;
		}

		rc = cxl_port_perf_data_calculate(port, &dsmas_list);
		if (rc) {
			dev_dbg(&port->dev,
				"Failed to do perf coord calculations.\n");
			goto out;
		}

		cxl_memdev_set_qos_class(cxlds, &dsmas_list);
out:
		cxl_cdat_dsmas_list_destroy(&dsmas_list);
		rc = 0;
	}

	return rc;
}

static int cxl_port_probe(struct device *dev)
{
	struct cxl_port *port = to_cxl_port(dev);

	if (is_cxl_endpoint(port))
		return cxl_endpoint_port_probe(port);
	return cxl_switch_port_probe(port);
}

static ssize_t CDAT_read(struct file *filp, struct kobject *kobj,
			 struct bin_attribute *bin_attr, char *buf,
			 loff_t offset, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct cxl_port *port = to_cxl_port(dev);

	if (!port->cdat_available)
		return -ENXIO;

	if (!port->cdat.table)
		return 0;

	return memory_read_from_buffer(buf, count, &offset,
				       port->cdat.table,
				       port->cdat.length);
}

static BIN_ATTR_ADMIN_RO(CDAT, 0);

static umode_t cxl_port_bin_attr_is_visible(struct kobject *kobj,
					    struct bin_attribute *attr, int i)
{
	struct device *dev = kobj_to_dev(kobj);
	struct cxl_port *port = to_cxl_port(dev);

	if ((attr == &bin_attr_CDAT) && port->cdat_available)
		return attr->attr.mode;

	return 0;
}

static struct bin_attribute *cxl_cdat_bin_attributes[] = {
	&bin_attr_CDAT,
	NULL,
};

static struct attribute_group cxl_cdat_attribute_group = {
	.bin_attrs = cxl_cdat_bin_attributes,
	.is_bin_visible = cxl_port_bin_attr_is_visible,
};

static const struct attribute_group *cxl_port_attribute_groups[] = {
	&cxl_cdat_attribute_group,
	NULL,
};

static struct cxl_driver cxl_port_driver = {
	.name = "cxl_port",
	.probe = cxl_port_probe,
	.id = CXL_DEVICE_PORT,
	.drv = {
		.dev_groups = cxl_port_attribute_groups,
	},
};

module_cxl_driver(cxl_port_driver);
MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(CXL);
MODULE_ALIAS_CXL(CXL_DEVICE_PORT);
