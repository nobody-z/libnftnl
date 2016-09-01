/*
 * (C) 2012-2015 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "internal.h"

#include <time.h>
#include <endian.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/expr.h>
#include <libnftnl/nexpr.h>
#include <buffer.h>

struct nftnl_nexpr {
	struct list_head 	head;

	const char		*table;
	const char		*name;
	struct nftnl_expr	*expr;
	uint32_t		family;
	uint32_t		use;
	uint32_t		flags;
};

struct nftnl_nexpr *nftnl_nexpr_alloc(void)
{
	return calloc(1, sizeof(struct nftnl_nexpr));
}
EXPORT_SYMBOL(nftnl_nexpr_alloc);

void nftnl_nexpr_free(const struct nftnl_nexpr *ne)
{
	if (ne->flags & (1 << NFTNL_NEXPR_TABLE))
		xfree(ne->table);
	if (ne->flags & (1 << NFTNL_NEXPR_NAME))
		xfree(ne->name);
	if (ne->flags & (1 << NFTNL_NEXPR_EXPR))
		nftnl_expr_free(ne->expr);

	xfree(ne);
}
EXPORT_SYMBOL(nftnl_nexpr_free);

bool nftnl_nexpr_is_set(const struct nftnl_nexpr *ne, uint16_t attr)
{
	return ne->flags & (1 << attr);
}
EXPORT_SYMBOL(nftnl_nexpr_is_set);

void nftnl_nexpr_unset(struct nftnl_nexpr *ne, uint16_t attr)
{
	if (!(ne->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFTNL_NEXPR_TABLE:
		xfree(ne->table);
		ne->table = NULL;
		break;
	case NFTNL_NEXPR_NAME:
		xfree(ne->name);
		ne->name = NULL;
		break;
	case NFTNL_NEXPR_EXPR:
		if (ne->expr != NULL) {
			nftnl_expr_free(ne->expr);
			ne->expr = NULL;
		}
		break;
	case NFTNL_NEXPR_FAMILY:
	case NFTNL_NEXPR_USE:
		break;
	}
	ne->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nftnl_nexpr_unset);

static uint32_t nftnl_nexpr_validate[NFTNL_NEXPR_MAX + 1] = {
	[NFTNL_NEXPR_FAMILY]	= sizeof(uint32_t),
	[NFTNL_NEXPR_USE]	= sizeof(uint32_t),
};

void nftnl_nexpr_set_data(struct nftnl_nexpr *ne, uint16_t attr,
			  const void *data, uint32_t data_len)
{
	if (attr > NFTNL_NEXPR_MAX)
		return;

	nftnl_assert_validate(data, nftnl_nexpr_validate, attr, data_len);

	switch (attr) {
	case NFTNL_NEXPR_TABLE:
		xfree(ne->table);
		ne->table = strdup(data);
		break;
	case NFTNL_NEXPR_NAME:
		xfree(ne->name);
		ne->name = strdup(data);
		break;
	case NFTNL_NEXPR_EXPR:
		if (ne->expr != NULL)
			nftnl_expr_free(ne->expr);
		ne->expr = (struct nftnl_expr *)data;
		break;
	case NFTNL_NEXPR_FAMILY:
		ne->family = *((uint32_t *)data);
		break;
	case NFTNL_NEXPR_USE:
		ne->use = *((uint32_t *)data);
		break;
	}
	ne->flags |= (1 << attr);
}
EXPORT_SYMBOL(nftnl_nexpr_set_data);

void nftnl_nexpr_set(struct nftnl_nexpr *ne, uint16_t attr, const void *data)
{
	nftnl_nexpr_set_data(ne, attr, data, nftnl_nexpr_validate[attr]);
}
EXPORT_SYMBOL(nftnl_nexpr_set);

void nftnl_nexpr_set_u32(struct nftnl_nexpr *ne, uint16_t attr, uint32_t val)
{
	nftnl_nexpr_set_data(ne, attr, &val, sizeof(uint32_t));
}
EXPORT_SYMBOL(nftnl_nexpr_set_u32);

void nftnl_nexpr_set_str(struct nftnl_nexpr *ne, uint16_t attr, const char *str)
{
	nftnl_nexpr_set_data(ne, attr, str, 0);
}
EXPORT_SYMBOL(nftnl_nexpr_set_str);

const void *nftnl_nexpr_get_data(struct nftnl_nexpr *ne, uint16_t attr,
				 uint32_t *data_len)
{
	if (!(ne->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFTNL_NEXPR_TABLE:
		return ne->table;
	case NFTNL_NEXPR_NAME:
		return ne->name;
	case NFTNL_NEXPR_EXPR:
		return ne->expr;
	case NFTNL_NEXPR_FAMILY:
		*data_len = sizeof(uint32_t);
		return &ne->family;
	case NFTNL_NEXPR_USE:
		*data_len = sizeof(uint32_t);
		return &ne->use;
	}
	return NULL;
}
EXPORT_SYMBOL(nftnl_nexpr_get_data);

const void *nftnl_nexpr_get(struct nftnl_nexpr *ne, uint16_t attr)
{
	uint32_t data_len;
	return nftnl_nexpr_get_data(ne, attr, &data_len);
}
EXPORT_SYMBOL(nftnl_nexpr_get);

uint32_t nftnl_nexpr_get_u32(struct nftnl_nexpr *ne, uint16_t attr)
{
	const void *ret = nftnl_nexpr_get(ne, attr);
	return ret == NULL ? 0 : *((uint32_t *)ret);
}
EXPORT_SYMBOL(nftnl_nexpr_get_u32);

const char *nftnl_nexpr_get_str(struct nftnl_nexpr *ne, uint16_t attr)
{
	return nftnl_nexpr_get(ne, attr);
}
EXPORT_SYMBOL(nftnl_nexpr_get_str);

void nftnl_nexpr_nlmsg_build_payload(struct nlmsghdr *nlh,
				     const struct nftnl_nexpr *ne)
{
	if (ne->flags & (1 << NFTNL_NEXPR_TABLE))
		mnl_attr_put_strz(nlh, NFTA_NEXPR_TABLE, ne->table);
	if (ne->flags & (1 << NFTNL_NEXPR_NAME))
		mnl_attr_put_strz(nlh, NFTA_NEXPR_NAME, ne->name);
	if (ne->flags & (1 << NFTNL_NEXPR_EXPR)) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_NEXPR_EXPR);
		nftnl_expr_build_payload(nlh, ne->expr);
		mnl_attr_nest_end(nlh, nest);
	}
}
EXPORT_SYMBOL(nftnl_nexpr_nlmsg_build_payload);

static int nftnl_nexpr_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_NEXPR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_NEXPR_TABLE:
	case NFTA_NEXPR_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_NEXPR_EXPR:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			abi_breakage();
		break;
	case NFTA_NEXPR_USE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

int nftnl_nexpr_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_nexpr *ne)
{
	struct nlattr *tb[NFTA_NEXPR_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

	if (mnl_attr_parse(nlh, sizeof(*nfg), nftnl_nexpr_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_NEXPR_TABLE]) {
		ne->table = strdup(mnl_attr_get_str(tb[NFTA_NEXPR_TABLE]));
		ne->flags |= (1 << NFTNL_NEXPR_TABLE);
	}
	if (tb[NFTA_NEXPR_NAME]) {
		ne->name = strdup(mnl_attr_get_str(tb[NFTA_NEXPR_NAME]));
		ne->flags |= (1 << NFTNL_NEXPR_NAME);
	}
	if (tb[NFTA_NEXPR_EXPR]) {
		struct nftnl_expr *expr;

		expr = nftnl_expr_parse(tb[NFTA_NEXPR_EXPR]);
		if (expr == NULL)
			goto err1;

		ne->expr = expr;
		ne->flags |= (1 << NFTNL_NEXPR_EXPR);
	}
	if (tb[NFTA_NEXPR_USE]) {
		ne->use = ntohl(mnl_attr_get_u32(tb[NFTA_NEXPR_USE]));
		ne->flags |= (1 << NFTNL_NEXPR_USE);
	}

	ne->family = nfg->nfgen_family;
	ne->flags |= (1 << NFTNL_NEXPR_FAMILY);

	return 0;
err1:
	nftnl_nexpr_free(ne);
	return -1;
}
EXPORT_SYMBOL(nftnl_nexpr_nlmsg_parse);

#ifdef XML_PARSING
int nftnl_mxml_nexpr_parse(mxml_node_t *tree, struct nftnl_nexpr *ne,
			   struct nftnl_parse_err *err)
{
	const char *table, *name;

	table = nftnl_mxml_str_parse(tree, "nexpr", MXML_DESCEND_FIRST,
				   NFT_XML_MAND, err);
	if (table != NULL)
		nftnl_nexpr_set_str(t, NFTNL_NEXPR_TABLE, table);

	name = nftnl_mxml_str_parse(tree, "name", MXML_DESCEND,
				  NFT_XML_MAND, err);
	if (name != NULL)
		nftnl_nexpr_set_str(t, NFTNL_NEXPR_NAME, name);

	/* XXX */

	if (nftnl_mxml_num_parse(tree, "use", MXML_DESCEND, BASE_DEC,
			       &use, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nftnl_nexpr_set_u32(t, NFTNL_NEXPR_USE, use);

	return 0;
}
#endif

static int nftnl_nexpr_xml_parse(struct nftnl_nexpr *ne, const void *data,
				 struct nftnl_parse_err *err,
				 enum nftnl_parse_input input)
{
#ifdef XML_PARSING
	int ret;
	mxml_node_t *tree;

	tree = nftnl_mxml_build_tree(data, "nexpr", err, input);
	if (tree == NULL)
		return -1;

	ret = nftnl_mxml_table_parse(tree, ne, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef JSON_PARSING
int nftnl_jansson_parse_table(struct nftnl_nexpr *t, json_t *tree,
			      struct nftnl_parse_err *err)
{
	json_t *root;
	uint32_t flags, use;
	const char *str, *dev;
	int family;

	root = nftnl_jansson_get_node(tree, "nexpr", err);
	if (root == NULL)
		return -1;

	str = nftnl_jansson_parse_str(root, "table", err);
	if (str != NULL)
		nftnl_nexpr_set_str(t, NFTNL_NEXPR_TABLE, str);

	str = nftnl_jansson_parse_str(root, "name", err);
	if (str != NULL)
		nftnl_nexpr_set_str(t, NFTNL_NEXPR_NAME, str);

	return 0;
}
#endif

static int nftnl_nexpr_json_parse(struct nftnl_nexpr *t, const void *json,
				  struct nftnl_parse_err *err,
				  enum nftnl_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;
	int ret;

	tree = nftnl_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	ret = nftnl_jansson_parse_table(t, tree, err);

	nftnl_jansson_free_root(tree);

	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_nexpr_do_parse(struct nftnl_nexpr *ne,
				enum nftnl_parse_type type,
				const void *data, struct nftnl_parse_err *err,
				enum nftnl_parse_input input)
{
	int ret;
	struct nftnl_parse_err perr;

	switch (type) {
	case NFTNL_PARSE_XML:
		ret = nftnl_nexpr_xml_parse(ne, data, &perr, input);
		break;
	case NFTNL_PARSE_JSON:
		ret = nftnl_nexpr_json_parse(ne, data, &perr, input);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}

	if (err != NULL)
		*err = perr;

	return ret;
}

int nftnl_nexpr_parse(struct nftnl_nexpr *ne, enum nftnl_parse_type type,
		      const char *data, struct nftnl_parse_err *err)
{
	return nftnl_nexpr_do_parse(ne, type, data, err, NFTNL_PARSE_BUFFER);
}
EXPORT_SYMBOL(nftnl_nexpr_parse);

int nftnl_nexpr_parse_file(struct nftnl_nexpr *ne, enum nftnl_parse_type type,
			   FILE *fp, struct nftnl_parse_err *err)
{
	return nftnl_nexpr_do_parse(ne, type, fp, err, NFTNL_PARSE_FILE);
}
EXPORT_SYMBOL(nftnl_nexpr_parse_file);

static int nftnl_nexpr_export(char *buf, size_t size,
			      const struct nftnl_nexpr *ne,
			      uint32_t type, uint32_t flags)
{
	NFTNL_BUF_INIT(b, buf, size);

	nftnl_buf_open(&b, type, TABLE);
	if (ne->flags & (1 << NFTNL_NEXPR_TABLE))
		nftnl_buf_str(&b, type, ne->name, NAME);
	if (ne->flags & (1 << NFTNL_NEXPR_NAME))
		nftnl_buf_str(&b, type, ne->name, NAME);
	if (ne->flags & (1 << NFTNL_NEXPR_FAMILY))
		nftnl_buf_str(&b, type, nftnl_family2str(ne->family), FAMILY);
	if (ne->flags & (1 << NFTNL_NEXPR_USE))
		nftnl_buf_u32(&b, type, ne->use, USE);
	if (ne->flags & (1 << NFTNL_NEXPR_EXPR))
		ne->expr->ops->snprintf(buf + b.len, size - b.len,
					type, flags, ne->expr);

	nftnl_buf_close(&b, type, TABLE);

	return nftnl_buf_done(&b);
}

static int nftnl_nexpr_snprintf_dflt(char *buf, size_t size,
				     const struct nftnl_nexpr *ne,
				     uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;

	ret = snprintf(buf, size, "table %s name %s use %d ",
		       ne->table, ne->name, ne->use);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return nftnl_expr_snprintf(buf + offset, offset, ne->expr, type, flags);
}

static int nftnl_nexpr_cmd_snprintf(char *buf, size_t size,
				    const struct nftnl_nexpr *ne, uint32_t cmd,
				    uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;

	ret = nftnl_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch (type) {
	case NFT_OUTPUT_DEFAULT:
		ret = nftnl_nexpr_snprintf_dflt(buf + offset, len, ne, type,
						flags);
		break;
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		ret = nftnl_nexpr_export(buf + offset, len, ne, type, flags);
		break;
	default:
		return -1;
	}
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nftnl_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nftnl_nexpr_snprintf(char *buf, size_t size, const struct nftnl_nexpr *ne,
			 uint32_t type, uint32_t flags)
{
	return nftnl_nexpr_cmd_snprintf(buf, size, ne, nftnl_flag2cmd(flags), type,
				      flags);
}
EXPORT_SYMBOL(nftnl_nexpr_snprintf);

static int nftnl_nexpr_do_snprintf(char *buf, size_t size, const void *ne,
				   uint32_t cmd, uint32_t type, uint32_t flags)
{
	return nftnl_nexpr_snprintf(buf, size, ne, type, flags);
}

int nftnl_nexpr_fprintf(FILE *fp, const struct nftnl_nexpr *ne, uint32_t type,
			uint32_t flags)
{
	return nftnl_fprintf(fp, ne, NFT_CMD_UNSPEC, type, flags,
			   nftnl_nexpr_do_snprintf);
}
EXPORT_SYMBOL(nftnl_nexpr_fprintf);

struct nftnl_nexpr_list {
	struct list_head list;
};

struct nftnl_nexpr_list *nftnl_nexpr_list_alloc(void)
{
	struct nftnl_nexpr_list *list;

	list = calloc(1, sizeof(struct nftnl_nexpr_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL(nftnl_nexpr_list_alloc);

void nftnl_nexpr_list_free(struct nftnl_nexpr_list *list)
{
	struct nftnl_nexpr *r, *tmp;

	list_for_each_entry_safe(r, tmp, &list->list, head) {
		list_del(&r->head);
		nftnl_nexpr_free(r);
	}
	xfree(list);
}
EXPORT_SYMBOL(nftnl_nexpr_list_free);

int nftnl_nexpr_list_is_empty(struct nftnl_nexpr_list *list)
{
	return list_empty(&list->list);
}
EXPORT_SYMBOL(nftnl_nexpr_list_is_empty);

void nftnl_nexpr_list_add(struct nftnl_nexpr *r, struct nftnl_nexpr_list *list)
{
	list_add(&r->head, &list->list);
}
EXPORT_SYMBOL(nftnl_nexpr_list_add);

void nftnl_nexpr_list_add_tail(struct nftnl_nexpr *r,
			       struct nftnl_nexpr_list *list)
{
	list_add_tail(&r->head, &list->list);
}
EXPORT_SYMBOL(nftnl_nexpr_list_add_tail);

void nftnl_nexpr_list_del(struct nftnl_nexpr *t)
{
	list_del(&t->head);
}
EXPORT_SYMBOL(nftnl_nexpr_list_del);

int nftnl_nexpr_list_foreach(struct nftnl_nexpr_list *table_list,
			     int (*cb)(struct nftnl_nexpr *t, void *data),
			     void *data)
{
	struct nftnl_nexpr *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &table_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(nftnl_nexpr_list_foreach);

struct nftnl_nexpr_list_iter {
	struct nftnl_nexpr_list	*list;
	struct nftnl_nexpr	*cur;
};

struct nftnl_nexpr_list_iter *
nftnl_nexpr_list_iter_create(struct nftnl_nexpr_list *l)
{
	struct nftnl_nexpr_list_iter *iter;

	iter = calloc(1, sizeof(struct nftnl_nexpr_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	if (nftnl_nexpr_list_is_empty(l))
		iter->cur = NULL;
	else
		iter->cur = list_entry(l->list.next, struct nftnl_nexpr, head);

	return iter;
}
EXPORT_SYMBOL(nftnl_nexpr_list_iter_create);

struct nftnl_nexpr *nftnl_nexpr_list_iter_next(struct nftnl_nexpr_list_iter *iter)
{
	struct nftnl_nexpr *r = iter->cur;

	if (r == NULL)
		return NULL;

	/* get next table, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nftnl_nexpr, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}
EXPORT_SYMBOL(nftnl_nexpr_list_iter_next);

void nftnl_nexpr_list_iter_destroy(struct nftnl_nexpr_list_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL(nftnl_nexpr_list_iter_destroy);
