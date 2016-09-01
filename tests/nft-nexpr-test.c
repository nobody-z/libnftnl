/*
 * (C) 2013 by Ana Rey Botello <anarey@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include <linux/netfilter/nf_tables.h>
#include <libnftnl/nexpr.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void cmp_nftnl_nexpr(struct nftnl_nexpr *a, struct nftnl_nexpr *b)
{
	const struct nftnl_expr *x, *y;

	if (strcmp(nftnl_nexpr_get_str(a, NFTNL_NEXPR_TABLE),
		   nftnl_nexpr_get_str(b, NFTNL_NEXPR_TABLE)) != 0)
		print_err("table name mismatches");
	if (strcmp(nftnl_nexpr_get_str(a, NFTNL_NEXPR_NAME),
		   nftnl_nexpr_get_str(b, NFTNL_NEXPR_NAME)) != 0)
		print_err("name mismatches");
	if (nftnl_nexpr_get_u32(a, NFTNL_NEXPR_FAMILY) !=
	    nftnl_nexpr_get_u32(b, NFTNL_NEXPR_FAMILY))
		print_err("family mismatches");

	x = nftnl_nexpr_get(a, NFTNL_NEXPR_EXPR);
	y = nftnl_nexpr_get(b, NFTNL_NEXPR_EXPR);

	if (nftnl_expr_get_u64(x, NFTNL_EXPR_CTR_BYTES) !=
	    nftnl_expr_get_u64(y, NFTNL_EXPR_CTR_BYTES))
		print_err("bytes mismatches");
	if (nftnl_expr_get_u64(x, NFTNL_EXPR_CTR_PACKETS) !=
	    nftnl_expr_get_u64(y, NFTNL_EXPR_CTR_PACKETS))
		print_err("packets mismatches");
}

int main(int argc, char *argv[])
{
	char buf[4096];
	struct nlmsghdr *nlh;
	struct nftnl_nexpr *a;
	struct nftnl_nexpr *b;
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("counter");
	if (expr == NULL)
		print_err("OOM");

	nftnl_expr_set_u64(expr, NFTNL_EXPR_CTR_BYTES, 0x12345678abcd);
	nftnl_expr_set_u64(expr, NFTNL_EXPR_CTR_PACKETS, 0xcd12345678ab);

	a = nftnl_nexpr_alloc();
	b = nftnl_nexpr_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");

	nftnl_nexpr_set_str(a, NFTNL_NEXPR_TABLE, "test");
	nftnl_nexpr_set_str(a, NFTNL_NEXPR_NAME, "test");
	nftnl_nexpr_set_u32(a, NFTNL_NEXPR_FAMILY, AF_INET);
	nftnl_nexpr_set_u32(a, NFTNL_NEXPR_USE, 1);
	nftnl_nexpr_set(a, NFTNL_NEXPR_EXPR, expr);

	/* cmd extracted from include/linux/netfilter/nf_tables.h */
	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_NEWNEXPR, AF_INET, 0, 1234);
	nftnl_nexpr_nlmsg_build_payload(nlh, a);

	if (nftnl_nexpr_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	cmp_nftnl_nexpr(a, b);

	nftnl_nexpr_free(a);
	nftnl_nexpr_free(b);
	if (!test_ok)
		exit(EXIT_FAILURE);

	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;
}
