/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/nexpr.h>

static struct nftnl_nexpr *nexpr_add_parse(int argc, char *argv[])
{
	struct nftnl_nexpr *t;
	struct nftnl_expr *e;
	uint16_t family;

	if (strcmp(argv[1], "ip") == 0)
		family = NFPROTO_IPV4;
	else if (strcmp(argv[1], "ip6") == 0)
		family = NFPROTO_IPV6;
	else if (strcmp(argv[1], "bridge") == 0)
		family = NFPROTO_BRIDGE;
	else if (strcmp(argv[1], "arp") == 0)
		family = NFPROTO_ARP;
	else {
		fprintf(stderr, "Unknown family: ip, ip6, bridge, arp\n");
		return NULL;
	}

	t = nftnl_nexpr_alloc();
	if (t == NULL) {
		perror("OOM");
		return NULL;
	}

	nftnl_nexpr_set_u32(t, NFTNL_NEXPR_FAMILY, family);
	nftnl_nexpr_set_str(t, NFTNL_NEXPR_TABLE, argv[2]);
	nftnl_nexpr_set_str(t, NFTNL_NEXPR_NAME, argv[3]);

	e = nftnl_expr_alloc("counter");
	if (e == NULL) {
		perror("expr counter oom");
		exit(EXIT_FAILURE);
	}
	nftnl_nexpr_set(t, NFTNL_NEXPR_EXPR, e);

	return t;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, nexpr_seq, family;
	struct nftnl_nexpr *t;
	struct mnl_nlmsg_batch *batch;
	int ret;

	if (argc != 4) {
		fprintf(stderr, "%s <family> <table> <name>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	t = nexpr_add_parse(argc, argv);
	if (t == NULL)
		exit(EXIT_FAILURE);

	seq = time(NULL);
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	nexpr_seq = seq;
	family = nftnl_nexpr_get_u32(t, NFTNL_NEXPR_FAMILY);
	nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				    NFT_MSG_NEWNEXPR, family, NLM_F_ACK, seq++);
	nftnl_nexpr_nlmsg_build_payload(nlh, t);
	nftnl_nexpr_free(t);
	mnl_nlmsg_batch_next(batch);

	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
			      mnl_nlmsg_batch_size(batch)) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	mnl_nlmsg_batch_stop(batch);

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, nexpr_seq, portid, NULL, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}
	mnl_socket_close(nl);

	return EXIT_SUCCESS;
}
