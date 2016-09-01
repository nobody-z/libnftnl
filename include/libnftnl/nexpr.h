#ifndef _NEXPR_H_
#define _NEXPR_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/expr.h>
#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	NFTNL_NEXPR_TABLE	= 0,
	NFTNL_NEXPR_NAME,
	NFTNL_NEXPR_EXPR,
	NFTNL_NEXPR_FAMILY,
	NFTNL_NEXPR_USE,
	__NFTNL_NEXPR_MAX
};
#define NFTNL_NEXPR_MAX (__NFTNL_NEXPR_MAX - 1)

struct nftnl_nexpr;

struct nftnl_nexpr *nftnl_nexpr_alloc(void);
void nftnl_nexpr_free(const struct nftnl_nexpr *ne);

bool nftnl_nexpr_is_set(const struct nftnl_nexpr *ne, uint16_t attr);
void nftnl_nexpr_unset(struct nftnl_nexpr *ne, uint16_t attr);
void nftnl_nexpr_set_data(struct nftnl_nexpr *ne, uint16_t attr,
			     const void *data, uint32_t data_len);
void nftnl_nexpr_set(struct nftnl_nexpr *ne, uint16_t attr, const void *data);
void nftnl_nexpr_set_u32(struct nftnl_nexpr *ne, uint16_t attr, uint32_t val);
void nftnl_nexpr_set_str(struct nftnl_nexpr *ne, uint16_t attr, const char *str);
const void *nftnl_nexpr_get_data(struct nftnl_nexpr *ne, uint16_t attr,
				    uint32_t *data_len);
const void *nftnl_nexpr_get(struct nftnl_nexpr *ne, uint16_t attr);
uint32_t nftnl_nexpr_get_u32(struct nftnl_nexpr *ne, uint16_t attr);
const char *nftnl_nexpr_get_str(struct nftnl_nexpr *ne, uint16_t attr);

void nftnl_nexpr_nlmsg_build_payload(struct nlmsghdr *nlh,
				   const struct nftnl_nexpr *ne);
int nftnl_nexpr_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_nexpr *ne);
int nftnl_nexpr_parse(struct nftnl_nexpr *ne, enum nftnl_parse_type type,
		    const char *data, struct nftnl_parse_err *err);
int nftnl_nexpr_parse_file(struct nftnl_nexpr *ne, enum nftnl_parse_type type,
			 FILE *fp, struct nftnl_parse_err *err);
int nftnl_nexpr_snprintf(char *buf, size_t size, const struct nftnl_nexpr *ne,
		       uint32_t type, uint32_t flags);
int nftnl_nexpr_fprintf(FILE *fp, const struct nftnl_nexpr *ne, uint32_t type,
		      uint32_t flags);

struct nftnl_nexpr_list;
struct nftnl_nexpr_list *nftnl_nexpr_list_alloc(void);
void nftnl_nexpr_list_free(struct nftnl_nexpr_list *list);
int nftnl_nexpr_list_is_empty(struct nftnl_nexpr_list *list);
void nftnl_nexpr_list_add(struct nftnl_nexpr *r, struct nftnl_nexpr_list *list);
void nftnl_nexpr_list_add_tail(struct nftnl_nexpr *r, struct nftnl_nexpr_list *list);
void nftnl_nexpr_list_del(struct nftnl_nexpr *t);
int nftnl_nexpr_list_foreach(struct nftnl_nexpr_list *table_list,
			   int (*cb)(struct nftnl_nexpr *t, void *data),
			   void *data);

struct nftnl_nexpr_list_iter;
struct nftnl_nexpr_list_iter *nftnl_nexpr_list_iter_create(struct nftnl_nexpr_list *l);
struct nftnl_nexpr *nftnl_nexpr_list_iter_next(struct nftnl_nexpr_list_iter *iter);
void nftnl_nexpr_list_iter_destroy(struct nftnl_nexpr_list_iter *iter);

#ifdef __cplusplusg
} /* extern "C" */
#endif

#endif /* _NEXPR_H_ */
