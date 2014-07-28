/*
 * Copyright (c) 2014  Yanchuan Nian <ycnian@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. You may also obtain a copy of the GNU General Public License
 * from the Free Software Foundation by visiting their web site 
 * (http://www.fsf.org/) or by writing to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include <parser.h>
#include <statement.h>
#include <rule.h>
#include <utils.h>
#include <netlink.h>
#include <mnl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libnftnl/common.h>
#include <libnftnl/ruleset.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>


#include <gui_nftables.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <gui_datacheck.h>
#include <gui_expression.h>

void gui_rule_free(struct gui_rule *rule)
{
	if (!rule)
		return;
	if (rule->table)
		xfree(rule->table);
	if (rule->chain)
		xfree(rule->chain);
	if (rule->stmt)
		xfree(rule->stmt);
	xfree(rule);
}

void gui_chain_free(struct chain_list_data *chain)
{
	if (!chain)
		return;
	if (chain->table)
		xfree(chain->table);
	if (chain->chain)
		xfree(chain->chain);
	if (chain->type)
		xfree(chain->type);
	xfree(chain);
}

void gui_set_free(struct set_list_data *set)
{
	if (!set)
		return;
	if (set->table)
		xfree(set->table);
	if (set->name)
		xfree(set->name);
	if (set->keytype)
		xfree(set->keytype);
	if (set->datatype)
		xfree(set->datatype);
	xfree(set);
}

/*
 * Get number of rules in a chain.
 * @family:  nftables family
 * @table:   which table this chain belongs to
 * @chain:   chain name
 * @nrules:  parameter used to store the result
 */
int gui_get_rules_number(int family, char *table, char *chain, int *nrules)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct table		*tablee = NULL;
	struct rule		*rulee;
	int			res;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.chain = chain;
	handle.set = NULL;
	handle.handle = 0;
	handle.position = 0;
	handle.comment = NULL;

	tablee = table_lookup(&handle);
	if (tablee == NULL) {
		tablee = table_alloc();
		init_list_head(&tablee->sets);
		handle_merge(&tablee->handle, &handle);
		table_add_hash(tablee);
	}

	table_list_sets(tablee);
	res = netlink_list_chain(&ctx, &handle, &loc);
	if (res < 0)
		return RULE_KERNEL_ERROR;

	res = 0;
	list_for_each_entry(rulee, &ctx.list, list) {
		res++;
	}
	*nrules = res;

	return RULE_SUCCESS;
}

static int rule_snprint(char *str, size_t size, const struct rule *rule)
{
	int	res = 0;
	int	len;
	const struct stmt *stmt;

	if (!str) {
		list_for_each_entry(stmt, &rule->stmts, list) {
			res += snprintf(NULL, 0, " ");
			res += stmt_snprint(NULL, 0, stmt);
		}
		return res;
	}

	list_for_each_entry(stmt, &rule->stmts, list) {
		len = snprintf(str + res, size - res, " ");
		res += len;
		if ((size_t)res >= size)
			return -1;
		len = stmt_snprint(str + res, size - res, stmt);
		res += len;
		if ((size_t)res >= size)
			return -1;
	}
	return res;
}

int gui_get_rules_list(struct list_head *head, int family, char *table, char *chain)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct table		*tablee = NULL;
	struct rule		*rulee;
	int			res;
	struct gui_rule		*gui_rule;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.chain = chain;
	handle.set = NULL;
	handle.handle = 0;
	handle.position = 0;
	handle.comment = NULL;

	tablee = table_lookup(&handle);
	if (tablee == NULL) {
		tablee = table_alloc();
		handle_merge(&tablee->handle, &handle);
		table_add_hash(tablee);
	}

	res = netlink_list_chain(&ctx, &handle, &loc);
	if (res < 0)
		return -1;

	list_for_each_entry(rulee, &ctx.list, list) {
		int	rule_len;
		gui_rule = (struct gui_rule  *)malloc(sizeof(*gui_rule));
		gui_rule->handle = rulee->handle.handle;
		gui_rule->family = rulee->handle.family;
		gui_rule->table = strdup(rulee->handle.table);
		gui_rule->chain = strdup(rulee->handle.chain);
		rule_len = rule_snprint(NULL, 0, rulee);
		gui_rule->stmt = xmalloc(rule_len + 1);
		rule_snprint(gui_rule->stmt, rule_len + 1, rulee);
		list_add_tail(&gui_rule->list, head);
	}

	return 0;
}


int gui_get_rule(int family, const char *table, const char *chain, int handle_no, struct rule_create_data  **content)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res = TABLE_SUCCESS;
	struct rule	*rule;
	struct stmt	*stmt;
	struct rule_create_data  *data;

	LIST_HEAD(msgs);
	LIST_HEAD(err_list);

//	res = gui_check_chain_exist(family, table, chain);
//	if (res != TABLE_SUCCESS)
//		return res;

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.chain = chain;
	handle.handle = handle_no;
	handle.position = 0;
	handle.comment = NULL;

	// get rule.
	if (netlink_get_rule(&ctx, &handle, &loc) < 0) {
			res = RULE_KERNEL_ERROR;
			return res;
	}

	rule = list_first_entry(&ctx.list, struct rule, list);
	rule_de_expressions(rule, &data);
	data->family = rule->handle.family;
	data->table = xstrdup(rule->handle.table);
	data->chain = xstrdup(rule->handle.chain);
	data->handle = rule->handle.handle;
	*content = data;

	return res;
}

int gui_delete_rule(int family, const char *table, const char *chain, int handle_no)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res = TABLE_SUCCESS;
	bool batch_supported;

	LIST_HEAD(msgs);
	LIST_HEAD(err_list);

//	res = gui_check_chain_exist(family, table, chain);
//	if (res != TABLE_SUCCESS)
//		return res;

	batch_supported = netlink_batch_supported();

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.chain = chain;
	handle.handle = handle_no;
	handle.position = 0;
	handle.comment = NULL;

	 mnl_batch_begin();
	// delete rule.
	if (netlink_del_rule_batch(&ctx, &handle, &loc) < 0) {
			res = TABLE_KERNEL_ERROR;
	}
	mnl_batch_end();

	if (mnl_batch_ready())
		netlink_batch_send(&err_list);
	return res;
}


int gui_add_rule(struct rule_create_data *data)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	int	res = TABLE_SUCCESS;
	bool batch_supported;
	struct  rule	rule;
	uint32_t flags = 0;

	LIST_HEAD(msgs);
	LIST_HEAD(err_list);


	batch_supported = netlink_batch_supported();

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);
	init_list_head(&rule.stmts);

	handle.family = data->family;
	handle.table = xstrdup(data->table);
	handle.chain = xstrdup(data->chain);
	handle.handle = data->handle;
	handle.position = 0;
	handle.comment = NULL;
	if (handle.handle)
		flags = NLM_F_REPLACE;
	else if (!data->insert) {
		flags |= NLM_F_APPEND;
		handle.position = data->position;
	}
	rule.handle = handle;

	list_splice_tail(&data->exprs, &rule.stmts);

	mnl_batch_begin();
	if (netlink_add_rule_batch(&ctx, &handle, &rule, flags) < 0) {
			res = TABLE_KERNEL_ERROR;
	}
	mnl_batch_end();


	if (mnl_batch_ready()) {
		netlink_batch_send(&err_list);
	} else
		mnl_batch_reset();
	return res;

}


/*
 * Get number of sets in a table.
 * We have to design this function since the number cannot be got through
 * NFT_MSG_GETTABLE directly.
 * @family:  nftable family
 * @table:   table name
 * @nsets:   used to store the result
 */
int gui_get_sets_number(int family, char *table, int *nsets)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct set		*set, *tmp;

	*nsets = 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.set = NULL;

	if (netlink_list_sets(&ctx, &handle, &loc) < 0)
		return SET_KERNEL_ERROR;

	list_for_each_entry_safe(set, tmp, &ctx.list, list) {
		if (!(set->flags & SET_F_ANONYMOUS))
			(*nsets)++;
		set_free(set);
	}
	return SET_SUCCESS;
}

int table_list_sets(struct table *table)
{
	struct netlink_ctx	ctx;
	struct location		loc;
        struct set *set, *nset;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

        if (netlink_list_sets(&ctx, &table->handle, &loc) < 0)
                return -1;

        list_for_each_entry_safe(set, nset, &ctx.list, list) {
                if (netlink_get_setelems(&ctx, &set->handle, &loc, set) < 0)
                        return -1;
                list_move_tail(&set->list, &table->sets);
        }
        return 0;
}

int gui_get_sets_list(struct list_head *head, int family, char *table, char *desc)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct set		*set, *s;
	struct set_list_data  *gui_set, *gs;
	int	nelems;
	int	res;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.set = NULL;

	if (netlink_list_sets(&ctx, &handle, &loc) < 0)
		return SET_KERNEL_ERROR;

	list_for_each_entry_safe(set, s, &ctx.list, list) {
		if (set->flags & SET_F_ANONYMOUS)
			goto skipe;
		if (strcmp(desc, "all") && strcmp(desc, set->keytype->desc))
			goto skipe;
		gui_set = (struct set_list_data *)xzalloc(sizeof(struct set_list_data));
		gui_set->family = set->handle.family;
		gui_set->table = xstrdup(set->handle.table);
		gui_set->name = xstrdup(set->handle.set);
		gui_set->keytype = xstrdup(set->keytype->desc);
		if (set->flags & SET_F_MAP)
			gui_set->datatype = xstrdup(set->datatype->desc);
		netlink_get_setelems(&ctx, &set->handle, &loc, set);
		gui_set->nelems = set->init->size;
		list_add_tail(&gui_set->list, head);
skipe:
		list_del(&set->list);
		set_free(set);
	}

	return SET_SUCCESS;
error:
	list_for_each_entry_safe(set, s, &ctx.list, list) {
		list_del(&set->list);
		set_free(set);
	}
	list_for_each_entry_safe(gui_set, gs, head, list) {
		list_del(&gui_set->list);
		xfree(gui_set->table);
		xfree(gui_set->name);
		xfree(gui_set);
	}
	return SET_KERNEL_ERROR;

	return 0;
}


/*
 * Get basic information of chains in nftables.
 * @head: chains listed here
 * @family: nftables family
 * @table:  table name
 * @type:   chain type, only show chains in this type
 */
int gui_get_chains_list(struct list_head *head, int family, char *table, char *type)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct chain		*chain, *c;
	struct chain_list_data  *gui_chain, *gc;
	int	nrules;
	int	res;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.chain = NULL;

	if (netlink_list_chains(&ctx, &handle, &loc) < 0)
		return CHAIN_KERNEL_ERROR;

	list_for_each_entry_safe(chain, c, &ctx.list, list) {
		if (!strcmp(type, "all") ||
			(!(chain->flags & CHAIN_F_BASECHAIN) && !strcmp(type, "user")) ||
			((chain->flags & CHAIN_F_BASECHAIN) && !strcmp(type, chain->type))) {
			gui_chain = (struct chain_list_data *)xmalloc(sizeof(struct chain_list_data));
			gui_chain->family = chain->handle.family;
			gui_chain->table = xstrdup(chain->handle.table);
			gui_chain->chain = xstrdup(chain->handle.chain);
			if (chain->flags & CHAIN_F_BASECHAIN) {
				gui_chain->basechain = 1;
				gui_chain->hook = chain->hooknum;
				gui_chain->priority = chain->priority;
				gui_chain->type = xstrdup(chain->type);
			}
			else {
				gui_chain->basechain = 0;
				gui_chain->type = NULL;
			}
			res = gui_get_rules_number(gui_chain->family, gui_chain->table, gui_chain->chain, &nrules);
			if (res != RULE_SUCCESS) {
				gui_chain_free(gui_chain);
				goto error;
			}
			gui_chain->nrules = nrules;
			list_add_tail(&gui_chain->list, head);
		}
		list_del(&chain->list);
		chain_free(chain);
	}

	return CHAIN_SUCCESS;
error:
	list_for_each_entry_safe(chain, c, &ctx.list, list) {
		list_del(&chain->list);
		chain_free(chain);
	}
	list_for_each_entry_safe(gui_chain, gc, head, list) {
		list_del(&gui_chain->list);
		gui_chain_free(gui_chain);
	}
	return CHAIN_KERNEL_ERROR;
}


/*
 * Create a new chain.
 *
 */
int gui_add_chain(struct chain_create_data *gui_chain)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct chain		chain;

	bool batch_supported = netlink_batch_supported();
	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);

	handle.family = gui_chain->family;
	handle.table = gui_chain->table;
	handle.chain = gui_chain->chain;
	handle.handle = 0;

	if (gui_chain->basechain) {
		chain.flags |= CHAIN_F_BASECHAIN;
		chain.type = gui_chain->type;
		chain.hooknum = gui_chain->hook;
		chain.priority = gui_chain->priority;
	} else
		chain.flags = 0;
	init_list_head(&chain.list);
	init_list_head(&chain.rules);

	if (netlink_add_chain(&ctx, &handle, &loc, &chain, false) < 0) {
		if (errno == EEXIST)
			return CHAIN_EXIST;
		else
			return CHAIN_KERNEL_ERROR;
	}

	return CHAIN_SUCCESS;
}


/*
 * Check whether a chain exists.
 * @family:  nftables family
 * @table:   table name
 * @chain:   chain name
 */
int gui_check_chain_exist(int family, char *table, char *chain)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int			res;

	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.chain = chain;

	res = netlink_get_chain(&ctx, &handle, &loc);
	if (res < 0) {
		if (errno == ENOENT)
			return CHAIN_NOT_EXIST;
		else
			return CHAIN_KERNEL_ERROR;
	}
	return CHAIN_SUCCESS;
}

/*
 * Get basic information of tables from kernel, 
 * including: family, table name, number of chains, number of sets.
 * @head: list used to store data
 * @family: nftable family
 */
int gui_get_tables_list(struct list_head *head, int family)
{
	int		nsets = 0;
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct table		*table, *t;
	struct table_list_data	*gui_table, *gt;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	if (netlink_list_tables(&ctx, &handle, &loc) < 0)
		return TABLE_KERNEL_ERROR;

	list_for_each_entry_safe(table, t, &ctx.list, list) {
		gui_table = (struct table_list_data  *)xmalloc(sizeof(struct table_list_data));
		gui_table->family = table->handle.family;
		gui_table->table = xstrdup(table->handle.table);
		gui_table->nchains = table->nchains;
		if (gui_get_sets_number(family, gui_table->table, &nsets) != SET_SUCCESS) {
			xfree(gui_table->table);
			xfree(gui_table);
			goto error;
		}
		gui_table->nsets = nsets;
		list_add_tail(&gui_table->list, head);
		list_del(&table->list);
		table_free(table);
	}
	return TABLE_SUCCESS;

error:
	list_for_each_entry_safe(table, t, &ctx.list, list) {
		list_del(&table->list);
		table_free(table);
	}
	list_for_each_entry_safe(gui_table, gt, head, list) {
		list_del(&gui_table->list);
		xfree(gui_table->table);
		xfree(gui_table);
	}
	return TABLE_KERNEL_ERROR;
}



/*
 * Create a new table by sending NFT_MSG_NEWTABLE netlink message.
 * @data: data set into netlink message
 */
int gui_add_table(struct table_create_data *data)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	family = data->family;
	char	*name = data->table;

	bool batch_supported = netlink_batch_supported();
	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = name;

	if (netlink_add_table(&ctx, &handle, &loc, NULL, true) < 0) {
		if (errno == EEXIST)
			return TABLE_EXIST;
		else
			return TABLE_KERNEL_ERROR;
	}
	return TABLE_SUCCESS;
}


/*
 * Check whether a table exists.
 * @family:  nftables family
 * @name:    table name
 */
int gui_check_table_exist(int family, char *name)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int			res;

	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = name;

	res = netlink_get_table(&ctx, &handle, &loc);
	if (res < 0) {
		if (errno == ENOENT)
			return TABLE_NOT_EXIST;
		else
			return TABLE_KERNEL_ERROR;
	}
	return TABLE_SUCCESS;
}



/*
 * Delete a chain and all rules in the chain
 * @family: nftables family
 * @table:  table name
 * @chain:  chain name
 */
int gui_delete_chain(int family, const char *table, const char *chain)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res = CHAIN_SUCCESS;
	bool batch_supported;

	LIST_HEAD(msgs);
	LIST_HEAD(err_list);

	batch_supported = netlink_batch_supported();

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.chain = chain;
	handle.handle = 0;

	mnl_batch_begin();
	// delete all rules in the chain.
	if (netlink_del_rule_batch(&ctx, &handle, &loc) < 0) {
		return CHAIN_KERNEL_ERROR;
	}
	mnl_batch_end();

	if (mnl_batch_ready()) {
		res = netlink_batch_send(&err_list);
		if (res < 0)
			return CHAIN_KERNEL_ERROR;
	}

	if (netlink_delete_chain(&ctx, &handle, &loc) < 0) {
		res = CHAIN_KERNEL_ERROR;
	}

	return CHAIN_SUCCESS;
}



int gui_flush_table(int family, char *name)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res;
	bool batch_supported;

	LIST_HEAD(msgs);
	batch_supported = netlink_batch_supported();

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = name;

	res = netlink_flush_table(&ctx, &handle, &loc);
	if (res != 0)
		return TABLE_KERNEL_ERROR;
	else
		return TABLE_SUCCESS;
}

/*
 * Delete a table and all rules in it.
 *
 */
int gui_delete_table(int family, char *name)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res;
	bool batch_supported;
	struct chain_list_data  *gui_chain, *gc;
	struct set_list_data  *gui_set, *gs;

	LIST_HEAD(msgs);
	LIST_HEAD(chains_list);
	LIST_HEAD(sets_list);

	batch_supported = netlink_batch_supported();

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = name;

	res = gui_get_chains_list(&chains_list, family, name, (char *)"all");
	if (res != CHAIN_SUCCESS)
		return TABLE_KERNEL_ERROR;
	list_for_each_entry_safe(gui_chain, gc, &chains_list, list) {
		list_del(&gui_chain->list);
		gui_delete_chain(gui_chain->family, gui_chain->table, gui_chain->chain);
		gui_chain_free(gui_chain);
	}

	// delete all sets in the table
	gui_get_sets_list(&sets_list, family, name, "all");
	list_for_each_entry_safe(gui_set, gs, &sets_list, list) {
		list_del(&gui_set->list);
		gui_delete_set(gui_set->family, gui_set->table, gui_set->name);
		gui_set_free(gui_set);
	}

	// delete table.
	if (netlink_delete_table(&ctx, &handle, &loc) < 0) {
		return TABLE_KERNEL_ERROR;
	}
	return TABLE_SUCCESS;
}




int str2family(const char *family)
{
	if (!strcmp(family, "inet"))
		return NFPROTO_INET;
	else if (!strcmp(family, "ipv4"))
		return NFPROTO_IPV4;
	else if (!strcmp(family, "arp"))
		return NFPROTO_ARP;
	else if (!strcmp(family, "bridge"))
		return NFPROTO_BRIDGE;
	else if (!strcmp(family, "ipv6"))
		return NFPROTO_IPV6;
	else if (!strcmp(family, "decnet"))
		return NFPROTO_DECNET;
	else if (!strcmp(family, "all"))
		return NFPROTO_UNSPEC;
	else
		return -1;
}

int gui_add_set(struct set_create_data *gui_set)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct set		set;
	int	res = SET_SUCCESS;

	bool batch_supported = netlink_batch_supported();
	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = 0;
	init_list_head(&ctx.list);

	handle.family = gui_set->family;
	handle.table = xstrdup(gui_set->table);
	handle.set = xstrdup(gui_set->set);
	handle.handle = 0;

	set.handle = handle;
	set.flags = 0;
	set.keytype = gui_set->keytype;
	set.keylen = gui_set->keylen;
	set.init = NULL;

	if (!list_empty(&(gui_set->elems)))
		res = set_gen_expressions(&set, gui_set);
	if (res != SET_SUCCESS)
		return CHAIN_KERNEL_ERROR;

	if (netlink_add_set(&ctx, &handle, &set) < 0) {
		return CHAIN_KERNEL_ERROR;
	}
	if (set.init != NULL) {
		if (netlink_add_setelems(&ctx, &set.handle, set.init) < 0)
			return CHAIN_KERNEL_ERROR;
	}

	return SET_SUCCESS;
}

int gui_get_set(struct set_create_data *gui_set)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int			res;
	struct set	*set;

	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = gui_set->family;
	handle.table = gui_set->table;
	handle.set = gui_set->set;

	res = netlink_get_set(&ctx, &handle, &loc);
	if (res < 0) {
		return SET_KERNEL_ERROR;
	}

	set = list_first_entry(&ctx.list, struct set, list);
	gui_set->keytype = set->keytype;
	gui_set->keylen = set->keylen;

	netlink_get_setelems(&ctx, &handle, &loc, set);
	set_de_expressions(set, gui_set);

	return SET_SUCCESS;
}
	

int gui_delete_set(int family, char *table, char *set)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res = SET_SUCCESS;

	LIST_HEAD(msgs);
	LIST_HEAD(err_list);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.set = set;
	handle.handle = 0;

	if (netlink_delete_set(&ctx, &handle, &loc) < 0) {
		res = SET_KERNEL_ERROR;
	}

	return res;
}


int gui_flush_set(int family, char *table, char *name)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int			res;
	struct set	*set;

	LIST_HEAD(msgs);
	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	handle.family = family;
	handle.table = table;
	handle.set = name;

	res = netlink_get_set(&ctx, &handle, &loc);
	if (res < 0) {
		return SET_KERNEL_ERROR;
	}

	set = list_first_entry(&ctx.list, struct set, list);
	netlink_get_setelems(&ctx, &handle, &loc, set);
	netlink_delete_setelems(&ctx, &handle, set->init);

	return SET_SUCCESS;
}

int gui_edit_set(struct set_create_data *gui_set)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct set		set;
	int	res = SET_SUCCESS;

	bool batch_supported = netlink_batch_supported();
	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = 0;
	init_list_head(&ctx.list);

	handle.family = gui_set->family;
	handle.table = xstrdup(gui_set->table);
	handle.set = xstrdup(gui_set->set);
	handle.handle = 0;

	set.handle = handle;
	set.flags = 0;
	set.keytype = gui_set->keytype;
	set.keylen = gui_set->keylen;
	set.init = NULL;

	if (!list_empty(&(gui_set->elems)))
		res = set_gen_expressions(&set, gui_set);
	if (res != SET_SUCCESS)
		return CHAIN_KERNEL_ERROR;

	gui_flush_set(handle.family, handle.table, handle.set);
	if (set.init != NULL) {
		if (netlink_add_setelems(&ctx, &set.handle, set.init) < 0)
			return CHAIN_KERNEL_ERROR;
	}

	return SET_SUCCESS;
}


static void rule_fprint(FILE *f, struct rule *rule)
{
	const struct stmt *stmt;

	list_for_each_entry(stmt, &rule->stmts, list) {
		int	size;
		char	*buf;
		fprintf(f, " ");
		size = stmt_snprint(NULL, 0, stmt);
		buf = xmalloc(size + 1);
		stmt_snprint(buf, size + 1, stmt);
		fprintf(f, "%s", buf);
		xfree(buf);
	}
	if (handle_output > 0)
	fprintf(f, " # handle %" PRIu64, rule->handle.handle);
}


static void chain_fprint(FILE *f, struct chain *chain)
{
	struct rule *rule;

	fprintf(f, "\tchain %s {\n", chain->handle.chain);
	if (chain->flags & CHAIN_F_BASECHAIN) {
		fprintf(f, "\t\t type %s hook %s priority %u;\n", chain->type,
			hooknum2str(chain->handle.family, chain->hooknum),
			chain->priority);
	}
	list_for_each_entry(rule, &chain->rules, list) {
		fprintf(f, "\t\t");
		rule_fprint(f, rule);
		if (rule->handle.comment)
			fprintf(f, " comment \"%s\"\n", rule->handle.comment);
		else
			fprintf(f, "\n");
	}
	fprintf(f, "\t}\n");
}

struct print_fmt_options {
	const char      *tab;
	const char      *nl;
	const char      *table;
	const char      *family;
	const char      *stmt_separator;
};

static void do_set_fprint(FILE *f, const struct set *set, struct print_fmt_options *opts)
{
	const char *delim = "";
	const char *type;

	type = set->flags & SET_F_MAP ? "map" : "set";
	fprintf(f, "%s%s", opts->tab, type);

	if (opts->family != NULL)
		fprintf(f, " %s", opts->family);

	if (opts->table != NULL)
		fprintf(f, " %s", opts->table);

	fprintf(f, " %s { %s", set->handle.set, opts->nl);

	fprintf(f, "%s%stype %s", opts->tab, opts->tab, set->keytype->name);
	if (set->flags & SET_F_MAP)
		fprintf(f, " : %s", set->datatype->name);
	fprintf(f, "%s", opts->stmt_separator);

	if (set->flags & (SET_F_CONSTANT | SET_F_INTERVAL)) {
		fprintf(f, "%s%sflags ", opts->tab, opts->tab);
		if (set->flags & SET_F_CONSTANT) {
			fprintf(f, "%sconstant", delim);
			delim = ",";
		}
		if (set->flags & SET_F_INTERVAL) {
			fprintf(f, "%sinterval", delim);
			delim = ",";
		}
		fprintf(f, "%s", opts->nl);
	}

	if (set->init != NULL && set->init->size > 0) {
		int	size;
		char	*buf;
		fprintf(f, "%s%selements = ", opts->tab, opts->tab);
		size = expr_snprint(NULL, 0, set->init);
		buf = xmalloc(size + 1);
		expr_snprint(buf, size + 1, set->init);
		fprintf(f, "%s", buf);
		fprintf(f, "%s", opts->nl);
		xfree(buf);
	}
	fprintf(f, "%s}%s", opts->tab, opts->nl);
}


static void set_fprint(FILE *f, struct set *set)
{
	struct print_fmt_options opts = {
		.tab            = "\t",
		.nl             = "\n",
		.stmt_separator = "\n",
	};

	do_set_fprint(f, set, &opts);
}

static void table_fprint(FILE *f, struct table *table)
{
	struct chain *chain;
	struct set *set;
	const char *delim = "";
	const char *family = family2str(table->handle.family);

	fprintf(f, "table %s %s {\n", family, table->handle.table);
	list_for_each_entry(set, &table->sets, list) {
		if (set->flags & SET_F_ANONYMOUS)
			continue;
		fprintf(f, "%s", delim);
		set_fprint(f, set);
		delim = "\n";
	}
	list_for_each_entry(chain, &table->chains, list) {
		fprintf(f, "%s", delim);
		chain_fprint(f, chain);
		delim = "\n";
	}
	fprintf(f, "}\n");
}

static int table_details(FILE *f, struct handle *handle)
{
	struct chain *chain;
	struct rule *rule, *nrule;
	struct table *table;
	struct set *set, *nset;
	struct netlink_ctx	ctx;
	struct location		loc;

	init_list_head(&ctx.list);

	table = table_lookup(handle);
	if (netlink_list_sets(&ctx, handle, &loc) < 0 )
		return -1;
        list_for_each_entry_safe(set, nset, &ctx.list, list) {
                if (netlink_get_setelems(&ctx, &set->handle, &loc, set) < 0)
                        return -1;
                list_move_tail(&set->list, &table->sets);
        }
	if (netlink_list_chains(&ctx, handle, &loc) < 0)
		return -1;
	list_splice_tail_init(&ctx.list, &table->chains);
	if (netlink_list_table(&ctx, handle, &loc) < 0)
		return -1;

	list_for_each_entry_safe(rule, nrule, &ctx.list, list) {
		table = table_lookup(&rule->handle);
		chain = chain_lookup(table, &rule->handle);
		if (chain == NULL) {
			chain = chain_alloc(rule->handle.chain);
			chain_add_hash(chain, table);
		}
		list_move_tail(&rule->list, &chain->rules);
	}

	table_fprint(f, table);


	return 0;
}

int tables_fprint(char *filename)
{
	FILE	*f;
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct table *table = NULL;
	struct table *iter = NULL;
	struct table *tmp = NULL;
	struct chain *chain, *nchain;
	struct set *set, *nset;

	init_list_head(&ctx.list);
	f = fopen(filename, "w+");
	if (!f)
		return -1;

	handle.family = NFPROTO_IPV4;
	if (netlink_list_tables(&ctx, &handle, &loc) < 0) {
		fclose(f);
		return -1;
	}

	list_for_each_entry_safe(iter, tmp, &ctx.list, list) {
		table = table_lookup(&iter->handle);
		if (table == NULL) {
			table = table_alloc();
			handle_merge(&table->handle, &iter->handle);
			table_add_hash(table);
		}
		table_details(f, &iter->handle);

		list_for_each_entry_safe(chain, nchain, &table->chains, list) {
			list_del(&chain->list);
			chain_free(chain);
		}
		list_for_each_entry_safe(set, nset, &table->sets, list) {
			list_del(&set->list);
			set_free(set);
		}
	}
	fclose(f);
	return 0;
}

int tables_load(char *filename)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	struct table *iter = NULL;
	struct table *tmp = NULL;

	struct parser_state state;
	void *scanner;
	LIST_HEAD(msgs);
	char *buf = NULL;

	init_list_head(&ctx.list);

	handle.family = NFPROTO_IPV4;
	if (netlink_list_tables(&ctx, &handle, &loc) < 0) {
		return -1;
	}

	list_for_each_entry_safe(iter, tmp, &ctx.list, list) {
		gui_delete_table(iter->handle.family, iter->handle.table);
	}

	parser_init(&state, &msgs);
	scanner = scanner_init(&state);
	if (scanner_read_file(scanner, filename, &internal_location) < 0)
		goto out;
	nft_run(scanner, &state, &msgs);
out:
	scanner_destroy(scanner);
//	erec_print_list(stdout, &msgs);
	xfree(buf);
	return 0;
}
