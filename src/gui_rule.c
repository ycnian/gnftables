/*
 * Copyright (c) 2008-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

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


// This is a tmp function, save rule in a tmp file.
// We will get the data in an other way.
int get_rule_data(struct rule *rule, char *file)
{
	freopen(file, "w+", stdout);
	rule_print(rule);
	freopen("/dev/tty", "w", stdout);
	return 0;
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

	char		*file = "/tmp/sjfosfaaheofsofaofa.txt";
	int		fd;

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
		gui_rule = (struct gui_rule  *)malloc(sizeof(*gui_rule));
		gui_rule->handle = rulee->handle.handle;
		gui_rule->family = rulee->handle.family;
		gui_rule->table = strdup(rulee->handle.table);
		gui_rule->chain = strdup(rulee->handle.chain);
		gui_rule->stmt = (char *)malloc(1024);
		memset(gui_rule->stmt, 0, 1024);
		get_rule_data(rulee, file);
		fd = open(file, O_RDONLY);
		read(fd, gui_rule->stmt, 1023);
		list_add_tail(&gui_rule->list, head);
	}

	return 0;
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
	handle.handle = 0;
	handle.position = 0;
	handle.comment = NULL;
	rule.handle = handle;

	list_splice_tail(&data->exprs, &rule.stmts);

	mnl_batch_begin();
	if (netlink_add_rule_batch(&ctx, &handle, &rule, NLM_F_APPEND) < 0) {
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

int gui_get_sets_list(struct list_head *head, int family, char *table)
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

	netlink_add_chain(&ctx, &handle, &loc, &chain, false);
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

	LIST_HEAD(msgs);
	LIST_HEAD(chains_list);

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
	//gui_get_sets_list(&sets_list, family, name, "all");
	//list_for_each_entry_safe(gui_set, gs, &sets_list, list) {
	//	list_del(&gui_set->list);
	//	gui_delete_set(gui_set->family, gui_set->table, gui_set->set);
	//	gui_set_free(gui_set);
	//}

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

