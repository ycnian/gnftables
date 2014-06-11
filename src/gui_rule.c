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



void gui_rule_free(struct gui_rule *rule)
{
	if (!rule)
		return;
	if (rule->table)
		free(rule->table);
	if (rule->chain)
		free(rule->chain);
	if (rule->stmt)
		free(rule->stmt);
	free(rule);
}

void gui_chain_free(struct gui_chain *chain)
{
	if (!chain)
		return;
	if (chain->table)
		free(chain->table);
	if (chain->chain)
		free(chain->chain);
	if (chain->type)
		free(chain->type);
	free(chain);
}


int gui_get_rules_number(int family, char *table, char *chain)
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
		handle_merge(&tablee->handle, &handle);
		table_add_hash(tablee);
	}

	res = netlink_list_chain(&ctx, &handle, &loc);
	if (res < 0)
		return -1;

	res = 0;
	list_for_each_entry(rulee, &ctx.list, list) {
		res++;
	}

	return res;
}


// This is a tmp function, save rule in a tmp file.
// We will get the data in an other way.
int get_rule_data(struct rule *rule, char *file)
{
	freopen(file, "w", stdout);
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
//		rule_print(rulee);

		gui_rule = (struct gui_rule  *)malloc(sizeof(*gui_rule));
		gui_rule->handle = rulee->handle.handle;
		gui_rule->family = rulee->handle.family;
		gui_rule->table = strdup(rulee->handle.table);
		gui_rule->chain = strdup(rulee->handle.chain);
		gui_rule->stmt = (char *)malloc(1024);
		memset(gui_rule->stmt, 0, sizeof(gui_rule->stmt));
		get_rule_data(rulee, file);
		fd = open(file, O_RDONLY);
		read(fd, gui_rule->stmt, 1023);
		list_add_tail(&gui_rule->list, head);
	}

	return 0;
}


int gui_get_chains_number(int family, char *table)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	struct chain *chain;

	handle.family = family;
	handle.table = table;
	handle.chain = NULL;

	if (netlink_list_chains(&ctx, &handle, &loc) < 0)
		return -1;

	list_for_each_entry(chain, &ctx.list, list) {
		res++;
	}

	return res;
}


int gui_get_chains_list(struct list_head *head, int family, char *table)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int			nrules;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	struct chain *chain;
	struct gui_chain  *gui_chain = NULL;

	handle.family = family;
	handle.table = table;
	handle.chain = NULL;

	if (netlink_list_chains(&ctx, &handle, &loc) < 0)
		return -1;

	list_for_each_entry(chain, &ctx.list, list) {
		gui_chain = (struct gui_chain  *)malloc(sizeof(*gui_chain));
		gui_chain->family = chain->handle.family;
		gui_chain->table = strdup(chain->handle.table);
		gui_chain->chain = strdup(chain->handle.chain);
		if (chain->flags & CHAIN_F_BASECHAIN) {
			gui_chain->basechain = 1;
			gui_chain->hook = chain->hooknum;
			gui_chain->priority = chain->priority;
			gui_chain->type = strdup(chain->type);
		}
		else {
			gui_chain->basechain = 0;
			gui_chain->type = NULL;
		}
		nrules = gui_get_rules_number(gui_chain->family, gui_chain->table, gui_chain->chain);
		// if (nrules < 0)
		// 	error;
		gui_chain->nrules = nrules;

		list_add_tail(&gui_chain->list, head);
	}

	return 0;
}



int gui_get_tables_list(struct list_head *head, uint32_t family)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	nchains;

	memset(&ctx, 0, sizeof(ctx));
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);

	struct table *table;
	struct gui_table  *gui_table = NULL;

	handle.family = family;

	if (netlink_list_tables(&ctx, &handle, &loc) < 0)
		return -1;


	list_for_each_entry(table, &ctx.list, list) {
		gui_table = (struct gui_table  *)malloc(sizeof(*gui_table));
		gui_table->family = table->handle.family;
		gui_table->table = strdup(table->handle.table);
		nchains = gui_get_chains_number(family, gui_table->table);
		// if (nchains < 0)
		// 	error;
		gui_table->nchains = nchains;

		list_add_tail(&gui_table->list, head);
	}

	return 0;
}




int gui_add_chain(struct gui_chain *gui_chain)
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

	return 0;
}

int gui_add_table(int family, char *name)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;

	bool batch_supported = netlink_batch_supported();
	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);


	handle.family = family;
	handle.table = strdup(name);

	if (netlink_add_table(&ctx, &handle, &loc, NULL, true) < 0) {
		if (errno == EEXIST)
			return TABLE_EXIST;
		else
			return TABLE_KERNEL_ERROR;
	}
	return TABLE_SUCCESS;
}


int gui_check_table_exist(int family, char *name)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;

	LIST_HEAD(msgs);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	init_list_head(&ctx.list);


	handle.family = family;
	handle.table = strdup(name);

	if (netlink_get_table(&ctx, &handle, &loc) < 0) {
		if (errno == ENOENT)
			return TABLE_NOT_EXIST;
		else {
			return TABLE_KERNEL_ERROR;
		}
	}
	return TABLE_SUCCESS;
}




int gui_delete_chain(int family, const char *table, const char *chain)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res = TABLE_SUCCESS;
	bool batch_supported;

	LIST_HEAD(msgs);

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


	// delete all rules in the chain.


	// delete chain.
	if (netlink_delete_chain(&ctx, &handle, &loc) < 0) {
			res = TABLE_KERNEL_ERROR;
	}
	return res;
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

int gui_delete_table(int family, char *name)
{
	struct netlink_ctx	ctx;
	struct handle		handle;
	struct location		loc;
	int	res;
	bool batch_supported;

	LIST_HEAD(msgs);

//	res = gui_check_table_exist(family, name);
//	if (res != TABLE_SUCCESS)
//		return res;

	batch_supported = netlink_batch_supported();

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	ctx.seqnum  = mnl_seqnum_alloc();
	ctx.batch_supported = batch_supported;
	init_list_head(&ctx.list);


	handle.family = family;
	handle.table = strdup(name);


	// delete all rules and chains in the table,
	res = gui_flush_table(family, name);
	if (res != TABLE_SUCCESS)
		return res;

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

