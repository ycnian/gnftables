/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
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
#include <inttypes.h>
#include <string.h>

#include <statement.h>
#include <utils.h>
#include <list.h>

struct stmt *stmt_alloc(const struct location *loc,
			const struct stmt_ops *ops)
{
	struct stmt *stmt;

	stmt = xzalloc(sizeof(*stmt));
	init_list_head(&stmt->list);
	stmt->location = *loc;
	stmt->ops      = ops;
	return stmt;
}

void stmt_free(struct stmt *stmt)
{
	if (stmt->ops->destroy)
		stmt->ops->destroy(stmt);
	xfree(stmt);
}

void stmt_list_free(struct list_head *list)
{
	struct stmt *i, *next;

	list_for_each_entry_safe(i, next, list, list) {
		list_del(&i->list);
		stmt_free(i);
	}
}

void stmt_print(const struct stmt *stmt)
{
	stmt->ops->print(stmt);
}

int stmt_snprint(char *str, size_t size, const struct stmt *stmt)
{
	return stmt->ops->snprint(str, size, stmt);
}

static void expr_stmt_print(const struct stmt *stmt)
{
	expr_print(stmt->expr);
}

static int expr_stmt_snprint(char *str, size_t size, const struct stmt *stmt)
{
	return expr_snprint(str, size, stmt->expr);
}

static void expr_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->expr);
}

static const struct stmt_ops expr_stmt_ops = {
	.type		= STMT_EXPRESSION,
	.name		= "expression",
	.print		= expr_stmt_print,
	.snprint	= expr_stmt_snprint,
	.destroy	= expr_stmt_destroy,
};

struct stmt *expr_stmt_alloc(const struct location *loc, struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &expr_stmt_ops);
	stmt->expr = expr;
	return stmt;
}

static const struct stmt_ops verdict_stmt_ops = {
	.type		= STMT_VERDICT,
	.name		= "verdict",
	.print		= expr_stmt_print,
	.snprint	= expr_stmt_snprint,
	.destroy	= expr_stmt_destroy,
};

struct stmt *verdict_stmt_alloc(const struct location *loc, struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &verdict_stmt_ops);
	stmt->expr = expr;
	return stmt;
}

static void counter_stmt_print(const struct stmt *stmt)
{
	printf("counter packets %" PRIu64 " bytes %" PRIu64,
	       stmt->counter.packets, stmt->counter.bytes);
}

static int counter_stmt_snprint(char *str, size_t size, const struct stmt *stmt)
{
	int	res;
	res = snprintf(str, size, "counter packets %" PRIu64 " bytes %" PRIu64,
	       stmt->counter.packets, stmt->counter.bytes);
	if (str && (size_t)res >= size)
		return -1;
	else
		return res;
}

static const struct stmt_ops counter_stmt_ops = {
	.type		= STMT_COUNTER,
	.name		= "counter",
	.print		= counter_stmt_print,
	.snprint	= counter_stmt_snprint,
};

struct stmt *counter_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &counter_stmt_ops);
}

static void log_stmt_print(const struct stmt *stmt)
{
	printf("log");
	if (stmt->log.prefix != NULL)
		printf(" prefix \"%s\"", stmt->log.prefix);
	if (stmt->log.group)
		printf(" group %u", stmt->log.group);
	if (stmt->log.snaplen)
		printf(" snaplen %u", stmt->log.snaplen);
	if (stmt->log.qthreshold)
		printf(" queue-threshold %u", stmt->log.qthreshold);
}

static int log_stmt_snprint(char *str, size_t size, const struct stmt *stmt)
{
	int	res = 0;
	int	len;
	if (!str) {
		res = snprintf(NULL, 0, "log");
		if (stmt->log.prefix != NULL)
			res += snprintf(NULL, 0, " prefix \"%s\"", stmt->log.prefix);
		if (stmt->log.group)
			res += snprintf(NULL, 0, " group %u", stmt->log.group);
		if (stmt->log.snaplen)
			res += snprintf(NULL, 0, " snaplen %u", stmt->log.snaplen);
		if (stmt->log.qthreshold)
			res += snprintf(NULL, 0, " queue-threshold %u", stmt->log.qthreshold);
		return res;
	}

	len = snprintf(str, size, "log");
	res += len;
	if ((size_t)res >= size)
		return -1;
	if (stmt->log.prefix != NULL) {
		len = snprintf(str + res, size - res, " prefix \"%s\"", stmt->log.prefix);
		res += len;
		if ((size_t)res >= size)
			return -1;
	}
	if (stmt->log.group) {
		len = snprintf(str + res, size - res, " group %u", stmt->log.group);
		res += len;
		if ((size_t)res >= size)
			return -1;
	}
	if (stmt->log.snaplen) {
		len = snprintf(str + res, size - res, " snaplen %u", stmt->log.snaplen);
		res += len;
		if ((size_t)res >= size)
			return -1;
	}
	if (stmt->log.qthreshold) {
		len = snprintf(str + res, size - res, " queue-threshold %u", stmt->log.qthreshold);
		res += len;
		if ((size_t)res >= size)
			return -1;
	}
	return res;
}

static void log_stmt_destroy(struct stmt *stmt)
{
	xfree(stmt->log.prefix);
}

static const struct stmt_ops log_stmt_ops = {
	.type		= STMT_LOG,
	.name		= "log",
	.print		= log_stmt_print,
	.snprint	= log_stmt_snprint,
	.destroy	= log_stmt_destroy,
};

struct stmt *log_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &log_stmt_ops);
}

static const char *get_unit(uint64_t u)
{
	switch (u) {
	case 1: return "second";
	case 60: return "minute";
	case 60 * 60: return "hour";
	case 60 * 60 * 24: return "day";
	case 60 * 60 * 24 * 7: return "week";
	}

	return "error";
}

static void limit_stmt_print(const struct stmt *stmt)
{
	printf("limit rate %" PRIu64 "/%s",
	       stmt->limit.rate, get_unit(stmt->limit.unit));
}

static int limit_stmt_snprint(char *str, size_t size, const struct stmt *stmt)
{
	int	res;
	res = snprintf(str, size, "limit rate %" PRIu64 "/%s",
	       stmt->limit.rate, get_unit(stmt->limit.unit));
	if (str && (size_t)res >= size)
		return -1;
	else
		return res;
}

static const struct stmt_ops limit_stmt_ops = {
	.type		= STMT_LIMIT,
	.name		= "limit",
	.print		= limit_stmt_print,
	.snprint	= limit_stmt_snprint,
};

struct stmt *limit_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &limit_stmt_ops);
}

static void queue_stmt_print(const struct stmt *stmt)
{
	int one = 0;

	printf("queue num %u total %u",
		stmt->queue.queuenum, stmt->queue.queues_total);
	if (stmt->queue.flags)
		printf(" options ");
	if (stmt->queue.flags & NFT_QUEUE_FLAG_BYPASS) {
		printf("bypass");
		one = 1;
	}
	if (stmt->queue.flags & NFT_QUEUE_FLAG_CPU_FANOUT) {
		if (one)
			printf (",");
		printf("fanout");
	}

}

static int queue_stmt_snprint(char *str, size_t size, const struct stmt *stmt)
{
	int one = 0;
	int res = 0;
	int len;

	if (!str) {
		res += snprintf(NULL, 0, "queue num %u total %u",
			stmt->queue.queuenum, stmt->queue.queues_total);
		if (stmt->queue.flags)
			res += snprintf(NULL, 0, " options ");
		if (stmt->queue.flags & NFT_QUEUE_FLAG_BYPASS) {
			res += snprintf(NULL, 0, "bypass");
			one = 1;
		}
		if (stmt->queue.flags & NFT_QUEUE_FLAG_CPU_FANOUT) {
			if (one)
				res += snprintf (NULL, 0, ",");
			res += snprintf(NULL, 0, "fanout");
		}
		return res;
	}

	len = snprintf(str, size, "queue num %u total %u",
		stmt->queue.queuenum, stmt->queue.queues_total);
	res += len;
	if ((size_t)res >= size) {
		return -1;
	}
	if (stmt->queue.flags) {
		len = snprintf(str, size, " options ");
		res += len;
		if ((size_t)res >= size) {
			return -1;
		}
	}
	if (stmt->queue.flags & NFT_QUEUE_FLAG_BYPASS) {
		len = snprintf(str, size, "bypass");
		res += len;
		if ((size_t)res >= size) {
			return -1;
		}
		one = 1;
	}
	if (stmt->queue.flags & NFT_QUEUE_FLAG_CPU_FANOUT) {
		if (one) {
			len = snprintf(str, size, ",");
			res += len;
			if ((size_t)res >= size) {
				return -1;
			}
		}
		len = snprintf(str, size, "fanout");
		res += len;
		if ((size_t)res >= size) {
			return -1;
		}
	}
	return res;
}

static const struct stmt_ops queue_stmt_ops = {
	.type		= STMT_QUEUE,
	.name		= "queue",
	.print		= queue_stmt_print,
	.snprint	= queue_stmt_snprint,
};

struct stmt *queue_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &queue_stmt_ops);
}

static void reject_stmt_print(const struct stmt *stmt)
{
	printf("reject");
}

static int reject_stmt_snprint(char *str, size_t size, const struct stmt *stmt)
{
	int	res;
	res = snprintf(str, size, "reject");
	if (str && (size_t)res >= size)
		return -1;
	else
		return res;
}

static const struct stmt_ops reject_stmt_ops = {
	.type		= STMT_REJECT,
	.name		= "reject",
	.print		= reject_stmt_print,
	.snprint	= reject_stmt_snprint,
};

struct stmt *reject_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &reject_stmt_ops);
}

static void nat_stmt_print(const struct stmt *stmt)
{
	static const char *nat_types[] = {
		[NFT_NAT_SNAT]	= "snat",
		[NFT_NAT_DNAT]	= "dnat",
	};

	printf("%s ", nat_types[stmt->nat.type]);
	if (stmt->nat.addr)
		expr_print(stmt->nat.addr);
	if (stmt->nat.proto) {
		printf(":");
		expr_print(stmt->nat.proto);
	}
}

static int nat_stmt_snprint(char *str, size_t size, const struct stmt *stmt)
{
	int	res = 0;
	int	len;
	static const char *nat_types[] = {
		[NFT_NAT_SNAT]	= "snat",
		[NFT_NAT_DNAT]	= "dnat",
	};

	if (!str) {
		res += snprintf(NULL, 0, "%s ", nat_types[stmt->nat.type]);
		if (stmt->nat.addr)
			res += expr_snprint(NULL, 0, stmt->nat.addr);
		if (stmt->nat.proto) {
			res += snprintf(NULL, 0, ":");
			res += expr_snprint(NULL, 0, stmt->nat.proto);
		}
		return res;
	}

	len = snprintf(str + res, size - res, "%s ", nat_types[stmt->nat.type]);
	res += len;
	if ((size_t)res >= size)
		return -1;
	if (stmt->nat.addr) {
		len = expr_snprint(str + res, size - res, stmt->nat.addr);
		res += len;
		if ((size_t)res >= size)
			return -1;
	}
	if (stmt->nat.proto) {
		len = snprintf(str + res, size - res, ":");
		res += len;
		if ((size_t)res >= size)
			return -1;
		len = expr_snprint(str + res, size - res, stmt->nat.proto);
		res += len;
		if ((size_t)res >= size)
			return -1;
	}
	return res;
}

static void nat_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->nat.addr);
	expr_free(stmt->nat.proto);
}

static const struct stmt_ops nat_stmt_ops = {
	.type		= STMT_NAT,
	.name		= "nat",
	.print		= nat_stmt_print,
	.snprint	= nat_stmt_snprint,
	.destroy	= nat_stmt_destroy,
};

struct stmt *nat_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &nat_stmt_ops);
}
