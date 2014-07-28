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

#include <gui_expression.h>
#include <gui_nftables.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <statement.h>
#include <proto.h>
#include <netlink.h>
#include <string.h>
#include <net/if.h>
#include <erec.h>

int rule_addrlist_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	struct expr  *payload = NULL;
	struct expr  *constant = NULL;
	struct expr  *rela = NULL;
	struct expr  *elem = NULL;
	struct expr  *symbol = NULL;
	struct expr  *se = NULL;
	struct stmt  *stmt = NULL;
	struct set   *set = NULL;
	unsigned int	type;
	enum ops	op;
	struct ip_convert	*convert;
	char	*ip;
	struct error_record	*erec;
	struct netlink_ctx      ctx;
	struct table		*table;
	struct set		*clone;
	char	*iplist;
	LIST_HEAD(msgs);

	if (!addr->iplist)
		return RULE_SUCCESS;

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
//	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	op = OP_LOOKUP;
	payload = payload_expr_alloc(data->loc, &proto_ip, type);
	elem = set_expr_alloc(data->loc);

	iplist = xstrdup(addr->iplist);
	ip = string_skip_space(strtok(iplist, ","));
	while(ip) {
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, ip);
		xfree(ip);
		expr_set_type(symbol, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &constant);
		if (erec) {
			expr_free(payload);
			expr_free(elem);
			expr_free(symbol);
			return RULE_HEADER_IP_INVALID;
		}
		expr_free(symbol);
		compound_expr_add(elem, constant);
		ip = string_skip_space(strtok(NULL, ","));
	}
	xfree(iplist);

	set = set_alloc(data->loc);
        set->flags	= SET_F_CONSTANT | SET_F_ANONYMOUS;
        set->handle.set = xstrdup("set%d");
        set->keytype    = &ipaddr_type;
        set->keylen     = 4 * BITS_PER_BYTE;
        set->init       = elem;
	set->handle.family = data->family;
	set->handle.table = xstrdup(data->table);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
//	ctx.seqnum  = mnl_seqnum_alloc();
	netlink_add_set(&ctx, &set->handle, set);
	netlink_add_setelems(&ctx, &set->handle, set->init);

	table = table_lookup(&set->handle);
	if (table == NULL) {
		table = table_alloc();
		init_list_head(&table->sets);
		handle_merge(&table->handle, &set->handle);
		table_add_hash(table);
	}
	if (!set_lookup(table, set->handle.set)) {
		clone = set_clone(set);
		set_add_hash(clone, table);
	}

	se = set_ref_expr_alloc(data->loc, set);

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, se);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_addrsubnet_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	struct expr  *payload = NULL;
	struct expr  *symbol = NULL;
	struct expr  *base = NULL;
	struct expr  *prefix = NULL;
	struct expr  *rela = NULL;
	struct stmt  *stmt = NULL;
	int	res;
	struct error_record	*erec;
	unsigned int	type;
	enum ops	op;
	unsigned char   ip[4];
	unsigned int	mask;
	int	i;
	int	tmp;

	if (!addr->subnet.ip && !addr->subnet.mask)
		return RULE_SUCCESS;

	res = strtouint(addr->subnet.mask, &mask);
	if (res != 0 || mask > 32)
		return RULE_HEADER_MASK_INVALID;

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	payload = payload_expr_alloc(data->loc, &proto_ip, type);
	symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, addr->subnet.ip);
	expr_set_type(symbol, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
	erec = symbol_parse(symbol, &base);
	if (erec) {
		expr_free(symbol);
		expr_free(payload);
		xfree(erec->msg);
		xfree(erec);
		return RULE_HEADER_IP_INVALID;
	}
	expr_free(symbol);

	prefix = prefix_expr_alloc(data->loc, base, mask);
	prefix->byteorder = base->byteorder;
	prefix->len = base->len;
	prefix->dtype = base->dtype;
	prefix->flags |= EXPR_F_CONSTANT;

	tmp = base->len/BITS_PER_BYTE;
	mpz_export_data(ip, base->value, base->byteorder, tmp);
	for (i = 0; i < tmp; i++) {
		if (mask < 0)
			ip[i] = 0;
		else if (mask < 8) {
			ip[i] = (ip[i] & ((-1 << (8-mask)) & 0xff));
		}
		mask -= 8;
	}
	mpz_import_data(base->value, ip, base->byteorder, tmp);

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, prefix);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_addrrange_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	struct expr  *payload = NULL;
	struct expr  *left = NULL;
	struct expr  *right = NULL;
	struct expr  *range = NULL;
	struct expr  *rela = NULL;
	struct expr  *symbol = NULL;
	struct stmt  *stmt = NULL;
	unsigned int	type;
	enum ops	op;
	struct error_record	*erec;
	int	res = RULE_SUCCESS;
	char	*from = addr->range.from;
	char	*to = addr->range.to;

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
	payload = payload_expr_alloc(data->loc, &proto_ip, type);

	if (from && to) {
		op = (addr->exclude) ? OP_NEQ : OP_EQ;
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, from);
		expr_set_type(symbol, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &left);
		if (erec) {
			res = RULE_HEADER_IP_INVALID;
			goto err;
		}
		expr_free(symbol);
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, to);
		expr_set_type(symbol, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &right);
		if (erec) {
			res = RULE_HEADER_IP_INVALID;
			goto err;
		}
		expr_free(symbol);
		range = range_expr_alloc(data->loc, left, right);
		range->dtype = left->dtype;
		range->flags |= EXPR_F_CONSTANT;
		if (mpz_cmp(left->value, right->value) >= 0) {
			res = RULE_HEADER_IP_RANGE_INVALID;
			goto err;
		}
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, range);
		rela->op = op;
	} else if (from) {
		op = (addr->exclude) ? OP_LT : OP_GTE;
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, from);
		expr_set_type(symbol, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &left);
		if (erec) {
			res = RULE_HEADER_IP_INVALID;
			goto err;
		}
		expr_free(symbol);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, left);
		rela->op = op;
	} else if (to) {
		op = (addr->exclude) ? OP_GT : OP_LTE;
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, to);
		expr_set_type(symbol, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &right);
		if (erec) {
			res = RULE_HEADER_IP_INVALID;
			goto err;
		}
		expr_free(symbol);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, right);
		rela->op = op;
	} else
		return RULE_SUCCESS;

	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
err:
	if (payload)
		expr_free(payload);
	if (symbol)
		expr_free(symbol);
	if (range) {
		expr_free(range);
		left = NULL;
		right = NULL;
	}
	if (left)
		expr_free(left);
	if (right)
		expr_free(right);
	if (erec) {
		xfree(erec->msg);
		xfree(erec);
	}
	return res;
}

int rule_addrset_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	struct expr  *payload = NULL;
	struct expr  *constant = NULL;
	struct expr  *rela = NULL;
	struct expr  *elem = NULL;
	struct expr  *symbol = NULL;
	struct expr  *se = NULL;
	struct stmt  *stmt = NULL;
	struct set   *set = NULL;
	unsigned int	type;
	enum ops	op;
	struct ip_convert	*convert;
	char	*ip;
	struct error_record	*erec;
	struct netlink_ctx      ctx;
	struct table		*table;
	struct set		*clone;
	char	*iplist;
	struct handle		*handle;
	int	res;
	LIST_HEAD(msgs);

	if (!addr->iplist)
		return RULE_SUCCESS;

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
//	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	op = OP_LOOKUP;

	handle = xzalloc(sizeof(struct handle));
	handle->family = data->family;
	handle->table = xstrdup(data->table);
	handle->set = xstrdup(addr->set);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	init_list_head(&ctx.list);
	res = netlink_get_set(&ctx, handle, data->loc);
	handle_free(handle);
	if (res < 0)
		return RULE_HEADER_SET_NOT_EXIST;
	set = list_first_entry(&ctx.list, struct set, list);

	payload = payload_expr_alloc(data->loc, &proto_ip, type);
	elem = set_expr_alloc(data->loc);

	table = table_lookup(&set->handle);
	if (table == NULL) {
		table = table_alloc();
		init_list_head(&table->sets);
		handle_merge(&table->handle, &set->handle);
		table_add_hash(table);
	}
	if (!set_lookup(table, set->handle.set)) {
		clone = set_clone(set);
		set_add_hash(clone, table);
	}

	se = set_ref_expr_alloc(data->loc, set);

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, se);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_addr_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	enum address_type	ip_type;
	int	res = RULE_SUCCESS;

	ip_type = addr->ip_type;
	switch (ip_type) {
	case ADDRESS_EXACT:
		res = rule_addrlist_gen_exprs(data, addr, source);
		break;
	case ADDRESS_SUBNET:
		res = rule_addrsubnet_gen_exprs(data, addr, source);
		break;
	case ADDRESS_RANGE:
		res = rule_addrrange_gen_exprs(data, addr, source);
		break;
	case ADDRESS_SET:
		res = rule_addrset_gen_exprs(data, addr, source);
		break;
	default:
		break;
	}

	return res;
}

int rule_portlist_gen_exprs(struct rule_create_data *data,
		struct trans_port_data *port, enum transport_type type, int source)
{
	struct expr  *payload = NULL;
	struct expr  *constant = NULL;
	struct expr  *rela = NULL;
	struct expr  *elem = NULL;
	struct expr  *se = NULL;
	struct expr  *symbol = NULL;
	struct stmt  *stmt = NULL;
	struct set   *set = NULL;
	unsigned int	sport;
	const struct proto_desc *desc;
	struct error_record	*erec;
	enum ops	op;
	struct unsigned_short_elem	*convert;
	unsigned short	port_value;
	struct netlink_ctx      ctx;
	struct table		*table;
	struct set		*clone;
	char	*portlist;
	char	*portdata;
	LIST_HEAD(msgs);

	if (!port->portlist)
		return RULE_SUCCESS;

	switch (type) {
	case TRANSPORT_TCP:
		sport = source ? TCPHDR_SPORT : TCPHDR_DPORT;
		desc = &proto_tcp;
		break;
	case TRANSPORT_UDP:
		sport = source ? UDPHDR_SPORT : UDPHDR_DPORT;
		desc = &proto_udp;
		break;
	default:
		BUG("invalid transport protocol.");
	}
//	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	op = OP_LOOKUP;
	payload = payload_expr_alloc(data->loc, desc, sport);
	elem = set_expr_alloc(data->loc);

	portlist = xstrdup(port->portlist);
	portdata = string_skip_space(strtok(portlist, ","));
	while (portdata) {
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, portdata);
		xfree(portdata);
		expr_set_type(symbol, &inet_service_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &constant);
		if (erec) {
			expr_free(payload);
			expr_free(elem);
			expr_free(symbol);
			return RULE_HEADER_PORT_INVALID;
		}
		expr_free(symbol);
		compound_expr_add(elem, constant);
		portdata = string_skip_space(strtok(NULL, ","));
	}

	set = set_alloc(data->loc);
        set->flags	= SET_F_CONSTANT | SET_F_ANONYMOUS;
        set->handle.set = xstrdup("set%d");
        set->keytype    = &inet_service_type;
        set->keylen     = 2 * 8;
        set->init       = elem;
	set->handle.family = data->family;
	set->handle.table = xstrdup(data->table);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
//	ctx.seqnum  = mnl_seqnum_alloc();
	netlink_add_set(&ctx, &set->handle, set);
	netlink_add_setelems(&ctx, &set->handle, set->init);

	table = table_lookup(&set->handle);
	if (table == NULL) {
		table = table_alloc();
		init_list_head(&table->sets);
		handle_merge(&table->handle, &set->handle);
		table_add_hash(table);
	}
	if (!set_lookup(table, set->handle.set)) {
		clone = set_clone(set);
		set_add_hash(clone, table);
	}

	se = set_ref_expr_alloc(data->loc, set);

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, se);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_portrange_gen_exprs(struct rule_create_data *data,
		struct trans_port_data *port, enum transport_type type, int source)
{
	struct expr  *payload = NULL;
	struct expr  *left = NULL;
	struct expr  *right = NULL;
	struct expr  *range = NULL;
	struct expr  *rela = NULL;
	struct expr  *symbol = NULL;
	struct stmt  *stmt = NULL;
	unsigned int	sport;
	const struct proto_desc *desc;
	enum ops	op;
	struct error_record	*erec;
	int	res = RULE_SUCCESS;
	char	*from = port->range.from;
	char	*to = port->range.to;

	switch (type) {
	case TRANSPORT_TCP:
		sport = source ? TCPHDR_SPORT : TCPHDR_DPORT;
		desc = &proto_tcp;
		break;
	case TRANSPORT_UDP:
		sport = source ? UDPHDR_SPORT : UDPHDR_DPORT;
		desc = &proto_udp;
		break;
	default:
		BUG("invalid transport protocol.");
	}
	payload = payload_expr_alloc(data->loc, desc, sport);

	if (from && to) {
		op = (port->exclude) ? OP_NEQ : OP_EQ;
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, from);
		expr_set_type(symbol, &inet_service_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &left);
		if (erec) {
			res = RULE_HEADER_PORT_INVALID;
			goto err;
		}
		expr_free(symbol);
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, to);
		expr_set_type(symbol, &inet_service_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &right);
		if (erec) {
			res = RULE_HEADER_PORT_INVALID;
			goto err;
		}
		expr_free(symbol);
		range = range_expr_alloc(data->loc, left, right);
		range->dtype = left->dtype;
		range->flags |= EXPR_F_CONSTANT;
		if (mpz_cmp(left->value, right->value) >= 0) {
			res = RULE_HEADER_PORT_RANGE_INVALID;
			goto err;
		}
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, range);
		rela->op = op;
	} else if (from) {
		op = (port->exclude) ? OP_LT : OP_GTE;
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, from);
		expr_set_type(symbol, &inet_service_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &left);
		if (erec) {
			res = RULE_HEADER_PORT_INVALID;
			goto err;
		}
		expr_free(symbol);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, left);
		rela->op = op;
	} else if (to) {
		op = (port->exclude) ? OP_GT : OP_LTE;
		symbol = symbol_expr_alloc(data->loc, SYMBOL_VALUE, NULL, to);
		expr_set_type(symbol, &inet_service_type, BYTEORDER_BIG_ENDIAN);
		erec = symbol_parse(symbol, &right);
		if (erec) {
			res = RULE_HEADER_PORT_INVALID;
			goto err;
		}
		expr_free(symbol);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, right);
		rela->op = op;
	} else
		return RULE_SUCCESS;

	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
err:
	if (payload)
		expr_free(payload);
	if (symbol)
		expr_free(symbol);
	if (range) {
		expr_free(range);
		left = NULL;
		right = NULL;
	}
	if (left)
		expr_free(left);
	if (right)
		expr_free(right);
	if (erec) {
		xfree(erec->msg);
		xfree(erec);
	}
	return res;
}

int rule_portset_gen_exprs(struct rule_create_data *data,
		struct trans_port_data *port, enum transport_type type, int source)
{
	struct expr  *payload = NULL;
	struct expr  *constant = NULL;
	struct expr  *rela = NULL;
	struct expr  *elem = NULL;
	struct expr  *se = NULL;
	struct expr  *symbol = NULL;
	struct stmt  *stmt = NULL;
	struct set   *set = NULL;
	unsigned int	sport;
	const struct proto_desc *desc;
	struct error_record	*erec;
	enum ops	op;
	struct unsigned_short_elem	*convert;
	unsigned short	port_value;
	struct netlink_ctx      ctx;
	struct table		*table;
	struct set		*clone;
	char	*portlist;
	char	*portdata;
	struct handle	*handle;
	int	res;
	LIST_HEAD(msgs);

	if (!port->set)
		return RULE_SUCCESS;

	switch (type) {
	case TRANSPORT_TCP:
		sport = source ? TCPHDR_SPORT : TCPHDR_DPORT;
		desc = &proto_tcp;
		break;
	case TRANSPORT_UDP:
		sport = source ? UDPHDR_SPORT : UDPHDR_DPORT;
		desc = &proto_udp;
		break;
	default:
		BUG("invalid transport protocol.");
	}
//	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	op = OP_LOOKUP;

	handle = xzalloc(sizeof(struct handle));
	handle->family = data->family;
	handle->table = xstrdup(data->table);
	handle->set = xstrdup(port->set);

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	init_list_head(&ctx.list);
	res = netlink_get_set(&ctx, handle, data->loc);
	handle_free(handle);
	if (res < 0)
		return RULE_HEADER_SET_NOT_EXIST;
	set = list_first_entry(&ctx.list, struct set, list);

	payload = payload_expr_alloc(data->loc, desc, sport);
	elem = set_expr_alloc(data->loc);

	table = table_lookup(&set->handle);
	if (table == NULL) {
		table = table_alloc();
		init_list_head(&table->sets);
		handle_merge(&table->handle, &set->handle);
		table_add_hash(table);
	}
	if (!set_lookup(table, set->handle.set)) {
		clone = set_clone(set);
		set_add_hash(clone, table);
	}

	se = set_ref_expr_alloc(data->loc, set);

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, se);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_port_gen_exprs(struct rule_create_data *data, struct trans_port_data *port, enum transport_type type, int source)
{
	enum port_type	port_type;
	int	res = RULE_SUCCESS;

	port_type = port->port_type;
	switch (port_type) {
	case PORT_EXACT:
		res = rule_portlist_gen_exprs(data, port, type, source);
		break;
	case PORT_RANGE:
		res = rule_portrange_gen_exprs(data, port, type, source);
		break;
	case PORT_SET:
		res = rule_portset_gen_exprs(data, port, type, source);
		break;
	default:
		break;
	}

	return res;
}

int rule_transall_gen_exprs(struct rule_create_data *data, struct trans_all_data *all)
{

	return RULE_SUCCESS;
}


int rule_ip_upper_expr(struct rule_create_data *data, enum transport_type upper)
{
	struct expr  *payload;
	struct expr  *constant;
	struct expr *rela;
	struct stmt *stmt;
	unsigned char	proto = -1;

	switch (upper) {
	case TRANSPORT_TCP:
		proto = IPPROTO_TCP;
		break;
	case TRANSPORT_UDP:
		proto = IPPROTO_UDP;
		break;
	default:
		break;
	}

	payload = payload_expr_alloc(data->loc, &proto_ip, IPHDR_PROTOCOL);
	constant = constant_expr_alloc(data->loc, &inet_protocol_type, BYTEORDER_HOST_ENDIAN,
			8, &proto);
	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, constant);
	rela->op = OP_EQ;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_transtcp_gen_exprs(struct rule_create_data *data, struct trans_tcp_data *tcp, enum transport_type type)
{
	int	res = RULE_SUCCESS;

	// res = rule_ip_tcp_expr(data);
	// if (res == RULE_SUCCESS)
	// 	return res;
	res = rule_port_gen_exprs(data, tcp->sport, type, 1);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_port_gen_exprs(data, tcp->dport, type, 0);

	return res;
}

int rule_transudp_gen_exprs(struct rule_create_data *data, struct trans_udp_data *udp, enum transport_type type)
{
	int	res = RULE_SUCCESS;

	// res = rule_ip_udp_expr(data);
	// if (res == RULE_SUCCESS)
	// 	return res;
	res = rule_port_gen_exprs(data, udp->sport, type, 1);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_port_gen_exprs(data, udp->dport, type, 0);

	return res;

}

int rule_trans_gen_exprs(struct rule_create_data *data, struct transport_data *trans)
{
	enum transport_type	type;
	int	res = RULE_SUCCESS;

	type = trans->trans_type;
	switch (type) {
	case TRANSPORT_ALL:
		res = rule_transall_gen_exprs(data, trans->all);
		break;
	case TRANSPORT_TCP:
		res = rule_ip_upper_expr(data, type);
		if (res != RULE_SUCCESS)
			break;
		res = rule_transtcp_gen_exprs(data, trans->tcp, TRANSPORT_TCP);
		break;
	case TRANSPORT_UDP:
		res = rule_ip_upper_expr(data, type);
		if (res != RULE_SUCCESS)
			break;
		res = rule_transudp_gen_exprs(data, trans->udp, TRANSPORT_UDP);
		break;
	default:
		break;
	}

	return res;
}


int rule_header_gen_exprs(struct rule_create_data *data, struct pktheader *header)
{
	int	res = RULE_SUCCESS;

	res = rule_addr_gen_exprs(data, header->saddr, 1);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_addr_gen_exprs(data, header->daddr, 0);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_trans_gen_exprs(data, header->transport_data);

	return res;
}

/*
 * meta iftype doesn't support anonymous now.
 */
int rule_ifname_gen_exprs(struct rule_create_data *data, struct list_head *head, int source)
{
	struct expr  *meta;
	struct expr  *constant;
	struct expr  *rela;
	struct stmt  *stmt;
	enum ops	op;
	struct string_elem	*s_elem;
	enum nft_meta_keys key;

	if (list_empty(head))
		return RULE_SUCCESS;
	if (source)
		key = NFT_META_IIFNAME;
	else
		key = NFT_META_OIFNAME;
	op = OP_EQ;
	meta = meta_expr_alloc(data->loc, key);

	s_elem = list_first_entry(head, struct string_elem, list);
	constant = constant_expr_alloc(data->loc, &string_type, BYTEORDER_HOST_ENDIAN,
			(strlen(s_elem->value) + 1) * 8, s_elem->value);
	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, meta, constant);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_iftype_gen_exprs(struct rule_create_data *data, struct list_head *head, int source)
{
	struct expr  *meta;
	struct expr  *constant;
	struct expr  *rela;
	struct expr  *elem;
	struct expr  *se;
	struct stmt  *stmt;
	struct set   *set;
	enum ops	op;
	struct unsigned_short_elem	*s_elem;
	enum nft_meta_keys key;
	unsigned short	type;

	if (list_empty(head))
		return RULE_SUCCESS;
	if (source)
		key = NFT_META_IIFTYPE;
	else
		key = NFT_META_OIFTYPE;
	op = OP_LOOKUP;
	meta = meta_expr_alloc(data->loc, key);
	elem = set_expr_alloc(data->loc);

	list_for_each_entry(s_elem, head, list) {
		type = s_elem->value;
		constant = constant_expr_alloc(data->loc, &arphrd_type, BYTEORDER_HOST_ENDIAN,
			2 * 8, &type);
		compound_expr_add(elem, constant);
	}

	set = set_alloc(data->loc);
        set->flags	= SET_F_CONSTANT | SET_F_ANONYMOUS;
        set->handle.set = xstrdup("set%d");
        set->keytype    = &arphrd_type;
        set->keylen     = 2 * 8;
        set->init       = elem;
	set->handle.family = data->family;
	set->handle.table = xstrdup(data->table);

	struct netlink_ctx      ctx;
	struct table		*table;
	struct set		*clone;
	LIST_HEAD(msgs);
	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
//	ctx.seqnum  = mnl_seqnum_alloc();
	netlink_add_set(&ctx, &set->handle, set);
	netlink_add_setelems(&ctx, &set->handle, set->init);

	table = table_lookup(&set->handle);
	if (table == NULL) {
		table = table_alloc();
		init_list_head(&table->sets);
		handle_merge(&table->handle, &set->handle);
		table_add_hash(table);
	}
	if (!set_lookup(table, set->handle.set)) {
		clone = set_clone(set);
		set_add_hash(clone, table);
	}
	se = set_ref_expr_alloc(data->loc, set);

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, meta, se);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);
	return RULE_SUCCESS;
}

int rule_skid_gen_exprs(struct rule_create_data *data, struct list_head *head, int uid)
{
	struct expr  *meta;
	struct expr  *constant;
	struct expr  *rela;
	struct expr  *elem;
	struct expr  *se;
	struct stmt  *stmt;
	struct set   *set;
	enum ops	op;
	struct unsigned_int_elem	*i_elem;
	enum nft_meta_keys key;
	unsigned int	id;
	int	keylen;
	const struct datatype  *keytype;

	if (list_empty(head))
		return RULE_SUCCESS;
	if (uid) {
		key = NFT_META_SKUID;
		keylen = sizeof(uid_t) * 8;
		keytype = &uid_type;
	} else {
		key = NFT_META_SKGID;
		keylen = sizeof(gid_t) * 8;
		keytype = &gid_type;
	}
	op = OP_LOOKUP;
	meta = meta_expr_alloc(data->loc, key);
	elem = set_expr_alloc(data->loc);

	list_for_each_entry(i_elem, head, list) {
		id = i_elem->value;
		constant = constant_expr_alloc(data->loc, keytype, BYTEORDER_HOST_ENDIAN,
			keylen, &id);
		compound_expr_add(elem, constant);
	}

	set = set_alloc(data->loc);
        set->flags	= SET_F_CONSTANT | SET_F_ANONYMOUS;
        set->handle.set = xstrdup("set%d");
        set->keytype    = keytype;
        set->keylen     = keylen;
        set->init       = elem;
	set->handle.family = data->family;
	set->handle.table = xstrdup(data->table);

	struct netlink_ctx      ctx;
	struct table		*table;
	struct set		*clone;
	LIST_HEAD(msgs);
	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
//	ctx.seqnum  = mnl_seqnum_alloc();
	netlink_add_set(&ctx, &set->handle, set);
	netlink_add_setelems(&ctx, &set->handle, set->init);

	table = table_lookup(&set->handle);
	if (table == NULL) {
		table = table_alloc();
		init_list_head(&table->sets);
		handle_merge(&table->handle, &set->handle);
		table_add_hash(table);
	}
	if (!set_lookup(table, set->handle.set)) {
		clone = set_clone(set);
		set_add_hash(clone, table);
	}
	se = set_ref_expr_alloc(data->loc, set);

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, meta, se);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_pktmeta_gen_exprs(struct rule_create_data *data, struct pktmeta *pktmeta)
{
	int	res = RULE_SUCCESS;

	res = rule_ifname_gen_exprs(data, &pktmeta->iifname->name, 1);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_ifname_gen_exprs(data, &pktmeta->oifname->name, 0);
	if (res != RULE_SUCCESS)
		return res;

	res = rule_iftype_gen_exprs(data, &pktmeta->iiftype->type, 1);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_iftype_gen_exprs(data, &pktmeta->oiftype->type, 0);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_skid_gen_exprs(data, &pktmeta->skuid->id, 1);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_skid_gen_exprs(data, &pktmeta->skgid->id, 0);
	return res;
}

int rule_accept_gen_exprs(struct rule_create_data *data, struct action *action)
{
	struct expr	*expr;
	struct stmt	*stmt;
	expr = verdict_expr_alloc(data->loc, NF_ACCEPT, NULL);
	stmt = verdict_stmt_alloc(data->loc, expr);
	list_add_tail(&stmt->list, &data->exprs);
	return RULE_SUCCESS;
}

int rule_drop_gen_exprs(struct rule_create_data *data, struct action *action)
{
	struct expr	*expr;
	struct stmt	*stmt;
	expr = verdict_expr_alloc(data->loc, NF_DROP, NULL);
	stmt = verdict_stmt_alloc(data->loc, expr);
	list_add_tail(&stmt->list, &data->exprs);
	return RULE_SUCCESS;
}

int rule_jump_gen_exprs(struct rule_create_data *data, struct action *action)
{
	struct expr	*expr;
	struct stmt	*stmt;
	expr = verdict_expr_alloc(data->loc, NFT_JUMP, action->chain);
	stmt = verdict_stmt_alloc(data->loc, expr);
	list_add_tail(&stmt->list, &data->exprs);
	return RULE_SUCCESS;
}

int rule_counter_gen_exprs(struct rule_create_data *data, struct action *action)
{
	struct stmt *stmt;
	stmt = counter_stmt_alloc(data->loc);
	stmt->counter.packets = action->packets;
	stmt->counter.bytes = action->bytes;
	list_add_tail(&stmt->list, &data->exprs);
	return RULE_SUCCESS;
}

int rule_actions_gen_exprs(struct rule_create_data *data, struct actions *actions)
{
	int	res;
	struct action	*action;

	if (list_empty(&actions->list))
		return RULE_SUCCESS;
	list_for_each_entry(action, &actions->list, list) {
		switch (action->type) {
		case ACTION_ACCEPT:
			res = rule_accept_gen_exprs(data, action);
			if (res != RULE_SUCCESS)
				return res;
			break;
		case ACTION_DROP:
			res = rule_drop_gen_exprs(data, action);
			if (res != RULE_SUCCESS)
				return res;
			break;
		case ACTION_JUMP:
			res = rule_jump_gen_exprs(data, action);
			if (res != RULE_SUCCESS)
				return res;
			break;
		case ACTION_COUNTER:
			res = rule_counter_gen_exprs(data, action);
			if (res != RULE_SUCCESS)
				return res;
			break;
		default:
			BUG();
		}
	}
	return RULE_SUCCESS;
}

/*
 * Gen expressions according to data from rule creating page.
 * @data: data from rule creating page
 */
int rule_gen_expressions(struct rule_create_data *data)
{
	int res = RULE_SUCCESS;
	init_list_head(&data->exprs);
	res = rule_header_gen_exprs(data, data->header);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_pktmeta_gen_exprs(data, data->pktmeta);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_actions_gen_exprs(data, data->actions);
	return res;
}


int set_gen_expressions(struct set *set, struct set_create_data *gui_set)
{
	struct location	loc;
	struct expr  *elem;
	struct expr  *symbol;
	struct expr  *next;
	struct expr  *constant;
	struct expr  *tmp;
	struct elem_create_data	*data;

	elem = set_expr_alloc(&loc);
	list_for_each_entry(data, &(gui_set->elems), list) {
		symbol = symbol_expr_alloc(&loc, SYMBOL_VALUE, NULL, data->key);
		compound_expr_add(elem, symbol);
	}
	switch (gui_set->keytype->type) {
	case TYPE_IPADDR:
		elem->ops->set_type(elem, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
		break;
	case TYPE_INET_SERVICE:
		elem->ops->set_type(elem, &inet_service_type, BYTEORDER_BIG_ENDIAN);
		break;
	default:
		BUG();
	}
	list_for_each_entry_safe(symbol, tmp, &(elem->expressions), list) {
		next = list_entry(symbol->list.next, struct expr, list);
		list_del(&(symbol->list));
		symbol_parse(symbol, &constant);
		list_add_tail(&constant->list, &next->list);
		expr_free(symbol);
	}

	set->init = elem;
	return SET_SUCCESS;
}


struct header_parse{
	const char	*name;
	int		(*parse)(struct expr *expr, struct pktheader *header, enum ops op);
};

struct header_parse header_ip_parsers[IPHDR_DADDR + 1] = {
	{ .name = "invalid",	.parse = NULL},
	{ .name = "version",	.parse = NULL},
	{ .name = "hdrlength",	.parse = NULL},
	{ .name = "tos",	.parse = NULL},
	{ .name = "length",	.parse = NULL},
	{ .name = "id",		.parse = NULL},
	{ .name = "frag-off",	.parse = NULL},
	{ .name = "ttl",	.parse = NULL},
	{ .name = "protocol",	.parse = rule_parse_ip_protocol_expr},
	{ .name = "checksum",	.parse = NULL},
	{ .name = "saddr",	.parse = rule_parse_ip_saddr_expr},
	{ .name = "daddr",	.parse = rule_parse_ip_daddr_expr},
};

int rule_parse_ip_protocol_expr(struct expr *expr, struct pktheader *header, enum ops op)
{
	int	res;
	char	proto[10];
	struct transport_data   *trans;

	header->transport_data = xmalloc(sizeof(struct transport_data));
	trans = header->transport_data;
	expr_snprint(proto, 10, expr);
	if (!strcmp(proto, "tcp")) {
		trans->tcp = xmalloc(sizeof(struct trans_tcp_data));
		trans->trans_type = TRANSPORT_TCP;
	} else if (!strcmp(proto, "udp")) {
		trans->udp = xmalloc(sizeof(struct trans_udp_data));
		trans->trans_type = TRANSPORT_UDP;
	} else
		BUG();

	return RULE_SUCCESS;
}

int rule_parse_ip_addr_expr(struct expr *expr, struct ip_addr_data *addr, enum ops op)
{
	if (expr->ops->type == EXPR_PREFIX) {
		int   size;
		char  *buf;
		char  *ip, *mask;
		size = expr_snprint(NULL, 0, expr);
		buf = xzalloc(size + 1);
		addr->ip_type = ADDRESS_SUBNET;
		if (op == OP_EQ)
			addr->exclude = 0;
		else if (op == OP_NEQ)
			addr->exclude = 1;
		else
			BUG();
		expr_snprint(buf, size + 1, expr);
		ip = strtok(buf, "/");
		addr->subnet.ip = xstrdup(ip);
		mask = strtok(NULL, "/");
		addr->subnet.mask = xstrdup(mask);
		xfree(buf);
	} else if (expr->ops->type == EXPR_VALUE) {
		int	size;
		addr->ip_type = ADDRESS_RANGE;
		switch (op) {
		case OP_LT:
			addr->exclude = 1;
			size = expr_snprint(NULL, 0, expr);
			addr->range.from = xzalloc(size + 1);
			expr_snprint(addr->range.from, size + 1, expr);
			break;
		case OP_GT:
			addr->exclude = 1;
			size = expr_snprint(NULL, 0, expr);
			addr->range.to = xzalloc(size + 1);
			expr_snprint(addr->range.to, size + 1, expr);
			break;
		case OP_LTE:
			addr->exclude = 0;
			size = expr_snprint(NULL, 0, expr);
			addr->range.to = xzalloc(size + 1);
			expr_snprint(addr->range.to, size + 1, expr);
			break;
		case OP_GTE:
			addr->exclude = 0;
			size = expr_snprint(NULL, 0, expr);
			addr->range.from = xzalloc(size + 1);
			expr_snprint(addr->range.from, size + 1, expr);
			break;
		default:
			BUG();
		}
	} else if (expr->ops->type == EXPR_SET_REF) {
		int	size = expr_snprint(NULL, 0, expr);
		char	buf[size + 1];
		expr_snprint(buf, size + 1, expr);
		if (expr->set->flags & SET_F_ANONYMOUS) {
			addr->ip_type = ADDRESS_EXACT;
			addr->iplist = xzalloc(size - 2);
			strncpy(addr->iplist, buf + 2, size - 3);
		} else {
			addr->ip_type = ADDRESS_SET;
			addr->set = xzalloc(size);
			strncpy(addr->set, buf + 1, size - 1);
		}

	} else
		BUG();
	return RULE_SUCCESS;
}

int rule_parse_ip_saddr_expr(struct expr *expr, struct pktheader *header, enum ops op)
{
	if (!header->saddr)
		header->saddr = xmalloc(sizeof(struct ip_addr_data));
	return rule_parse_ip_addr_expr(expr, header->saddr, op);
}

int rule_parse_ip_daddr_expr(struct expr *expr, struct pktheader *header, enum ops op)
{
	if(!header->daddr)
		header->daddr = xmalloc(sizeof(struct ip_addr_data));
	return rule_parse_ip_addr_expr(expr, header->daddr, op);
}

struct header_parse header_tcp_parsers[TCPHDR_URGPTR + 1] = {
	{ .name = "invalid",	.parse = NULL},
	{ .name = "sport",	.parse = rule_parse_tcp_sport_expr},
	{ .name = "dport",	.parse = rule_parse_tcp_dport_expr},
	{ .name = "sequence",	.parse = NULL},
	{ .name = "ackseq",	.parse = NULL},
	{ .name = "doff",	.parse = NULL},
	{ .name = "reserved",	.parse = NULL},
	{ .name = "flags",	.parse = NULL},
	{ .name = "window",	.parse = NULL},
	{ .name = "checksum",	.parse = NULL},
	{ .name = "urgptr",	.parse = NULL},
};

int rule_parse_port_expr(struct expr *expr,  struct trans_port_data *port, enum ops op)
{
	if (expr->ops->type == EXPR_VALUE) {
		int	size;
		port->port_type = PORT_RANGE;
		switch (op) {
		case OP_LT:
			port->exclude = 1;
			size = expr_snprint(NULL, 0, expr);
			port->range.from = xzalloc(size + 1);
			expr_snprint(port->range.from, size + 1, expr);
			break;
		case OP_GT:
			port->exclude = 1;
			size = expr_snprint(NULL, 0, expr);
			port->range.to = xzalloc(size + 1);
			expr_snprint(port->range.to, size + 1, expr);
			break;
		case OP_LTE:
			port->exclude = 0;
			size = expr_snprint(NULL, 0, expr);
			port->range.to = xzalloc(size + 1);
			expr_snprint(port->range.to, size + 1, expr);
			break;
		case OP_GTE:
			port->exclude = 0;
			size = expr_snprint(NULL, 0, expr);
			port->range.from = xzalloc(size + 1);
			expr_snprint(port->range.from, size + 1, expr);
			break;
		default:
			BUG();
		}
	} else if (expr->ops->type == EXPR_SET_REF) {
		int	size = expr_snprint(NULL, 0, expr);
		char	buf[size + 1];
		expr_snprint(buf, size + 1, expr);
		if (expr->set->flags & SET_F_ANONYMOUS) {
			port->port_type = PORT_EXACT;
			port->portlist = xzalloc(size - 2);
			strncpy(port->portlist, buf + 2, size - 3);
		} else {
			port->port_type = PORT_SET;
			port->portlist = xzalloc(size);
			strncpy(port->portlist, buf + 1, size - 1);
		}
	} else
		BUG();

	return RULE_SUCCESS;
}

int rule_parse_tcp_sport_expr(struct expr *expr, struct pktheader *header, enum ops op)
{
	if (!header->transport_data)
		header->transport_data = xzalloc(sizeof(struct transport_data));
	if (!header->transport_data->tcp)
		header->transport_data->tcp = xzalloc(sizeof(struct trans_tcp_data));
	if (!header->transport_data->tcp->sport)
		header->transport_data->tcp->sport = xzalloc(sizeof(struct trans_port_data));
	header->transport_data->trans_type = TRANSPORT_TCP;
	return rule_parse_port_expr(expr, header->transport_data->tcp->sport, op);
}

int rule_parse_tcp_dport_expr(struct expr *expr, struct pktheader *header, enum ops op)
{
	if (!header->transport_data)
		header->transport_data = xzalloc(sizeof(struct transport_data));
	if (!header->transport_data->tcp)
		header->transport_data->tcp = xzalloc(sizeof(struct trans_tcp_data));
	if (!header->transport_data->tcp->dport)
		header->transport_data->tcp->dport = xzalloc(sizeof(struct trans_port_data));
	header->transport_data->trans_type = TRANSPORT_TCP;
	return rule_parse_port_expr(expr, header->transport_data->tcp->dport, op);
}

struct header_parse header_udp_parsers[UDPHDR_CHECKSUM + 1] = {
	{ .name = "invalid",	.parse = NULL},
	{ .name = "sport",	.parse = rule_parse_udp_sport_expr},
	{ .name = "dport",	.parse = rule_parse_udp_dport_expr},
	{ .name = "length",	.parse = NULL},
	{ .name = "checksum",	.parse = NULL},
};

int rule_parse_udp_sport_expr(struct expr *expr, struct pktheader *header, enum ops op)
{
	if (!header->transport_data)
		header->transport_data = xzalloc(sizeof(struct transport_data));
	if (!header->transport_data->udp)
		header->transport_data->udp = xzalloc(sizeof(struct trans_udp_data));
	if (!header->transport_data->udp->sport)
		header->transport_data->udp->sport = xzalloc(sizeof(struct trans_port_data));
	header->transport_data->trans_type = TRANSPORT_UDP;
	return rule_parse_port_expr(expr, header->transport_data->udp->sport, op);
}

int rule_parse_udp_dport_expr(struct expr *expr, struct pktheader *header, enum ops op)
{
	if (!header->transport_data)
		header->transport_data = xzalloc(sizeof(struct transport_data));
	if (!header->transport_data->udp)
		header->transport_data->udp = xzalloc(sizeof(struct trans_udp_data));
	if (!header->transport_data->udp->dport)
		header->transport_data->udp->dport = xzalloc(sizeof(struct trans_port_data));
	header->transport_data->trans_type = TRANSPORT_UDP;
	return rule_parse_port_expr(expr, header->transport_data->udp->dport, op);
}


int rule_parse_header_expr(struct expr *expr, struct pktheader *header)
{
	struct expr  *left;
	struct expr  *right;
	struct proto_desc   *desc;
	struct proto_hdr_template *tmpl;
	struct header_parse	*parse;
	enum ops	op;
	int	total = 0;
	int	i = 0;

	op = expr->op;
	left = expr->left;
	right = expr->right;
	desc = left->payload.desc;
	tmpl = left->payload.tmpl;

	if (!(strcmp(desc->name, "ip"))) {
		parse = header_ip_parsers;
		total = array_size(header_ip_parsers);
	} else if (!(strcmp(desc->name, "tcp"))) {
		parse = header_tcp_parsers;
		total = array_size(header_ip_parsers);
	} else if (!(strcmp(desc->name, "udp"))) {
		parse = header_udp_parsers;
		total = array_size(header_ip_parsers);
	} else
		BUG();


	for (i = 0; i < total; i++) {
		if (strcmp(tmpl->token, parse[i].name))
			continue;
		parse[i].parse(right, header, op);
		return RULE_SUCCESS;
	}
	return RULE_SUCCESS;
}

static int rule_parse_ifname_expr(struct expr *expr, union ifname *ifname)
{
	int	len = expr_snprint(NULL, 0, expr);
	char	p[len + 1];

	ifname->name_str = xzalloc(len - 1);
	expr_snprint(p, len + 1, expr);
	strncpy(ifname->name_str, p + 1, len - 2);
	return RULE_SUCCESS;
}

static int rule_parse_iftype_expr(struct expr *expr, union iftype *iftype)
{
	int	len = expr_snprint(NULL, 0, expr);
	char	p[len + 1];

	iftype->type_str = xzalloc(len - 2);
	expr_snprint(p, len + 1, expr);
	strncpy(iftype->type_str, p + 2, len - 3);
	return RULE_SUCCESS;
}

static int rule_parse_skuid_expr(struct expr *expr, union skid *uid)
{
	int	len = expr_snprint(NULL, 0, expr);
	char	p[len + 1];

	uid->id_str = xzalloc(len - 2);
	expr_snprint(p, len + 1, expr);
	strncpy(uid->id_str, p + 2, len - 3);

	return RULE_SUCCESS;
}

static int rule_parse_skgid_expr(struct expr *expr, union skid *gid)
{
	int	len = expr_snprint(NULL, 0, expr);
	char	p[len + 1];

	gid->id_str = xzalloc(len - 2);
	expr_snprint(p, len + 1, expr);
	strncpy(gid->id_str, p + 2, len - 3);

	return RULE_SUCCESS;
}

int rule_parse_pktmeta(struct expr *expr, struct pktmeta *pktmeta)
{
	switch (expr->left->meta.key) {
	case NFT_META_IIFNAME:
		pktmeta->iifname = xzalloc(sizeof(union ifname));
		return rule_parse_ifname_expr(expr->right, pktmeta->iifname);
	case NFT_META_OIFNAME:
		pktmeta->oifname = xzalloc(sizeof(union ifname));
		return rule_parse_ifname_expr(expr->right, pktmeta->oifname);
	case NFT_META_IIFTYPE:
		pktmeta->iiftype = xzalloc(sizeof(union iftype));
		return rule_parse_iftype_expr(expr->right, pktmeta->iiftype);
	case NFT_META_OIFTYPE:
		pktmeta->oiftype = xzalloc(sizeof(union iftype));
		return rule_parse_iftype_expr(expr->right, pktmeta->oiftype);
	case NFT_META_SKUID:
		pktmeta->skuid = xzalloc(sizeof(union skid));
		return rule_parse_skuid_expr(expr->right, pktmeta->skuid);
	case NFT_META_SKGID:
		pktmeta->skgid = xzalloc(sizeof(union skid));
		return rule_parse_skgid_expr(expr->right, pktmeta->skgid);
	default:
		BUG();
	}

	return RULE_SUCCESS;
}

int rule_parse_expr(struct stmt *stmt, struct rule_create_data *p)
{
	struct  expr	*expr;
	struct  expr	*left;

	expr = stmt->expr;
	left = expr->left;
	assert(expr->ops->type == EXPR_RELATIONAL);

	switch (left->ops->type) {
	case EXPR_PAYLOAD:
		return rule_parse_header_expr(expr, p->header);
	case EXPR_META:
		return rule_parse_pktmeta(expr, p->pktmeta);
	default:
		return RULE_SUCCESS;
	}
}

int rule_parse_accept_expr(struct expr *expr, struct actions *actions)
{
	struct action	*action;
	action = xzalloc(sizeof(struct action));
	action->type = ACTION_ACCEPT;
	list_add_tail(&action->list, &actions->list);
	return RULE_SUCCESS;
}

int rule_parse_drop_expr(struct expr *expr, struct actions *actions)
{
	struct action	*action;
	action = xzalloc(sizeof(struct action));
	action->type = ACTION_DROP;
	list_add_tail(&action->list, &actions->list);
	return RULE_SUCCESS;
}

int rule_parse_jump_expr(struct expr *expr, struct actions *actions)
{
	struct action	*action;
	action = xzalloc(sizeof(struct action));
	action->type = ACTION_JUMP;
	action->chain = xstrdup(expr->chain);
	list_add_tail(&action->list, &actions->list);
	return RULE_SUCCESS;
}

int rule_parse_verdict_stmt(struct stmt *stmt, struct rule_create_data *p)
{
	struct expr	*expr;
	expr = stmt->expr;
	switch (expr->verdict) {
	case NF_ACCEPT:
		return rule_parse_accept_expr(expr, p->actions);
	case NF_DROP:
		return rule_parse_drop_expr(expr, p->actions);
	case NFT_JUMP:
		return rule_parse_jump_expr(expr, p->actions);
	}
	return RULE_SUCCESS;
}

int rule_parse_counter_stmt(struct stmt *stmt, struct rule_create_data *p)
{
	struct action	*action;
	action = xzalloc(sizeof(struct action));
	action->type = ACTION_COUNTER;
	action->packets = stmt->counter.packets;
	action->bytes = stmt->counter.bytes;
	list_add_tail(&action->list, &p->actions->list);
	return RULE_SUCCESS;
}


int rule_parse_stmt(struct stmt *stmt, struct rule_create_data *p)
{
	switch (stmt->ops->type) {
	case STMT_EXPRESSION:
		return rule_parse_expr(stmt, p);
	case STMT_VERDICT:
		return rule_parse_verdict_stmt(stmt, p);
	case STMT_COUNTER:
		return rule_parse_counter_stmt(stmt, p);
	default:
		BUG("unknown statement type %s\n", stmt->ops->name);
	}
	return RULE_SUCCESS;
}

int rule_de_expressions(struct rule *rule, struct rule_create_data **data)
{
	int	res;
	struct  stmt	*stmt;
	struct rule_create_data *p;

	p = xmalloc(sizeof(struct rule_create_data));
	p->header = xmalloc(sizeof(struct pktheader));
	p->pktmeta = xmalloc(sizeof(struct pktmeta));
	p->loc = xzalloc(sizeof(struct location));
	p->actions = xzalloc(sizeof(struct actions));
	init_list_head(&p->actions->list);


	list_for_each_entry(stmt, &rule->stmts, list) {
		rule_parse_stmt(stmt, p);
	}
	*data = p;
	return RULE_SUCCESS;
}

int set_parse_expr(struct expr *expr, struct set_create_data *gui_set)
{
	int	size;
	char	*buf;
	struct elem_create_data	*elem;

	elem = xzalloc(sizeof(struct elem_create_data));
	elem->type = gui_set->keytype->type;
	size = expr_snprint(NULL, 0, expr);
	buf = xmalloc(size + 1);
	expr_snprint(buf, size + 1, expr);
	elem->key = buf;
	list_add_tail(&elem->list, &gui_set->elems);
	return SET_SUCCESS;
}

int set_de_expressions(struct set *set, struct set_create_data *gui_set)
{
	int	res;
	struct expr	*expr;

	list_for_each_entry(expr, &set->init->expressions, list) {
		set_parse_expr(expr, gui_set);
	}
	return SET_SUCCESS;
}
