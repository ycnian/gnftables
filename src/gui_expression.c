#include <gui_expression.h>
#include <gui_nftables.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <statement.h>
#include <proto.h>
#include <netlink.h>
#include <string.h>


int rule_addrlist_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	struct expr  *payload;
	struct expr  *constant;
	struct expr  *rela;
	struct expr  *elem;
	struct expr  *se;
	struct stmt  *stmt;
	struct set   *set;
	unsigned int	type;
	enum ops	op;
	struct ip_convert	*convert;

	if (list_empty(&(addr->iplist.ips)))
		return RULE_SUCCESS;

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
//	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	op = OP_LOOKUP;
	payload = payload_expr_alloc(data->loc, &proto_ip, type);
	elem = set_expr_alloc(data->loc);

	list_for_each_entry(convert, &(addr->iplist.ips), list) {
		constant = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
			4 * 8, convert->ip);
		compound_expr_add(elem, constant);
	}

	set = set_alloc(data->loc);
        set->flags	= SET_F_CONSTANT | SET_F_ANONYMOUS;
        set->handle.set = xstrdup("set%d");
        set->keytype    = &ipaddr_type;
        set->keylen     = 4 * 8;
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

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, se);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_addrsubnet_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	struct expr  *payload;
	struct expr  *constant;
	struct expr  *prefix;
	struct expr *rela;
	struct stmt *stmt;
	unsigned int	type;
	enum ops	op;
	unsigned char   ip[4];
	int	mask;
	int	i;
	memcpy(ip, addr->subnet.ip, 4);
	mask = addr->subnet.mask;

	for (i = 0; i < 4; i++) {
		if (mask < 0)
			ip[i] = 0;
		else if (mask < 8) {
			ip[i] = (ip[i] & ((-1 << (8-mask)) & 0xff));
		}
		mask -= 8;
	}

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	payload = payload_expr_alloc(data->loc, &proto_ip, type);
	constant = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
			4 * 8, ip);
	prefix = prefix_expr_alloc(data->loc, constant, addr->subnet.mask);
	prefix->byteorder = BYTEORDER_BIG_ENDIAN;
	prefix->len = 4 * 8;
	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, prefix);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_addrrange_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	struct expr  *payload;
	struct expr  *left;
	struct expr  *right;
	struct expr  *range;
	struct expr  *rela;
	struct stmt  *stmt;
	unsigned int	type;
	enum ops	op;
	unsigned int	from = *(unsigned int *)(addr->range.from);
	unsigned int	to = *(unsigned int *)(addr->range.to);

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
	payload = payload_expr_alloc(data->loc, &proto_ip, type);

	if (from && to) {
		op = (addr->exclude) ? OP_NEQ : OP_EQ;
		left = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
				4 * 8, addr->range.from);
		right = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
				4 * 8, addr->range.to);
		range = range_expr_alloc(data->loc, left, right);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, range);
		rela->op = op;
	} else if (from) {
		op = (addr->exclude) ? OP_LT : OP_GTE;
		left = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
				4 * 8, addr->range.from);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, left);
		rela->op = op;
	} else if (to) {
		op = (addr->exclude) ? OP_GT : OP_LTE;
		right = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
				4 * 8, addr->range.to);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, right);
		rela->op = op;
	} else
		return RULE_SUCCESS;

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
		break;
	default:
		break;
	}

	return res;
}

int rule_portlist_gen_exprs(struct rule_create_data *data,
		struct trans_port_data *port)
{

	return RULE_SUCCESS;
}

int rule_portrange_gen_exprs(struct rule_create_data *data,
		struct trans_port_data *port)
{

	return RULE_SUCCESS;
}

int rule_port_gen_exprs(struct rule_create_data *data, struct trans_port_data *port)
{
	enum port_type	port_type;
	int	res = RULE_SUCCESS;

	port_type = port->port_type;
	switch (port_type) {
	case PORT_EXACT:
		res = rule_portlist_gen_exprs(data, port);
		break;
	case PORT_RANGE:
		res = rule_portrange_gen_exprs(data, port);
		break;
	case PORT_SET:
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

int rule_transtcp_gen_exprs(struct rule_create_data *data, struct trans_tcp_data *tcp)
{
	int	res = RULE_SUCCESS;

	// res = rule_ip_tcp_expr(data);
	// if (res == RULE_SUCCESS)
	// 	return res;
	res = rule_port_gen_exprs(data, tcp->sport);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_port_gen_exprs(data, tcp->dport);

	return res;
}

int rule_transudp_gen_exprs(struct rule_create_data *data, struct trans_udp_data *udp)
{
	int	res = RULE_SUCCESS;

	// res = rule_ip_udp_expr(data);
	// if (res == RULE_SUCCESS)
	// 	return res;
	res = rule_port_gen_exprs(data, udp->sport);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_port_gen_exprs(data, udp->dport);

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
		res = rule_transtcp_gen_exprs(data, trans->tcp);
		break;
	case TRANSPORT_UDP:
		res = rule_ip_upper_expr(data, type);
		if (res != RULE_SUCCESS)
			break;
		res = rule_transudp_gen_exprs(data, trans->udp);
		break;
	default:
		break;
	}

	return res;
}


int rule_header_gen_exprs(struct rule_create_data *data, struct header *header)
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

int rule_pktmeta_gen_exprs(struct rule_create_data *data, struct pktmeta *pktmeta)
{

	return RULE_SUCCESS;
}

int rule_counter_gen_exprs(struct rule_create_data *data)
{
	struct stmt *stmt;
	stmt = counter_stmt_alloc(data->loc);
	stmt->counter.packets = 0;
	stmt->counter.bytes = 0;
	list_add_tail(&stmt->list, &data->exprs);

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
	res = rule_counter_gen_exprs(data);
	return res;
}
