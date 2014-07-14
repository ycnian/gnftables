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
		struct trans_port_data *port, enum transport_type type, int source)
{
	struct expr  *payload;
	struct expr  *constant;
	struct expr  *rela;
	struct expr  *elem;
	struct expr  *se;
	struct stmt  *stmt;
	struct set   *set;
	unsigned int	sport;
	const struct proto_desc *desc;
	enum ops	op;
	struct port_convert	*convert;
	unsigned short	port_value;

	if (list_empty(&(port->portlist.ports)))
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

	list_for_each_entry(convert, &(port->portlist.ports), list) {
		port_value = ((convert->port & 0xff) << 8) + ((convert->port >> 8) & 0xff);
		constant = constant_expr_alloc(data->loc, &inet_service_type, BYTEORDER_BIG_ENDIAN,
				2 * 8, &port_value);
		compound_expr_add(elem, constant);
	}

	set = set_alloc(data->loc);
        set->flags	= SET_F_CONSTANT | SET_F_ANONYMOUS;
        set->handle.set = xstrdup("set%d");
        set->keytype    = &inet_service_type;
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

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, se);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_portrange_gen_exprs(struct rule_create_data *data,
		struct trans_port_data *port, enum transport_type type, int source)
{
	struct expr  *payload;
	struct expr  *left;
	struct expr  *right;
	struct expr  *range;
	struct expr  *rela;
	struct stmt  *stmt;
	unsigned int	sport;
	const struct proto_desc *desc;
	enum ops	op;
	unsigned short	from = port->range.from;
	unsigned short	to = port->range.to;
	from = ((from & 0xff) << 8) + ((from >> 8) & 0xff);
	to = ((to & 0xff) << 8) + ((to >> 8) & 0xff);

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
		left = constant_expr_alloc(data->loc, &inet_service_type, BYTEORDER_BIG_ENDIAN,
				2 * 8, &from);
		right = constant_expr_alloc(data->loc, &inet_service_type, BYTEORDER_BIG_ENDIAN,
				2 * 8, &to);
		range = range_expr_alloc(data->loc, left, right);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, range);
		rela->op = op;
	} else if (from) {
		op = (port->exclude) ? OP_LT : OP_GTE;
		left = constant_expr_alloc(data->loc, &inet_service_type, BYTEORDER_BIG_ENDIAN,
				2 * 8, &from);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, left);
		rela->op = op;
	} else if (to) {
		op = (port->exclude) ? OP_GT : OP_LTE;
		right = constant_expr_alloc(data->loc, &inet_service_type, BYTEORDER_BIG_ENDIAN,
				2 * 8, &to);
		rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, right);
		rela->op = op;
	} else
		return RULE_SUCCESS;

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

struct header_parse{
	const char	*name;
	int		(*parse)(struct expr *expr, struct header *header);
};

struct header_parse header_ip_parsers[IPHDR_DADDR + 1] = {
	{ .name = "invalid",	.parse = NULL},
	{ .name = "version",	.parse = NULL},
	{ .name = "hdrlength",	.parse = NULL},
	{ .name = "tos",	.parse = NULL},
	{ .name = "length",	.parse = NULL},
	{ .name = "id",	.parse = NULL},
	{ .name = "frag-off",	.parse = NULL},
	{ .name = "ttl",	.parse = NULL},
	{ .name = "protocol",	.parse = rule_parse_ip_protocol_expr},
	{ .name = "checksum",	.parse = NULL},
	{ .name = "saddr",	.parse = rule_parse_ip_saddr_expr},
	{ .name = "daddr",	.parse = rule_parse_ip_daddr_expr},
};

int rule_parse_ip_protocol_expr(struct expr *expr, struct header *header)
{

	return RULE_SUCCESS;
}

int rule_parse_ip_saddr_expr(struct expr *expr, struct header *header)
{
	return RULE_SUCCESS;
}

int rule_parse_ip_daddr_expr(struct expr *expr, struct header *header)
{
	return RULE_SUCCESS;
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

int rule_parse_tcp_sport_expr(struct expr *expr, struct header *header)
{

	return RULE_SUCCESS;
}

int rule_parse_tcp_dport_expr(struct expr *expr, struct header *header)
{

	return RULE_SUCCESS;
}

struct header_parse header_udp_parsers[UDPHDR_CHECKSUM + 1] = {
	{ .name = "invalid",	.parse = NULL},
	{ .name = "sport",	.parse = rule_parse_udp_sport_expr},
	{ .name = "dport",	.parse = rule_parse_udp_dport_expr},
	{ .name = "length",	.parse = NULL},
	{ .name = "csumcov",	.parse = NULL},
	{ .name = "checksum",	.parse = NULL},
};

int rule_parse_udp_sport_expr(struct expr *expr, struct header *header)
{

	return RULE_SUCCESS;
}

int rule_parse_udp_dport_expr(struct expr *expr, struct header *header)
{

	return RULE_SUCCESS;
}


int rule_parse_header_expr(struct expr *expr, struct header *header)
{
	struct expr  *left;
	struct expr  *right;
	struct proto_desc   *desc;
	struct proto_hdr_template *tmpl;
	struct header_parse	*parse;
	int	total = 0;
	int	i = 0;

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
		parse[i].parse(right, header);
		return RULE_SUCCESS;
	}
	return RULE_SUCCESS;
}

int rule_parse_pktmeta(struct expr *expr, struct pktmeta *pktmeta)
{

	return RULE_SUCCESS;
}

int rule_parse_expr(struct stmt *stmt, struct rule_create_data *p)
{
	struct  expr	*expr;
	struct  expr	*left;
	const struct proto_desc  *desc;

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

int rule_parse_verdict_stmt(struct stmt *stmt, struct rule_create_data *p)
{

	return RULE_SUCCESS;
}

int rule_parse_counter_stmt(struct stmt *stmt, struct rule_create_data *p)
{

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
	p->header = xmalloc(sizeof(struct header));
	p->pktmeta = xmalloc(sizeof(struct pktmeta));
	init_list_head(&p->exprs);
	p->header->saddr = xmalloc(sizeof(struct ip_addr_data));
	p->header->daddr = xmalloc(sizeof(struct ip_addr_data));
	p->header->transport_data = xmalloc(sizeof(struct transport_data));
	init_list_head(&p->header->saddr->iplist.ips);
	init_list_head(&p->header->daddr->iplist.ips);
	p->loc = xzalloc(sizeof(struct location));

	list_for_each_entry(stmt, &rule->stmts, list) {
		rule_parse_stmt(stmt, p);
	}


	return RULE_SUCCESS;
}
