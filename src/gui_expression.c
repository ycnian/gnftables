#include <gui_expression.h>
#include <gui_nftables.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <statement.h>
#include <proto.h>
#include <netlink.h>
#include <string.h>
#include <net/if.h>


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
	struct unsigned_short_elem	*convert;
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
		// bug: this works on in little-endian order.
		port_value = ((convert->value & 0xff) << 8) + ((convert->value >> 8) & 0xff);
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
	expr->ops->snprint(proto, 10, expr);
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
		size = expr->ops->snprint(NULL, 0, expr);
		buf = xzalloc(size + 1);
		addr->ip_type = ADDRESS_SUBNET;
		if (op == OP_EQ)
			addr->exclude = 0;
		else if (op == OP_NEQ)
			addr->exclude = 1;
		else
			BUG();
		expr->ops->snprint(buf, size + 1, expr);
		ip = strtok(buf, "/");
		addr->subnet_str.ip = xstrdup(ip);
		mask = strtok(NULL, "/");
		addr->subnet_str.mask = xstrdup(mask);
		xfree(buf);
	} else if (expr->ops->type == EXPR_VALUE) {
		int	size;
		addr->ip_type = ADDRESS_RANGE;
		switch (op) {
		case OP_LT:
			addr->exclude = 1;
			size = expr->ops->snprint(NULL, 0, expr);
			addr->range_str.from = xzalloc(size + 1);
			expr->ops->snprint(addr->range_str.from, size + 1, expr);
			break;
		case OP_GT:
			addr->exclude = 1;
			size = expr->ops->snprint(NULL, 0, expr);
			addr->range_str.to = xzalloc(size + 1);
			expr->ops->snprint(addr->range_str.to, size + 1, expr);
			break;
		case OP_LTE:
			addr->exclude = 0;
			size = expr->ops->snprint(NULL, 0, expr);
			addr->range_str.to = xzalloc(size + 1);
			expr->ops->snprint(addr->range_str.to, size + 1, expr);
			break;
		case OP_GTE:
			addr->exclude = 0;
			size = expr->ops->snprint(NULL, 0, expr);
			addr->range_str.from = xzalloc(size + 1);
			expr->ops->snprint(addr->range_str.from, size + 1, expr);
			break;
		default:
			BUG();
		}
	} else if (expr->ops->type == EXPR_SET_REF) {
		int	size = expr->ops->snprint(NULL, 0, expr);
		char	buf[size + 1];
		addr->ip_type = ADDRESS_EXACT;
		addr->iplist_str.ips = xzalloc(size - 2);
		expr->ops->snprint(buf, size + 1, expr);
		strncpy(addr->iplist_str.ips, buf + 2, size - 3);
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
			size = expr->ops->snprint(NULL, 0, expr);
			port->range_str.from = xzalloc(size + 1);
			expr->ops->snprint(port->range_str.from, size + 1, expr);
			break;
		case OP_GT:
			port->exclude = 1;
			size = expr->ops->snprint(NULL, 0, expr);
			port->range_str.to = xzalloc(size + 1);
			expr->ops->snprint(port->range_str.to, size + 1, expr);
			break;
		case OP_LTE:
			port->exclude = 0;
			size = expr->ops->snprint(NULL, 0, expr);
			port->range_str.to = xzalloc(size + 1);
			expr->ops->snprint(port->range_str.to, size + 1, expr);
			break;
		case OP_GTE:
			port->exclude = 0;
			size = expr->ops->snprint(NULL, 0, expr);
			port->range_str.from = xzalloc(size + 1);
			expr->ops->snprint(port->range_str.from, size + 1, expr);
			break;
		default:
			BUG();
		}
	} else if (expr->ops->type == EXPR_SET_REF) {
		int	size = expr->ops->snprint(NULL, 0, expr);
		char	buf[size + 1];
		port->port_type = PORT_EXACT;
		size = expr->ops->snprint(NULL, 0, expr);
		port->portlist_str.ports = xzalloc(size - 2);
		expr->ops->snprint(buf, size + 1, expr);
		strncpy(port->portlist_str.ports, buf + 2, size - 3);
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
	int	len = expr->ops->snprint(NULL, 0, expr);
	char	p[len + 1];

	ifname->name_str = xzalloc(len - 1);
	expr->ops->snprint(p, len + 1, expr);
	strncpy(ifname->name_str, p + 1, len - 2);
	return RULE_SUCCESS;
}

static int rule_parse_iftype_expr(struct expr *expr, union iftype *iftype)
{
	int	len = expr->ops->snprint(NULL, 0, expr);
	char	p[len + 1];

	iftype->type_str = xzalloc(len - 2);
	expr->ops->snprint(p, len + 1, expr);
	strncpy(iftype->type_str, p + 2, len - 3);
	return RULE_SUCCESS;
}

static int rule_parse_skuid_expr(struct expr *expr, union skid *uid)
{
	int	len = expr->ops->snprint(NULL, 0, expr);
	char	p[len + 1];

	uid->id_str = xzalloc(len - 2);
	expr->ops->snprint(p, len + 1, expr);
	strncpy(uid->id_str, p + 2, len - 3);

	return RULE_SUCCESS;
}

static int rule_parse_skgid_expr(struct expr *expr, union skid *gid)
{
	int	len = expr->ops->snprint(NULL, 0, expr);
	char	p[len + 1];

	gid->id_str = xzalloc(len - 2);
	expr->ops->snprint(p, len + 1, expr);
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
