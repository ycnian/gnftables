#include <gui_expression.h>
#include <gui_nftables.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <statement.h>
#include <proto.h>


int rule_addrlist_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{
	struct expr  *payload;
	struct expr  *constant;
	struct expr *rela;
	struct stmt *stmt;
	unsigned int	type;
	enum ops	op;

	if (list_empty(&(addr->iplist.ips)))
		return RULE_SUCCESS;

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	payload = payload_expr_alloc(data->loc, &proto_ip, type);
	constant = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
			4 * 8, list_first_entry(&(addr->iplist.ips), struct ip_convert, list)->ip);
	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, constant);
	rela->op = op;
	stmt = expr_stmt_alloc(data->loc, rela);
	list_add_tail(&stmt->list, &data->exprs);

	return RULE_SUCCESS;
}

int rule_addrsubnet_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source)
{

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

	if (list_empty(&(addr->iplist.ips)))
		return RULE_SUCCESS;

	type = source ? IPHDR_SADDR: IPHDR_DADDR;
	op = (addr->exclude) ? OP_NEQ: OP_EQ;
	payload = payload_expr_alloc(data->loc, &proto_ip, type);

	left = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
			4 * 8, addr->range.from);
	right = constant_expr_alloc(data->loc, &ipaddr_type, BYTEORDER_BIG_ENDIAN,
			4 * 8, addr->range.to);
	range = range_expr_alloc(data->loc, left, right);

	rela = relational_expr_alloc(data->loc, OP_IMPLICIT, payload, range);
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
