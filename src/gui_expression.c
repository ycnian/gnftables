#include <gui_expression.h>
#include <gui_nftables.h>
#include <gui_rule.h>
#include <gui_error.h>


int rule_addrlist_gen_exprs(struct list_head *head, struct ip_addr_data *addr)
{

	return RULE_SUCCESS;
}

int rule_addrsubnet_gen_exprs(struct list_head *head, struct ip_addr_data *addr)
{

	return RULE_SUCCESS;
}

int rule_addrrange_gen_exprs(struct list_head *head, struct ip_addr_data *addr)
{

	return RULE_SUCCESS;
}


int rule_addr_gen_exprs(struct list_head *head, struct ip_addr_data *addr)
{
	enum address_type	ip_type;
	int	res = RULE_SUCCESS;

	ip_type = addr->ip_type;
	switch (ip_type) {
	case ADDRESS_EXACT:
		res = rule_addrlist_gen_exprs(head, addr);
		break;
	case ADDRESS_SUBNET:
		res = rule_addrsubnet_gen_exprs(head, addr);
		break;
	case ADDRESS_RANGE:
		res = rule_addrrange_gen_exprs(head, addr);
		break;
	case ADDRESS_SET:
		break;
	default:
		break;
	}

	return res;
}

int rule_portlist_gen_exprs(struct list_head *head,
		struct trans_port_data *port)
{

	return RULE_SUCCESS;
}

int rule_portrange_gen_exprs(struct list_head *head,
		struct trans_port_data *port)
{

	return RULE_SUCCESS;
}

int rule_port_gen_exprs(struct list_head *head, struct trans_port_data *port)
{
	enum port_type	port_type;
	int	res = RULE_SUCCESS;

	port_type = port->port_type;
	switch (port_type) {
	case PORT_EXACT:
		res = rule_portlist_gen_exprs(head, port);
		break;
	case PORT_RANGE:
		res = rule_portrange_gen_exprs(head, port);
		break;
	case PORT_SET:
		break;
	default:
		break;
	}

	return res;

}

int rule_transall_gen_exprs(struct list_head *head, struct trans_all_data *data)
{

	return RULE_SUCCESS;
}

int rule_transtcp_gen_exprs(struct list_head *head, struct trans_tcp_data *data)
{
	int	res = RULE_SUCCESS;

	// res = rule_ip_tcp_expr(head);
	// if (res == RULE_SUCCESS)
	// 	return res;
	res = rule_port_gen_exprs(head, data->sport);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_port_gen_exprs(head, data->dport);

	return res;
}

int rule_transudp_gen_exprs(struct list_head *head, struct trans_udp_data *data)
{
	int	res = RULE_SUCCESS;

	// res = rule_ip_udp_expr(head);
	// if (res == RULE_SUCCESS)
	// 	return res;
	res = rule_port_gen_exprs(head, data->sport);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_port_gen_exprs(head, data->dport);

	return res;

}

int rule_trans_gen_exprs(struct list_head *head, struct transport_data *trans)
{
	enum transport_type	type;
	int	res = RULE_SUCCESS;

	type = trans->trans_type;
	switch (type) {
	case TRANSPORT_ALL:
		res = rule_transall_gen_exprs(head, trans->all);
		break;
	case TRANSPORT_TCP:
		res = rule_transtcp_gen_exprs(head, trans->tcp);
		break;
	case TRANSPORT_UDP:
		res = rule_transudp_gen_exprs(head, trans->udp);
		break;
	default:
		break;
	}

	return res;
}


int rule_header_gen_exprs(struct list_head *head, struct header *header)
{
	int	res = RULE_SUCCESS;

	res = rule_addr_gen_exprs(head, header->saddr);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_addr_gen_exprs(head, header->daddr);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_trans_gen_exprs(head, header->transport_data);

	return res;
}

int rule_pktmeta_gen_exprs(struct list_head *head, struct pktmeta *pktmeta)
{

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
	res = rule_header_gen_exprs(&data->exprs, data->header);
	if (res != RULE_SUCCESS)
		return res;
	res = rule_pktmeta_gen_exprs(&data->exprs, data->pktmeta);

	return res;
}
