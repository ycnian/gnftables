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

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>

#include <utils.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <gui_datacheck.h>
#include <gui_nftables.h>
#include <gui_expression.h>


char *string_skip_space(char *str)
{
	int	start = 0;
	char	*p;
	int	end;

	if (string_is_null(str))
		return NULL;
	end = strlen(str) - 1;
	while (isblank(str[start]))
		start++;
	while (isblank(str[end]))
		end--;
	p = xstrndup(str + start, end - start + 1);
	return p;
}

/*
 * Get data from gtk page. Skipe spaces at begin or end of data.
 * If entry is NULL or only contains spaces, return NULL.
 * @entry: gtk entry.
 */
char *get_data_from_entry(GtkEntry *entry)
{
	int	start = 0;
	int	end;
	char	*p;
        char	*data = (char *)gtk_entry_get_text(entry);

	if (string_is_null(data))
		return NULL;
	end = strlen(data) - 1;
	while (isblank(data[start]))
		start++;
	while (isblank(data[end]))
		end--;
	p = xstrndup(data + start, end - start + 1);
	return p;
}

/*
 * Check name, only letter, number, underscore allowed.
 * @name:  a string to be checked
 * Return Value:
 * 	0:  name is valid
 * 	-1: name contains invalid character
 */
int name_check(char *name)
{
	int	i;
	int	len = strlen(name);

	for (i = 0; i < len; i++) {
		if ((name[i] != '_') && !(isalnum(name[i])))
			return -1;
	}
	return 0;
}


/*
 * Check integer, only +, -, 0-9 allowed.
 * Skipe spaces at the start and end of integer.
 * @integer:  a string to be checked
 * Return Value:
 * 	0:  integer is valid
 * 	-1: integer is not valid
 */
int integer_check(char *integer)
{
	int	i = 0;
	int	j;
	int	len = strlen(integer);
	if (len == 0)
		return 0;

	while (isblank(integer[i]))
		i++;
	if (i == len)
		return 0;
	if ((integer[i] != '+') && (integer[i] != '-') && !isdigit(integer[i]))
		return -1;
	for (j = i + 1; j < len; j++) {
		if (isblank(integer[j]))
			break;
		if (!isdigit(integer[j]))
			return -1;
	}
	for (i = j + 1; i < len; i++) {
		if (!isblank(integer[i]))
			return -1;
	}
	return 0;
}


/*
 * Check positive integer, 0-9 allowed.
 * Skipe spaces at the start and end of integer.
 * @integer:  a string to be checked
 * Return Value:
 * 	0:  integer is valid
 * 	-1: integer is not valid
 */
int unsigned_int_check(char *integer)
{
	int	i = 0;
	int	j;
	int	len = strlen(integer);

	if (len == 0)
		return 0;

	while (isblank(integer[i]))
		i++;
	if (i == len)
		return 0;
	for (j = i + 1; j < len; j++) {
		if (isblank(integer[j]))
			break;
		if (!isdigit(integer[j]))
			return -1;
	}
	for (i = j + 1; i < len; i++) {
		if (!isblank(integer[i]))
			return -1;
	}
	return 0;
}

/*
 * Get data from page, and check it
 * @widget:  widgets containing data in table creating
 */
int table_create_getdata(struct table_submit_argsnnn  *widget,
		struct table_create_data **data)
{
	int	res;
	char	*name;
	int		family;
	GtkTreeModel    *model;
	GtkTreeIter     iter;
	struct table_create_data *p = NULL;

	name = get_data_from_entry(GTK_ENTRY(widget->name));
	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget->family));
	gtk_combo_box_get_active_iter(GTK_COMBO_BOX(widget->family), &iter);
	gtk_tree_model_get(model, &iter, 0, &family, -1);
	if (!name)
		return TABLE_NAME_EMPTY;

	res = name_check(name);
	if (res == -1) {
		xfree(name);
		return TABLE_NAME_INVALID;
	}

	p = xzalloc(sizeof(struct table_create_data));
	p->table = name;
	p->family = family;
	*data = p;
	return TABLE_SUCCESS;
}

/*
 * Check chain priority. This function needs enhancement.
 * We must make sure the priority isn't overflow.
 * @priority: chain priority in string format.
 */
int chain_priority_check(char *priority)
{
	return integer_check(priority);
}

/*
 * Get data from page, and check it
 * @widget:  widgets containing data in chain creating
 */
int chain_create_getdata(struct chain_submit_argsnnn  *widget,
		struct chain_create_data **data)
{
	int	res;
	char	*name;
	int	basechain;
	char	*type;
	const char	*hook_str;
	int	priority;
	int	hook;
	char	*priority_str = NULL;
	struct chain_create_data *p = NULL;

	name = get_data_from_entry(GTK_ENTRY(widget->name));
	if (!name)
		return CHAIN_NAME_EMPTY;
	basechain = !!gtk_toggle_button_get_active(
			GTK_TOGGLE_BUTTON(widget->basechain));
	if (basechain) {
		type = gtk_combo_box_text_get_active_text(
			GTK_COMBO_BOX_TEXT(widget->type));
		hook_str = (const char *)gtk_combo_box_text_get_active_text(
			GTK_COMBO_BOX_TEXT(widget->hook));
		hook = str2hooknum(widget->family, hook_str);
		priority_str = get_data_from_entry(
			GTK_ENTRY(widget->priority));
	}

	res = name_check(name);
	if (res == -1) {
		xfree(name);
		return CHAIN_NAME_INVALID;
	}

	if (basechain && priority_str) {
		res = chain_priority_check(priority_str);
		if (res != 0) {
			xfree(name);
			xfree(priority_str);
			return CHAIN_PRIORITY_INVALID;
		}
	}

	p = xzalloc(sizeof (struct chain_create_data));
	p->family = widget->family;
	p->table = xstrdup(widget->table);
	p->chain = name;
	if (basechain) {
		p->basechain = 1;
		p->type = xstrdup(type);
		p->hook = hook;
		if (priority_str) {
			res = strtoint(priority_str, &priority);
			if (res == -1) {
				xfree(name);
				xfree(priority_str);
				return CHAIN_PRIORITY_OVERFLOW;
			} else
				p->priority = priority;
		}
		else
			p->priority = 0;
	} else {
		p->basechain = 0;
		p->type = NULL;
	}

	*data = p;
	xfree(priority_str);
	return CHAIN_SUCCESS;
}

/*
 * Check whether a string is empty or contains only space.
 */
int string_is_null(char *str)
{
	int	i = 0;
	int	len;

	if (!str)
		return 1;
	len = strlen(str);
	for (i = 0; i < len; i++) {
		if (!isblank(str[i]))
			return 0;
	}
	return 1;
}

/*
 * Get ip address information from rule creating page. It's maybe ip address
 * list or a subnet or an ip address range.
 * 
 */
int get_header_addr_from_page(struct ip_address  *widget,
		struct ip_addr_data *data)
{
	int	res = RULE_SUCCESS;
	data->ip_type = widget->type;
	data->exclude = widget->exclude;
	switch (widget->type) {
	case ADDRESS_EXACT:
		data->iplist = get_data_from_entry(
			GTK_ENTRY(widget->exact_ip.ip));
		break;
	case ADDRESS_SUBNET:
		data->subnet.ip = get_data_from_entry(
			GTK_ENTRY(widget->subnet.ip));
		data->subnet.mask = get_data_from_entry(
			GTK_ENTRY(widget->subnet.mask));
		if (data->subnet.ip && !data->subnet.mask)
			res = RULE_HEADER_MASK_EMPTY;
		if (!data->subnet.ip && data->subnet.mask)
			res = RULE_HEADER_IP_EMPTY;
		break;
	case ADDRESS_RANGE:
		data->range.from = get_data_from_entry(
			GTK_ENTRY(widget->range.from));
		data->range.to = get_data_from_entry(
			GTK_ENTRY(widget->range.to));
		break;
	case ADDRESS_SET:
		data->set = gtk_combo_box_text_get_active_text(
			GTK_COMBO_BOX_TEXT(widget->sets.set));
		if (!data->set)
			res = RULE_HEADER_SET_EMPTY;
		break;
	default:
		break;
	}

	return res;
}


/*
 * Get port information from rule creating page. It's maybe a port list or
 * port range.
 *
 */
int get_header_port_from_page(struct transport_port_info *widget,
		struct trans_port_data *data)
{
	int	res = RULE_SUCCESS;
	data->port_type = widget->value->type;
	data->exclude = widget->value->exclude;
	switch (widget->value->type) {
	case PORT_EXACT:
		data->portlist = get_data_from_entry(
			GTK_ENTRY(widget->value->portlist.port));
		break;
	case PORT_RANGE:
		data->range.from = get_data_from_entry(
			GTK_ENTRY(widget->value->range.from));
		data->range.to = get_data_from_entry(
			GTK_ENTRY(widget->value->range.to));
		break;
	case PORT_SET:
		data->set = gtk_combo_box_text_get_active_text(
			GTK_COMBO_BOX_TEXT(widget->value->sets.set));
		if (!data->set)
			res = RULE_HEADER_SET_EMPTY;
		break;
	default:
		break;
	}

	return res;
}

/*
 * If transport protocol is "all", this function will be runned.
 * "all" means matching packets no natter what tranport protocol it using.
 */
int get_header_transall_from_page(struct transport_all *widget,
		struct trans_all_data *data)
{

	return RULE_SUCCESS;
}


/*
 * Get TCP information from rule creating page. Currently, we only get
 * source port and destination port.
 */
int get_header_transtcp_from_page(struct transport_tcp *widget,
		struct trans_tcp_data *data)
{
	int	res;
	data->protocol = IPPROTO_TCP;
	data->sport = xmalloc(sizeof(struct trans_port_data));
	res = get_header_port_from_page(widget->sport, data->sport);
	if (res != RULE_SUCCESS)
		return res;
	data->dport = xmalloc(sizeof(struct trans_port_data));
	res = get_header_port_from_page(widget->dport, data->dport);
	return res;
}


/*
 * Get UDP information from rule creating page. Currently, we only get
 * source port and destination port.
 */
int get_header_transudp_from_page(struct transport_udp *widget,
		struct trans_udp_data *data)
{
	int	res;
	data->protocol = IPPROTO_UDP;
	data->sport = xmalloc(sizeof(struct trans_port_data));
	res = get_header_port_from_page(widget->sport, data->sport);
	if (res != RULE_SUCCESS)
		return res;
	data->dport = xmalloc(sizeof(struct trans_port_data));
	res = get_header_port_from_page(widget->dport, data->dport);
	return res;
}


/*
 * Get transport protocol information from rule creating page.
 */
int get_header_trans_from_page(struct transport_info *widget,
		struct transport_data *data)
{
	enum transport_type     type;
	int  res = RULE_SUCCESS;

	type = widget->type;
	data->trans_type = type;
	switch (type) {
	case TRANSPORT_ALL:
		res = get_header_transall_from_page(widget->all, data->all);
		break;
	case TRANSPORT_TCP:
		data->tcp = xmalloc(sizeof(struct trans_tcp_data));
		res = get_header_transtcp_from_page(widget->tcp, data->tcp);
		break;
	case TRANSPORT_UDP:
		data->udp = xmalloc(sizeof(struct trans_udp_data));
		res = get_header_transudp_from_page(widget->udp, data->udp);
		break;
	default:
		break;
	}
	return res;
}


/*
 * Get packet header informations from rule creating page, includeing
 * networking layer and transport layer.
 *
 */
int get_header_data_from_page(struct match_header *widget,
				struct pktheader *data)
{
	int	res;

	if (data->saddr)
		data->saddr = xzalloc(sizeof(struct ip_addr_data));
	res = get_header_addr_from_page(widget->saddr.value, data->saddr);
	if (res != RULE_SUCCESS)
		return res;
	if (data->daddr)
		data->daddr = xzalloc(sizeof(struct ip_addr_data));
	res = get_header_addr_from_page(widget->daddr.value, data->daddr);
	if (res != RULE_SUCCESS)
		return res;
	if (data->transport_data)
		data->transport_data = xzalloc(sizeof(struct transport_data));
	res = get_header_trans_from_page(
			widget->transport.value, data->transport_data);
	return res;
}

int get_pktmeta_ifname_from_page(GtkWidget *ifname, struct  list_head *list)
{
	char	*names;
	char	*name;
	struct  string_elem  *elem;

	names = get_data_from_entry(GTK_ENTRY(ifname));
	if (!names)
		return RULE_SUCCESS;
	name = string_skip_space(strtok(names, ","));
	while (name) {
		elem  = xzalloc(sizeof(struct string_elem));
		elem->value = name;
		list_add_tail(&elem->list, list);
		name = string_skip_space(strtok(NULL, ","));
	}
	xfree(names);
	return RULE_SUCCESS;
}

int pktmeta_iftype_check(char *type, unsigned short *value)
{
	if (!(strcmp(type, "ether"))) {
		*value = ARPHRD_ETHER;
		return RULE_SUCCESS;
	} else if (!(strcmp(type, "ppp"))) {
		*value = ARPHRD_PPP;
		return RULE_SUCCESS;
	} else if (!(strcmp(type, "ipip"))) {
		*value = ARPHRD_TUNNEL;
		return RULE_SUCCESS;
	} else if (!(strcmp(type, "ipip6"))) {
		*value = ARPHRD_TUNNEL;
		return RULE_SUCCESS;
	} else if (!(strcmp(type, "lookback"))) {
		*value = ARPHRD_LOOPBACK;
		return RULE_SUCCESS;
	} else if (!(strcmp(type, "sit"))) {
		*value = ARPHRD_SIT;
		return RULE_SUCCESS;
	} else if (!(strcmp(type, "ipgre"))) {
		*value = ARPHRD_IPGRE;
		return RULE_SUCCESS;
	} else
		return RULE_PKTMETA_IFTYPE_INVALID;
}

int get_pktmeta_iftype_from_page(GtkWidget *iftype, struct  list_head *list)
{
	int	res = RULE_SUCCESS;
	char	*types;
	char	*type;
	unsigned short type_value;
	struct  unsigned_short_elem  *elem;

	types = get_data_from_entry(GTK_ENTRY(iftype));
	if(!types)
		return RULE_SUCCESS;
	type = string_skip_space(strtok(types, ","));
	while (type) {
		res = pktmeta_iftype_check(type, &type_value);
		if (res != RULE_SUCCESS) {
			xfree(type);
			goto error;
		}
		xfree(type);
		elem  = xzalloc(sizeof(struct unsigned_short_elem));
		elem->value = type_value;
		list_add_tail(&elem->list, list);
		type = string_skip_space(strtok(NULL, ","));
	}
error:
	xfree(types);
	return res;
}

int get_pktmeta_skid_from_page(GtkWidget *skid, struct  list_head *list)
{
	int	res = RULE_SUCCESS;
	char	*ids;
	char	*id;
	unsigned int id_value;
	struct  unsigned_int_elem  *elem;

	ids = get_data_from_entry(GTK_ENTRY(skid));
	if (!ids)
		return RULE_SUCCESS;
	id = string_skip_space(strtok(ids, ","));
	while (id) {
		res = strtouint(id, &id_value);
		if (res != RULE_SUCCESS) {
			res = RULE_PKTMETA_SKID_INVALID;
			xfree(id);
			goto error;
		}
		xfree(id);
		elem  = xzalloc(sizeof(struct unsigned_int_elem));
		elem->value = id_value;
		list_add_tail(&elem->list, list);
		id = string_skip_space(strtok(NULL, ","));
	}
error:
	xfree(ids);
	return res;
}

int get_pktmeta_iifname_from_page(GtkWidget *iifname, struct pktmeta *data)
{
	int	res;

	data->iifname = xzalloc(sizeof(union ifname));
	init_list_head(&data->iifname->name);
	res = get_pktmeta_ifname_from_page(iifname, &data->iifname->name);
	return res;
}

int get_pktmeta_oifname_from_page(GtkWidget *oifname, struct pktmeta *data)
{
	int	res;

	data->oifname = xzalloc(sizeof(union ifname));
	init_list_head(&data->oifname->name);
	res = get_pktmeta_ifname_from_page(oifname, &data->oifname->name);
	return res;
}

int get_pktmeta_iiftype_from_page(GtkWidget *iiftype, struct pktmeta *data)
{
	int	res;

	data->iiftype = xzalloc(sizeof(union iftype));
	init_list_head(&data->iiftype->type);
	res = get_pktmeta_iftype_from_page(iiftype, &data->iiftype->type);
	if (res == RULE_PKTMETA_IFTYPE_INVALID)
		res = RULE_PKTMETA_IIFTYPE_INVALID;
	return res;
}

int get_pktmeta_oiftype_from_page(GtkWidget *oiftype, struct pktmeta *data)
{
	int	res;

	data->oiftype = xzalloc(sizeof(union iftype));
	init_list_head(&data->oiftype->type);
	res = get_pktmeta_iftype_from_page(oiftype, &data->oiftype->type);
	if (res == RULE_PKTMETA_IFTYPE_INVALID)
		res = RULE_PKTMETA_OIFTYPE_INVALID;
	return res;
}

int get_pktmeta_skuid_from_page(GtkWidget *skuid, struct pktmeta *data)
{
	int	res;

	data->skuid = xzalloc(sizeof(union skid));
	init_list_head(&data->skuid->id);
	res = get_pktmeta_skid_from_page(skuid, &data->skuid->id);
	if (res == RULE_PKTMETA_SKID_INVALID)
		res = RULE_PKTMETA_SKUID_INVALID;
	return res;
}

int get_pktmeta_skgid_from_page(GtkWidget *skgid, struct pktmeta *data)
{
	int	res;

	data->skgid = xzalloc(sizeof(union skid));
	init_list_head(&data->skgid->id);
	res = get_pktmeta_skid_from_page(skgid, &data->skgid->id);
	if (res == RULE_PKTMETA_SKID_INVALID)
		res = RULE_PKTMETA_SKGID_INVALID;
	return res;
}

/*
 * Get packet metainformations from rule creating page.
 */
int get_pktmeta_data_from_page(struct match_pktmeta  *widget,
		struct pktmeta *data)
{
	int	res;

	res = get_pktmeta_iifname_from_page(widget->iifname, data);
	if (res != RULE_SUCCESS)
		return res;
	res = get_pktmeta_oifname_from_page(widget->oifname, data);
	if (res != RULE_SUCCESS)
		return res;
	res = get_pktmeta_iiftype_from_page(widget->iiftype, data);
	if (res != RULE_SUCCESS)
		return res;
	res = get_pktmeta_oiftype_from_page(widget->oiftype, data);
	if (res != RULE_SUCCESS)
		return res;
	res = get_pktmeta_skuid_from_page(widget->skuid, data);
	if (res != RULE_SUCCESS)
		return res;
	res = get_pktmeta_skgid_from_page(widget->skgid, data);
	return res;
}

int get_accept_data_from_page(struct action_elem *elem, struct actions *data)
{
	struct action *action;
	action = xzalloc(sizeof(struct action));
	action->type = ACTION_ACCEPT;
	list_add_tail(&action->list, &data->list);
	return RULE_SUCCESS;
}

int get_drop_data_from_page(struct action_elem *elem, struct actions *data)
{
	struct action *action;
	action = xzalloc(sizeof(struct action));
	action->type = ACTION_DROP;
	list_add_tail(&action->list, &data->list);
	return RULE_SUCCESS;
}

int get_jump_data_from_page(struct action_elem *elem, struct actions *data)
{
	struct action *action;
	action = xzalloc(sizeof(struct action));
	action->type = ACTION_JUMP;
	action->chain = gtk_combo_box_text_get_active_text(
			GTK_COMBO_BOX_TEXT(elem->widget1));
	list_add_tail(&action->list, &data->list);
	return RULE_SUCCESS;
}

int get_counter_data_from_page(struct action_elem *elem, struct actions *data)
{
	unsigned int	packets;
	unsigned int	bytes;
	char	*packets_str;
	char	*bytes_str;
	struct action *action;
	action = xzalloc(sizeof(struct action));
	action->type = ACTION_COUNTER;
	packets_str = get_data_from_entry(GTK_ENTRY(elem->widget2));
	bytes_str = get_data_from_entry(GTK_ENTRY(elem->widget4));
	strtouint(packets_str, &packets);
	strtouint(bytes_str, &bytes);
	action->packets = packets;
	action->bytes = bytes;
	list_add_tail(&action->list, &data->list);
	return RULE_SUCCESS;
}

int get_actions_data_from_page(struct actions_all *widget, struct actions *data)
{
	int	res = RULE_SUCCESS;
	struct action_elem	*elem;

	if (list_empty(&widget->list))
		return RULE_SUCCESS;
	list_for_each_entry(elem, &widget->list, list) {
		switch(elem->type) {
		case ACTION_ACCEPT:
			res = get_accept_data_from_page(elem, data);
			if (res != RULE_SUCCESS)
				goto out;
			break;
		case ACTION_DROP:
			res = get_drop_data_from_page(elem, data);
			if (res != RULE_SUCCESS)
				goto out;
			break;
		case ACTION_JUMP:
			res = get_jump_data_from_page(elem, data);
			if (res != RULE_SUCCESS)
				goto out;
			break;
		case ACTION_COUNTER:
			res = get_counter_data_from_page(elem, data);
			if (res != RULE_SUCCESS)
				goto out;
			break;
		default:
			BUG();
		}
	}

out:
	return res;
}

static int get_position_from_page(struct rule_create_widget  *widget,
		struct rule_create_data *data)
{
	char	*index;
	int	res;
	unsigned int	value;
	unsigned int	i = 0;
	struct gui_rule   *rule, *r;
	LIST_HEAD(rule_list);

	if (data->handle)
		return RULE_SUCCESS;
	index = get_data_from_entry(GTK_ENTRY(widget->index_value));
	if (!index) {
		data->position = 0;
		return RULE_SUCCESS;
	}
	res = strtouint(index, &value);
	if (res != 0 || value == 0)
		return RULE_INDEX_INVALID;
	gui_get_rules_list(&rule_list, data->family, data->table, data->chain);

	if (value == 1) {
		data->position = 0;
		data->insert = 1;
	}
	list_for_each_entry_safe(rule, r, &rule_list, list) {
		if (i == value - 2) {
			data->position = rule->handle;
			break;
		}
		i++;
	}
	if (!rule)
		data->position = 0;
	list_for_each_entry_safe(rule, r, &rule_list, list) {
		list_del(&rule->list);
		gui_rule_free(rule);
	}
	return RULE_SUCCESS;
}

/*
 * Get all informations from rule creating page.
 */
int get_data_from_page(struct rule_create_widget  *widget,
		struct rule_create_data *data)
{
	int	res;

	res = get_header_data_from_page(widget->header, data->header);
	if (res != RULE_SUCCESS)
		return res;
	res = get_pktmeta_data_from_page(widget->meta, data->pktmeta);
	if (res != RULE_SUCCESS)
		return res;
	res = get_actions_data_from_page(widget->actions, data->actions);
	if (res != RULE_SUCCESS)
		return res;
	res = get_position_from_page(widget, data);

	return res;
}


/*
 * Free memory a rule_create_data instance used.
 */
void rule_free_data(struct rule_create_data *data)
{

}

/*
 * Get data from page, and check it
 * @widget:  widgets containing data in rule creating page
 */
int rule_create_getdata(struct rule_create_widget  *widget,
		struct rule_create_data **data)
{
	int	res;
	struct rule_create_data	*p;
	p = xmalloc(sizeof(struct rule_create_data));
	p->header = xzalloc(sizeof(struct pktheader));
	p->pktmeta = xzalloc(sizeof(struct pktmeta));
	p->actions = xzalloc(sizeof(struct actions));
	init_list_head(&p->actions->list);
	init_list_head(&p->exprs);
	p->header->saddr = xmalloc(sizeof(struct ip_addr_data));
	p->header->daddr = xmalloc(sizeof(struct ip_addr_data));
	p->header->transport_data = xmalloc(sizeof(struct transport_data));
	p->loc = xzalloc(sizeof(struct location));

	p->family = widget->family;
	p->table = xstrdup(widget->table);
	p->chain = xstrdup(widget->chain);

	res = get_data_from_page(widget, p);
	if (res != RULE_SUCCESS)
		goto error;

	res = rule_gen_expressions(p);
	if (res != RULE_SUCCESS)
		goto error;
	*data = p;
	return RULE_SUCCESS;
error:
	rule_free_data(p);
	return res;
}

static int set_get_name_from_page(struct set_submit_argsnnn *widget,
		struct set_create_data *data)
{
	char	*name;
	name = get_data_from_entry(GTK_ENTRY(widget->name));
	if (!name)
		return SET_NAME_EMPTY;
	if (name_check(name) != 0) {
		xfree(name);
		return SET_NAME_INVALID;
	}
	data->set = name;
	return SET_SUCCESS;
}

static int set_get_type_from_page(struct set_submit_argsnnn *widget,
		struct set_create_data *data)
{
	char	*type;
	type = gtk_combo_box_text_get_active_text(
			GTK_COMBO_BOX_TEXT(widget->type));
	data->keytype = datatype_lookup_bydesc(type);
	data->keylen = data->keytype->size;
	return SET_SUCCESS;
}

static int set_get_elems_from_page(struct set_submit_argsnnn *widget,
		struct set_create_data *data)
{
	GtkTreeIter     iter;
	GtkTreeView     *treeview;
	GtkTreeModel    *model;
	char    *value;
	int     valid = 1;
	struct elem_create_data *elem;

	treeview = GTK_TREE_VIEW(widget->treeview);
	model = gtk_tree_view_get_model(treeview);
	if (gtk_tree_model_get_iter_first(model, &iter) == FALSE)
		return SET_SUCCESS;

	while(valid) {
		elem = xzalloc(sizeof(struct elem_create_data));
		elem->type = data->keytype->type;
		gtk_tree_model_get(model, &iter, 0, &value, -1);
		elem->key = value;
		valid = gtk_tree_model_iter_next(model, &iter);
		list_add_tail(&elem->list, &data->elems);
	}
	return SET_SUCCESS;
}

int set_create_getdata(struct set_submit_argsnnn  *widget,
		struct set_create_data **data)
{
	int	res;
	struct set_create_data	*p;

	p = xzalloc(sizeof(struct set_create_data));
	p->family = widget->family;
	p->table = xstrdup(widget->table);
	init_list_head(&p->elems);

	res = set_get_name_from_page(widget, p);
	if (res != SET_SUCCESS)
		goto out;
	res = set_get_type_from_page(widget, p);
	if (res != SET_SUCCESS)
		goto out;
	res = set_get_elems_from_page(widget, p);
	if (res != SET_SUCCESS)
		goto out;

	*data = p;
	return SET_SUCCESS;
out:
	xfree(p->table);
	xfree(p->set);
	xfree(p);
	return res;
}
