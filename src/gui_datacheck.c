#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <utils.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <gui_datacheck.h>
#include <gui_nftables.h>
#include <gui_expression.h>


/*
 * Check name, only letter, number, underscore allowed.
 * Skipe spaces at the start and end of name.
 * @name:  a string to be checked
 * @start: parameter used to save the first valid character in name
 * @end:   parameter used to save the last valid character in name
 * Return Value:
 * 	0:  name is valid
 * 	-1: name contains invalid character
 * 	-2: name is empty
 */
int name_check(char *name, int *start, int *end)
{
	int	i;
	int	len = strlen(name);
	*start = -1;
	*end = -1;

	for (i = 0; i < len; i++) {
		if (isblank(name[i])) {
			if ((*start != -1) && (*end == -1))
				*end = i - 1;
			continue;
		}
		if ((name[i] != '_') && !(isalnum(name[i])))
			return -1;
		if (*end != -1)
			return -1;
		if (*start == -1)
			*start = i;
	}

	if (*start == -1)
		return -2;
	if (*end == -1)
		*end = len - 1;
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
 * Check table name
 */
int table_name_check(char *name, int *start, int *end)
{
	return name_check(name, start, end);
}


/*
 * Get data from page, and check it
 * @widget:  widgets containing data in table creating
 */
int table_create_getdata(struct table_create_widget  *widget,
		struct table_create_data **data)
{
	int	res;
	char	*name;
	int	start = -1;
	int	end = -1;
	int		family;
	GtkTreeModel    *model;
	GtkTreeIter     iter;
	struct table_create_data *p = NULL;

        name = (char *)gtk_entry_get_text(GTK_ENTRY(widget->name));
        model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget->family));
        gtk_combo_box_get_active_iter(GTK_COMBO_BOX(widget->family), &iter);
        gtk_tree_model_get(model, &iter, 0, &family, -1);

	res = table_name_check(name, &start, &end);
	if (res == -1)
		return TABLE_NAME_INVALID;
	else if (res == -2)
		return TABLE_NAME_EMPTY;

	p = xmalloc(sizeof(struct table_create_data));
	p->table = xmalloc(end - start + 2);
	memcpy(p->table, name + start, end - start + 1);
	p->table[end + 1] = '\0';
	p->family = family;
	*data = p;
	return TABLE_SUCCESS;
}


/*
 * Check chain name
 */
int chain_name_check(char *name, int *start, int *end)
{
	return name_check(name, start, end);
}

int chain_priority_check(char *priority)
{
	return integer_check(priority);
}

/*
 * Get data from page, and check it
 * @widget:  widgets containing data in chain creating
 */
int chain_create_getdata(struct chain_create_widget  *widget,
		struct chain_create_data **data)
{
	int	res;
	char	*name;
	int	basechain;
	char	*type;
	const char	*hook_str;
	int	hook;
	char	*priority_str;
	int	start = -1;
	int	end = -1;
	struct chain_create_data *p = NULL;

	name = (char *)gtk_entry_get_text(GTK_ENTRY(widget->name));
	basechain = !!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget->basechain));
	if (basechain) {
		type = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(widget->type));
		hook_str = (const char *)gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(widget->hook));
		hook = str2hooknum(widget->family, hook_str);
		priority_str = (char *)gtk_entry_get_text(GTK_ENTRY(widget->priority));
	}

	res = chain_name_check(name, &start, &end);
	if (res == -1)
		return CHAIN_NAME_INVALID;
	else if (res == -2)
		return CHAIN_NAME_EMPTY;

	if (basechain) {
		res = chain_priority_check(priority_str);
		if (res != 0)
			return CHAIN_PRIORITY_INVALID;
	}

	p = xmalloc(sizeof (struct chain_create_data));
	p->family = widget->family;
	p->table = xstrdup(widget->table);
	p->chain = xmalloc(end - start + 2);
	memcpy(p->chain, name + start, end - start + 1);
	p->chain[end + 1] = '\0';
	if (basechain) {
		p->basechain = 1;
		p->type = xstrdup(type);
		p->hook = hook;
		p->priority = atoi(priority_str);
	} else {
		p->basechain = 0;
		p->type = NULL;
	}

	*data = p;
	return CHAIN_SUCCESS;
}


int get_heade_iplist_from_page(struct ip_address  *widget,
		struct ip_addr_data *data)
{
	char	*ip;
	char	*iplist;
	struct ip_convert  *ipnet;
	iplist = xstrdup(gtk_entry_get_text(GTK_ENTRY(widget->exact_ip.ip)));
	ip = strtok(iplist, " ");
	while (ip) {
		ipnet = xmalloc(sizeof(struct ip_convert));
		if (!inet_pton(AF_INET, ip, ipnet->ip)) {
			xfree(ipnet);
			xfree(iplist);
			return RULE_HEADER_IP_INVALID;
		}
		list_add_tail(&ipnet->list, &data->iplist.ips);
		ip = strtok(NULL, " ");
	}
	xfree(iplist);
	return RULE_SUCCESS;
}

int get_heade_ipsubnet_from_page(struct ip_address  *widget,
		struct ip_addr_data *data)
{


	return RULE_SUCCESS;
}

int ipv4_addr_cmp(unsigned char *ip1, unsigned char *ip2)
{
	int i = 0;
	for (i = 0; i < 4; i++) {
		if (ip1[i] > ip2[i])
			return 1;
		else if (ip1[i] < ip2[i])
			return -1;
	}
	return 0;
}

int string_is_null(char *str)
{
	int	i = 0;
	int	len = strlen(str);
	for (i = 0; i < len; i++) {
		if (!isblank(str[i]))
			return 0;
	}
	return 1;
}

int get_heade_iprange_from_page(struct ip_address  *widget,
		struct ip_addr_data *data)
{
	char	*from;
	char	*to;
	int	fnull;
	int	tnull;
	int	res = RULE_SUCCESS;

	from = xstrdup(gtk_entry_get_text(GTK_ENTRY(widget->range.from)));
	to = xstrdup(gtk_entry_get_text(GTK_ENTRY(widget->range.to)));
	fnull = string_is_null(from);
	tnull = string_is_null(to);

	if (fnull)
		memset(data->range.from, 0, 4);
	else if (!inet_pton(AF_INET, from, data->range.from)) {
		res = RULE_HEADER_IP_INVALID;
		goto out;
	}
	if (tnull)
		memset(data->range.to, 0, 4);
	else if (!inet_pton(AF_INET, to, data->range.to)) {
		res = RULE_HEADER_IP_INVALID;
		goto out;
	}
	if (!fnull && !tnull && ipv4_addr_cmp(data->range.from, data->range.to) >= 0)
		res = RULE_HEADER_IP_RANGE_INVALID;
out:
	xfree(from);
	xfree(to);
	return res;

}

int get_header_addr_from_page(struct ip_address  *widget,
		struct ip_addr_data *data)
{
	enum address_type       type;
	int	exclude;
	int	res = RULE_SUCCESS;

	type = widget->type;
	exclude = widget->exclude;
	data->ip_type = type;
	data->exclude = exclude;
	switch (type) {
	case ADDRESS_EXACT:
		res = get_heade_iplist_from_page(widget, data);
		break;
	case ADDRESS_SUBNET:
		res = get_heade_ipsubnet_from_page(widget, data);
		break;
	case ADDRESS_RANGE:
		res = get_heade_iprange_from_page(widget, data);
		break;
	case ADDRESS_SET:
		break;
	default:
		break;
	}

	return res;
}



int get_header_data_from_page(struct match_header *widget, struct header *data)
{
	int	res;

	res = get_header_addr_from_page(widget->saddr.value, data->saddr);
	if (res != RULE_SUCCESS)
		return res;
	res = get_header_addr_from_page(widget->daddr.value, data->daddr);
	if (res != RULE_SUCCESS)
		return res;
	return RULE_SUCCESS;
}


int get_pktmeta_data_from_page(struct match_pktmeta  *widget,
		struct pktmeta *data)
{

	return RULE_SUCCESS;
}

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

	return RULE_SUCCESS;
}

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
	p->header = xmalloc(sizeof(struct header));
	p->pktmeta = xmalloc(sizeof(struct pktmeta));
	init_list_head(&p->exprs);
	p->header->saddr = xmalloc(sizeof(struct ip_addr_data));
	p->header->daddr = xmalloc(sizeof(struct ip_addr_data));
	p->header->transport_data = xmalloc(sizeof(struct transport_data));
	init_list_head(&p->header->saddr->iplist.ips);
	init_list_head(&p->header->daddr->iplist.ips);

	res = get_data_from_page(widget, p);
	if (res != RULE_SUCCESS)
		goto error;

//	struct ip_convert   *convert;
//	list_for_each_entry(convert, &p->header->saddr->iplist.ips, list)
//		printf("%d  %d  %d  %d\n", convert->ip[0]&0xff, convert->ip[1]&0xff, convert->ip[2]&0xff, convert->ip[3]&0xff);
//	list_for_each_entry(convert, &p->header->daddr->iplist.ips, list)
//		printf("%d  %d  %d  %d\n", convert->ip[0]&0xff, convert->ip[1]&0xff, convert->ip[2]&0xff, convert->ip[3]&0xff);

	res = rule_gen_expressions(p);
	if (res != RULE_SUCCESS)
		goto error;
	return RULE_SUCCESS;
error:
	rule_free_data(p);
	return res;
}
