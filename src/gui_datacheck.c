#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <utils.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <gui_datacheck.h>
#include <gui_nftables.h>


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
