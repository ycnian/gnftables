#include <string.h>

#include <utils.h>
#include <gui_rule.h>
#include <gui_error.h>
#include <gui_datacheck.h>
#include <gui_nftables.h>


/*
 * Check name
 */
int name_check(char *name)
{
	int	i;
	int	len = strlen(name);

	for (i = 0; i < len; i++)
		if ((name[i] != '_') && !(name[i] >= '0' && name[i] <= '9') &&
			!(name[i] >= 'a' && name[i] <= 'z') &&
			!(name[i] >= 'A' && name[i] <= 'Z'))
			return -1;
	return 0;
}

/*
 * Check table name
 */
int table_name_check(char *name)
{
	int res;
	if (strlen(name) == 0)
		return TABLE_NAME_EMPTY;
	res = name_check(name);
	if (res < 0)
		return TABLE_NAME_INVALID;
	else
		return TABLE_SUCCESS;
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
	int		family;
	GtkTreeModel    *model;
	GtkTreeIter     iter;
	struct table_create_data *p = NULL;

        name = (char *)gtk_entry_get_text(GTK_ENTRY(widget->name));
        model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget->family));
        gtk_combo_box_get_active_iter(GTK_COMBO_BOX(widget->family), &iter);
        gtk_tree_model_get(model, &iter, 0, &family, -1);

	if ((res = table_name_check(name)) != TABLE_SUCCESS)
		return res;

	p = xmalloc(sizeof(struct table_create_data));
	p->table = xstrdup(name);
	p->family = family;
	*data = p;
	return TABLE_SUCCESS;
}
