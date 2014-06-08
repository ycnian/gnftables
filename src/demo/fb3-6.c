#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <gtk/gtk.h>



struct new_table {
	GtkWidget	*notebook;
	GtkWidget	*name;
	GtkWidget	*family;
};


/* 从笔记本上删除一个页面 */
// 这个函数需要保留，因为我会用到这个函数.
void remove_book( GtkButton   *button,
                  GtkNotebook *notebook )
{
    gint page;
  
    page = gtk_notebook_get_current_page (notebook);
    gtk_notebook_remove_page (notebook, page);
  /* 需要刷新构件, 这会迫使构件重绘自身。 */
    gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


void select_page(GtkNotebook *notebook, GtkWidget   *page, guint page_num, gpointer user_data)
{
	gint	num = gtk_notebook_get_n_pages(notebook);
	gint    i;
	for (i = page_num + 1; i < num - 1; i++)
		gtk_notebook_remove_page (notebook, i);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


gint load_rules(GtkWidget *widget, GtkWidget *event, gpointer data )
{
	GtkWidget	*dialog;
	GtkFileChooserAction	action = GTK_FILE_CHOOSER_ACTION_OPEN;
	gint	res;

	dialog = gtk_file_chooser_dialog_new("Open File", NULL, action, 
			"Cancel", GTK_RESPONSE_CANCEL,
			"Open", GTK_RESPONSE_ACCEPT,
			NULL);
	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_ACCEPT) {
		char	*filename;
		GtkFileChooser	*chooser = GTK_FILE_CHOOSER(dialog);
		filename = gtk_file_chooser_get_filename(chooser);
		printf("%s\n", filename);
		g_free(filename);
	}

	gtk_widget_destroy(dialog);
	return FALSE;
}


gint save_rules(GtkWidget *widget, GtkWidget *event, gpointer data)
{
	gint		res;
	GtkWidget	*dialog;
	GtkFileChooser  *chooser;
	GtkFileChooserAction	action = GTK_FILE_CHOOSER_ACTION_SAVE;

	dialog = gtk_file_chooser_dialog_new("Load rules", NULL, action, 
			"Cancel", GTK_RESPONSE_CANCEL,
			"Save", GTK_RESPONSE_ACCEPT,
			NULL);
	chooser = GTK_FILE_CHOOSER (dialog);
	gtk_file_chooser_set_do_overwrite_confirmation (chooser, TRUE);

//	if (user_edited_a_new_document)
//		gtk_file_chooser_set_current_name (chooser, "Untitled document");
//	else
//		gtk_file_chooser_set_filename (chooser, existing_filename);


	res = gtk_dialog_run(GTK_DIALOG(dialog));

	if (res == GTK_RESPONSE_ACCEPT) {
		char	*filename;
		filename = gtk_file_chooser_get_filename(chooser);
		printf("%s\n", filename);
		g_free(filename);
	}

	gtk_widget_destroy(dialog);
	return FALSE;
}


GdkPixbuf  *create_pixbuf(const gchar *filename)
{
	GdkPixbuf  *pixbuf;
	GError     *error = NULL;

	pixbuf = gdk_pixbuf_new_from_file(filename, &error);
	if (!pixbuf)
		g_error_free(error);

	return pixbuf;
}

void gnftables_table_init(GtkWidget *notebook, const char *table_proto, void *data);


void get_tables_info()
{

}

void begin_create_new_table(GtkButton *button, gpointer  info)
{
	const gchar	*name;
	struct  new_table  *data = (struct  new_table  *)info;

	// get and check data
	// name = gtk_entry_get_text(GTK_ENTRY(data->name));
	// printf("%s\n", name);

	// if all data is valid, submit to kernel.


	// back to table list
	gtk_notebook_remove_page(GTK_NOTEBOOK(data->notebook), 0);
	get_tables_info();
	gnftables_table_init(GTK_WIDGET(data->notebook), "all", NULL);
	gtk_widget_show_all(GTK_WIDGET(data->notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(data->notebook), 0);

}




void back_to_table_list (GtkButton *button, gpointer  notebook)
{
	gtk_notebook_remove_page(notebook, 0);
	get_tables_info();
	gnftables_table_init(GTK_WIDGET(notebook), "all", NULL);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);

}



void create_new_chain(GtkButton *button, gpointer  notebook)
{



}

void create_new_table(GtkButton *button, gpointer  notebook)
{
	GtkWidget	*page;
	gint		i;
	GtkWidget	*layout;
	GtkWidget	*label;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	GtkWidget	*scrolledwindow;
	GtkWidget	*frame;
	GtkWidget	*layout_info;
	GtkWidget	*name;
	GtkWidget	*name_value;
	GtkWidget	*name_desc;
	GtkWidget	*family;
	GtkWidget	*family_value;

	struct	new_table  *info = malloc(sizeof(info));
	if (!info)
		// error
		return;
	info->notebook = GTK_WIDGET(notebook);

	gtk_notebook_remove_page(notebook, 0);

	layout = gtk_layout_new(NULL, NULL);
	label = gtk_label_new("Tables (all)");
	gtk_widget_set_size_request(label, 200, 10);

	frame = gtk_frame_new ("Create a new table");
	gtk_container_set_border_width (GTK_CONTAINER (frame), 0);
	gtk_widget_set_size_request(frame, 600, 371);
	gtk_layout_put(GTK_LAYOUT(layout), frame, 150, 40);


	layout_info = gtk_layout_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(frame), layout_info);

	name = gtk_label_new("Name:");
	gtk_layout_put(GTK_LAYOUT(layout_info), name, 30, 60);
	info->name = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(info->name), 30);
	gtk_layout_put(GTK_LAYOUT(layout_info), info->name, 100, 60);
	name_desc = gtk_label_new("(no more than 100 characters)");
	gtk_layout_put(GTK_LAYOUT(layout_info), name_desc, 360, 60);

	family = gtk_label_new("Family:");
	gtk_layout_put(GTK_LAYOUT(layout_info), family, 30, 110);
	info->family = gtk_combo_box_text_new();
	gtk_widget_set_size_request(info->family, 30, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(info->family), "ipv4", "ipv4");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(info->family), "ipv6", "ipv6");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(info->family), "apr", "apr");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(info->family), "brige", "brige");
	gtk_combo_box_set_active(GTK_COMBO_BOX(info->family), 0);
	gtk_layout_put(GTK_LAYOUT(layout_info), info->family, 100, 110);



    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(back_to_table_list), notebook);
	gtk_layout_put(GTK_LAYOUT(layout_info), cancel, 360, 310);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(begin_create_new_table), info);
	gtk_layout_put(GTK_LAYOUT(layout_info), ok, 480, 310);


	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, label, 0);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);

}


void gnftables_set_rule_init(GtkButton *button, gpointer  notebook)
{



}


void gnftables_set_chain_init(GtkButton *button, gpointer  notebook)
{

	GtkWidget	*label;
	GtkWidget	*layout;
	GtkWidget	*type;
	GtkWidget	*combo_type;
	GtkWidget	*hook;
	GtkWidget	*combo_hook;
	GtkWidget	*create_table;
	GtkWidget	*tmp;
	GtkWidget	*list_tables;
	GtkWidget	*scrolledwindow;
	GtkTreeIter	iter;
	GtkListStore	*store;
	GtkCellRenderer	*renderer;


	label = gtk_label_new("Sets & Chains (Table: filter)");
	gtk_widget_set_size_request(label, 200, 10);
	layout = gtk_layout_new(NULL, NULL);


	type = gtk_label_new("Type");
	gtk_layout_put(GTK_LAYOUT(layout), type, 10, 10);

	combo_type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(combo_type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "all", "all");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "filter", "filter");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "nat", "nat");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "route", "route");
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_type), 0);
	gtk_layout_put(GTK_LAYOUT(layout), combo_type, 90, 10);


	hook = gtk_label_new("Type");
	gtk_layout_put(GTK_LAYOUT(layout), hook, 200, 10);

	combo_hook = gtk_combo_box_text_new();
	gtk_widget_set_size_request(combo_hook, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_hook), "all", "all");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_hook), "input", "input");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_hook), "output", "output");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_hook), "forward", "forward");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_hook), "prerouting", "prerouting");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_hook), "postrouting", "postrouting");
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_hook), 0);
	gtk_layout_put(GTK_LAYOUT(layout), combo_hook, 290, 10);



    	create_table = gtk_button_new_with_label("Create Chain");
	gtk_widget_set_size_request(create_table, 150, 10);
	g_signal_connect(G_OBJECT(create_table), "clicked", G_CALLBACK(create_new_chain), notebook);
	gtk_layout_put(GTK_LAYOUT(layout), create_table, 700, 10);


    	tmp = gtk_button_new_with_label("A tmp button, link to rules");
	gtk_widget_set_size_request(tmp, 250, 10);
	g_signal_connect(G_OBJECT(tmp), "clicked", G_CALLBACK(gnftables_set_rule_init), NULL);
	gtk_layout_put(GTK_LAYOUT(layout), tmp, 400, 10);




	list_tables = gtk_tree_view_new();
	enum {id = 0, name, table, rules, basechain, chaintype, chainhook, priority,  columns_total};
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Id", renderer, "text", id, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Name", renderer, "text", name, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Table", renderer, "text", table, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Rules", renderer, "text", rules, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "basechain", renderer, "text", basechain, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Type", renderer, "text", chaintype, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Hook", renderer, "text", chainhook, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Priority", renderer, "text", priority, NULL);
	gtk_tree_view_set_enable_tree_lines (GTK_TREE_VIEW(list_tables), TRUE);

	store = gtk_list_store_new(columns_total, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	gtk_tree_view_set_model(GTK_TREE_VIEW(list_tables), GTK_TREE_MODEL(store));


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// list data here.
	gtk_list_store_append(GTK_LIST_STORE(store), &iter);
	gtk_list_store_set(GTK_LIST_STORE(store), &iter, id, "1", name, "chain1", table, "filter", rules, "8", basechain, "ture", chaintype, "filter", chainhook, "input", priority, "0", -1);
	gtk_list_store_append(GTK_LIST_STORE(store), &iter);
	gtk_list_store_set(GTK_LIST_STORE(store), &iter, id, "1", name, "chain1", table, "filter", rules, "8", basechain, "ture", chaintype, "filter", chainhook, "input", priority, "0", -1);
	gtk_list_store_append(GTK_LIST_STORE(store), &iter);
	gtk_list_store_set(GTK_LIST_STORE(store), &iter, id, "1", name, "chain1", table, "filter", rules, "8", basechain, "ture", chaintype, "filter", chainhook, "input", priority, "0", -1);
	gtk_list_store_append(GTK_LIST_STORE(store), &iter);
	gtk_list_store_set(GTK_LIST_STORE(store), &iter, id, "1", name, "chain1", table, "filter", rules, "8", basechain, "ture", chaintype, "filter", chainhook, "input", priority, "0", -1);
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolledwindow), 876);
	gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolledwindow), 410);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), GTK_SHADOW_ETCHED_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
                                GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_tables);

	gtk_layout_put(GTK_LAYOUT(layout), scrolledwindow, 0, 50);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, label, 1);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);


}



void gnftables_table_init(GtkWidget *notebook, const char *table_proto, void *data)
{
	GtkWidget	*label;
	GtkWidget	*layout;
	GtkWidget	*proto;
	GtkWidget	*combo;
	GtkWidget	*create_table;
	GtkWidget	*tmp;
	GtkWidget	*list_tables;
	GtkWidget	*scrolledwindow;
	GtkTreeIter	iter;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkTreeViewColumn *column;

	char		title[20] = {0};

	sprintf(title, "Tables (%s)", table_proto);
	label = gtk_label_new(title);
	gtk_widget_set_size_request(label, 200, 10);
	layout = gtk_layout_new(NULL, NULL);


	proto = gtk_label_new("Protocol ");
	gtk_layout_put(GTK_LAYOUT(layout), proto, 10, 10);

	combo = gtk_combo_box_text_new();
	gtk_widget_set_size_request(combo, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "all", "all");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "ipv4", "ipv4");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "ipv6", "ipv6");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "apr", "apr");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "brige", "brige");
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
	gtk_layout_put(GTK_LAYOUT(layout), combo, 90, 10);

    	create_table = gtk_button_new_with_label("Create Table");
	gtk_widget_set_size_request(create_table, 150, 10);
	g_signal_connect(G_OBJECT(create_table), "clicked", G_CALLBACK(create_new_table), notebook);
	gtk_layout_put(GTK_LAYOUT(layout), create_table, 700, 10);


    	tmp = gtk_button_new_with_label("A tmp button, link to sets and chains");
	gtk_widget_set_size_request(tmp, 250, 10);
	g_signal_connect(G_OBJECT(tmp), "clicked", G_CALLBACK(gnftables_set_chain_init), notebook);
	gtk_layout_put(GTK_LAYOUT(layout), tmp, 400, 10);


	enum {id = 0, name, family, sets, chains, actions, columns_total};
	store = gtk_tree_store_new(columns_total, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);


	// 这里在添加数据
	gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
	gtk_tree_store_set(GTK_TREE_STORE(store), &iter, id, "2", name, "filter2", family, "ipv4", sets, "2", chains, "7", actions, "action", -1);
	gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
	gtk_tree_store_set(GTK_TREE_STORE(store), &iter, id, "2", name, "filter2", family, "ipv4", sets, "2", chains, "7", actions, "action", -1);
	gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
	gtk_tree_store_set(GTK_TREE_STORE(store), &iter, id, "2", name, "filter2", family, "ipv4", sets, "2", chains, "7", actions, "action", -1);
	gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
	gtk_tree_store_set(GTK_TREE_STORE(store), &iter, id, "2", name, "filter2", family, "ipv4", sets, "2", chains, "7", actions, "action", -1);


	// 下面开始设计显示方式
	list_tables = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();
//	g_object_set(G_OBJECT(renderer), "foreground", "red", NULL);
	column = gtk_tree_view_column_new_with_attributes("Id", renderer, "text", id, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer, "text", name, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Family", renderer, "text", family, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Sets", renderer, "text", sets, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Chains", renderer, "text", chains, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("ACTIONS", renderer, "text", actions, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);




//	list_tables = gtk_tree_view_new();
//	renderer = gtk_cell_renderer_text_new();
//	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Id", renderer, "text", id, NULL);
//	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Name", renderer, "text", name, NULL);
//	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Protocol", renderer, "text", family, NULL);
//	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Sets", renderer, "text", sets, NULL);
//	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(list_tables), -1, "Chains", renderer, "text", chains, NULL);
//	gtk_tree_view_set_enable_tree_lines (GTK_TREE_VIEW(list_tables), TRUE);
//
//	store = gtk_list_store_new(columns_total, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
//	gtk_tree_view_set_model(GTK_TREE_VIEW(list_tables), GTK_TREE_MODEL(store));
//
//
//	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	// list data here.
//	gtk_list_store_append(GTK_LIST_STORE(store), &iter);
//	gtk_list_store_set(GTK_LIST_STORE(store), &iter, id, "2", name, "filter2", family, "ipv4", sets, "2", chains, "7", -1);
//	gtk_list_store_append(GTK_LIST_STORE(store), &iter);
//	gtk_list_store_set(GTK_LIST_STORE(store), &iter, id, "2", name, "filter2", family, "ipv4", sets, "2", chains, "7", -1);
//	gtk_list_store_append(GTK_LIST_STORE(store), &iter);
//	gtk_list_store_set(GTK_LIST_STORE(store), &iter, id, "2", name, "filter2", family, "ipv4", sets, "2", chains, "7", -1);
//	gtk_list_store_append(GTK_LIST_STORE(store), &iter);
//	gtk_list_store_set(GTK_LIST_STORE(store), &iter, id, "2", name, "filter2", family, "ipv4", sets, "2", chains, "7", -1);
//	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////







        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolledwindow), 876);
	gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolledwindow), 410);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), GTK_SHADOW_ETCHED_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
                                GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_tables);

	gtk_layout_put(GTK_LAYOUT(layout), scrolledwindow, 0, 50);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, label, 0);
}



void gnftables_about_init(GtkWidget *notebook)
{
	GtkWidget	*content;
	GtkWidget	*label;

	const gchar *text = "gnftables 0.1.0\n\ngnftables is a gui tool aimed to simplify the configuration of nftables from command line. It is compatibility with nft, and can recognize all the rules configured by nft, so don't worry about migration. If you need more help, please visit the project's home site (http://ycnian.org/projects/gnftables.php).\n\nCopyright (c) 2014  Yanchuan Nian <ycnian@gmail.com>\n\nThis program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the licence, or (at your option) any later version.\n\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.\n\nYou should have received a copy of the GNU General Public License along with this program. You may also obtain a copy of the GNU General Public License from the Free Software Foundation by visiting their web site (http://www.fsf.org/) or by writing to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA";
	content = gtk_label_new(NULL);
	gtk_label_set_width_chars(GTK_LABEL(content), 100);
	gtk_label_set_justify(GTK_LABEL(content), GTK_JUSTIFY_LEFT);
	gtk_label_set_line_wrap(GTK_LABEL(content), TRUE);
	gtk_label_set_selectable (GTK_LABEL(content), FALSE);
	gtk_label_set_text(GTK_LABEL(content), text);

	label = gtk_label_new ("About gnftables");
	gtk_widget_set_size_request(label, 200, 10);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), content, label);      
}




int main(int argc, char *argv[])
{
	GtkWidget	*window;
	GtkWidget	*layout;
	GtkWidget	*button;
	GtkWidget	*notebook;

	
	gchar		*table_proto = "all";


	GtkWidget *label;
	GtkWidget *checkbutton;
	GtkWidget *view;
	GtkWidget *label_about;

	gtk_init(&argc, &argv);

        window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(window), "gnftables");
        gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(window, 900, 556);
	gtk_window_set_icon(GTK_WINDOW(window), create_pixbuf("gnftables.png"));

	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	gtk_container_set_border_width(GTK_CONTAINER (window), 10);

	layout = gtk_layout_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER (window), layout);

	notebook = gtk_notebook_new();
	gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
	gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook), TRUE);
	gtk_notebook_set_show_border(GTK_NOTEBOOK(notebook), TRUE);
	gtk_widget_set_size_request(notebook, 880, 500);
	gtk_widget_show(notebook);
	gtk_layout_put(GTK_LAYOUT(layout), notebook, 0, 0);


	gnftables_table_init(notebook, table_proto, NULL);
	gnftables_about_init(notebook);


	gtk_notebook_set_current_page (GTK_NOTEBOOK (notebook), 0);
	g_signal_connect(G_OBJECT(notebook), "switch-page", G_CALLBACK(select_page), notebook);


	button = gtk_button_new_with_label("Load rules from file");
	g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(load_rules), NULL);
	gtk_widget_set_size_request(button, 435, 10);
	gtk_layout_put(GTK_LAYOUT(layout), button, 0, 500);

	button = gtk_button_new_with_label("Save rules to file");
	g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK(save_rules), notebook);
	gtk_widget_set_size_request(button, 435, 10);
	gtk_layout_put(GTK_LAYOUT(layout), button, 445, 500);
    

	gtk_widget_show_all(window);
	gtk_main ();

	return 0;
}
