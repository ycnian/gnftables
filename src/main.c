/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>

#include <nftables.h>
#include <utils.h>
#include <parser.h>
#include <rule.h>
#include <netlink.h>
#include <erec.h>
#include <mnl.h>

///////////////////////////    added for gnftables   /////////////////////////////////////
#include <list.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <gtk/gtk.h>
#include <netlink.h>
#include <netinet/ip.h>
#include <gui_nftables.h>
#include <linux/netfilter.h>
#include <gui_error.h>
#include <gui_rule.h>
///////////////////////////   end added for gnftables   /////////////////////////////////////



unsigned int max_errors = 10;
unsigned int numeric_output;
unsigned int handle_output;
#ifdef DEBUG
unsigned int debug_level;
#endif

const char *include_paths[INCLUDE_PATHS_MAX] = { DEFAULT_INCLUDE_PATH };

enum opt_vals {
	OPT_HELP		= 'h',
	OPT_VERSION		= 'v',
	OPT_FILE		= 'f',
	OPT_INTERACTIVE		= 'i',
	OPT_INCLUDEPATH		= 'I',
	OPT_NUMERIC		= 'n',
	OPT_DEBUG		= 'd',
	OPT_HANDLE_OUTPUT	= 'a',
	OPT_INVALID		= '?',
};

#define OPTSTRING	"hvf:iI:vna"

static const struct option options[] = {
	{
		.name		= "help",
		.val		= OPT_HELP,
	},
	{
		.name		= "version",
		.val		= OPT_VERSION,
	},
	{
		.name		= "file",
		.val		= OPT_FILE,
		.has_arg	= 1,
	},
	{
		.name		= "interactive",
		.val		= OPT_INTERACTIVE,
	},
	{
		.name		= "numeric",
		.val		= OPT_NUMERIC,
	},
	{
		.name		= "includepath",
		.val		= OPT_INCLUDEPATH,
		.has_arg	= 1,
	},
#ifdef DEBUG
	{
		.name		= "debug",
		.val		= OPT_DEBUG,
		.has_arg	= 1,
	},
#endif
	{
		.name		= "handle",
		.val		= OPT_HANDLE_OUTPUT,
	},
	{
		.name		= NULL
	}
};


#ifdef DEBUG
static const struct {
	const char		*name;
	enum debug_level	level;
} debug_param[] = {
	{
		.name		= "scanner",
		.level		= DEBUG_SCANNER,
	},
	{
		.name		= "parser",
		.level		= DEBUG_PARSER,
	},
	{
		.name		= "eval",
		.level		= DEBUG_EVALUATION,
	},
	{
		.name		= "netlink",
		.level		= DEBUG_NETLINK,
	},
	{
		.name		= "mnl",
		.level		= DEBUG_MNL,
	},
	{
		.name		= "proto-ctx",
		.level		= DEBUG_PROTO_CTX,
	},
	{
		.name		= "segtree",
		.level		= DEBUG_SEGTREE,
	},
	{
		.name		= "all",
		.level		= ~0,
	},
};
#endif

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

static int nft_netlink(struct parser_state *state, struct list_head *msgs)
{
	struct netlink_ctx ctx;
	struct cmd *cmd, *next;
	struct mnl_err *err, *tmp;
	LIST_HEAD(err_list);
	uint32_t batch_seqnum;
	bool batch_supported = netlink_batch_supported();
	int ret = 0;

	batch_seqnum = mnl_batch_begin();
	list_for_each_entry(cmd, &state->cmds, list) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.msgs = msgs;
		ctx.seqnum = cmd->seqnum = mnl_seqnum_alloc();
		ctx.batch_supported = batch_supported;
		init_list_head(&ctx.list);
		ret = do_command(&ctx, cmd);
		if (ret < 0)
			return ret;
	}
	mnl_batch_end();

	if (mnl_batch_ready())
		ret = netlink_batch_send(&err_list);
	else {
		mnl_batch_reset();
		goto out;
	}

	list_for_each_entry_safe(err, tmp, &err_list, head) {
		list_for_each_entry(cmd, &state->cmds, list) {
			if (err->seqnum == cmd->seqnum ||
			    err->seqnum == batch_seqnum) {
				netlink_io_error(&ctx, &cmd->location,
						 "Could not process rule: %s",
						 strerror(err->err));
				if (err->seqnum == cmd->seqnum) {
					mnl_err_list_free(err);
					break;
				}
			}
		}
	}
out:
	list_for_each_entry_safe(cmd, next, &state->cmds, list) {
		list_del(&cmd->list);
		cmd_free(cmd);
	}

	return ret;
}

int nft_run(void *scanner, struct parser_state *state, struct list_head *msgs)
{
	int ret;

	ret = nft_parse(scanner, state);
	if (ret != 0 || state->nerrs > 0)
		return -1;

	return nft_netlink(state, msgs);
}




//////////////////////////////////////////   add for gnftables   //////////////////////////////////////////


GtkWidget	*window;

void remove_book( GtkButton   *button,
                  GtkNotebook *notebook )
{
    gint page;
  
    page = gtk_notebook_get_current_page (notebook);
    gtk_notebook_remove_page (notebook, page);
    gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


// This function will be modified in the future.
// Before goto the right page, data need be updated.
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


void begin_create_new_chain(GtkButton *button, gpointer  info)
{
	

	GtkTreeModel	*model;
	GtkTreeIter	iter;
	struct new_chain	*args = (struct new_chain *)info;
	GtkWidget	*notebook = args->notebook;
	GtkWidget	*name = args->chain;
	GtkWidget	*base = args->basechain;
	GtkWidget	*type = args->type;
	GtkWidget	*hook = args->hook;
	GtkWidget	*priority = args->priority;

	struct gui_chain	*chain = (struct gui_chain *)malloc(sizeof(*chain));

//	if (!chain)
//		error;

	chain->family = args->family;
	chain->table = strdup(args->table);
	chain->chain = (char *)gtk_entry_get_text(GTK_ENTRY(name));
	if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(base)))
		chain->basechain = 0;
	else {
		chain->basechain = 1;
		model = gtk_combo_box_get_model(GTK_COMBO_BOX(type));
		gtk_combo_box_get_active_iter(GTK_COMBO_BOX(type), &iter);
		gtk_tree_model_get(model, &iter, 0, &chain->type, -1);
		model = gtk_combo_box_get_model(GTK_COMBO_BOX(hook));
		gtk_combo_box_get_active_iter(GTK_COMBO_BOX(hook), &iter);
		gtk_tree_model_get(model, &iter, 0, &chain->hook, -1);
		chain->priority = atoi(gtk_entry_get_text(GTK_ENTRY(priority)));
	}


	gui_add_chain(chain);

	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);

	gnftables_set_chain_init(args->family, args->table, notebook);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));

}



void begin_create_new_table(GtkButton *button, gpointer  info)
{
	const gchar	*name;
	GtkTreeModel	*model;
	GtkTreeIter	iter;
	uint32_t	family;
	struct  new_table  *data;
	int  ret;

	data = (struct  new_table  *)info;

	// get data
	name = gtk_entry_get_text(GTK_ENTRY(data->name));
	model = gtk_combo_box_get_model(GTK_COMBO_BOX(data->family));
	gtk_combo_box_get_active_iter(GTK_COMBO_BOX(data->family), &iter);
	gtk_tree_model_get(model, &iter, 0, &family, -1);

	// check data

	// if all data is valid, submit to kernel.
	ret = gui_add_table(family, (char *)name);
	if (ret != TABLE_SUCCESS) {
//		gtk_label_set_text(GTK_LABEL(data->aaa), table_error[ret]);
		return;
	}

	// back to table list
	gtk_notebook_remove_page(GTK_NOTEBOOK(data->notebook), 0);
	gnftables_table_init(GTK_WIDGET(data->notebook));
	gtk_widget_show_all(GTK_WIDGET(data->notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(data->notebook), 0);
	gtk_widget_queue_draw(GTK_WIDGET(data->notebook));

}


void back_to_chain_list(GtkButton *button, gpointer  info)
{
	struct new_chain  *chain = (struct new_chain *)info;
	GtkWidget	*notebook = chain->notebook;
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);

	gnftables_set_chain_init(chain->family, chain->table, notebook);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


void back_to_table_list (GtkButton *button, gpointer  info)
{
	GtkWidget	*notebook = ((struct new_table *)info)->notebook;
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 0);
//	free(info);
	gnftables_table_init(GTK_WIDGET(notebook));
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}



void create_new_chain(GtkButton *button, gpointer  data)
{
	GtkWidget	*layout;
	GtkWidget	*label;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	GtkWidget	*frame;
	GtkWidget	*layout_chain;
	GtkWidget	*name;
	GtkWidget	*name_value;
	GtkWidget	*name_desc;
	GtkWidget	*family;
	GtkWidget	*family_valuee;
	GtkWidget	*type;
	GtkWidget	*type_value;
	GtkWidget	*hook;
	GtkWidget	*hook_value;
	GtkWidget	*priority;
	GtkWidget	*priority_value;
	GtkWidget	*notebook;

	GtkListStore	*store;
	GtkCellRenderer	*renderer;
	GtkTreeIter	iter;
	struct  basechain_info  *basechain = g_malloc(sizeof(*basechain));
	struct new_chain	*new_chain = g_malloc(sizeof(*new_chain));
	struct chain_list_args	*chain_arg = (struct chain_list_args *)data;
	notebook = chain_arg->notebook;
	new_chain->notebook = notebook;
	new_chain->family = chain_arg->family;
	new_chain->table = chain_arg->table;



	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);

	layout = gtk_layout_new(NULL, NULL);
	label = gtk_label_new("Sets & Chains");
	gtk_widget_set_size_request(label, 200, 10);

	frame = gtk_frame_new ("Create a new chain");
	gtk_container_set_border_width (GTK_CONTAINER(frame), 0);
	gtk_widget_set_size_request(frame, 600, 371);
	gtk_layout_put(GTK_LAYOUT(layout), frame, 150, 40);


	layout_chain = gtk_layout_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(frame), layout_chain);

	name = gtk_label_new("Name:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), name, 30, 30);
	name_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(name_value), 30);
	gtk_layout_put(GTK_LAYOUT(layout_chain), name_value, 100, 30);
	name_desc = gtk_label_new("(no more than 100 characters)");
	gtk_layout_put(GTK_LAYOUT(layout_chain), name_desc, 360, 30);
	new_chain->chain = name_value;

	family = gtk_label_new("basechain:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), family, 30, 80);

	family_valuee = gtk_check_button_new();
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(family_valuee), TRUE);
	gtk_layout_put(GTK_LAYOUT(layout_chain), family_valuee, 100, 80);
	g_signal_connect(family_valuee, "toggled", G_CALLBACK(basechain_selected), basechain);
	new_chain->basechain = family_valuee;


	type = gtk_label_new("Type:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), type, 30, 130);
	store = gtk_list_store_new(1, G_TYPE_STRING);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, "filter", -1);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, "nat", -1);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, "route", -1);
	type_value = gtk_combo_box_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();
	gtk_combo_box_set_active(GTK_COMBO_BOX(type_value), 0);
	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(type_value), renderer, TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(type_value), renderer, "text", 0, NULL);
//	g_signal_connect(type_value, "changed", G_CALLBACK(callback), data);
	gtk_layout_put(GTK_LAYOUT(layout_chain), type_value, 100, 130);
	basechain->type = type;
	basechain->type_value = type_value;
	new_chain->type = type_value;


	hook = gtk_label_new("Hook:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), hook, 30, 180);
	store = gtk_list_store_new(2, G_TYPE_INT, G_TYPE_STRING);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, NF_INET_PRE_ROUTING, 1, "prerouting", -1);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, NF_INET_LOCAL_IN, 1, "input", -1);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, NF_INET_FORWARD, 1, "forward", -1);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, NF_INET_POST_ROUTING, 1, "postrouting", -1);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, NF_INET_LOCAL_OUT, 1, "output", -1);
	hook_value = gtk_combo_box_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();
	gtk_combo_box_set_active(GTK_COMBO_BOX(hook_value), 0);
	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(hook_value), renderer, TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(hook_value), renderer, "text", 1, NULL);
//	g_signal_connect(hook_value, "changed", G_CALLBACK(callback), data);
	gtk_layout_put(GTK_LAYOUT(layout_chain), hook_value, 100, 180);
	basechain->hook = hook;
	basechain->hook_value = hook_value;
	new_chain->hook = hook_value;


	priority = gtk_label_new("Priority:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), priority, 30, 230);
	priority_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(priority_value), 30);
	gtk_layout_put(GTK_LAYOUT(layout_chain), priority_value, 100, 230);
	basechain->priority = priority;
	basechain->priority_value = priority_value;
	new_chain->priority = priority_value;


    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(back_to_chain_list), new_chain);
	gtk_layout_put(GTK_LAYOUT(layout_chain), cancel, 360, 310);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(begin_create_new_chain), new_chain);
	gtk_layout_put(GTK_LAYOUT(layout_chain), ok, 480, 310);


	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, label, 1);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}




void create_new_table(GtkButton *button, gpointer  notebook)
{
	GtkWidget	*layout;
	GtkWidget	*label;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	GtkWidget	*frame;
	GtkWidget	*layout_info;
	GtkWidget	*name;
	GtkWidget	*name_value;
	GtkWidget	*name_desc;
	GtkWidget	*family;
	GtkWidget	*family_value;
	GtkWidget	*msg;

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
	name_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(name_value), 30);
	gtk_layout_put(GTK_LAYOUT(layout_info), name_value, 100, 60);
	name_desc = gtk_label_new("(no more than 100 characters)");
	gtk_layout_put(GTK_LAYOUT(layout_info), name_desc, 360, 60);
	info->name = name_value;

	family = gtk_label_new("Family:");
	gtk_layout_put(GTK_LAYOUT(layout_info), family, 30, 110);


	family_value = create_family_list(0, NULL, NULL);
	gtk_widget_set_size_request(family_value, 30, 10);
	gtk_combo_box_set_active(GTK_COMBO_BOX(family_value), 0);
	gtk_layout_put(GTK_LAYOUT(layout_info), family_value, 100, 110);
	info->family = family_value;

	msg = gtk_label_new("hello world");
	gtk_layout_put(GTK_LAYOUT(layout_info), msg, 30, 250);
//	info->aaa = name_value;

    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(back_to_table_list), info);
	gtk_layout_put(GTK_LAYOUT(layout_info), cancel, 360, 310);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(begin_create_new_table), info);
	gtk_layout_put(GTK_LAYOUT(layout_info), ok, 480, 310);


	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, label, 0);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}



void gnftables_set_rule_init(gint family, gchar *table_name, gchar *chain_name, GtkWidget *notebook)
{

	GtkWidget	*label;
	GtkWidget	*layout;
	GtkWidget	*type;
	GtkWidget	*combo_type;
	GtkWidget	*hook;
	GtkWidget	*combo_hook;
	GtkWidget	*create_table;
	GtkWidget	*tmp;
	GtkWidget	*list_chains;
	GtkWidget	*scrolledwindow;
	GtkTreeIter	iter;
	GtkListStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer1;
	GtkCellRenderer	*renderer2;
	GtkTreeViewColumn	*column;

	struct chain_list_args  *chain_arg = g_malloc(sizeof(*chain_arg));
	chain_arg->notebook = notebook;
	chain_arg->family = family;
	chain_arg->table = table_name;

	store = gtk_tree_store_new(RULE_TOTAL, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);

	label = gtk_label_new("Rules (Chain: input)");
	gtk_widget_set_size_request(label, 200, 10);
	layout = gtk_layout_new(NULL, NULL);


    	create_table = gtk_button_new_with_label("Create Rule");
	gtk_widget_set_size_request(create_table, 150, 10);
	g_signal_connect(G_OBJECT(create_table), "clicked", G_CALLBACK(create_new_chain), chain_arg);
	gtk_layout_put(GTK_LAYOUT(layout), create_table, 700, 10);


	rule_update_data(family, table_name, chain_name, GTK_TREE_STORE(store));

	// treeview style
	list_chains = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	g_signal_connect(list_chains, "button-press-event", G_CALLBACK(show_treeview_menu), NULL); 
	renderer = gtk_cell_renderer_text_new();
	chain_arg->list_chains = list_chains;

	column = gtk_tree_view_column_new_with_attributes("Id", renderer, "text", RULE_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 50);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Table", renderer, "text", RULE_TABLE, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Chain", renderer, "text", RULE_CHAIN, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Selectors", renderer, "text", RULE_CONTENT, NULL);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);


	renderer1 = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer1, "toggled", G_CALLBACK(chain_callback_detail), chain_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Detail", renderer1, "active", RULE_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_max_width(column, 60);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);

	renderer2 = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer2, "toggled", G_CALLBACK(chain_callback_delete), chain_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Delete", renderer2, "active", RULE_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_max_width(column, 60);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);



        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolledwindow), 876);
	gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolledwindow), 410);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), GTK_SHADOW_ETCHED_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
                                GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_chains);

	gtk_layout_put(GTK_LAYOUT(layout), scrolledwindow, 0, 50);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, label, 2);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
}




void chain_callback_detail(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*chain;
	GtkTreeModel		*model;
	GtkTreeView		*treeview;
	GtkWidget		*notebook;
	struct chain_list_args	*chain_args = (struct chain_list_args *)data;

	treeview = GTK_TREE_VIEW(chain_args->list_chains);
	table = chain_args->table;
	family = chain_args->family;
	notebook = chain_args->notebook;

	model = gtk_tree_view_get_model(treeview);
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, CHAIN_NAME, &chain, -1);

	// check chain exists
	// if ((!chain exists) && !(table exits))
	// 	show tables list page
	// else (!(chain exists))
	// 	chain_update_data(family, table, GTK_TREE_STORE(model));
	// else
	// 	show rule list page
		gnftables_set_rule_init(family, table, chain, notebook);

	return;


}

void basechain_selected(GtkWidget *check_button, gpointer data) 
{
	struct basechain_info  *basechain = (struct basechain_info *)data;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check_button))) {
		gtk_widget_show(GTK_WIDGET(basechain->type));
		gtk_widget_show(GTK_WIDGET(basechain->type_value));
		gtk_widget_show(GTK_WIDGET(basechain->hook));
		gtk_widget_show(GTK_WIDGET(basechain->hook_value));
		gtk_widget_show(GTK_WIDGET(basechain->priority));
		gtk_widget_show(GTK_WIDGET(basechain->priority_value));
	} else {
		gtk_widget_hide(GTK_WIDGET(basechain->type));
		gtk_widget_hide(GTK_WIDGET(basechain->type_value));
		gtk_widget_hide(GTK_WIDGET(basechain->hook));
		gtk_widget_hide(GTK_WIDGET(basechain->hook_value));
		gtk_widget_hide(GTK_WIDGET(basechain->priority));
		gtk_widget_hide(GTK_WIDGET(basechain->priority_value));
	}
}


void chain_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*chain;
	GtkTreeModel		*model;
	GtkTreeView		*treeview;
	struct chain_list_args	*chain_args = (struct chain_list_args *)data;

	gint	res;
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_WARNING,
                                 GTK_BUTTONS_OK_CANCEL,
                                 "The chain and all rules in the chain will be deleted. Are you sure?"
                                 );

	treeview = GTK_TREE_VIEW(chain_args->list_chains);
	table = chain_args->table;
	family = chain_args->family;

	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = gtk_tree_view_get_model(treeview);
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, CHAIN_NAME, &chain, -1);

		gui_delete_chain(family, table, chain);
		chain_update_data(family, table, GTK_TREE_STORE(model));
	}

	gtk_widget_destroy(dialog);
	return;
}


void rule_update_data(gint family, gchar *table_name, gchar *chain_name, GtkTreeStore *store)
{
	uint32_t	index = 0;
	GtkTreeIter	iter;

	struct gui_rule   *rule;
	LIST_HEAD(rule_list);

	gui_get_rules_list(&rule_list, family, table_name, chain_name);

	gtk_tree_store_clear (store);



	// display rules in treeview
	list_for_each_entry(rule, &rule_list, list) {
		index++;
		gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
		gtk_tree_store_set(GTK_TREE_STORE(store), &iter, RULE_ID, index, RULE_TABLE, rule->table, RULE_CHAIN, rule->chain, RULE_CONTENT, rule->stmt, RULE_DETAIL, TRUE, RULE_DELETE, TRUE, -1);
		gui_rule_free(rule);	
	}
}


void chain_update_data(gint family, gchar *table_name, GtkTreeStore *store)
{
	uint32_t	index = 0;
	GtkTreeIter	iter;

	struct gui_chain   *chain;
	LIST_HEAD(chain_list);

	gui_get_chains_list(&chain_list, family, table_name);

	gtk_tree_store_clear (store);

	// display chains in treeview
	list_for_each_entry(chain, &chain_list, list) {
		index++;
		gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
		if (chain->basechain) {
			char	priority[50];
			sprintf(priority, "%d", chain->priority);
			gtk_tree_store_set(GTK_TREE_STORE(store), &iter, CHAIN_ID, index, CHAIN_NAME, chain->chain, CHAIN_TABLE, chain->table, CHAIN_RULES, chain->nrules, CHAIN_BASECHAIN, "Yes", CHAIN_TYPE, chain->type, CHAIN_HOOK, hooknum2str(family, chain->hook), CHAIN_PRIORITY, priority, CHAIN_DETAIL, TRUE, CHAIN_DELETE, TRUE, -1);
		} else 
			gtk_tree_store_set(GTK_TREE_STORE(store), &iter, CHAIN_ID, index, CHAIN_NAME, chain->chain, CHAIN_TABLE, chain->table, CHAIN_RULES, chain->nrules, CHAIN_BASECHAIN, "No", CHAIN_TYPE, "X", CHAIN_HOOK, "X", CHAIN_PRIORITY, "X", CHAIN_DETAIL, TRUE, CHAIN_DELETE, TRUE, -1);
		gui_chain_free(chain);	
	}
}




// zzzz
void gnftables_set_chain_init(gint family, gchar *table_name, GtkWidget *notebook)
{

	GtkWidget	*label;
	GtkWidget	*layout;
	GtkWidget	*type;
	GtkWidget	*combo_type;
	GtkWidget	*hook;
	GtkWidget	*combo_hook;
	GtkWidget	*create_table;
	GtkWidget	*list_chains;
	GtkWidget	*scrolledwindow;
	GtkTreeIter	iter;
	GtkListStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer1;
	GtkCellRenderer	*renderer2;
	GtkTreeViewColumn	*column;

	struct chain_list_args  *chain_arg = g_malloc(sizeof(*chain_arg));
	chain_arg->notebook = notebook;
	chain_arg->family = family;
	chain_arg->table = table_name;

	store = gtk_tree_store_new(CHAIN_TOTAL, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);

	label = gtk_label_new("Sets & Chains (Table: filter)");
	gtk_widget_set_size_request(label, 200, 10);
	layout = gtk_layout_new(NULL, NULL);


	type = gtk_label_new("Type");
	gtk_layout_put(GTK_LAYOUT(layout), type, 10, 10);

	combo_type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(combo_type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "all", "all");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "user", "user");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "filter", "filter");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "nat", "nat");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type), "route", "route");
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_type), 0);
	gtk_layout_put(GTK_LAYOUT(layout), combo_type, 90, 10);


	hook = gtk_label_new("Hook");
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
	g_signal_connect(G_OBJECT(create_table), "clicked", G_CALLBACK(create_new_chain), chain_arg);
	gtk_layout_put(GTK_LAYOUT(layout), create_table, 700, 10);


	chain_update_data(family, table_name, GTK_TREE_STORE(store));

	// treeview style
	list_chains = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	g_signal_connect(list_chains, "button-press-event", G_CALLBACK(show_treeview_menu), NULL); 
	renderer = gtk_cell_renderer_text_new();
	chain_arg->list_chains = list_chains;

	column = gtk_tree_view_column_new_with_attributes("Id", renderer, "text", CHAIN_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 50);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer, "text", CHAIN_NAME, NULL);
	gtk_tree_view_column_set_min_width(column, 150);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Table", renderer, "text", CHAIN_TABLE, NULL);
	gtk_tree_view_column_set_min_width(column, 150);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Rules", renderer, "text", CHAIN_RULES, NULL);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Base Chain", renderer, "text", CHAIN_BASECHAIN, NULL);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Type", renderer, "text", CHAIN_TYPE, NULL);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Hook", renderer, "text", CHAIN_HOOK, NULL);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Priority", renderer, "text", CHAIN_PRIORITY, NULL);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);


	renderer1 = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer1, "toggled", G_CALLBACK(chain_callback_detail), chain_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Detail", renderer1, "active", CHAIN_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);

	renderer2 = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer2, "toggled", G_CALLBACK(chain_callback_delete), chain_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Delete", renderer2, "active", CHAIN_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);



        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolledwindow), 876);
	gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolledwindow), 410);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), GTK_SHADOW_ETCHED_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
                                GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_chains);

	gtk_layout_put(GTK_LAYOUT(layout), scrolledwindow, 0, 50);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, label, 1);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
}


void table_update_data(gint family, GtkTreeStore *store)
{
	uint32_t	index = 0;
	GtkTreeIter	iter;

	struct gui_table   *table;
	LIST_HEAD(table_list);

	// only ipve is supported now.
	gui_get_tables_list(&table_list, NFPROTO_IPV4);

	gtk_tree_store_clear (store);

	// display tables in treeview
	list_for_each_entry(table, &table_list, list) {
		index++;
		gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
		if (table->family == NFPROTO_IPV4)
			gtk_tree_store_set(GTK_TREE_STORE(store), &iter, TABLE_ID, index, TABLE_NAME, table->table, TABLE_FAMILY, "ipv4", TABLE_SETS, table->nsets, TABLE_CHAINS, table->nchains, TABLE_DETAIL, TRUE, TABLE_DELETE, TRUE, -1);
		else
			gtk_tree_store_set(GTK_TREE_STORE(store), &iter, TABLE_ID, index, TABLE_NAME, table->table, TABLE_FAMILY, family2str(table->family), TABLE_SETS, table->nsets, TABLE_CHAINS, table->nchains, TABLE_DETAIL, TRUE, TABLE_DELETE, TRUE, -1);
		
	}
}


void select_family(GtkComboBox *widget, gpointer data)
{
	GtkTreeModel	*model;
	GtkTreeIter	iter;
	uint32_t	family;
	GtkTreeStore	*store = GTK_TREE_STORE(data);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget));
	gtk_combo_box_get_active_iter(GTK_COMBO_BOX(widget), &iter);
	gtk_tree_model_get(model, &iter, 0, &family, -1);

	table_update_data(family, store);

}


GtkWidget *create_family_list(gint list, void (*callback)(GtkComboBox *widget, gpointer data), gpointer data)
{
	GtkWidget	*combo;
	GtkListStore	*store;
	GtkTreeIter	iter;
	GtkCellRenderer	*renderer;

	store = gtk_list_store_new(2, G_TYPE_INT, G_TYPE_STRING);
	if (list) {
		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter, 0, NFPROTO_UNSPEC, 1, "all", -1);
	}
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, 0, NFPROTO_IPV4, 1, "ipv4", -1);

	combo = gtk_combo_box_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);

	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo), renderer, TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo), renderer, "text", 1, NULL);
	if (callback)
		g_signal_connect(combo, "changed", G_CALLBACK(callback), data);
	return combo;
}


void table_callback_detail(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	gchar			*name;
	gchar			*family_str;
	int			family;
	GtkTreeModel		*model;
	int			res;

	struct list_sets_and_chains  *info = (struct list_sets_and_chains *)data;
	GtkWidget	*treeview = info->treeview;
	GtkWidget	*notebook = info->notebook;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, TABLE_NAME, &name, TABLE_FAMILY, &family_str, -1);
	family = str2family(family_str);

//	res = gui_check_table_exist(family, name);
//	if (res == TABLE_SUCCESS)
		gnftables_set_chain_init(family, name, notebook);
//	else
//		table_update_data(NFPROTO_UNSPEC, GTK_TREE_STORE(model));
//	g_free(name);		// 这些不能随便删，那么会不会造成内存泄漏呢???
//	g_free(family_str);
}

void table_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	gchar			*name;
	gchar			*family_str;
	int			family;
	GtkTreeModel		*model;

	gint	res;
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new (GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_WARNING,
                                 GTK_BUTTONS_OK_CANCEL,
                                 "The table and all rules in the table will be deleted. Are you sure?"
                                 );

	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, TABLE_NAME, &name, TABLE_FAMILY, &family_str, -1);

		family = str2family(family_str);
		gui_delete_table(family, name);
		table_update_data(NFPROTO_UNSPEC, GTK_TREE_STORE(model));

		g_free(name);
		g_free(family_str);
	}

	gtk_widget_destroy(dialog);
	return;
}


gboolean show_treeview_menu(GtkWidget *widget, GdkEvent  *event, gpointer   user_data)
{
	if (event->type == GDK_BUTTON_PRESS && event->button.button == 3)  { 
		printf("hello world\n");
	} 

	return FALSE;
}



void gnftables_table_init(GtkWidget *notebook)
{
	GtkWidget	*label;
	GtkWidget	*layout;
	GtkWidget	*proto;
	GtkWidget	*combo;
	GtkWidget	*create_table;
	GtkWidget	*list_tables;
	GtkWidget	*scrolledwindow;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer1;
	GtkCellRenderer	*renderer2;
	GtkTreeViewColumn *column;

	struct list_sets_and_chains  *data = malloc(sizeof(*data));

	store = gtk_tree_store_new(TABLE_TOTAL, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);

	label = gtk_label_new("Table (all)");
	gtk_widget_set_size_request(label, 200, 10);
	layout = gtk_layout_new(NULL, NULL);


	proto = gtk_label_new("Protocol ");
	gtk_layout_put(GTK_LAYOUT(layout), proto, 10, 10);

	combo = create_family_list(1, select_family, store);
	gtk_layout_put(GTK_LAYOUT(layout), combo, 90, 10);


    	create_table = gtk_button_new_with_label("Create Table");
	gtk_widget_set_size_request(create_table, 150, 10);
	g_signal_connect(G_OBJECT(create_table), "clicked", G_CALLBACK(create_new_table), notebook);
	gtk_layout_put(GTK_LAYOUT(layout), create_table, 700, 10);


	table_update_data(NFPROTO_UNSPEC, store);


	// treeview style
	list_tables = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	g_signal_connect(list_tables, "button-press-event", G_CALLBACK(show_treeview_menu), NULL); 
	renderer = gtk_cell_renderer_text_new();
//	g_object_set(G_OBJECT(renderer), "foreground", "red", NULL);
	column = gtk_tree_view_column_new_with_attributes("Id", renderer, "text", TABLE_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer, "text", TABLE_NAME, NULL);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Family", renderer, "text", TABLE_FAMILY, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Sets", renderer, "text", TABLE_SETS, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Chains", renderer, "text", TABLE_CHAINS, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

	renderer1 = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer1, "toggled", G_CALLBACK(table_callback_detail), data) ;
	column = gtk_tree_view_column_new_with_attributes("Detail", renderer1, "active", TABLE_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 140);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

	renderer2 = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer2, "toggled", G_CALLBACK(table_callback_delete), list_tables) ;
	column = gtk_tree_view_column_new_with_attributes("Delete", renderer2, "active", TABLE_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

	data->treeview = list_tables;
	data->notebook = notebook;

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

	const gchar *text = "gnftables 0.1.0\n\ngnftables is a gui tool aimed to simplify the configuration of nftables from command line. It's in heavy develpment now. If you need more help, please visit the project's home site (http://ycnian.org/projects/gnftables.php).\n\nCopyright (c) 2014  Yanchuan Nian <ycnian@gmail.com>\n\nThis program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the licence, or (at your option) any later version.\n\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.\n\nYou should have received a copy of the GNU General Public License along with this program. You may also obtain a copy of the GNU General Public License from the Free Software Foundation by visiting their web site (http://www.fsf.org/) or by writing to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA";
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
//	GtkWidget	*window;
	GtkWidget	*layout;
	GtkWidget	*button;
	GtkWidget	*notebook;

	



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


	gnftables_table_init(notebook);
	gnftables_about_init(notebook);


	gtk_notebook_set_current_page (GTK_NOTEBOOK (notebook), 0);
	g_signal_connect(G_OBJECT(notebook), "switch-page", G_CALLBACK(select_page), notebook);


	button = gtk_button_new_with_label("Load rules from file");
	g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(load_rules), NULL);
	gtk_widget_set_size_request(button, 445, 10);
	gtk_layout_put(GTK_LAYOUT(layout), button, 0, 500);

	button = gtk_button_new_with_label("Save rules to file");
	g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK(save_rules), notebook);
	gtk_widget_set_size_request(button, 445, 10);
	gtk_layout_put(GTK_LAYOUT(layout), button, 455, 500);
    

	gtk_widget_show_all(window);
	gtk_main ();

	return 0;
}



