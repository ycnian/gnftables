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
#include <gui_expression.h>
#include <gui_datacheck.h>
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
		tables_fprint(filename);
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


//  nft add rule ip filter input ip saddr 192.168.1.101 ip daddr 192.168.1.102  counter accept
void begin_create_new_rule(GtkButton *button, gpointer  info)
{
	GtkWidget	*notebook;
	int		res;
	struct rule_create_widget	*widget;
	struct rule_create_data		*data;

	widget = (struct rule_create_widget *)info;
	notebook = widget->notebook;

	// check table exists
	res = gui_check_table_exist(widget->family, widget->table);
	if (res == TABLE_NOT_EXIST) {
		gtk_label_set_text(GTK_LABEL(widget->msg), rule_error[RULE_TABLE_NOT_EXIST]);
		return;
	} else if (res == TABLE_KERNEL_ERROR) {
		gtk_label_set_text(GTK_LABEL(widget->msg), rule_error[RULE_KERNEL_ERROR]);
		return;
	}

	// check chain exists
	res = gui_check_chain_exist(widget->family, widget->table, widget->chain);
	if (res == CHAIN_NOT_EXIST) {
		gtk_label_set_text(GTK_LABEL(widget->msg), rule_error[RULE_CHAIN_NOT_EXIST]);
		return;
	} else if (res == CHAIN_KERNEL_ERROR) {
		gtk_label_set_text(GTK_LABEL(widget->msg), rule_error[CHAIN_KERNEL_ERROR]);
		return;
	}

	// get data
	res = rule_create_getdata(widget, &data);
	// rule_gen_expressions(gui_rule, rule);
	if (res != RULE_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), rule_error[res]);
		return;
	}

	data->family = widget->family;
	data->table = xstrdup(widget->table);
	data->chain = xstrdup(widget->chain);
	data->handle = widget->handle;
	res = gui_add_rule(data);
	// xfree(data);
	if (res != CHAIN_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), chain_error[res]);
		return;
	}


	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 2);
	gnftables_rule_init(widget->family, widget->table, widget->chain, notebook);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));

}

void begin_create_new_set(GtkButton *button, gpointer  info)
{
	GtkWidget	*notebook;
	int		res;
	struct chain_list_args *datac;
	struct set_create_widget *widget;
	struct set_create_data	*data = NULL;

	widget = (struct set_create_widget *)info;
	notebook = widget->notebook;

	// check table exists
	res = gui_check_table_exist(widget->family, widget->table);
	if (res == TABLE_NOT_EXIST) {
		gtk_label_set_text(GTK_LABEL(widget->msg), set_error[SET_TABLE_NOT_EXIST]);
		return;
	} else if (res == TABLE_KERNEL_ERROR) {
		gtk_label_set_text(GTK_LABEL(widget->msg), set_error[SET_KERNEL_ERROR]);
		return;
	}

	// get data
	res = set_create_getdata(widget, &data);
	if (res != SET_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), set_error[res]);
		return;
	}

	if (widget->create)
		res = gui_add_set(data);
	else
		res = gui_edit_set(data);
//	xfree(data->table);
//	xfree(data->set);
	xfree(data);
	if (res != SET_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), set_error[res]);
		return;
	}

	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);
	datac = xzalloc(sizeof(struct chain_list_args));
	datac->notebook = widget->notebook;
	datac->family = widget->family;
	datac->table = widget->table;
	gnftables_set_init(NULL, datac);
}

/*
 * Get data from chain creating page and send NFT_MSG_NEWCHAIN message to kernel.
 */
void begin_create_new_chain(GtkButton *button, gpointer  info)
{
	GtkWidget	*notebook;
	int		res;
	struct chain_create_widget	*widget;
	struct chain_create_data	*data = NULL;

	widget = (struct chain_create_widget *)info;
	notebook = widget->notebook;

	// check table exists
	res = gui_check_table_exist(widget->family, widget->table);
	if (res == TABLE_NOT_EXIST) {
		gtk_label_set_text(GTK_LABEL(widget->msg), chain_error[CHAIN_TABLE_NOT_EXIST]);
		return;
	} else if (res == TABLE_KERNEL_ERROR) {
		gtk_label_set_text(GTK_LABEL(widget->msg), chain_error[CHAIN_KERNEL_ERROR]);
		return;
	}

	// get data
	res = chain_create_getdata(widget, &data);
	if (res != CHAIN_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), chain_error[res]);
		return;
	}

	res = gui_add_chain(data);
	xfree(data->table);
	xfree(data->chain);
	xfree(data->type);
	xfree(data);
	if (res != CHAIN_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), chain_error[res]);
		return;
	}

	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);

	gnftables_set_chain_init(widget->family, widget->table, notebook);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


/*
 * Get data from table creating page, and send netlink message to kernel.
 * @button:  OK button in table creating page
 * @info:    instance of struct table_create_widget
 */
void begin_create_new_table(GtkButton *button, gpointer  info)
{
	struct  table_create_widget	*widget;
	struct	table_create_data	*data = NULL;
	int  res;

	widget = (struct table_create_widget  *)info;

	// get data
	res = table_create_getdata(widget, &data);
	if (res != TABLE_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), table_error[res]);
		return;
	}

	// if all data is valid, submit to kernel.
	res = gui_add_table(data);
	xfree(data->table);
	xfree(data);
	if (res != TABLE_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), table_error[res]);
		return;
	}

	// back to table list
	gtk_notebook_remove_page(GTK_NOTEBOOK(widget->notebook), 0);
	gnftables_table_init(GTK_WIDGET(widget->notebook));
	gtk_widget_show_all(GTK_WIDGET(widget->notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(widget->notebook), 0);
	gtk_widget_queue_draw(GTK_WIDGET(widget->notebook));
}


void back_to_rule_list(GtkButton *button, gpointer  info)
{
	struct rule_create_widget  *rule = (struct rule_create_widget *)info;
	GtkWidget	*notebook = rule->notebook;
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 2);

	gnftables_rule_init(rule->family, rule->table, rule->chain, notebook);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}

void back_to_set_list(GtkButton *button, gpointer info)
{
	struct chain_list_args *data;
	struct set_create_widget  *args;
	args = (struct set_create_widget *)info;
	data = xzalloc(sizeof(struct chain_list_args));
	GtkWidget	*notebook = args->notebook;
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);

	data->notebook = args->notebook;
	data->family = args->family;
	data->table = args->table;
	gnftables_set_init(NULL, data);
}


void back_to_chain_list(GtkButton *button, gpointer  info)
{
	struct chain_create_widget  *args = (struct chain_create_widget *)info;
	GtkWidget	*notebook = args->notebook;
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);

	gnftables_set_chain_init(args->family, args->table, notebook);
}

/*
 * Back to table list page
 */
void back_to_table_list(GtkButton *button, gpointer args)
{
	GtkWidget	*notebook;
	notebook = ((struct table_create_widget *)args)->notebook;
	xfree(args);
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 0);
	gnftables_table_init(GTK_WIDGET(notebook));
}


static void expander_callback (GObject    *object,
                   GParamSpec *param_spec,
                   gpointer    user_data)
{
	GtkExpander		*expander;
	struct rule_create_widget	*widget;

	expander = GTK_EXPANDER(object);
	widget = (struct rule_create_widget *)user_data;

	if ((void *)expander == (void *)(widget->header->expander)) {
		if (gtk_expander_get_expanded(expander))
			widget->header->expanded = 1;
		else
			widget->header->expanded = 0;
		update_pktmeta_position(widget);
		update_actions_position(widget);
		update_cancel_ok_position(widget);
	} else if ((void *)expander == (void *)(widget->meta->expander)) {
		if (gtk_expander_get_expanded(expander))
			widget->meta->expanded = 1;
		else
			widget->meta->expanded = 0;
		update_actions_position(widget);
		update_cancel_ok_position(widget);
	} else if ((void *)expander == (void *)(widget->actions->expander)) {
		if (gtk_expander_get_expanded(expander))
			widget->actions->expanded = 1;
		else
			widget->actions->expanded = 0;
		update_cancel_ok_position(widget);
	}
}

void header_transport_porttype_changed(struct transport_port_info  *port_info)
{
	switch (port_info->value->type) {
	case PORT_EXACT:
		gtk_entry_set_text(GTK_ENTRY(port_info->value->portlist.port), "");
		gtk_widget_show(port_info->value->portlist.port);
		gtk_widget_hide(port_info->value->range.from);
		gtk_widget_hide(port_info->value->range.dash);
		gtk_widget_hide(port_info->value->range.to);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(port_info->exclude), FALSE);
		break;
	case PORT_RANGE:
		gtk_widget_hide(port_info->value->portlist.port);
		gtk_entry_set_text(GTK_ENTRY(port_info->value->range.from), "");
		gtk_widget_show(port_info->value->range.from);
		gtk_widget_show(port_info->value->range.dash);
		gtk_entry_set_text(GTK_ENTRY(port_info->value->range.to), "");
		gtk_widget_show(port_info->value->range.to);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(port_info->exclude), FALSE);
		break;
	case PORT_SET:
		break;
	}

}

void header_transport_show_all(GtkWidget *fixed, struct transport_info *transport)
{
	gtk_widget_hide(transport->fixed);
	gtk_widget_hide(transport->fixed);
}

void header_transport_show_tcp(GtkWidget *fixed, struct transport_info *transport)
{
	gtk_widget_hide(transport->fixed);
	gtk_widget_show(transport->fixed);
	header_transport_porttype_changed(transport->tcp->sport);
	header_transport_porttype_changed(transport->tcp->dport);
}

void header_transport_show_udp(GtkWidget *fixed, struct transport_info *transport)
{
	gtk_widget_hide(transport->fixed);
	gtk_widget_show(transport->fixed);
	header_transport_porttype_changed(transport->udp->sport);
	header_transport_porttype_changed(transport->udp->dport);
}


void update_header_transport_widgets(GtkWidget *fixed, struct transport_info *transport)
{
	enum transport_type type = transport->type;
	switch (type) {
	case TRANSPORT_ALL:
		header_transport_show_all(fixed, transport);
		break;
	case TRANSPORT_TCP:
		header_transport_show_tcp(fixed, transport);
		break;
	case TRANSPORT_UDP:
		header_transport_show_udp(fixed, transport);
		break;
	default:
		break;
	}
}

void update_pktmeta_position(struct rule_create_widget  *widget)
{
	GtkWidget  *fixed = widget->fixed;
	GtkWidget  *expander = widget->meta->expander;
	int	len = 0;
	if (widget->header->expanded)
		len += widget->header->len;
	len += 40;

	gtk_fixed_move(GTK_FIXED(fixed), expander, 0, len);
}

void update_actions_position(struct rule_create_widget  *widget)
{
	GtkWidget  *fixed = widget->fixed;
	GtkWidget  *expander = widget->actions->expander;
	int	len = 0;
	if (widget->header->expanded)
		len += widget->header->len;
	if (widget->meta->expanded)
		len += widget->meta->len;
	len += 80;

	gtk_fixed_move(GTK_FIXED(fixed), expander, 0, len);
}

void update_cancel_ok_position(struct rule_create_widget  *widget)
{
	GtkWidget  *fixed = widget->fixed;
	GtkWidget  *msg = widget->msg;
	GtkWidget  *cancel = widget->cancel;
	GtkWidget  *ok = widget->ok;
	int	len = 0;
	if (widget->header->expanded)
		len +=  widget->header->len;
	if (widget->meta->expanded)
		len +=  widget->meta->len;
	if (widget->actions->expanded)
		len +=  widget->actions->len;
	len += 120;
	if (len < 360)
		len = 360;
	gtk_fixed_move(GTK_FIXED(fixed), msg, 40, len);
	gtk_fixed_move(GTK_FIXED(fixed), cancel, 540, len);
	gtk_fixed_move(GTK_FIXED(fixed), ok, 660, len);
}


void transport_callback_do(struct rule_create_widget  *widget)
{
	GtkWidget	*fixed_header = widget->header->fixed;
	struct transport_info *transport = widget->header->transport.value;
	update_header_transport_widgets(fixed_header, transport);
	update_pktmeta_position(widget);
	update_actions_position(widget);
	update_cancel_ok_position(widget);
}

static void header_addr_exactip_show(struct ip_address *addr)
{
	gtk_entry_set_text(GTK_ENTRY(addr->exact_ip.ip), "");
	gtk_widget_show(addr->exact_ip.ip);
}

static void header_addr_exactip_hide(struct ip_address *addr)
{
	gtk_widget_hide(addr->exact_ip.ip);
}

static void header_addr_subnet_show(struct ip_address *addr)
{
	gtk_entry_set_text(GTK_ENTRY(addr->subnet.ip), "");
	gtk_entry_set_text(GTK_ENTRY(addr->subnet.mask), "");
	gtk_widget_show(addr->subnet.ip);
	gtk_widget_show(addr->subnet.slash);
	gtk_widget_show(addr->subnet.mask);
}

static void header_addr_subnet_hide(struct ip_address *addr)
{
	gtk_widget_hide(addr->subnet.ip);
	gtk_widget_hide(addr->subnet.slash);
	gtk_widget_hide(addr->subnet.mask);
}

static void header_addr_range_show(struct ip_address *addr)
{
	gtk_entry_set_text(GTK_ENTRY(addr->range.from), "");
	gtk_entry_set_text(GTK_ENTRY(addr->range.to), "");
	gtk_widget_show(addr->range.from);
	gtk_widget_show(addr->range.dash);
	gtk_widget_show(addr->range.to);
}

static void header_addr_range_hide(struct ip_address *addr)
{
	gtk_widget_hide(addr->range.from);
	gtk_widget_hide(addr->range.dash);
	gtk_widget_hide(addr->range.to);
}

static void header_addr_callback(GtkComboBoxText *widget, gpointer data)
{
	struct ip_address	*addr;
	struct match_header	*args;
	args = (struct match_header *)data;

	if ((void *)widget == (void *)args->saddr.type)
		addr = args->saddr.value;
	else
		addr = args->daddr.value;

	char	*type = gtk_combo_box_text_get_active_text(widget);
	if (!(strcmp(type, "exact ip"))) {
		addr->type = ADDRESS_EXACT;
		header_addr_subnet_hide(addr);
		header_addr_range_hide(addr);
		header_addr_exactip_show(addr);
	} else if (!(strcmp(type, "subnet"))) {
		addr->type = ADDRESS_SUBNET;
		header_addr_exactip_hide(addr);
		header_addr_range_hide(addr);
		header_addr_subnet_show(addr);
	} else if (!(strcmp(type, "range"))) {
		addr->type = ADDRESS_RANGE;
		header_addr_exactip_hide(addr);
		header_addr_subnet_hide(addr);
		header_addr_range_show(addr);
	}
	// else
	// 	bug();
}

void header_daddr_exclude(GtkWidget *check_button, gpointer data) 
{
	struct ip_address	*daddr;
	struct rule_create_widget  *args;
	args = (struct rule_create_widget *)data;
	daddr = args->header->daddr.value;

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check_button)))
		daddr->exclude = 1;
	else
		daddr->exclude = 0;
}

void header_trans_port_init(const char *string, GtkWidget *fixed, int vertical,
		struct transport_port_info *port,
		void (* porttype_callback)(GtkComboBoxText *widget, gpointer data),
		void (* port_exclude)(GtkWidget *check_button, gpointer data))
{
	GtkWidget	*label;
	GtkWidget	*type;
	GtkWidget	*exclude;
	GtkWidget	*protlist;
	GtkWidget	*range_from;
	GtkWidget	*range_dash;
	GtkWidget	*range_to;

	label = gtk_label_new(string);
	gtk_fixed_put(GTK_FIXED(fixed), label, 40, vertical);
	port->label = label;

	type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type),
			"port list", "port list");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type),
			"range", "range");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type),
//			"sets", "sets");
	gtk_combo_box_set_active(GTK_COMBO_BOX(type), 0);
	g_signal_connect(type, "changed", G_CALLBACK(porttype_callback), port);
	gtk_fixed_put(GTK_FIXED(fixed), type, 150, vertical);
	port->type = type;

	exclude = gtk_check_button_new_with_label("Exclude");
	g_signal_connect(exclude, "toggled", G_CALLBACK(port_exclude), port);
	gtk_fixed_put(GTK_FIXED(fixed), exclude, 700, vertical);
	port->exclude = exclude;
	port->value->exclude = 0;

	protlist = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(protlist), 47);
	gtk_fixed_put(GTK_FIXED(fixed), protlist, 280, vertical);
	port->value->type = PORT_EXACT;
	port->value->portlist.port = protlist;

	range_from = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(range_from), 20);
	gtk_fixed_put(GTK_FIXED(fixed), range_from, 280, vertical);
	port->value->range.from = range_from;
	range_dash = gtk_label_new("-");
	gtk_fixed_put(GTK_FIXED(fixed), range_dash, 470, vertical);
	port->value->range.dash = range_dash;
	range_to = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(range_to), 20);
	gtk_fixed_put(GTK_FIXED(fixed), range_to, 500, vertical);
	port->value->range.to = range_to;
}

void header_trans_all_init()
{

}

void transport_port_callback(GtkComboBoxText *widget, gpointer data)
{
	struct transport_port_info  *port_info;
	port_info = (struct transport_port_info *)data;

	char	*type = gtk_combo_box_text_get_active_text(widget);
	if (!(strcmp(type, "port list")))
		port_info->value->type = PORT_EXACT;
	else if (!(strcmp(type, "range")))
		port_info->value->type = PORT_RANGE;
	// else
	// 	bug();

	header_transport_porttype_changed(port_info);
}

void transport_port_exclude(GtkWidget *check_button, gpointer data)
{
	struct transport_port_info  *port_info;
	port_info = (struct transport_port_info *)data;

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check_button)))
		port_info->value->exclude = 1;
	else
		port_info->value->exclude = 0;
}

// zzzzz
void header_trans_tcp_init(GtkWidget *fixed, struct transport_port_info *sport, struct transport_port_info *dport)
{
	header_trans_port_init("source port:", fixed, 0, sport,
		transport_port_callback, transport_port_exclude);
	header_trans_port_init("dest port:", fixed, 40, dport,
		transport_port_callback, transport_port_exclude);
}

void header_trans_udp_init(GtkWidget *fixed, struct transport_port_info *sport, struct transport_port_info *dport)
{
	header_trans_port_init("source port:", fixed, 0, sport,
		transport_port_callback, transport_port_exclude);
	header_trans_port_init("dest port:", fixed, 40, dport,
		transport_port_callback, transport_port_exclude);
}

void create_new_rule(GtkButton *button, gpointer  data)
{
	create_new_rule_begin(data);
}

struct rule_create_widget *rule_widget_container_create(struct rule_list_args *rule_arg)
{
	struct rule_create_widget	*container;
	container = xzalloc(sizeof(struct rule_create_widget));

	container->header = xzalloc(sizeof(struct match_header));
	container->header->saddr.value = xzalloc(sizeof(struct ip_address));
	container->header->daddr.value = xzalloc(sizeof(struct ip_address));
	container->header->transport.value = xzalloc(sizeof(struct transport_info));

	container->header->transport.value->all = xzalloc(sizeof(struct transport_all));
	container->header->transport.value->tcp = xzalloc(sizeof(struct transport_tcp));
	container->header->transport.value->tcp->sport = xzalloc(sizeof(struct transport_port_info));
	container->header->transport.value->tcp->sport->value = xzalloc(sizeof(struct transport_port_details));
	container->header->transport.value->tcp->dport = xzalloc(sizeof(struct transport_port_info));
	container->header->transport.value->tcp->dport->value = xzalloc(sizeof(struct transport_port_details));
	container->header->transport.value->udp = xzalloc(sizeof(struct transport_udp));
	container->header->transport.value->udp->sport = xzalloc(sizeof(struct transport_port_info));
	container->header->transport.value->udp->sport->value = xzalloc(sizeof(struct transport_port_details));
	container->header->transport.value->udp->dport = xzalloc(sizeof(struct transport_port_info));
	container->header->transport.value->udp->dport->value = xzalloc(sizeof(struct transport_port_details));

	container->meta = xzalloc(sizeof(struct match_pktmeta));
	container->track = xzalloc(sizeof(struct match_trackmeta));
	container->actions = xzalloc(sizeof(struct actions_all));
	init_list_head(&container->actions->list);

	container->notebook = rule_arg->notebook;
	container->family = rule_arg->family;
	container->table = xstrdup(rule_arg->table);
	container->chain = xstrdup(rule_arg->chain);
	container->handle = rule_arg->handle;

	return container;
}

static void rule_add_content_header_addr(struct match_header *header, struct ip_addr_data *addr, int source)
{
	GtkWidget	*addr_label;
	GtkWidget	*fixed;
	GtkWidget	*addr_type;
	GtkWidget	*addr_not;
	GtkWidget	*addr_exact_ip;
	GtkWidget	*addr_subnet_ip;
	GtkWidget	*addr_subnet_slash;
	GtkWidget	*addr_subnet_mask;
	GtkWidget	*addr_range_from;
	GtkWidget	*addr_range_dash;
	GtkWidget	*addr_range_to;
	int		offset;
	char		*label;
	struct ip_address	*ipaddr;

	fixed = header->fixed;
	header->len += 40;
	if (source) {
		ipaddr = header->saddr.value;
		offset = 0;
		label = "source addr:";
	} else {
		ipaddr = header->daddr.value;
		offset = 40;
		label = "dest addr:";
	}
	addr_label = gtk_label_new(label);
	gtk_fixed_put(GTK_FIXED(fixed), addr_label, 40, offset);
	addr_type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(addr_type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(addr_type),
			"exact ip", "exact ip");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(addr_type),
			"subnet", "subnet");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(addr_type),
			"range", "range");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(addr_type),
//			"sets", "sets");
	gtk_fixed_put(GTK_FIXED(fixed), addr_type, 150, offset);
	if (source)
		header->saddr.type = addr_type;
	else
		header->daddr.type = addr_type;
	g_signal_connect(addr_type, "changed", G_CALLBACK(header_addr_callback), header);
	
	addr_not = gtk_check_button_new_with_label("Exclude");
	gtk_fixed_put(GTK_FIXED(fixed), addr_not, 700, offset);

	addr_exact_ip = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(addr_exact_ip), 47);
	gtk_fixed_put(GTK_FIXED(fixed), addr_exact_ip, 280, offset);
	ipaddr->exact_ip.ip = addr_exact_ip;

	addr_subnet_ip = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(addr_subnet_ip), 20);
	gtk_fixed_put(GTK_FIXED(fixed), addr_subnet_ip, 280, offset);
	ipaddr->subnet.ip = addr_subnet_ip;
	addr_subnet_slash = gtk_label_new("/");
	gtk_fixed_put(GTK_FIXED(fixed), addr_subnet_slash, 470, offset);
	ipaddr->subnet.slash = addr_subnet_slash;
	addr_subnet_mask = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(addr_subnet_mask), 20);
	gtk_fixed_put(GTK_FIXED(fixed), addr_subnet_mask, 500, offset);
	ipaddr->subnet.mask = addr_subnet_mask;

	addr_range_from = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(addr_range_from), 20);
	gtk_fixed_put(GTK_FIXED(fixed), addr_range_from, 280, offset);
	ipaddr->range.from = addr_range_from;
	addr_range_dash = gtk_label_new("-");
	gtk_fixed_put(GTK_FIXED(fixed), addr_range_dash, 470, offset);
	ipaddr->range.dash = addr_range_dash;
	addr_range_to = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(addr_range_to), 20);
	gtk_fixed_put(GTK_FIXED(fixed), addr_range_to, 500, offset);
	ipaddr->range.to = addr_range_to;

	if (!addr) {
		gtk_combo_box_set_active(GTK_COMBO_BOX(addr_type), 0);
		gtk_widget_show(GTK_WIDGET(addr_exact_ip));
	} else {
		gtk_combo_box_set_active(GTK_COMBO_BOX(addr_type), addr->ip_type);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(addr_not), addr->exclude);
		header->expanded = 1;
		switch (addr->ip_type) {
		case ADDRESS_EXACT:
			gtk_entry_set_text(GTK_ENTRY(addr_exact_ip), addr->iplist_str.ips);
			gtk_widget_show(GTK_WIDGET(addr_exact_ip));
			break;
		case ADDRESS_SUBNET:
			gtk_entry_set_text(GTK_ENTRY(addr_subnet_ip), addr->subnet_str.ip);
			gtk_entry_set_text(GTK_ENTRY(addr_subnet_mask), addr->subnet_str.mask);
			gtk_widget_show(GTK_WIDGET(addr_subnet_ip));
			gtk_widget_show(GTK_WIDGET(addr_subnet_slash));
			gtk_widget_show(GTK_WIDGET(addr_subnet_mask));
			break;
		case ADDRESS_RANGE:
			gtk_entry_set_text(GTK_ENTRY(addr_range_from), addr->range_str.from);
			gtk_entry_set_text(GTK_ENTRY(addr_range_to), addr->range_str.to);
			gtk_widget_show(GTK_WIDGET(addr_range_from));
			gtk_widget_show(GTK_WIDGET(addr_range_dash));
			gtk_widget_show(GTK_WIDGET(addr_range_to));
			break;
		}
	}
	gtk_widget_show(GTK_WIDGET(addr_label));
	gtk_widget_show(GTK_WIDGET(addr_type));
	gtk_widget_show(GTK_WIDGET(addr_not));
}

static void rule_add_content_header_saddr(struct match_header *header, struct pktheader *header_data)
{
	struct ip_addr_data *addr = NULL;
	if (header_data)
		addr = header_data->saddr;
	rule_add_content_header_addr(header, addr, 1);
}

static void rule_add_content_header_daddr(struct match_header *header, struct pktheader *header_data)
{
	struct ip_addr_data *addr = NULL;
	if (header_data)
		addr = header_data->daddr;
	rule_add_content_header_addr(header, addr, 0);
}

static void header_port_list_show(struct transport_port_info *port)
{
	gtk_entry_set_text(GTK_ENTRY(port->value->portlist.port), "");
	gtk_widget_show(port->value->portlist.port);
}

static void header_port_list_hide(struct transport_port_info *port)
{
	gtk_widget_hide(port->value->portlist.port);
}

static void header_port_range_show(struct transport_port_info *port)
{
	gtk_entry_set_text(GTK_ENTRY(port->value->range.from), "");
	gtk_entry_set_text(GTK_ENTRY(port->value->range.to), "");
	gtk_widget_show(port->value->range.from);
	gtk_widget_show(port->value->range.dash);
	gtk_widget_show(port->value->range.to);
}

static void header_port_range_hide(struct transport_port_info *port)
{
	gtk_widget_hide(port->value->range.from);
	gtk_widget_hide(port->value->range.dash);
	gtk_widget_hide(port->value->range.to);
}

static void header_port_callback(GtkComboBoxText *widget, gpointer data)
{
	struct transport_port_info *port;
	port = (struct transport_port_info *)data;
	char	*type = gtk_combo_box_text_get_active_text(widget);

	if (!(strcmp(type, "port list"))) {
		port->value->type = PORT_EXACT;
		header_port_range_hide(port);
		header_port_list_show(port);
	} else if (!(strcmp(type, "range"))) {
		port->value->type = PORT_RANGE;
		header_port_range_show(port);
		header_port_list_hide(port);
	}
	// else
	// 	bug();
}

static void rule_add_content_header_port(GtkWidget *fixed,
		struct transport_port_info *port, struct trans_port_data *data, 
		void (*callback)(GtkComboBoxText *widget, gpointer data), int source)
{
	GtkWidget	*port_label;
	GtkWidget	*port_type;
	GtkWidget	*port_not;
	GtkWidget	*port_list;
	GtkWidget	*port_range_from;
	GtkWidget	*port_range_dash;
	GtkWidget	*port_range_to;
	int		offset;
	char		*label;

	if (source) {
		offset = 0;
		label = "source port:";
	} else {
		offset = 40;
		label = "dest port:";
	}
	port_label = gtk_label_new(label);
	gtk_fixed_put(GTK_FIXED(fixed), port_label, 40, offset);
	port->label = port_label;
	port_type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(port_type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(port_type),
			"port list", "port list");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(port_type),
			"range", "range");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(port_type),
//			"sets", "sets");
	gtk_fixed_put(GTK_FIXED(fixed), port_type, 150, offset);
	port->type = port_type;
	g_signal_connect(port_type, "changed", G_CALLBACK(callback), port);
	
	port_not = gtk_check_button_new_with_label("Exclude");
	gtk_fixed_put(GTK_FIXED(fixed), port_not, 700, offset);
	port->exclude = port_not;

	port_list = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(port_list), 47);
	gtk_fixed_put(GTK_FIXED(fixed), port_list, 280, offset);
	port->value->portlist.port = port_list;

	port_range_from = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(port_range_from), 20);
	gtk_fixed_put(GTK_FIXED(fixed), port_range_from, 280, offset);
	port->value->range.from = port_range_from;
	port_range_dash = gtk_label_new("-");
	gtk_fixed_put(GTK_FIXED(fixed), port_range_dash, 470, offset);
	port->value->range.dash = port_range_dash;
	port_range_to = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(port_range_to), 20);
	gtk_fixed_put(GTK_FIXED(fixed), port_range_to, 500, offset);
	port->value->range.to = port_range_to;

	if (!data) {
		gtk_combo_box_set_active(GTK_COMBO_BOX(port_type), 0);
		gtk_widget_show(GTK_WIDGET(port_list));
	} else {
		gtk_combo_box_set_active(GTK_COMBO_BOX(port_type), data->port_type);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(port_not), data->exclude);
		switch (data->port_type) {
		case PORT_EXACT:
			gtk_entry_set_text(GTK_ENTRY(port_list), data->portlist_str.ports);
			gtk_widget_show(GTK_WIDGET(port_list));
			break;
		case PORT_RANGE:
			gtk_entry_set_text(GTK_ENTRY(port_range_from), data->range_str.from);
			gtk_entry_set_text(GTK_ENTRY(port_range_to), data->range_str.to);
			gtk_widget_show(GTK_WIDGET(port_range_from));
			gtk_widget_show(GTK_WIDGET(port_range_dash));
			gtk_widget_show(GTK_WIDGET(port_range_to));
			break;
		case PORT_SET:
			break;
		}
	}

	gtk_widget_show(GTK_WIDGET(port_label));
	gtk_widget_show(GTK_WIDGET(port_type));
	gtk_widget_show(GTK_WIDGET(port_not));
}

static void rule_add_content_header_all(struct match_header *header)
{
	GtkWidget	*fixed;
	struct transport_info	*widget;

	widget = header->transport.value;
	if (widget->type != TRANSPORT_ALL)
		header->len -= 80;
	widget->type = TRANSPORT_ALL;
	gtk_combo_box_set_active(GTK_COMBO_BOX(header->transport.type), TRANSPORT_ALL);
	if (widget->fixed)
		gtk_widget_destroy(widget->fixed);
	fixed = gtk_fixed_new();
	gtk_fixed_put(GTK_FIXED(header->fixed), fixed, 0, 120);
	gtk_widget_show(GTK_WIDGET(fixed));
	widget->fixed = fixed;

}

static void rule_add_content_header_tcp(struct match_header *header, struct trans_tcp_data *data)
{
	GtkWidget	*fixed;
	struct transport_info	*widget;

	widget = header->transport.value;
	if (widget->type == TRANSPORT_ALL)
		header->len += 80;
	if (widget->fixed)
		gtk_widget_destroy(widget->fixed);
	widget->type = TRANSPORT_TCP;
	gtk_combo_box_set_active(GTK_COMBO_BOX(header->transport.type), TRANSPORT_TCP);
	fixed = gtk_fixed_new();
	gtk_fixed_put(GTK_FIXED(header->fixed), fixed, 0, 120);
	gtk_widget_show(GTK_WIDGET(fixed));
	widget->fixed = fixed;
	rule_add_content_header_port(fixed, widget->tcp->sport, data ? data->sport : NULL, header_port_callback, 1);
	rule_add_content_header_port(fixed, widget->tcp->dport, data ? data->dport : NULL, header_port_callback, 0);
}

static void rule_add_content_header_udp(struct match_header *header, struct trans_udp_data *data)
{
	GtkWidget	*fixed;
	struct transport_info	*widget;

	widget = header->transport.value;
	if (widget->type == TRANSPORT_ALL)
		header->len += 80;
	if (widget->fixed)
		gtk_widget_destroy(widget->fixed);
	widget->type = TRANSPORT_UDP;
	gtk_combo_box_set_active(GTK_COMBO_BOX(header->transport.type), TRANSPORT_UDP);
	fixed = gtk_fixed_new();
	gtk_fixed_put(GTK_FIXED(header->fixed), fixed, 0, 120);
	gtk_widget_show(GTK_WIDGET(fixed));
	widget->fixed = fixed;
	rule_add_content_header_port(fixed, widget->udp->sport, data ? data->sport : NULL, header_port_callback, 1);
	rule_add_content_header_port(fixed, widget->udp->dport, data ? data->dport : NULL, header_port_callback, 0);
}

static void header_transport_callback(GtkComboBoxText *widget, gpointer data)
{
	char	*type;
	struct rule_create_widget *rule;
	
	rule = (struct match_header *)data;
	type = gtk_combo_box_text_get_active_text(widget);
	if (!(strcmp(type, "all")))
		rule_add_content_header_all(rule->header);
	else if (!(strcmp(type, "tcp")))
		rule_add_content_header_tcp(rule->header, NULL);
	else if (!(strcmp(type, "udp")))
		rule_add_content_header_udp(rule->header, NULL);
	// else
	// 	bug();

	update_pktmeta_position(rule);
	update_actions_position(rule);
	update_cancel_ok_position(rule);
}

static void rule_add_content_header_trans(struct rule_create_widget *new_rule, struct pktheader *header_data)
{
	GtkWidget	*fixed;
	GtkWidget	*transport;
	GtkWidget	*transport_value;
	struct match_header	*header;
	struct transport_data	*trans = NULL;

	header = new_rule->header;
	if (header_data)
		trans = header_data->transport_data;
	fixed = header->fixed;
	header->len += 40;

	transport = gtk_label_new("transport:");
	gtk_fixed_put(GTK_FIXED(fixed), transport, 40, 80);

	transport_value = gtk_combo_box_text_new();
	gtk_widget_set_size_request(transport_value, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(transport_value),
			"all", "all");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(transport_value),
			"tcp", "tcp");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(transport_value),
			"udp", "udp");
	gtk_fixed_put(GTK_FIXED(fixed), transport_value, 150, 80);
	header->transport.type = transport_value;
	gtk_combo_box_set_active(GTK_COMBO_BOX(transport_value), TRANSPORT_ALL);
	header->transport.value->type = TRANSPORT_ALL;

	if (trans) {
		switch (trans->trans_type) {
		case TRANSPORT_ALL:
			break;
		case TRANSPORT_TCP:
			header->expanded = 1;
			rule_add_content_header_tcp(header, trans->tcp);
			break;
		case TRANSPORT_UDP:
			header->expanded = 1;
			rule_add_content_header_udp(header, trans->udp);
			break;
		default:
			break;
		}
	}
	g_signal_connect(transport_value, "changed", G_CALLBACK(header_transport_callback), new_rule);

	gtk_widget_show(GTK_WIDGET(transport));
	gtk_widget_show(GTK_WIDGET(transport_value));
}

static void rule_add_content_header_data(struct rule_create_widget *new_rule, struct pktheader *header_data)
{
	rule_add_content_header_saddr(new_rule->header, header_data);
	rule_add_content_header_daddr(new_rule->header, header_data);
	rule_add_content_header_trans(new_rule, header_data);
}


void rule_add_content_header(struct rule_create_widget *new_rule, struct rule_list_args *rule_arg)
{
	GtkWidget	*fixed;
	GtkWidget	*fixed_header;
	GtkWidget	*expander_header;
	struct match_header	*header;
	struct rule_create_data	*data = rule_arg->data;
	struct pktheader	*header_data = NULL;

	fixed = new_rule->fixed;
	header = new_rule->header;
	if (data)
		header_data = data->header;

	fixed_header = gtk_fixed_new();
	expander_header = gtk_expander_new("Matching packet header fields");
	gtk_fixed_put(GTK_FIXED(fixed), expander_header, 0, 0);
	gtk_container_add(GTK_CONTAINER(expander_header), fixed_header);
	g_signal_connect(expander_header, "notify::expanded", G_CALLBACK(expander_callback), new_rule);
	new_rule->header->expander = expander_header;
	new_rule->header->fixed = fixed_header;
	new_rule->header->expanded = 0;
	new_rule->header->len = 0;

	rule_add_content_header_data(new_rule, header_data);

//	gtk_expander_set_expanded(GTK_EXPANDER(header->expander), header->expanded);
	gtk_widget_show(GTK_WIDGET(fixed_header));
	gtk_widget_show(GTK_WIDGET(expander_header));
}

void rule_add_content_pktmeta(struct rule_create_widget *new_rule, struct rule_list_args *rule_arg)
{
	GtkWidget	*fixed_pktmeta;
	GtkWidget	*expander_pktmeta;
	GtkWidget	*iifname;
	GtkWidget	*iifname_value;
	GtkWidget	*oifname;
	GtkWidget	*oifname_value;
	GtkWidget	*iiftype;
	GtkWidget	*iiftype_value;
	GtkWidget	*oiftype;
	GtkWidget	*oiftype_value;
	GtkWidget	*skuid;
	GtkWidget	*skuid_value;
	GtkWidget	*skgid;
	GtkWidget	*skgid_value;
	GtkWidget	*fixed;
	struct pktmeta	*pktmeta = NULL;

	fixed = new_rule->fixed;
	if (rule_arg && rule_arg->data)
		pktmeta = rule_arg->data->pktmeta;

	fixed_pktmeta = gtk_fixed_new();
	expander_pktmeta = gtk_expander_new("Matching packet metainformation");
	gtk_fixed_put(GTK_FIXED(fixed), expander_pktmeta, 0, new_rule->header->expanded ? new_rule->header->len + 40: 40);
	gtk_container_add(GTK_CONTAINER(expander_pktmeta), fixed_pktmeta);
	g_signal_connect(expander_pktmeta, "notify::expanded", G_CALLBACK(expander_callback), new_rule);
	new_rule->meta->expander = expander_pktmeta;
	new_rule->meta->fixed = fixed_pktmeta;
	new_rule->meta->expanded = 0;
	new_rule->meta->len = 240;

	iifname = gtk_label_new("input interface:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), iifname, 40, 0);
	iifname_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(iifname_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), iifname_value, 150, 0);
	new_rule->meta->iifname = iifname_value;
	if (pktmeta && pktmeta->iifname) {
		gtk_entry_set_text(GTK_ENTRY(iifname_value), pktmeta->iifname->name_str);
		new_rule->meta->expanded = 1;
	}

	oifname = gtk_label_new("output interface:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), oifname, 40, 40);
	oifname_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(oifname_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), oifname_value, 150, 40);
	new_rule->meta->oifname = oifname_value;
	if (pktmeta && pktmeta->oifname) {
		gtk_entry_set_text(GTK_ENTRY(oifname_value), pktmeta->oifname->name_str);
		new_rule->meta->expanded = 1;
	}

	iiftype = gtk_label_new("input type:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), iiftype, 40, 80);
	iiftype_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(iiftype_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), iiftype_value, 150, 80);
	new_rule->meta->iiftype = iiftype_value;
	if (pktmeta && pktmeta->iiftype) {
		gtk_entry_set_text(GTK_ENTRY(iiftype_value), pktmeta->iiftype->type_str);
		new_rule->meta->expanded = 1;
	}

	oiftype = gtk_label_new("output type:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), oiftype, 40, 120);
	oiftype_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(oiftype_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), oiftype_value, 150, 120);
	new_rule->meta->oiftype = oiftype_value;
	if (pktmeta && pktmeta->oiftype) {
		gtk_entry_set_text(GTK_ENTRY(oiftype_value), pktmeta->oiftype->type_str);
		new_rule->meta->expanded = 1;
	}

	skuid = gtk_label_new("user:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), skuid, 40, 160);
	skuid_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(skuid_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), skuid_value, 150, 160);
	new_rule->meta->skuid = skuid_value;
	if (pktmeta && pktmeta->skuid) {
		gtk_entry_set_text(GTK_ENTRY(skuid_value), pktmeta->skuid->id_str);
		new_rule->meta->expanded = 1;
	}

	skgid = gtk_label_new("group:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), skgid, 40, 200);
	skgid_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(skgid_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), skgid_value, 150, 200);
	new_rule->meta->skgid = skgid_value;
	if (pktmeta && pktmeta->skgid) {
		gtk_entry_set_text(GTK_ENTRY(skgid_value), pktmeta->skgid->id_str);
		new_rule->meta->expanded = 1;
	}

//	gtk_expander_set_expanded(GTK_EXPANDER(new_rule->meta->expander), new_rule->meta->expanded);
	gtk_widget_show_all(GTK_WIDGET(expander_pktmeta));
}

static void rule_actions_remove(GtkButton *button, gpointer data)
{
	struct rule_create_widget *rule;
	struct actions_all	*actions;
	struct action_elem *elem;
	int	offset = 40;	

	elem = (struct action_elem *)data;
	rule = elem->rule;
	actions = rule->actions;
	list_del(&elem->list);
	actions->len = 40;
	switch (elem->type) {
	case ACTION_ACCEPT:
		gtk_widget_destroy(elem->label);
		gtk_widget_destroy(elem->remove);
		gtk_widget_set_sensitive(actions->action_list, TRUE);
		gtk_widget_set_sensitive(actions->action, TRUE);
		break;
	case ACTION_DROP:
		gtk_widget_destroy(elem->label);
		gtk_widget_destroy(elem->remove);
		gtk_widget_set_sensitive(actions->action_list, TRUE);
		gtk_widget_set_sensitive(actions->action, TRUE);
		break;
	case ACTION_JUMP:
		gtk_widget_destroy(elem->label);
		gtk_widget_destroy(elem->widget1);
		gtk_widget_destroy(elem->remove);
		break;
	case ACTION_COUNTER:
		gtk_widget_destroy(elem->label);
		gtk_widget_destroy(elem->widget1);
		gtk_widget_destroy(elem->widget2);
		gtk_widget_destroy(elem->widget3);
		gtk_widget_destroy(elem->widget4);
		gtk_widget_destroy(elem->remove);
		break;
	default:
		BUG();
	}

	list_for_each_entry(elem, &actions->list, list) {
		switch (elem->type) {
		case ACTION_ACCEPT:
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->label, 100, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->remove, 40, offset);
			offset += 40;
			actions->len += 40;
			break;
		case ACTION_DROP:
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->label, 100, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->remove, 40, offset);
			offset += 40;
			actions->len += 40;
			break;
		case ACTION_JUMP:
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->label, 100, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->widget1, 160, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->remove, 40, offset);
			offset += 40;
			actions->len += 40;
			break;
		case ACTION_COUNTER:
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->label, 100, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->widget1, 380, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->widget2, 160, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->widget3, 700, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->widget4, 480, offset);
			gtk_fixed_move(GTK_FIXED(actions->fixed), elem->remove, 40, offset);
			offset += 40;
			actions->len += 40;
			break;
		default:
			BUG();
		}
	}

	update_cancel_ok_position(rule);
}

static void rule_actions_add_jump(struct rule_create_widget *new_rule, struct action *action)
{
	struct action_elem *elem;
	struct actions_all	*actions;
	LIST_HEAD(chain_list);
	struct chain_list_data   *chain, *c;
	int	res;
	int	index = 0;
	int	selected = 0;

	res = gui_get_chains_list(&chain_list, new_rule->family, new_rule->table, "user");
	if (res != CHAIN_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_ERROR,
                                 GTK_BUTTONS_OK,
                                 chain_error[res]
                                 );

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}


	actions = new_rule->actions;
	elem = xzalloc(sizeof(struct action_elem));
	elem->rule = new_rule;
	elem->type = ACTION_JUMP;
	elem->label = gtk_label_new("Jump to:");

	elem->widget1 = gtk_combo_box_text_new();
	gtk_widget_set_size_request(elem->widget1, 150, 10);
	list_for_each_entry_safe(chain, c, &chain_list, list) {
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(elem->widget1),
				xstrdup(chain->chain), xstrdup(chain->chain));
		list_del(&chain->list);
		gui_chain_free(chain);	
		if (action) {
			if (!strcpy(action->chain, chain->chain))
				selected = index;
		}
		index++;
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(elem->widget1), selected);
	elem->remove = gtk_button_new_with_label("X");
	g_signal_connect(G_OBJECT(elem->remove), "clicked", G_CALLBACK(rule_actions_remove), elem);
	list_add_tail(&elem->list, &actions->list);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->label, 100, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->widget1, 160, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->remove, 40, actions->len);
	actions->len += 40;
	gtk_widget_show(elem->label);
	gtk_widget_show(elem->widget1);
	gtk_widget_show(elem->remove);
	gtk_widget_set_sensitive(actions->action_list, FALSE);
	gtk_widget_set_sensitive(actions->action, FALSE);
}

static void rule_actions_add_counter(struct rule_create_widget *new_rule, struct action *action)
{
	struct action_elem *elem;
	struct actions_all	*actions;

	actions = new_rule->actions;
	elem = xzalloc(sizeof(struct action_elem));
	elem->rule = new_rule;
	elem->type = ACTION_COUNTER;
	elem->label = gtk_label_new("Counter:");
	elem->widget1 = gtk_label_new("(packets)");
	elem->widget2 = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(elem->widget2), 25);
	gtk_entry_set_max_length(GTK_ENTRY(elem->widget2), 30);
	elem->widget3 = gtk_label_new("(bytes)");
	elem->widget4 = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(elem->widget4), 25);
	gtk_entry_set_max_length(GTK_ENTRY(elem->widget4), 30);
	elem->remove = gtk_button_new_with_label("X");
	g_signal_connect(G_OBJECT(elem->remove), "clicked", G_CALLBACK(rule_actions_remove), elem);
	list_add_tail(&elem->list, &actions->list);
	if (action) {
		char  packets[100];
		char  bytes[100];
		snprintf(packets, 100, "%u", action->packets);
		snprintf(bytes, 100, "%u", action->bytes);
		gtk_entry_set_text(GTK_ENTRY(elem->widget2), packets);
		gtk_entry_set_text(GTK_ENTRY(elem->widget4), bytes);
	}
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->label, 100, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->widget1, 380, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->widget2, 160, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->widget3, 700, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->widget4, 480, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->remove, 40, actions->len);
	actions->len += 40;
	gtk_widget_show(elem->label);
	gtk_widget_show(elem->widget1);
	gtk_widget_show(elem->widget2);
	gtk_widget_show(elem->widget3);
	gtk_widget_show(elem->widget4);
	gtk_widget_show(elem->remove);
}

static void rule_actions_add_accept(struct rule_create_widget *new_rule, struct action *action)
{
	struct action_elem *elem;
	struct actions_all	*actions;

	actions = new_rule->actions;
	elem = xzalloc(sizeof(struct action_elem));
	elem->rule = new_rule;
	elem->type = ACTION_ACCEPT;
	elem->label = gtk_label_new("Accept:");
	elem->remove = gtk_button_new_with_label("X");
	g_signal_connect(G_OBJECT(elem->remove), "clicked", G_CALLBACK(rule_actions_remove), elem);
	list_add_tail(&elem->list, &actions->list);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->label, 100, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->remove, 40, actions->len);
	actions->len += 40;
	gtk_widget_show(elem->label);
	gtk_widget_show(elem->remove);
	gtk_widget_set_sensitive(actions->action_list, FALSE);
	gtk_widget_set_sensitive(actions->action, FALSE);
}

static void rule_actions_add_drop(struct rule_create_widget *new_rule, struct action *action)
{
	struct action_elem *elem;
	struct actions_all	*actions;

	actions = new_rule->actions;
	elem = xzalloc(sizeof(struct action_elem));
	elem->rule = new_rule;
	elem->type = ACTION_DROP;
	elem->label = gtk_label_new("Drop:");
	elem->remove = gtk_button_new_with_label("X");
	g_signal_connect(G_OBJECT(elem->remove), "clicked", G_CALLBACK(rule_actions_remove), elem);
	list_add_tail(&elem->list, &actions->list);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->label, 100, actions->len);
	gtk_fixed_put(GTK_FIXED(actions->fixed), elem->remove, 40, actions->len);
	actions->len += 40;
	gtk_widget_show(elem->label);
	gtk_widget_show(elem->remove);
	gtk_widget_set_sensitive(actions->action_list, FALSE);
	gtk_widget_set_sensitive(actions->action, FALSE);
}

void rule_actions_add(GtkButton *button, gpointer data)
{
	struct rule_create_widget *new_rule;
	GtkComboBoxText  *combo;
	char *action;

	new_rule = (struct rule_create_widget *)data;
	combo = GTK_COMBO_BOX_TEXT(new_rule->actions->action_list);
	action = gtk_combo_box_text_get_active_text(combo);
	if (!(strcmp(action, "accept")))
		rule_actions_add_accept(new_rule, NULL);
	else if (!(strcmp(action, "drop")))
		rule_actions_add_drop(new_rule, NULL);
	else if (!(strcmp(action, "go to")))
		rule_actions_add_jump(new_rule, NULL);
	else if (!(strcmp(action, "counter")))
		rule_actions_add_counter(new_rule, NULL);
	else
		BUG();
	update_cancel_ok_position(new_rule);
}

void rule_add_content_actions(struct rule_create_widget *new_rule, struct rule_list_args *rule_arg)
{
	GtkWidget	*fixed_actions;
	GtkWidget	*expander_actions;
	GtkWidget	*fixed;
	GtkWidget	*list;
	GtkWidget	*add;
	int	offset = 80;
	struct actions_all	*actions;
	struct actions	*data = NULL;
	struct action	*data_act;

	actions = new_rule->actions;
	actions->len = 40;
	actions->expanded = 0;
	fixed = new_rule->fixed;
	if (rule_arg && rule_arg->data) {
		data = rule_arg->data->actions;
	}

	if (new_rule->header->expanded)
		offset += new_rule->header->len;
	if (new_rule->meta->expanded)
		offset += new_rule->meta->len;


	fixed_actions = gtk_fixed_new();
	expander_actions = gtk_expander_new("Actions");
	gtk_fixed_put(GTK_FIXED(fixed), expander_actions, 0, offset);
	gtk_container_add(GTK_CONTAINER(expander_actions), fixed_actions);
	g_signal_connect(expander_actions, "notify::expanded", G_CALLBACK(expander_callback), new_rule);
	actions->fixed = fixed_actions;
	actions->expander = expander_actions;

	list = gtk_combo_box_text_new();
	gtk_widget_set_size_request(list, 150, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(list),
			"accept", "accept");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(list),
			"drop", "drop");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(list),
			"go to", "go to");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(list),
			"counter", "counter");
//	g_signal_connect(list, "changed",
//			G_CALLBACK(rule_actions_add), new_rule);
	gtk_combo_box_set_active(GTK_COMBO_BOX(list), 0);
	gtk_fixed_put(GTK_FIXED(fixed_actions), list, 40, 0);
    	add = gtk_button_new_with_label("Add action");
	g_signal_connect(G_OBJECT(add), "clicked", G_CALLBACK(rule_actions_add), new_rule);
	gtk_fixed_put(GTK_FIXED(fixed_actions), add, 240, 0);
	actions->action_list = list;
	actions->action = add;

	if (data && !list_empty(&data->list)) {
		actions->expanded = 1;
		list_for_each_entry(data_act, &data->list, list) {
			switch (data_act->type) {
			case ACTION_ACCEPT:
				rule_actions_add_accept(new_rule, data_act);
				break;
			case ACTION_DROP:
				rule_actions_add_drop(new_rule, data_act);
				break;
			case ACTION_JUMP:
				rule_actions_add_jump(new_rule, data_act);
				break;
			case ACTION_COUNTER:
				rule_actions_add_counter(new_rule, data_act);
				break;
			default:
				BUG();
			}
		}
	}

	gtk_widget_show_all(GTK_WIDGET(expander_actions));


}

void rule_add_content_submit(struct rule_create_widget *new_rule)
{
	GtkWidget	*fixed;
	GtkWidget	*msg;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	int		offset;
	int		header_expanded;
	int		pktmeta_expanded;

	fixed = new_rule->fixed;
	header_expanded = new_rule->header->expanded;
	pktmeta_expanded = new_rule->meta->expanded;
	offset = new_rule->header->len * header_expanded + new_rule->meta->len * pktmeta_expanded;
	if (offset < 360)
		offset = 360;

	msg = gtk_label_new("");
	gtk_fixed_put(GTK_FIXED(fixed), msg, 40, offset);
	new_rule->msg = msg;

    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(back_to_rule_list), new_rule);
	gtk_fixed_put(GTK_FIXED(fixed), cancel, 540, offset);
	new_rule->cancel = cancel;

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(begin_create_new_rule), new_rule);
	gtk_fixed_put(GTK_FIXED(fixed), ok, 660, offset);
	new_rule->ok = ok;

	gtk_widget_show(GTK_WIDGET(msg));
	gtk_widget_show(GTK_WIDGET(ok));
	gtk_widget_show(GTK_WIDGET(cancel));
}

void rule_add_content(struct rule_create_widget *new_rule, struct rule_list_args *rule_arg)
{
	rule_add_content_header(new_rule, rule_arg);
	rule_add_content_pktmeta(new_rule, rule_arg);
	rule_add_content_actions(new_rule, rule_arg);
	rule_add_content_submit(new_rule);
	gtk_expander_set_expanded(GTK_EXPANDER(new_rule->header->expander), new_rule->header->expanded);
	gtk_expander_set_expanded(GTK_EXPANDER(new_rule->meta->expander), new_rule->meta->expanded);
	gtk_expander_set_expanded(GTK_EXPANDER(new_rule->actions->expander), new_rule->actions->expanded);
}

void create_new_rule_begin(gpointer  data)
{
	GtkWidget	*title;
	GtkWidget	*fixed_back;
	GtkWidget	*fixed_content;
	GtkWidget	*notebook;
	GtkWidget	*scrolledwindow;

	struct rule_list_args	*rule_arg;
	struct rule_create_widget	*new_rule;

	// new_rule_malloc();
	rule_arg = (struct rule_list_args *)data;
	new_rule = rule_widget_container_create(rule_arg);
	notebook = rule_arg->notebook;

	title = gtk_label_new("Create rule");
	gtk_widget_set_size_request(title, 200, 10);
	fixed_back = gtk_fixed_new();
	fixed_content = gtk_fixed_new();
	new_rule->fixed = fixed_content;

	rule_add_content(new_rule, rule_arg);

        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolledwindow), 856);
	gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolledwindow), 430);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), GTK_SHADOW_ETCHED_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
                                GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), fixed_content);

	gtk_fixed_put(GTK_FIXED(fixed_back), scrolledwindow, 10, 20);
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 2);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), fixed_back, title, 2);
	gtk_widget_show(GTK_WIDGET(fixed_content));
	gtk_widget_show(GTK_WIDGET(scrolledwindow));
	gtk_widget_show(GTK_WIDGET(fixed_back));
	gtk_widget_show(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


static void set_element_type_changed(GtkComboBoxText *widget, gpointer data)
{
	GtkTreeStore	*store;
	struct set_create_widget *widgets;

	widgets = (struct GtkTreeStore *)data;
	store = GTK_TREE_STORE(widgets->store);
	gtk_tree_store_clear(store);
}

static void set_add_element(GtkButton *button, gpointer  info)
{
	char	*value;
	GtkEntry	*add;
	GtkTreeIter	iter;
	GtkTreeStore	*store;
	struct set_create_widget *widgets;

	widgets = (struct GtkTreeStore *)info;
	store = GTK_TREE_STORE(widgets->store);
	add = GTK_ENTRY(widgets->add);
	value = get_data_from_entry(add);
	if (value) {
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter, 0, value, -1);
		gtk_entry_set_text(add, "");
	}
}

static void set_remove_element(GtkButton *button, gpointer  info)
{
	GtkTreeIter	iter;
	GtkTreeStore	*store;
	GtkTreeView	*treeview;
	GtkTreeModel	*model;
	GtkTreeSelection *selection;
	struct set_create_widget *widgets;

	widgets = (struct GtkTreeStore *)info;
	store = GTK_TREE_STORE(widgets->store);
	treeview = GTK_TREE_VIEW(widgets->treeview);
	selection  = gtk_tree_view_get_selection(treeview);
	model = gtk_tree_view_get_model(treeview);
	if (gtk_tree_model_get_iter_first(model, &iter) == FALSE)
		return;
	if (gtk_tree_selection_get_selected(GTK_TREE_SELECTION(selection),
			&model, &iter)) {
		gtk_tree_store_remove(store, &iter);
	}
}

static void create_new_set(GtkButton *button, gpointer  data)
{
	GtkWidget	*layout;
	GtkWidget	*title;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	GtkWidget	*frame;
	GtkWidget	*layout_chain;
	GtkWidget	*name;
	GtkWidget	*name_value;
	GtkWidget	*type;
	GtkWidget	*type_value;
	GtkWidget	*new;
	GtkWidget	*new_value;
	GtkWidget	*remove;
	GtkWidget	*remove_value;
	GtkWidget	*hook;
	GtkWidget	*hook_value;
	GtkWidget	*priority;
	GtkWidget	*priority_value;
	GtkWidget	*notebook;
	GtkWidget	*msg;
	GtkWidget	*scrolledwindow;
	GtkWidget	*elems;
	GtkWidget	*trash;
	GtkCellRenderer	*renderer;
	GtkTreeViewColumn	*column;
	GtkTreeStore	*store;
	GtkTreeIter	iter;

	struct set_list_args  *set_arg;
	struct set_create_widget *widgets;
	struct set_create_data	*set_data;
	struct elem_create_data	*elem_data;

	set_arg = (struct set_list_args *)data;
	widgets = xzalloc(sizeof(struct set_create_widget));
	notebook = set_arg->notebook;
	widgets->notebook = notebook;
	widgets->family = set_arg->family;
	widgets->table = set_arg->table;
	set_data = set_arg->data;

	if (!set_data)
		widgets->create = 1;
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);

	layout = gtk_layout_new(NULL, NULL);
	title = gtk_label_new("Sets");
	gtk_widget_set_size_request(title, 200, 10);

	frame = gtk_frame_new ("Create a new set");
	gtk_container_set_border_width (GTK_CONTAINER(frame), 0);
	gtk_widget_set_size_request(frame, 770, 420);
	gtk_layout_put(GTK_LAYOUT(layout), frame, 50, 20);


	layout_chain = gtk_layout_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(frame), layout_chain);

	name = gtk_label_new("Name:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), name, 30, 30);
	name_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(name_value), 30);
	gtk_entry_set_max_length(GTK_ENTRY(name_value), 32);
	if (set_data) {
		gtk_entry_set_text(GTK_ENTRY(name_value), set_data->set);
		gtk_widget_set_sensitive(name_value, FALSE);
	}
	gtk_layout_put(GTK_LAYOUT(layout_chain), name_value, 100, 30);
	widgets->name = name_value;

	type = gtk_label_new("Type:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), type, 30, 80);
	type_value = gtk_combo_box_text_new();
	gtk_widget_set_size_request(type_value, 150, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_value),
			"IPv4 address", "IPv4 address");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_value),
			"internet network service", "internet network service");
	if (set_data) {
		if (set_data->keytype->type == TYPE_IPADDR)
			gtk_combo_box_set_active(GTK_COMBO_BOX(type_value), 0);
		if (set_data->keytype->type == TYPE_INET_SERVICE)
			gtk_combo_box_set_active(GTK_COMBO_BOX(type_value), 1);
		gtk_widget_set_sensitive(type_value, FALSE);
	} else
		gtk_combo_box_set_active(GTK_COMBO_BOX(type_value), 0);
	gtk_layout_put(GTK_LAYOUT(layout_chain), type_value, 100, 80);
	widgets->type = type_value;

    	new = gtk_button_new_with_label("==>");
	gtk_layout_put(GTK_LAYOUT(layout_chain), new, 370, 130);
	new_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(new_value), 30);
	gtk_layout_put(GTK_LAYOUT(layout_chain), new_value, 100, 130);
	widgets->add = new_value;
    	remove = gtk_button_new_with_label("<==");
	gtk_layout_put(GTK_LAYOUT(layout_chain), remove, 370, 210);
	trash = gtk_image_new_from_file("trash.png");
	gtk_layout_put(GTK_LAYOUT(layout_chain), trash, 200, 180);

	store = gtk_tree_store_new(1, G_TYPE_STRING);
	widgets->store = store;
	elems = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(elems), FALSE);
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Id", renderer,
			"text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(elems), column);
	if (set_data) {
		list_for_each_entry(elem_data, &(set_data->elems), list) {
			gtk_tree_store_append(store, &iter, NULL);
			gtk_tree_store_set(store, &iter, 0, xstrdup(elem_data->key), -1);
		}
	}

        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(
			GTK_SCROLLED_WINDOW(scrolledwindow), 270);
	gtk_scrolled_window_set_min_content_height(
			GTK_SCROLLED_WINDOW(scrolledwindow), 300);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), elems);
	widgets->treeview = elems;

	gtk_layout_put(GTK_LAYOUT(layout_chain), scrolledwindow, 450, 30);

	g_signal_connect(type_value, "changed",
			G_CALLBACK(set_element_type_changed), widgets);
	g_signal_connect(G_OBJECT(new), "clicked", G_CALLBACK(set_add_element), widgets);
	g_signal_connect(G_OBJECT(remove), "clicked", G_CALLBACK(set_remove_element), widgets);


	msg = gtk_label_new("");
	gtk_layout_put(GTK_LAYOUT(layout_chain), msg, 30, 280);
	widgets->msg = msg;

    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(back_to_set_list), widgets);
	gtk_layout_put(GTK_LAYOUT(layout_chain), cancel, 480, 360);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(begin_create_new_set), widgets);
	gtk_layout_put(GTK_LAYOUT(layout_chain), ok, 600, 360);

	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, title, 1);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}

/*
 * Goto chain creating page
 *
 */
void create_new_chain(GtkButton *button, gpointer  data)
{
	GtkWidget	*layout;
	GtkWidget	*title;
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
	GtkWidget	*msg;

	struct  basechain_info  *basechain = xzalloc(sizeof(*basechain));
	struct chain_create_widget *widgets = xzalloc(sizeof(struct chain_create_widget));
	struct chain_list_args	*chain_arg = (struct chain_list_args *)data;
	notebook = chain_arg->notebook;
	widgets->notebook = notebook;
	widgets->family = chain_arg->family;
	widgets->table = chain_arg->table;



	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 1);

	layout = gtk_layout_new(NULL, NULL);
	title = gtk_label_new("Chains");
	gtk_widget_set_size_request(title, 200, 10);

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
	gtk_entry_set_max_length(GTK_ENTRY(name_value), 32);
	gtk_layout_put(GTK_LAYOUT(layout_chain), name_value, 100, 30);
	name_desc = gtk_label_new("(no more than 32 characters)");
	gtk_layout_put(GTK_LAYOUT(layout_chain), name_desc, 360, 30);
	widgets->name = name_value;

	family = gtk_label_new("basechain:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), family, 30, 80);

	family_valuee = gtk_check_button_new();
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(family_valuee), TRUE);
	gtk_layout_put(GTK_LAYOUT(layout_chain), family_valuee, 100, 80);
	g_signal_connect(family_valuee, "toggled", G_CALLBACK(basechain_selected), basechain);
	widgets->basechain = family_valuee;


	type = gtk_label_new("Type:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), type, 30, 130);

	type_value = gtk_combo_box_text_new();
	gtk_widget_set_size_request(type_value, 150, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_value),
			"filter", "filter");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_value),
			"nat", "nat");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_value),
			"route", "route");
	gtk_combo_box_set_active(GTK_COMBO_BOX(type_value), 0);
	gtk_layout_put(GTK_LAYOUT(layout_chain), type_value, 100, 130);
	basechain->type = type;
	basechain->type_value = type_value;
	widgets->type = type_value;

	hook = gtk_label_new("Hook:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), hook, 30, 180);

	hook_value = gtk_combo_box_text_new();
	gtk_widget_set_size_request(hook_value, 150, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook_value),
			"prerouting", "prerouting");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook_value),
			"input", "input");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook_value),
			"forward", "forward");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook_value),
			"postrouting", "postrouting");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook_value),
			"output", "output");
	gtk_combo_box_set_active(GTK_COMBO_BOX(hook_value), 0);
	gtk_layout_put(GTK_LAYOUT(layout_chain), hook_value, 100, 180);
	basechain->hook = hook;
	basechain->hook_value = hook_value;
	widgets->hook = hook_value;

	g_signal_connect(type_value, "changed",
			G_CALLBACK(chain_create_type_changed), hook_value);

	priority = gtk_label_new("Priority:");
	gtk_layout_put(GTK_LAYOUT(layout_chain), priority, 30, 230);
	priority_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(priority_value), 30);
	gtk_widget_set_tooltip_text(priority_value, "The priority can be used to order the chains or to put them before or after some Netfilter internal operations.\n\
For reference, here's the list of different priority used in iptables:\n\
-400: priority of defragmentation\n\
-300: traditional priority of the raw table placed before connection tracking operation\n\
-225: SELinux operations\n\
-200: Connection tracking operations\n\
-150: mangle operation\n\
-100: destination NAT\n\
   0: filtering operation, the filter table\n\
  50: Place of security table where secmark can be set for example\n\
 100: source NAT\n\
 225: SELInux at packet exit\n\
 300: connection tracking at exit");
	gtk_layout_put(GTK_LAYOUT(layout_chain), priority_value, 100, 230);
	basechain->priority = priority;
	basechain->priority_value = priority_value;
	widgets->priority = priority_value;

	msg = gtk_label_new("");
	gtk_layout_put(GTK_LAYOUT(layout_chain), msg, 30, 280);
	widgets->msg = msg;

    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(back_to_chain_list), widgets);
	gtk_layout_put(GTK_LAYOUT(layout_chain), cancel, 360, 310);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(begin_create_new_chain), widgets);
	gtk_layout_put(GTK_LAYOUT(layout_chain), ok, 480, 310);


	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, title, 1);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}



/*
 * Page in which you can create a new table.
 * button: "Create Table" button in table list page
 * notebook: GtkNotebook
 */
void create_new_table(GtkButton *button, gpointer  notebook)
{
	GtkWidget	*layout;
	GtkWidget	*title;
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

	struct	table_create_widget  *args;
	args = xzalloc(sizeof(struct table_create_widget));
	args->notebook = GTK_WIDGET(notebook);

	gtk_notebook_remove_page(notebook, 0);

	layout = gtk_layout_new(NULL, NULL);
	title = gtk_label_new("Tables");
	gtk_widget_set_size_request(title, 200, 10);

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
	gtk_entry_set_max_length(GTK_ENTRY(name_value), 32);
	gtk_layout_put(GTK_LAYOUT(layout_info), name_value, 100, 60);
	name_desc = gtk_label_new("(no more than 32 characters)");
	gtk_layout_put(GTK_LAYOUT(layout_info), name_desc, 360, 60);
	args->name = name_value;

	family = gtk_label_new("Family:");
	gtk_layout_put(GTK_LAYOUT(layout_info), family, 30, 110);
	family_value = create_family_list(0, NULL, NULL);
	gtk_widget_set_size_request(family_value, 30, 10);
	gtk_combo_box_set_active(GTK_COMBO_BOX(family_value), 0);
	gtk_layout_put(GTK_LAYOUT(layout_info), family_value, 100, 110);
	args->family = family_value;

	msg = gtk_label_new("");
	gtk_layout_put(GTK_LAYOUT(layout_info), msg, 30, 250);
	args->msg = msg;

    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked",
			G_CALLBACK(back_to_table_list), args);
	gtk_layout_put(GTK_LAYOUT(layout_info), cancel, 360, 310);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked",
			G_CALLBACK(begin_create_new_table), args);
	gtk_layout_put(GTK_LAYOUT(layout_info), ok, 480, 310);

	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, title, 0);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}



void gnftables_rule_init(gint family, gchar *table_name, gchar *chain_name, GtkWidget *notebook)
{
	GtkWidget	*title;
	GtkWidget	*layout;
	GtkWidget	*create_rule;
	GtkWidget	*list_rules;
	GtkWidget	*scrolledwindow;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer_details;
	GtkCellRenderer	*renderer_delete;
	GtkTreeViewColumn	*column;

	struct rule_list_args  *rule_arg = xzalloc(sizeof(*rule_arg));
	rule_arg->notebook = notebook;
	rule_arg->family = family;
	rule_arg->table = table_name;
	rule_arg->chain = chain_name;
	rule_arg->data = NULL;

	store = gtk_tree_store_new(RULE_TOTAL, G_TYPE_INT, G_TYPE_INT,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);
	rule_arg->store = store;

	title = gtk_label_new("Rules");
	gtk_widget_set_size_request(title, 200, 10);
	layout = gtk_layout_new(NULL, NULL);

    	create_rule = gtk_button_new_with_label("Create Rule");
	gtk_widget_set_size_request(create_rule, 150, 10);
	g_signal_connect(G_OBJECT(create_rule), "clicked",
			G_CALLBACK(create_new_rule), rule_arg);
	gtk_layout_put(GTK_LAYOUT(layout), create_rule, 700, 10);

	rule_update_data(rule_arg);

	// treeview style
	list_rules = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
//	g_signal_connect(list_rules, "button-press-event",
//			G_CALLBACK(show_treeview_menu), NULL); 
	renderer = gtk_cell_renderer_text_new();
	rule_arg->list_rules = list_rules;

	column = gtk_tree_view_column_new_with_attributes("Id", renderer,
			"text", RULE_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_rules), column);
	column = gtk_tree_view_column_new_with_attributes("Handle", renderer,
			"text", RULE_HANDLE, NULL);
	gtk_tree_view_column_set_visible(column, FALSE);
	gtk_tree_view_column_set_min_width(column, 50);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_rules), column);
	column = gtk_tree_view_column_new_with_attributes("Table", renderer,
			"text", RULE_TABLE, NULL);
	gtk_tree_view_column_set_visible(column, FALSE);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_rules), column);
	column = gtk_tree_view_column_new_with_attributes("Chain", renderer,
			"text", RULE_CHAIN, NULL);
	gtk_tree_view_column_set_visible(column, FALSE);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_rules), column);
	column = gtk_tree_view_column_new_with_attributes("Contents", renderer,
			"text", RULE_CONTENT, NULL);
	gtk_tree_view_column_set_min_width(column, 550);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_rules), column);


	renderer_details = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer_details, "toggled",
			G_CALLBACK(rule_callback_detail), rule_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Details",
			renderer_details, "active", RULE_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_max_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_rules), column);

	renderer_delete = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer_delete, "toggled",
			G_CALLBACK(rule_callback_delete), rule_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Delete",
			renderer_delete, "active", RULE_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_max_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_rules), column);

        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(
			GTK_SCROLLED_WINDOW(scrolledwindow), 876);
	gtk_scrolled_window_set_min_content_height(
			GTK_SCROLLED_WINDOW(scrolledwindow), 410);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_rules);

	gtk_layout_put(GTK_LAYOUT(layout), scrolledwindow, 0, 50);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, title, 2);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
}


static void set_callback_detail(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*set;
	GtkTreeModel		*model;
	GtkWidget		*notebook;
	struct set_list_args  *set_args;

	set_args = (struct set_list_args *)data;

	table = set_args->table;
	family = set_args->family;
	notebook = set_args->notebook;

	model = GTK_TREE_MODEL(set_args->model);
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, SET_NAME, &set, -1);
	set_args->set = set;
	set_args->data = xzalloc(sizeof(struct set_create_data));
	init_list_head(&(set_args->data->elems));
	set_args->data->family = set_args->family;
	set_args->data->table = xstrdup(set_args->table);
	set_args->data->set = xstrdup(set_args->set);
	gui_get_set(set_args->data);
	// check set exists
	// if ((!set exists) && !(table exits))
	// 	show tables list page
	// else (!(set exists))
	// 	set_update_data(family, table, GTK_TREE_STORE(model));
	// else
	// 	show set's details
	create_new_set(NULL, set_args);
}

void chain_callback_detail(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*chain;
	GtkTreeModel		*model;
	GtkWidget		*notebook;
	struct chain_list_args	*chain_args = (struct chain_list_args *)data;

	table = chain_args->table;
	family = chain_args->family;
	notebook = chain_args->notebook;

	model = GTK_TREE_MODEL(chain_args->model);
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, CHAIN_NAME, &chain, -1);

	// check chain exists
	// if ((!chain exists) && !(table exits))
	// 	show tables list page
	// else (!(chain exists))
	// 	chain_update_data(family, table, GTK_TREE_STORE(model));
	// else
	// 	show rule list page
		gnftables_rule_init(family, table, chain, notebook);

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

void rule_callback_detail(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*chain;
	uint64_t		handle;
	GtkTreeModel		*model;
	GtkTreeView		*treeview;
	struct rule_list_args	*rule_args = (struct rule_list_args *)data;
	gint	res;

	treeview = GTK_TREE_VIEW(rule_args->list_rules);
	table = rule_args->table;
	chain = rule_args->chain;
	family = rule_args->family;

	model = gtk_tree_view_get_model(treeview);
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, RULE_HANDLE, &handle, -1);
	rule_args->handle = handle;

	gui_get_rule(family, table, chain, handle, &rule_args->data);

	// goto rule edit page
	create_new_rule_begin(data);
}

void rule_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*chain;
	gint			handle;
	GtkTreeModel		*model;
	GtkTreeView		*treeview;
	struct rule_list_args	*rule_args = (struct rule_list_args *)data;

	gint	res;
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_WARNING,
                                 GTK_BUTTONS_OK_CANCEL,
                                 "The rule will be deleted. Are you sure?"
                                 );

	treeview = GTK_TREE_VIEW(rule_args->list_rules);
	table = rule_args->table;
	chain = rule_args->chain;
	family = rule_args->family;

	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = gtk_tree_view_get_model(treeview);
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, RULE_HANDLE, &handle, -1);

		gui_delete_rule(family, table, chain, handle);
		rule_update_data(rule_args);
	}

	gtk_widget_destroy(dialog);
	return;

}

static void set_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*set;
	GtkTreeModel		*model;
	struct set_list_args	*set_args = (struct set_list_args *)data;

	gint	res;
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_WARNING,
                                 GTK_BUTTONS_OK_CANCEL,
                                 "The set will be deleted. Are you sure?"
                                 );

	table = set_args->table;
	family = set_args->family;

	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = GTK_TREE_MODEL(set_args->model);
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, SET_NAME, &set, -1);

		gui_delete_set(family, table, set);
		set_update_data(set_args);
	}

	gtk_widget_destroy(dialog);
	return;


}

void chain_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*chain;
	GtkTreeModel		*model;
	struct chain_list_args	*chain_args = (struct chain_list_args *)data;

	gint	res;
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_WARNING,
                                 GTK_BUTTONS_OK_CANCEL,
                                 "The chain and all rules in the chain will be deleted. Are you sure?"
                                 );

	table = chain_args->table;
	family = chain_args->family;

	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = GTK_TREE_MODEL(chain_args->model);
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, CHAIN_NAME, &chain, -1);

		gui_delete_chain(family, table, chain);
		chain_update_data(chain_args);
	}

	gtk_widget_destroy(dialog);
	return;
}


/*
 * Get rules from kernel and display in rule list page.
 */
void rule_update_data(struct rule_list_args *args)
{
	uint32_t	index = 0;
	GtkTreeIter	iter;

	struct gui_rule   *rule, *r;
	LIST_HEAD(rule_list);

	gui_get_rules_list(&rule_list, args->family, args->table, args->chain);
	gtk_tree_store_clear(GTK_TREE_STORE(args->store));

	// display rules in treeview 
	list_for_each_entry_safe(rule, r, &rule_list, list) {
		list_del(&rule->list);
		index++;
		gtk_tree_store_append(GTK_TREE_STORE(args->store), &iter, NULL);
		gtk_tree_store_set(GTK_TREE_STORE(args->store), &iter,
			RULE_ID, index,
			RULE_HANDLE, rule->handle,
			RULE_TABLE, rule->table,
			RULE_CHAIN, rule->chain,
			RULE_CONTENT, rule->stmt,
			RULE_DETAIL, TRUE,
			RULE_DELETE, TRUE,
			-1);
		gui_rule_free(rule);	
	}
}


void set_update_data(struct set_list_args *args)
{
	uint32_t	index = 0;
	GtkTreeIter	iter;
	struct set_list_data   *set, *s;
	gint		family = args->family;
	gchar		*table_name = args->table;
//	gchar		*type = args->type;
	GtkTreeStore	*store = GTK_TREE_STORE(args->store);
	int		res;

	LIST_HEAD(set_list);

	res = gui_get_sets_list(&set_list, family, table_name);
	if (res != SET_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_ERROR,
                                 GTK_BUTTONS_OK,
                                 set_error[res]
                                 );

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	gtk_tree_store_clear (store);
	// display sets in treeview
	list_for_each_entry_safe(set, s, &set_list, list) {
		list_del(&set->list);
		index++;
		gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
		gtk_tree_store_set(GTK_TREE_STORE(store), &iter,
			SET_ID, index,
			SET_NAME, xstrdup(set->name),
			SET_KEYTYPE, xstrdup(set->keytype),
			SET_DATATYPE, set->datatype ? xstrdup(set->datatype) : "X",
			SET_ELEMS, set->nelems,
			SET_DETAIL, TRUE,
			SET_DELETE, TRUE, -1);
		xfree(set->table);
		xfree(set->name);
		xfree(set);
	}
}

/*
 * Get chains from kernel and display in chain list page
 */
void chain_update_data(struct chain_list_args *args)
{
	uint32_t	index = 0;
	GtkTreeIter	iter;
	struct chain_list_data   *chain, *c;
	gint		family = args->family;
	gchar		*table_name = args->table;
	gchar		*type = args->type;
	GtkTreeStore	*store = GTK_TREE_STORE(args->store);
	int		res;

	LIST_HEAD(chain_list);

	res = gui_get_chains_list(&chain_list, family, table_name, type);
	if (res != CHAIN_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_ERROR,
                                 GTK_BUTTONS_OK,
                                 chain_error[res]
                                 );

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	gtk_tree_store_clear (store);
	// display chains in treeview
	list_for_each_entry_safe(chain, c, &chain_list, list) {
		list_del(&chain->list);
		index++;
		gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
		if (chain->basechain) {
			char	priority[50];
			sprintf(priority, "%d", chain->priority);
			gtk_tree_store_set(GTK_TREE_STORE(store), &iter,
				CHAIN_ID, index,
				CHAIN_NAME, xstrdup(chain->chain),
				CHAIN_RULES, chain->nrules,
				CHAIN_BASECHAIN, "Yes",
				CHAIN_TYPE, xstrdup(chain->type),
				CHAIN_HOOK, hooknum2str(family, chain->hook),
				CHAIN_PRIORITY, priority,
				CHAIN_DETAIL, TRUE,
				CHAIN_DELETE, TRUE, -1);
		} else 
			gtk_tree_store_set(GTK_TREE_STORE(store), &iter,
				CHAIN_ID, index,
				CHAIN_NAME, xstrdup(chain->chain), 
				CHAIN_RULES, chain->nrules, 
				CHAIN_BASECHAIN, "No",
				CHAIN_TYPE, "x",
				CHAIN_HOOK, "x",
				CHAIN_PRIORITY, "x",
				CHAIN_DETAIL, TRUE,
				CHAIN_DELETE, TRUE, -1);
		gui_chain_free(chain);	
	}
}


void chain_list_type_changed(GtkComboBoxText *widget, gpointer data)
{
	struct chain_list_args  *args;
	args = (struct chain_list_args *)data;
	args->type = gtk_combo_box_text_get_active_text(widget);
	chain_update_data(args);
}

void chain_create_type_changed(GtkComboBoxText *widget, gpointer data)
{
	char	*type = gtk_combo_box_text_get_active_text(widget);
	GtkComboBoxText	*hook = GTK_COMBO_BOX_TEXT(data);
	gtk_combo_box_text_remove_all(hook);

	if (!(strcmp(type, "filter"))) {
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"prerouting", "prerouting");
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"input", "input");
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"forward", "forward");
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"postrouting", "postrouting");
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"output", "output");
		gtk_combo_box_set_active(GTK_COMBO_BOX(hook), 0);
	} else if (!(strcmp(type, "nat"))) {
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"prerouting", "prerouting");
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"input", "input");
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"postrouting", "postrouting");
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"output", "output");
		gtk_combo_box_set_active(GTK_COMBO_BOX(hook), 0);

	} else if (!(strcmp(type, "route"))) {
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(hook),
				"output", "output");
		gtk_combo_box_set_active(GTK_COMBO_BOX(hook), 0);
	}
}

void gnftables_goto_chain_list(GtkButton *button, gpointer  data)
{
	struct set_list_args  *set_arg;
	set_arg = (struct set_list_args  *)data;
	gnftables_set_chain_init(set_arg->family,
		set_arg->table, set_arg->notebook);
}

void gnftables_set_init(GtkButton *button, gpointer  data)
{
	GtkWidget	*title;
	GtkWidget	*layout;
	GtkWidget	*notebook;
	GtkWidget	*chain_list;
	GtkWidget	*create_set;
	GtkWidget	*list_sets;
	GtkWidget	*scrolledwindow;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer_details;
	GtkCellRenderer	*renderer_delete;
	GtkTreeViewColumn	*column;

	struct set_list_args  *set_arg;
	struct chain_list_args *chain_arg;

	chain_arg = (struct chain_list_args *)data;
	set_arg = xzalloc(sizeof(struct set_list_args));
	set_arg->notebook = chain_arg->notebook;
	set_arg->family = chain_arg->family;
	set_arg->table = chain_arg->table;
	notebook = chain_arg->notebook;

	store = gtk_tree_store_new(SET_TOTAL, G_TYPE_INT, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);

	title = gtk_label_new("Sets");
	gtk_widget_set_size_request(title, 200, 10);
	layout = gtk_layout_new(NULL, NULL);

    	chain_list = gtk_button_new_with_label("Go to chain list page");
	gtk_widget_set_size_request(chain_list, 150, 10);
	g_signal_connect(G_OBJECT(chain_list), "clicked",
			G_CALLBACK(gnftables_goto_chain_list), set_arg);
	gtk_layout_put(GTK_LAYOUT(layout), chain_list, 530, 10);

    	create_set = gtk_button_new_with_label("Create Set");
	gtk_widget_set_size_request(create_set, 150, 10);
	g_signal_connect(G_OBJECT(create_set), "clicked",
			G_CALLBACK(create_new_set), set_arg);
	gtk_layout_put(GTK_LAYOUT(layout), create_set, 700, 10);
	set_arg->store = store;

	set_update_data(set_arg);

	// treeview style
	list_sets = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();
	set_arg->model = gtk_tree_view_get_model(GTK_TREE_VIEW(list_sets));

	column = gtk_tree_view_column_new_with_attributes("Id", renderer,
			"text", SET_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 50);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer,
			"text", SET_NAME, NULL);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);
	column = gtk_tree_view_column_new_with_attributes("Key Type", renderer,
			"text", SET_KEYTYPE, NULL);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);
	column = gtk_tree_view_column_new_with_attributes("Data Type", renderer,
			"text", SET_DATATYPE, NULL);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);
	gtk_tree_view_column_set_visible(column, FALSE);
	column = gtk_tree_view_column_new_with_attributes("Elements", renderer,
			"text", SET_ELEMS, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);

	renderer_details = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer_details, "toggled",
			G_CALLBACK(set_callback_detail), set_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Details",
			renderer_details, "active", SET_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);

	renderer_delete = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer_delete, "toggled",
			G_CALLBACK(set_callback_delete), set_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Delete",
			renderer_delete, "active", SET_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);

        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(
			GTK_SCROLLED_WINDOW(scrolledwindow), 876);
	gtk_scrolled_window_set_min_content_height(
			GTK_SCROLLED_WINDOW(scrolledwindow), 410);
	gtk_scrolled_window_set_shadow_type(
			GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_sets);

	gtk_layout_put(GTK_LAYOUT(layout), scrolledwindow, 0, 50);
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 2);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, title, 1);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
}

/*
 * Add chains list page in notebook
 */
void gnftables_set_chain_init(gint family, gchar *table_name, GtkWidget *notebook)
{
	GtkWidget	*title;
	GtkWidget	*layout;
	GtkWidget	*type;
	GtkWidget	*combo_type;
	GtkWidget	*set_list;
	GtkWidget	*create_chain;
	GtkWidget	*list_chains;
	GtkWidget	*scrolledwindow;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer_details;
	GtkCellRenderer	*renderer_delete;
	GtkTreeViewColumn	*column;

	struct chain_list_args  *chain_arg;
	chain_arg = xzalloc(sizeof(struct chain_list_args));
	chain_arg->notebook = notebook;
	chain_arg->family = family;
	chain_arg->table = table_name;

	store = gtk_tree_store_new(CHAIN_TOTAL, G_TYPE_INT, G_TYPE_STRING,
			G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN,
			G_TYPE_BOOLEAN);

	title = gtk_label_new("Chains");
	gtk_widget_set_size_request(title, 200, 10);
	layout = gtk_layout_new(NULL, NULL);


	type = gtk_label_new("Type");
	gtk_layout_put(GTK_LAYOUT(layout), type, 20, 10);

	combo_type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(combo_type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
			"all", "all");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
			"user", "user");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
			"filter", "filter");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
//			"nat", "nat");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
//			"route", "route");
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_type), 0);
	chain_arg->type = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo_type));
	gtk_layout_put(GTK_LAYOUT(layout), combo_type, 60, 10);

    	set_list = gtk_button_new_with_label("Go to set list page");
	gtk_widget_set_size_request(set_list, 150, 10);
	g_signal_connect(G_OBJECT(set_list), "clicked",
			G_CALLBACK(gnftables_set_init), chain_arg);
	gtk_layout_put(GTK_LAYOUT(layout), set_list, 530, 10);

    	create_chain = gtk_button_new_with_label("Create Chain");
	gtk_widget_set_size_request(create_chain, 150, 10);
	g_signal_connect(G_OBJECT(create_chain), "clicked",
			G_CALLBACK(create_new_chain), chain_arg);
	gtk_layout_put(GTK_LAYOUT(layout), create_chain, 700, 10);
	chain_arg->store = store;

	chain_update_data(chain_arg);

	// treeview style
	list_chains = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();
	chain_arg->model = gtk_tree_view_get_model(GTK_TREE_VIEW(list_chains));
	g_signal_connect(combo_type, "changed",
			G_CALLBACK(chain_list_type_changed), chain_arg);

	column = gtk_tree_view_column_new_with_attributes("Id", renderer,
			"text", CHAIN_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 50);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer,
			"text", CHAIN_NAME, NULL);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Rules", renderer,
			"text", CHAIN_RULES, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Base Chain",
			renderer, "text", CHAIN_BASECHAIN, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Type", renderer,
			"text", CHAIN_TYPE, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Hook", renderer,
			"text", CHAIN_HOOK, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Priority", renderer,
			"text", CHAIN_PRIORITY, NULL);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);

	renderer_details = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer_details, "toggled",
			G_CALLBACK(chain_callback_detail), chain_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Details",
			renderer_details, "active", CHAIN_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);

	renderer_delete = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer_delete, "toggled",
			G_CALLBACK(chain_callback_delete), chain_arg) ;
	column = gtk_tree_view_column_new_with_attributes("Delete",
			renderer_delete, "active", CHAIN_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);

        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(
			GTK_SCROLLED_WINDOW(scrolledwindow), 876);
	gtk_scrolled_window_set_min_content_height(
			GTK_SCROLLED_WINDOW(scrolledwindow), 410);
	gtk_scrolled_window_set_shadow_type(
			GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_chains);

	gtk_layout_put(GTK_LAYOUT(layout), scrolledwindow, 0, 50);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, title, 1);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
}


/*
 * Get basic information of tables from kernel and display in treeview.
 * @family: nftable family
 * @store:  container used to store data from kernel
 */
void table_update_data(gint family, GtkTreeStore *store)
{
	gint		index = 0;
	GtkTreeIter	iter;
	gint		res;

	struct table_list_data   *table, *tmp;
	LIST_HEAD(table_list);

	// only ipv4 is supported now.
	res = gui_get_tables_list(&table_list, NFPROTO_IPV4);
	if (res != TABLE_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_ERROR,
                                 GTK_BUTTONS_OK,
                                 table_error[res]
                                 );

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}
	gtk_tree_store_clear(store);

	// display tables in treeview
	list_for_each_entry_safe(table, tmp, &table_list, list) {
		list_del(&table->list);
		index++;
		gtk_tree_store_append(GTK_TREE_STORE(store), &iter, NULL);
		if (table->family == NFPROTO_IPV4)
			gtk_tree_store_set(GTK_TREE_STORE(store), &iter,
				TABLE_ID, index, TABLE_NAME, xstrdup(table->table),
				TABLE_FAMILY, "ipv4", TABLE_SETS, table->nsets,
				TABLE_CHAINS, table->nchains, TABLE_DETAIL,
				TRUE, TABLE_DELETE, TRUE, -1);
		else
			gtk_tree_store_set(GTK_TREE_STORE(store), &iter,
				TABLE_ID, index, TABLE_NAME, xstrdup(table->table),
				TABLE_FAMILY, family2str(table->family),
				TABLE_SETS, table->nsets, TABLE_CHAINS,
				table->nchains, TABLE_DETAIL, TRUE,
				TABLE_DELETE, TRUE, -1);
		xfree(table->table);
		xfree(table);
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


/*
 * Goto chains list page
 *
 */
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

	// Check whether the table exists first. If it still exists,
	// goto chains list page. If not, leave in table list page.
	res = gui_check_table_exist(family, name);
	if (res == TABLE_SUCCESS)
		gnftables_set_chain_init(family, name, notebook);
	else {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                 0,
                                 GTK_MESSAGE_ERROR,
                                 GTK_BUTTONS_OK,
                                 table_error[res]
                                 );

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		table_update_data(NFPROTO_UNSPEC, GTK_TREE_STORE(model));
	}
}


/*
 * Delete a table,
 */
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
		0, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK_CANCEL,
		"The table and all rules in the table will be deleted. Are you sure?"
		);

	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, TABLE_NAME, &name,
				TABLE_FAMILY, &family_str, -1);
		family = str2family(family_str);
		gui_delete_table(family, name);
		table_update_data(NFPROTO_UNSPEC, GTK_TREE_STORE(model));
	}

	gtk_widget_destroy(dialog);
	return;
}


/*
gboolean show_treeview_menu(GtkWidget *widget, GdkEvent  *event, gpointer   user_data)
{
	if (event->type == GDK_BUTTON_PRESS && event->button.button == 3)  { 
		printf("hello world\n");
	} 

	return FALSE;
}
*/


// table list page
void gnftables_table_init(GtkWidget *notebook)
{
	GtkWidget	*title;
	GtkWidget	*layout;
	GtkWidget	*family;
	GtkWidget	*combo;
	GtkWidget	*create_table;
	GtkWidget	*list_tables;
	GtkWidget	*scrolledwindow;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer_details;
	GtkCellRenderer	*renderer_delete;
	GtkTreeViewColumn *column;

	struct list_sets_and_chains  *data;
	data = xzalloc(sizeof(struct list_sets_and_chains));

	store = gtk_tree_store_new(TABLE_TOTAL, G_TYPE_INT, G_TYPE_STRING, 
			G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT,G_TYPE_BOOLEAN,
			G_TYPE_BOOLEAN);

	// set title in table list page.
	title = gtk_label_new("Tables");
	gtk_widget_set_size_request(title, 200, 10);
	layout = gtk_layout_new(NULL, NULL);

	// only show talbes in selected family.
	family = gtk_label_new("Family");
	gtk_layout_put(GTK_LAYOUT(layout), family, 30, 10);
	combo = create_family_list(1, select_family, store);
	gtk_layout_put(GTK_LAYOUT(layout), combo, 90, 10);

	// create a new table.
    	create_table = gtk_button_new_with_label("Create Table");
	gtk_widget_set_size_request(create_table, 150, 10);
	g_signal_connect(G_OBJECT(create_table), "clicked",
			G_CALLBACK(create_new_table), notebook);
	gtk_layout_put(GTK_LAYOUT(layout), create_table, 700, 10);


	// treeview style
	list_tables = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
//	g_signal_connect(list_tables, "button-press-event",
//			G_CALLBACK(show_treeview_menu), NULL); 
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Id", renderer, 
			"text", TABLE_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer,
			"text", TABLE_NAME, NULL);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Family", renderer,
			"text", TABLE_FAMILY, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Sets", renderer,
			"text", TABLE_SETS, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Chains", renderer,
			"text", TABLE_CHAINS, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

	// use toggle temporarily，it will be changed when gnftables release.
	renderer_details = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer_details, "toggled",
			G_CALLBACK(table_callback_detail), data) ;
	column = gtk_tree_view_column_new_with_attributes("Details",
			renderer_details, "active", TABLE_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 140);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

	renderer_delete = gtk_cell_renderer_toggle_new();
	g_signal_connect(renderer_delete, "toggled",
			G_CALLBACK(table_callback_delete), list_tables) ;
	column = gtk_tree_view_column_new_with_attributes("Delete",
			renderer_delete, "active", TABLE_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

	data->treeview = list_tables;
	data->notebook = notebook;

	// all information listed in a scrolled window.
        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(
			GTK_SCROLLED_WINDOW(scrolledwindow), 876);
	gtk_scrolled_window_set_min_content_height(
			GTK_SCROLLED_WINDOW(scrolledwindow), 410);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow),
			GTK_SHADOW_ETCHED_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
                                GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_tables);

	gtk_layout_put(GTK_LAYOUT(layout), scrolledwindow, 0, 50);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), layout, title, 0);

	gtk_widget_show_all(window);
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));

	// get information of all tables from kernel.
	table_update_data(NFPROTO_UNSPEC, store);
}



void gnftables_about_init(GtkWidget *notebook)
{
	GtkWidget	*content;
	GtkWidget	*label;

	const gchar *text = "gnftables 0.1.0\n\ngnftables is a gui tool aimed to simplify the configuration of nftables from command line. It's in heavy develpment now. If you need more help, please visit the project's home site (http://ycnian.org/projects/gnftables.php).\n\nCopyright (c) 2014  Yanchuan Nian <ycnian@gmail.com>\n\nThis program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation. Note that *only* version 2 of the GPL applies, not any later version.\n\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.\n\nYou should have received a copy of the GNU General Public License along with this program. You may also obtain a copy of the GNU General Public License from the Free Software Foundation by visiting their web site (http://www.fsf.org/) or by writing to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA";
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
	gtk_container_add(GTK_CONTAINER(window), layout);

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


