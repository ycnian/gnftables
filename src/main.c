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


//  nft add rule ip filter input ip saddr 192.168.1.101 ip daddr 192.168.1.102  counter accept
void begin_create_new_rule(GtkButton *button, gpointer  info)
{
	struct rule_create_widget  *gui_rule = (struct rule_create_widget *)info;
	GtkWidget	*notebook = gui_rule->notebook;
	struct gui_rule	*rule = malloc(sizeof(struct gui_rule));
	rule->family = gui_rule->family;
	rule->table = gui_rule->table;
	rule->chain = gui_rule->chain;
	init_list_head(&rule->list);

	// data check
	//
	rule_gen_expressions(gui_rule, rule);

	gui_add_rule(rule);

	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 2);
	gnftables_rule_init(rule->family, rule->table, rule->chain, notebook);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));

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
		gtk_label_set_text(GTK_LABEL(widget->msg), chain_error[CHAIN_TABLE_KERNEL_ERROR]);
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
		update_cancel_ok_position(widget);
	} else if ((void *)expander == (void *)(widget->meta->expander)) {
		if (gtk_expander_get_expanded(expander))
			widget->meta->expanded = 1;
		else
			widget->meta->expanded = 0;
		update_cancel_ok_position(widget);
	}
}


void header_transport_show_all(GtkWidget *fixed, struct transport_info *transport)
{
	gtk_widget_hide(transport->tcp.sport);
	gtk_widget_hide(transport->tcp.sport_value);
	gtk_widget_hide(transport->tcp.dport);
	gtk_widget_hide(transport->tcp.dport_value);
	gtk_widget_hide(transport->udp.sport);
	gtk_widget_hide(transport->udp.sport_value);
	gtk_widget_hide(transport->udp.dport);
	gtk_widget_hide(transport->udp.dport_value);
}

void header_transport_show_tcp(GtkWidget *fixed, struct transport_info *transport)
{
	gtk_widget_hide(transport->udp.sport);
	gtk_widget_hide(transport->udp.sport_value);
	gtk_widget_hide(transport->udp.dport);
	gtk_widget_hide(transport->udp.dport_value);

	gtk_fixed_move(GTK_FIXED(fixed), transport->tcp.sport, 40, 140);
	gtk_fixed_move(GTK_FIXED(fixed), transport->tcp.sport_value, 150, 140);
	gtk_entry_set_text(GTK_ENTRY(transport->tcp.sport_value), "");
	gtk_fixed_move(GTK_FIXED(fixed), transport->tcp.dport, 40, 180);
	gtk_fixed_move(GTK_FIXED(fixed), transport->tcp.dport_value, 150, 180);
	gtk_entry_set_text(GTK_ENTRY(transport->tcp.dport_value), "");
	gtk_widget_show(transport->tcp.sport);
	gtk_widget_show(transport->tcp.sport_value);
	gtk_widget_show(transport->tcp.dport);
	gtk_widget_show(transport->tcp.dport_value);
}

void header_transport_show_udp(GtkWidget *fixed, struct transport_info *transport)
{
	gtk_widget_hide(transport->tcp.sport);
	gtk_widget_hide(transport->tcp.sport_value);
	gtk_widget_hide(transport->tcp.dport);
	gtk_widget_hide(transport->tcp.dport_value);

	gtk_fixed_move(GTK_FIXED(fixed), transport->udp.sport, 40, 140);
	gtk_fixed_move(GTK_FIXED(fixed), transport->udp.sport_value, 150, 140);
	gtk_entry_set_text(GTK_ENTRY(transport->udp.sport_value), "");
	gtk_fixed_move(GTK_FIXED(fixed), transport->udp.dport, 40, 180);
	gtk_fixed_move(GTK_FIXED(fixed), transport->udp.dport_value, 150, 180);
	gtk_entry_set_text(GTK_ENTRY(transport->udp.dport_value), "");
	gtk_widget_show(transport->udp.sport);
	gtk_widget_show(transport->udp.sport_value);
	gtk_widget_show(transport->udp.dport);
	gtk_widget_show(transport->udp.dport_value);
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
	if (widget->header->expanded) {
		enum transport_type type;
		len += widget->header->len;
		type = widget->header->transport.value->type;
		switch (type) {
		case  TRANSPORT_ALL:
			len += widget->header->transport.value->all.len;
			break;
		case  TRANSPORT_TCP:
			len += widget->header->transport.value->tcp.len;
			break;
		case  TRANSPORT_UDP:
			len += widget->header->transport.value->udp.len;
			break;
		}
	} else
		len += 40;

	widget->meta->offset = len;
	gtk_fixed_move(GTK_FIXED(fixed), expander, 0, len);
}

void update_cancel_ok_position(struct rule_create_widget  *widget)
{
	GtkWidget  *fixed = widget->fixed;
	GtkWidget  *cancel = widget->cancel;
	GtkWidget  *ok = widget->ok;
	int	len = widget->meta->offset;
	if (widget->meta->expanded)
		len +=  widget->meta->len;
	len += 40;
	if (len < 360)
		len = 360;
	gtk_fixed_move(GTK_FIXED(fixed), cancel, 540, len);
	gtk_fixed_move(GTK_FIXED(fixed), ok, 660, len);
}


void transport_callback_do(struct rule_create_widget  *widget)
{
	GtkWidget	*fixed_header = widget->header->fixed;
	struct transport_info *transport = widget->header->transport.value;
	update_header_transport_widgets(fixed_header, transport);
	update_pktmeta_position(widget);
	// update_trackmeta_position();
	update_cancel_ok_position(widget);
}

void transport_callback(GtkComboBoxText *widget, gpointer data)
{
	struct rule_create_widget  *args;
	args = (struct rule_create_widget *)data;
	
	char	*type = gtk_combo_box_text_get_active_text(widget);
	if (!(strcmp(type, "all")))
		args->header->transport.value->type = TRANSPORT_ALL;
	else if (!(strcmp(type, "tcp")))
		args->header->transport.value->type = TRANSPORT_TCP;
	else if (!(strcmp(type, "udp")))
		args->header->transport.value->type = TRANSPORT_UDP;
	// else
	// 	bug();

	transport_callback_do(args);
}

void create_new_rule(GtkButton *button, gpointer  data)
{
	GtkWidget	*title;
	GtkWidget	*fixed_back;
	GtkWidget	*fixed_content;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	GtkWidget	*notebook;
	GtkWidget	*scrolledwindow;

	GtkWidget	*fixed_header;
	GtkWidget	*expander_header;
	GtkWidget	*saddr;
	GtkWidget	*saddr_type;
	GtkWidget	*saddr_value;
	GtkWidget	*daddr;
	GtkWidget	*daddr_type;
	GtkWidget	*daddr_value;
	GtkWidget	*transport;
	GtkWidget	*transport_value;
	GtkWidget	*tcp_sport;
	GtkWidget	*tcp_sport_value;
	GtkWidget	*tcp_dport;
	GtkWidget	*tcp_dport_value;
	GtkWidget	*udp_sport;
	GtkWidget	*udp_sport_value;
	GtkWidget	*udp_dport;
	GtkWidget	*udp_dport_value;

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

	struct rule_list_args	*rule_arg;
	struct rule_create_widget	*new_rule;

	rule_arg = (struct rule_list_args *)data;
	new_rule = xmalloc(sizeof(struct rule_create_widget));
	new_rule->header = xmalloc(sizeof(struct match_header));
	new_rule->meta = xmalloc(sizeof(struct match_pktmeta));
	new_rule->track = xmalloc(sizeof(struct match_trackmeta));
	new_rule->header->saddr.value = xmalloc(sizeof(struct ip_address));
	new_rule->header->daddr.value = xmalloc(sizeof(struct ip_address));
	new_rule->header->transport.value = xmalloc(sizeof(struct transport_info));

	notebook = rule_arg->notebook;
	new_rule->notebook = notebook;
	new_rule->family = rule_arg->family;
	new_rule->table = rule_arg->table;
	new_rule->chain = rule_arg->chain;

	title = gtk_label_new("Create rule");
	gtk_widget_set_size_request(title, 200, 10);
	fixed_back = gtk_fixed_new();
	fixed_header = gtk_fixed_new();
	fixed_pktmeta = gtk_fixed_new();
	fixed_content = gtk_fixed_new();
	new_rule->fixed = fixed_content;
	
	expander_header = gtk_expander_new("Matching packet header fields");
	gtk_fixed_put(GTK_FIXED(fixed_content), expander_header, 0, 0);
	gtk_container_add(GTK_CONTAINER(expander_header), fixed_header);
	g_signal_connect(expander_header, "notify::expanded", G_CALLBACK(expander_callback), new_rule);
	new_rule->header->expander = expander_header;
	new_rule->header->fixed = fixed_header;
	new_rule->header->expanded = 0;
	new_rule->header->len = 180;

	saddr = gtk_label_new("source addres:");
	gtk_fixed_put(GTK_FIXED(fixed_header), saddr, 40, 20);
	saddr_type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(saddr_type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(saddr_type),
			"exact ip", "exact ip");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(saddr_type),
			"subnet", "subnet");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(saddr_type),
			"range", "range");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(saddr_type),
			"sets", "sets");
	gtk_combo_box_set_active(GTK_COMBO_BOX(saddr_type), 0);
	gtk_fixed_put(GTK_FIXED(fixed_header), saddr_type, 150, 20);
	saddr_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(saddr_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_header), saddr_value, 280, 20);
	new_rule->header->saddr.type = saddr_type;
	new_rule->header->saddr.value->type = ADDRESS_EXACT;
	new_rule->header->saddr.value->exact_ip.ip = saddr_value;

	daddr = gtk_label_new("dest addres:");
	gtk_fixed_put(GTK_FIXED(fixed_header), daddr, 40, 60);
	daddr_type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(daddr_type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(daddr_type),
			"exact ip", "exact ip");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(daddr_type),
			"subnet", "subnet");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(daddr_type),
			"range", "range");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(daddr_type),
			"sets", "sets");
	gtk_combo_box_set_active(GTK_COMBO_BOX(daddr_type), 0);
	gtk_fixed_put(GTK_FIXED(fixed_header), daddr_type, 150, 60);
	daddr_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(daddr_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_header), daddr_value, 280, 60);
	new_rule->header->daddr.type = daddr_type;
	new_rule->header->daddr.value->type = ADDRESS_EXACT;
	new_rule->header->daddr.value->exact_ip.ip = daddr_value;

	transport = gtk_label_new("transport:");
	gtk_fixed_put(GTK_FIXED(fixed_header), transport, 40, 100);

	transport_value = gtk_combo_box_text_new();
	gtk_widget_set_size_request(transport_value, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(transport_value),
			"all", "all");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(transport_value),
			"tcp", "tcp");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(transport_value),
			"udp", "udp");
	gtk_combo_box_set_active(GTK_COMBO_BOX(transport_value), 0);
	g_signal_connect(transport_value, "changed", G_CALLBACK(transport_callback), new_rule);
	gtk_fixed_put(GTK_FIXED(fixed_header), transport_value, 150, 100);
	new_rule->header->transport.type = transport_value;
	new_rule->header->transport.value->type = TRANSPORT_ALL;
	new_rule->header->transport.value->all.len = 0;

	tcp_sport = gtk_label_new("source port:");
	gtk_fixed_put(GTK_FIXED(fixed_header), tcp_sport, 0, 0);
	tcp_sport_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(tcp_sport_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_header), tcp_sport_value, 0, 0);
	tcp_dport = gtk_label_new("dest port:");
	gtk_fixed_put(GTK_FIXED(fixed_header), tcp_dport, 0, 0);
	tcp_dport_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(tcp_dport_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_header), tcp_dport_value, 0, 0);

	new_rule->header->transport.value->tcp.sport = tcp_sport;
	new_rule->header->transport.value->tcp.sport_value = tcp_sport_value;
	new_rule->header->transport.value->tcp.dport = tcp_dport;
	new_rule->header->transport.value->tcp.dport_value = tcp_dport_value;
	new_rule->header->transport.value->tcp.len = 80;

	udp_sport = gtk_label_new("source port:");
	gtk_fixed_put(GTK_FIXED(fixed_header), udp_sport, 0, 0);
	udp_sport_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(udp_sport_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_header), udp_sport_value, 0, 0);
	udp_dport = gtk_label_new("dest port:");
	gtk_fixed_put(GTK_FIXED(fixed_header), udp_dport, 0, 0);
	udp_dport_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(udp_dport_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_header), udp_dport_value, 0, 0);
	new_rule->header->transport.value->udp.sport = udp_sport;
	new_rule->header->transport.value->udp.sport_value = udp_sport_value;
	new_rule->header->transport.value->udp.dport = udp_dport;
	new_rule->header->transport.value->udp.dport_value = udp_dport_value;
	new_rule->header->transport.value->udp.len = 80;


	expander_pktmeta = gtk_expander_new("Matching packet metainformation");
	gtk_fixed_put(GTK_FIXED(fixed_content), expander_pktmeta, 0, 40);
	gtk_container_add(GTK_CONTAINER(expander_pktmeta), fixed_pktmeta);
	g_signal_connect(expander_pktmeta, "notify::expanded", G_CALLBACK(expander_callback), new_rule);
	new_rule->meta->expander = expander_pktmeta;
	new_rule->meta->expanded = 0;
	new_rule->meta->len = 280;

	iifname = gtk_label_new("input interface:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), iifname, 40, 20);
	iifname_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(iifname_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), iifname_value, 150, 20);
	new_rule->meta->iifname = iifname_value;

	oifname = gtk_label_new("output interface:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), oifname, 40, 60);
	oifname_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(oifname_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), oifname_value, 150, 60);
	new_rule->meta->oifname = oifname_value;

	iiftype = gtk_label_new("input type:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), iiftype, 40, 100);
	iiftype_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(iiftype_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), iiftype_value, 150, 100);
	new_rule->meta->iiftype = iiftype_value;

	oiftype = gtk_label_new("output type:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), oiftype, 40, 140);
	oiftype_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(oiftype_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), oiftype_value, 150, 140);
	new_rule->meta->oiftype = oiftype_value;

	skuid = gtk_label_new("user:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), skuid, 40, 180);
	skuid_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(skuid_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), skuid_value, 150, 180);
	new_rule->meta->skuid = skuid_value;

	skgid = gtk_label_new("group:");
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), skgid, 40, 220);
	skgid_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(skgid_value), 35);
	gtk_fixed_put(GTK_FIXED(fixed_pktmeta), skgid_value, 150, 220);
	new_rule->meta->skgid = skgid_value;


    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(back_to_rule_list), new_rule);
	gtk_fixed_put(GTK_FIXED(fixed_content), cancel, 540, 360);
	new_rule->cancel = cancel;

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
//	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(begin_create_new_rule), new_rule);
	gtk_fixed_put(GTK_FIXED(fixed_content), ok, 660, 360);
	new_rule->ok = ok;

        scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolledwindow), 856);
	gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolledwindow), 400);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), GTK_SHADOW_ETCHED_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
                                GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolledwindow), fixed_content);

	gtk_fixed_put(GTK_FIXED(fixed_back), scrolledwindow, 10, 40);
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 2);
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), fixed_back, title, 2);
	gtk_widget_show_all(GTK_WIDGET(notebook));
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));

	gtk_widget_hide(tcp_sport);
	gtk_widget_hide(tcp_sport_value);
	gtk_widget_hide(tcp_dport);
	gtk_widget_hide(tcp_dport_value);
	gtk_widget_hide(udp_sport);
	gtk_widget_hide(udp_sport_value);
	gtk_widget_hide(udp_dport);
	gtk_widget_hide(udp_dport_value);
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

	struct  basechain_info  *basechain = g_malloc(sizeof(*basechain));
	struct chain_create_widget *widgets = g_malloc(sizeof(struct chain_create_widget));
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
	args = xmalloc(sizeof(struct table_create_widget));
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

	struct rule_list_args  *rule_arg = g_malloc(sizeof(*rule_arg));
	rule_arg->notebook = notebook;
	rule_arg->family = family;
	rule_arg->table = table_name;
	rule_arg->chain = chain_name;

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
//	g_signal_connect(renderer_details, "toggled",
//			G_CALLBACK(rule_callback_detail), rule_arg) ;
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

/*
 * Add chains list page in notebook
 */
void gnftables_set_chain_init(gint family, gchar *table_name, GtkWidget *notebook)
{
	GtkWidget	*title;
	GtkWidget	*layout;
	GtkWidget	*type;
	GtkWidget	*combo_type;
	GtkWidget	*create_chain;
	GtkWidget	*list_chains;
	GtkWidget	*scrolledwindow;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer_details;
	GtkCellRenderer	*renderer_delete;
	GtkTreeViewColumn	*column;

	struct chain_list_args  *chain_arg;
	chain_arg = g_malloc(sizeof(struct chain_list_args));
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
	gtk_layout_put(GTK_LAYOUT(layout), type, 30, 10);

	combo_type = gtk_combo_box_text_new();
	gtk_widget_set_size_request(combo_type, 100, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
			"all", "all");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
			"user", "user");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
			"filter", "filter");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
			"nat", "nat");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
			"route", "route");
//	g_signal_connect(combo_type, "changed",
//			G_CALLBACK(nftables_type_changed), chain_arg);
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_type), 0);
	chain_arg->type = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo_type));
	gtk_layout_put(GTK_LAYOUT(layout), combo_type, 90, 10);

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
	data = xmalloc(sizeof(struct list_sets_and_chains));

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


