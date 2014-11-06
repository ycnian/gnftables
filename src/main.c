/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 * Copyright (c) 2014 Yanchuan Nian <ycnian@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <inttypes.h>
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
#include <gtkcellrendererpixbufclicked.h>
///////////////////////////   end added for gnftables   /////////////////////////////////////



unsigned int max_errors = 10;
unsigned int numeric_output = 1;
unsigned int handle_output;
#ifdef DEBUG
unsigned int debug_level;
#endif

const char *include_paths[INCLUDE_PATHS_MAX] = { DEFAULT_INCLUDE_PATH };

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


struct top_window  *top_window;


static void select_page(GtkNotebook *notebook, GtkWidget *page, guint page_num, gpointer user_data)
{
	unsigned int    i;
	unsigned	num;
	num = gtk_notebook_get_n_pages(notebook);
	if (top_window->silent) {
		top_window->silent = 0;
		return;
	}
	for (i = page_num + 1; i < num - 1; i++) {
		gtk_widget_hide(gtk_notebook_get_nth_page(notebook, i));
	}

	switch (page_num) {
	case 0:
		if (top_window->page_current != NOTEBOOK_TABLE_CREATE) {
			top_window->data->table = NULL;
			top_window->data->chain = NULL;
			top_window->data->set = NULL;
			top_window->data->type = NULL;
			gnftables_table_list();
		}
		break;
	case 1:
		if (top_window->page_current == NOTEBOOK_SET_LIST) {
			top_window->data->chain = NULL;
			top_window->data->set = NULL;
			top_window->data->type = (char *)"all";
			gnftables_set_list();
		}
		if (top_window->page_current == NOTEBOOK_CHAIN_LIST ||
			top_window->page_current & NOTEBOOK_RULE) {
			top_window->data->chain = NULL;
			top_window->data->set = NULL;
			top_window->data->type = (char *)"all";
			gnftables_chain_list();
		}
		break;
	case 2:
		if (top_window->page_current == NOTEBOOK_RULE_LIST)
			gnftables_rule_list();
		break;
	default:	
		break;
	}

	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


static void load_rules(GtkButton *button, gpointer data)
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
		tables_load(filename);
		g_free(filename);
	}

	gtk_widget_destroy(dialog);
	gnftables_table_list();
	if (top_window->chain_set_container)
		gtk_widget_hide(top_window->chain_set_container);
	if (top_window->rule_container)
		gtk_widget_hide(top_window->rule_container);
}


static void save_rules(GtkButton *button, gpointer data)
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
}


static GdkPixbuf *create_pixbuf(const gchar *filename)
{
	GdkPixbuf  *pixbuf;
	GError     *error = NULL;

	pixbuf = gdk_pixbuf_new_from_file(filename, &error);
	if (!pixbuf)
		g_error_free(error);

	return pixbuf;
}


static void update_pktmeta_position(struct rule_create_widget  *widget)
{
	GtkWidget  *fixed = widget->fixed;
	GtkWidget  *expander = widget->meta->expander;
	int	len = 0;
	if (widget->header->expanded)
		len += widget->header->len;
	len += 40;

	gtk_fixed_move(GTK_FIXED(fixed), expander, 0, len);
}


static void update_actions_position(struct rule_create_widget  *widget)
{
	GtkWidget  *fixed = widget->fixed;
	GtkWidget  *actions_fixed = widget->actions->fixed;
	int	len = 0;
	if (widget->header->expanded)
		len += widget->header->len;
	if (widget->meta->expanded)
		len += widget->meta->len;
	len += 80;

	gtk_fixed_move(GTK_FIXED(fixed), actions_fixed, 0, len);
}


static void update_cancel_ok_position(struct rule_create_widget  *widget)
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
	len += 240;
	if (len < 360)
		len = 360;
	gtk_fixed_move(GTK_FIXED(fixed), msg, 40, len);
	gtk_fixed_move(GTK_FIXED(fixed), cancel, 540, len);
	gtk_fixed_move(GTK_FIXED(fixed), ok, 660, len);
}


static void expander_callback(GObject *object,
		GParamSpec *param_spec, gpointer user_data)
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
	}
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


static void header_addr_set_show(struct ip_address *addr, int family, char *table, char *setname)
{
	int	res;
	GtkWidget	*addr_set = addr->sets.set;
	struct set_list_data   *set, *s;
	int	index = 0;
	int	selected = 0;

	LIST_HEAD(set_list);
	res = gui_get_sets_list(&set_list, family, table, (char *)"IPv4 address", 0);
	if (res != SET_SUCCESS)
		// error;
		;
	gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(addr_set));
	list_for_each_entry_safe(set, s, &set_list, list) {
		list_del(&set->list);
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(addr_set),
			xstrdup(set->name), xstrdup(set->name));
		if (setname) {
			if (!strcmp(setname, set->name))
				selected = index;
		}
		index++;
		xfree(set->table);
		xfree(set->name);
		xfree(set);
	}
	
	gtk_combo_box_set_active(GTK_COMBO_BOX(addr_set), selected);
	gtk_widget_show(addr->sets.set);
}


static void header_addr_set_hide(struct ip_address *addr)
{
	gtk_widget_hide(addr->sets.set);
}


static void header_addr_callback(GtkComboBoxText *widget, gpointer data)
{
	struct ip_address	*addr;
	struct match_header	*args;
	char	*type;
	args = (struct match_header *)data;

	if ((void *)widget == (void *)args->saddr.type)
		addr = args->saddr.value;
	else
		addr = args->daddr.value;

	type = gtk_combo_box_text_get_active_text(widget);
	if (!(strcmp(type, "ip list"))) {
		addr->type = ADDRESS_EXACT;
		header_addr_subnet_hide(addr);
		header_addr_range_hide(addr);
		header_addr_set_hide(addr);
		header_addr_exactip_show(addr);
	} else if (!(strcmp(type, "subnet"))) {
		addr->type = ADDRESS_SUBNET;
		header_addr_exactip_hide(addr);
		header_addr_range_hide(addr);
		header_addr_set_hide(addr);
		header_addr_subnet_show(addr);
	} else if (!(strcmp(type, "range"))) {
		addr->type = ADDRESS_RANGE;
		header_addr_exactip_hide(addr);
		header_addr_subnet_hide(addr);
		header_addr_set_hide(addr);
		header_addr_range_show(addr);
	}else if (!(strcmp(type, "sets"))) {
		addr->type = ADDRESS_SET;
		header_addr_exactip_hide(addr);
		header_addr_subnet_hide(addr);
		header_addr_range_hide(addr);
		header_addr_set_show(addr, args->family, args->table, NULL);
	}
	// else
	// 	bug();
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
	GtkWidget	*addr_set;
	int		offset;
	const char	*label;
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
			"ip list", "ip list");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(addr_type),
			"subnet", "subnet");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(addr_type),
			"range", "range");
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(addr_type),
			"sets", "sets");
	gtk_fixed_put(GTK_FIXED(fixed), addr_type, 150, offset);
	if (source)
		header->saddr.type = addr_type;
	else
		header->daddr.type = addr_type;
	
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

	addr_set =  gtk_combo_box_text_new();
	gtk_widget_set_size_request(addr_set, 200, 10);
	gtk_fixed_put(GTK_FIXED(fixed), addr_set, 280, offset);
	ipaddr->sets.set = addr_set;
	gtk_combo_box_set_active(GTK_COMBO_BOX(addr_type), 0);
	g_signal_connect(addr_type, "changed", G_CALLBACK(header_addr_callback), header);

	if (!addr) {
		gtk_combo_box_set_active(GTK_COMBO_BOX(addr_type), 0);
		gtk_widget_show(GTK_WIDGET(addr_exact_ip));
	} else {
		gtk_combo_box_set_active(GTK_COMBO_BOX(addr_type), addr->ip_type);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(addr_not), addr->exclude);
		header->expanded = 1;
		switch (addr->ip_type) {
		case ADDRESS_EXACT:
			gtk_entry_set_text(GTK_ENTRY(addr_exact_ip), addr->iplist);
			gtk_widget_show(GTK_WIDGET(addr_exact_ip));
			break;
		case ADDRESS_SUBNET:
			gtk_entry_set_text(GTK_ENTRY(addr_subnet_ip), addr->subnet.ip);
			gtk_entry_set_text(GTK_ENTRY(addr_subnet_mask), addr->subnet.mask);
			gtk_widget_show(GTK_WIDGET(addr_subnet_ip));
			gtk_widget_show(GTK_WIDGET(addr_subnet_slash));
			gtk_widget_show(GTK_WIDGET(addr_subnet_mask));
			break;
		case ADDRESS_RANGE:
			gtk_entry_set_text(GTK_ENTRY(addr_range_from), addr->range.from);
			gtk_entry_set_text(GTK_ENTRY(addr_range_to), addr->range.to);
			gtk_widget_show(GTK_WIDGET(addr_range_from));
			gtk_widget_show(GTK_WIDGET(addr_range_dash));
			gtk_widget_show(GTK_WIDGET(addr_range_to));
			break;
		case ADDRESS_SET:
			header_addr_set_show(ipaddr, header->family, header->table, addr->set);
			gtk_widget_show(GTK_WIDGET(addr_set));
			break;
		}
	}
	gtk_widget_show(GTK_WIDGET(addr_label));
	gtk_widget_show(GTK_WIDGET(addr_type));
//	gtk_widget_show(GTK_WIDGET(addr_not));
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


static void header_port_set_show(struct transport_port_info *port, char *setname)
{
	int	res;
	GtkWidget	*port_set = port->value->sets.set;
	struct set_list_data   *set, *s;
	int	index = 0;
	int	selected = 0;
	int	family = port->family;
	char	*table = port->table;

	LIST_HEAD(set_list);
	res = gui_get_sets_list(&set_list, family, table, (char *)"internet network service", 0);
	if (res != SET_SUCCESS)
		// error;
		;

	gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(port_set));
	list_for_each_entry_safe(set, s, &set_list, list) {
		list_del(&set->list);
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(port_set),
			xstrdup(set->name), xstrdup(set->name));
		if (setname) {
			if (!strcmp(setname, set->name))
				selected = index;
		}
		index++;
		xfree(set->table);
		xfree(set->name);
		xfree(set);
	}
	
	gtk_combo_box_set_active(GTK_COMBO_BOX(port_set), selected);
	gtk_widget_show(port_set);
}


static void header_port_set_hide(struct transport_port_info *port)
{
	if (port->value->sets.set)
		gtk_widget_hide(port->value->sets.set);
}


static void header_port_callback(GtkComboBoxText *widget, gpointer data)
{
	char	*type;
	struct transport_port_info *port;
	port = (struct transport_port_info *)data;
	type = gtk_combo_box_text_get_active_text(widget);

	if (!(strcmp(type, "port list"))) {
		port->value->type = PORT_EXACT;
		header_port_range_hide(port);
		header_port_set_hide(port);
		header_port_list_show(port);
	} else if (!(strcmp(type, "range"))) {
		port->value->type = PORT_RANGE;
		header_port_range_show(port);
		header_port_set_hide(port);
		header_port_list_hide(port);
	} else if (!(strcmp(type, "sets"))) {
		port->value->type = PORT_SET;
		header_port_set_show(port, NULL);
		header_port_range_hide(port);
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
	GtkWidget	*port_set;
	int		offset;
	const char	*label;

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
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(port_type),
			"sets", "sets");
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

	port_set = gtk_combo_box_text_new();
	gtk_widget_set_size_request(port_set, 200, 10);
	gtk_fixed_put(GTK_FIXED(fixed), port_set, 280, offset);
	port->value->sets.set = port_set;

	if (!data) {
		gtk_combo_box_set_active(GTK_COMBO_BOX(port_type), 0);
		gtk_widget_show(GTK_WIDGET(port_list));
	} else {
		gtk_combo_box_set_active(GTK_COMBO_BOX(port_type), data->port_type);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(port_not), data->exclude);
		switch (data->port_type) {
		case PORT_EXACT:
			gtk_entry_set_text(GTK_ENTRY(port_list), data->portlist);
			gtk_widget_show(GTK_WIDGET(port_list));
			break;
		case PORT_RANGE:
			gtk_entry_set_text(GTK_ENTRY(port_range_from), data->range.from);
			gtk_entry_set_text(GTK_ENTRY(port_range_to), data->range.to);
			gtk_widget_show(GTK_WIDGET(port_range_from));
			gtk_widget_show(GTK_WIDGET(port_range_dash));
			gtk_widget_show(GTK_WIDGET(port_range_to));
			break;
		case PORT_SET:
			header_port_set_show(port, data->set);
			break;
		}
	}

	gtk_widget_show(GTK_WIDGET(port_label));
	gtk_widget_show(GTK_WIDGET(port_type));
//	gtk_widget_show(GTK_WIDGET(port_not));
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
	widget->tcp->sport->family = header->family;
	widget->tcp->sport->table = header->table;
	widget->tcp->dport->family = header->family;
	widget->tcp->dport->table = header->table;
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
	widget->udp->sport->family = header->family;
	widget->udp->sport->table = header->table;
	widget->udp->dport->family = header->family;
	widget->udp->dport->table = header->table;
	rule_add_content_header_port(fixed, widget->udp->sport, data ? data->sport : NULL, header_port_callback, 1);
	rule_add_content_header_port(fixed, widget->udp->dport, data ? data->dport : NULL, header_port_callback, 0);
}


static void header_transport_callback(GtkComboBoxText *widget, gpointer data)
{
	char	*type;
	struct rule_create_widget *rule;
	
	rule = (struct rule_create_widget *)data;
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
	new_rule->header->family = new_rule->family;
	new_rule->header->table = new_rule->table;
	rule_add_content_header_saddr(new_rule->header, header_data);
	rule_add_content_header_daddr(new_rule->header, header_data);
	rule_add_content_header_trans(new_rule, header_data);
}


static void rule_add_content_header(struct rule_create_widget *new_rule, struct rule_create_data *rule_arg)
{
	GtkWidget	*fixed;
	GtkWidget	*fixed_header;
	GtkWidget	*expander_header;
	struct pktheader	*header_data = NULL;

	fixed = new_rule->fixed;
	if (rule_arg)
		header_data = rule_arg->header;

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


static void rule_add_content_pktmeta(struct rule_create_widget *new_rule, struct rule_create_data *rule_arg)
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
	if (rule_arg)
		pktmeta = rule_arg->pktmeta;

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

static void rule_add_content_actions(struct rule_create_widget *new_rule, struct rule_create_data *rule_arg)
{
	GtkWidget	*fixed_actions;
	GtkWidget	*fixed;
	GtkWidget	*accept;
	GtkWidget	*drop;
	GtkWidget	*jump;
	GtkWidget	*jump_to;
	GtkWidget	*counter;
	GtkWidget	*counter_value;
	GtkWidget	*counter_label;
	GtkWidget	*index;
	GtkWidget	*index_value;
	GtkWidget	*line;
	int	offset = 80;
	struct actions_all	*actions;
	LIST_HEAD(chain_list);
	struct chain_list_data   *chain, *c;
	int	res;
	struct actions  *data = NULL;
	struct action   *data_act;
	char  stats[100];
	int   len;
	char  *to_chain = NULL;
	int   iter = 0;
	int   selected = 0;
	int   usr_chain_num = 0;

	actions = new_rule->actions;
	actions->len = 40;
	actions->expanded = 0;
	fixed = new_rule->fixed;
	if (rule_arg) {
		data = rule_arg->actions;
	}

	if (new_rule->header->expanded)
		offset += new_rule->header->len;
	if (new_rule->meta->expanded)
		offset += new_rule->meta->len;

	fixed_actions = gtk_fixed_new();
	gtk_fixed_put(GTK_FIXED(fixed), fixed_actions, 0, offset);
	actions->fixed = fixed_actions;

	res = gui_get_chains_list(&chain_list, new_rule->family, new_rule->table, (char *)"user", 0);
	if (res != CHAIN_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				chain_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	accept = gtk_radio_button_new_with_label(NULL, "Accept");
	drop = gtk_radio_button_new_with_label(gtk_radio_button_get_group(GTK_RADIO_BUTTON(accept)), "Drop");
	jump = gtk_radio_button_new_with_label(gtk_radio_button_get_group(GTK_RADIO_BUTTON(drop)), "Jump to");
	jump_to = gtk_combo_box_text_new();
	counter = gtk_check_button_new_with_label("Counter");
	counter_value = gtk_entry_new();
	counter_label = gtk_label_new("(packets/bytes)");

	if (data && !list_empty(&data->list)) {
		list_for_each_entry(data_act, &data->list, list) {
			switch (data_act->type) {
			case ACTION_ACCEPT:
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(accept), TRUE);
				break;
			case ACTION_DROP:
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(drop), TRUE);
				break;
			case ACTION_JUMP:
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(jump), TRUE);
				to_chain = data_act->chain;
				break;
			case ACTION_COUNTER:
				len = snprintf(stats, 100, "%"PRIu64, data_act->packets);
				len += snprintf(stats + len, 100 - len, "%s", "/");
				snprintf(stats + len, 100 - len, "%"PRIu64, data_act->bytes);
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(counter), TRUE);
				gtk_entry_set_text(GTK_ENTRY(counter_value), stats);
				break;
			default:
			        BUG();
			}
		}
	}

	list_for_each_entry_safe(chain, c, &chain_list, list) {
		gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(jump_to),
				xstrdup(chain->chain), xstrdup(chain->chain));
		list_del(&chain->list);
		if (to_chain) {
			if (!strcmp(to_chain, chain->chain))
				selected = iter;
		}
		iter++;
		gui_chain_free(chain);	
		usr_chain_num++;
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(jump_to), selected);

//	line = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
	line = gtk_label_new("------------------------------------------------------------------------------------------------------------------------------------------------------------------");
	gtk_fixed_put(GTK_FIXED(fixed_actions), line, 20, 0);
	
	actions->accept = accept;
	actions->drop = drop;
	actions->jump = jump;
	actions->jump_to = jump_to;
	gtk_fixed_put(GTK_FIXED(fixed_actions), accept, 20, 40);
	gtk_fixed_put(GTK_FIXED(fixed_actions), drop, 130, 40);
	gtk_fixed_put(GTK_FIXED(fixed_actions), jump, 240, 40);
	gtk_fixed_put(GTK_FIXED(fixed_actions), jump_to, 340, 40);

	actions->counter = counter;
	actions->counter_value = counter_value;
	gtk_fixed_put(GTK_FIXED(fixed_actions), counter, 20, 80);
	gtk_fixed_put(GTK_FIXED(fixed_actions), counter_value, 120, 80);
	gtk_fixed_put(GTK_FIXED(fixed_actions), counter_label, 290, 80);
	
	index = gtk_label_new("Index:");
	gtk_fixed_put(GTK_FIXED(fixed_actions), index, 20, 120);
	actions->index = index;
	index_value = gtk_entry_new();
	gtk_fixed_put(GTK_FIXED(fixed_actions), index_value, 120, 120);
	actions->index = index_value;

	if (data && !list_empty(&data->list)) {
		list_for_each_entry(data_act, &data->list, list) {
			switch (data_act->type) {
			case ACTION_ACCEPT:
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(accept), TRUE);
				break;
			case ACTION_DROP:
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(drop), TRUE);
				break;
			case ACTION_JUMP:
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(jump), TRUE);
				gtk_entry_set_text(GTK_ENTRY(jump_to), data_act->chain);
				break;
			case ACTION_COUNTER:
				len = snprintf(stats, 100, "%"PRIu64, data_act->packets);
				len += snprintf(stats + len, 100 - len, "%s", "/");
				snprintf(stats + len, 100 - len, "%"PRIu64, data_act->bytes);
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(counter), TRUE);
				gtk_entry_set_text(GTK_ENTRY(counter_value), stats);
				break;
			default:
			        BUG();
			}
		}
	}

	gtk_widget_show_all(GTK_WIDGET(fixed_actions));
	if (!usr_chain_num) {
		gtk_widget_hide(jump);
		gtk_widget_hide(jump_to);
	}
	if (rule_arg) {
		gtk_widget_hide(index);
		gtk_widget_hide(index_value);
	}
}


static void rule_add_content_submit(struct rule_create_widget *new_rule)
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
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(gnftables_rule_list), NULL);
	gtk_fixed_put(GTK_FIXED(fixed), cancel, 540, offset);
	new_rule->cancel = cancel;

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(gnftables_rule_submit), new_rule);
	gtk_fixed_put(GTK_FIXED(fixed), ok, 660, offset);
	new_rule->ok = ok;

	gtk_widget_show(GTK_WIDGET(msg));
	gtk_widget_show(GTK_WIDGET(ok));
	gtk_widget_show(GTK_WIDGET(cancel));
}


static void rule_add_content(struct rule_create_widget *new_rule, struct rule_create_data *rule_arg)
{
	rule_add_content_header(new_rule, rule_arg);
	rule_add_content_pktmeta(new_rule, rule_arg);
	rule_add_content_actions(new_rule, rule_arg);
	rule_add_content_submit(new_rule);
	gtk_expander_set_expanded(GTK_EXPANDER(new_rule->header->expander), new_rule->header->expanded);
	gtk_expander_set_expanded(GTK_EXPANDER(new_rule->meta->expander), new_rule->meta->expanded);
}

static struct rule_create_widget *rule_widget_container_create(void)
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

	container->notebook = top_window->notebook;
	container->family = top_window->data->family;
	container->table = xstrdup(top_window->data->table);
	container->chain = xstrdup(top_window->data->chain);
//	container->handle = rule_arg->handle;

	return container;
}

void gnftables_rule_submit(GtkButton *button, gpointer info)
{
	int		res;
	struct rule_create_widget	*widget;
	struct rule_create_data		*data;

	widget = (struct rule_create_widget *)info;
	// check chain exists
	res = gui_check_chain_exist(widget->family, widget->table, widget->chain);
	if (res != CHAIN_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), chain_error[res]);
		return;
	}

	// get data
	res = rule_create_getdata(widget, &data);
	// rule_gen_expressions(gui_rule, rule);
	if (res != RULE_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), rule_error[res]);
		return;
	}

	data->family = top_window->data->family;
	data->table = xstrdup(top_window->data->table);
	data->chain = xstrdup(top_window->data->chain);
	data->handle = top_window->data->handle;
	res = gui_add_rule(data);
	// xfree(data);
	if (res != CHAIN_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), chain_error[res]);
		return;
	}
	top_window->data->handle = 0;
	gnftables_rule_list();
}


void gnftables_rule_add(GtkButton *button, gpointer data)
{
	GtkWidget	*fixed_back;
	GtkWidget	*fixed_content;
	GtkWidget	*notebook;
	GtkWidget	*container;
	GtkWidget	*scrolledwindow;

	int	res;
	int	family;
	char	*table;
	char	*chain;
	struct rule_create_widget	*new_rule;
	struct rule_create_data		*rule_arg;

	family = top_window->data->family;
	table = top_window->data->table;
	chain = top_window->data->chain;
	container = top_window->rule_container;
	notebook = top_window->notebook;

	res = gui_check_chain_exist(family, table, chain);
	if (res != CHAIN_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				chain_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		if (res == CHAIN_NOT_EXIST) {
			gnftables_chain_list();
			gtk_widget_hide(container);
		} else {
			gnftables_table_list();
			gtk_widget_hide(container);
			gtk_widget_hide(top_window->chain_set_container);
		}
		return;
	}

	// new_rule_malloc();
	rule_arg = (struct rule_create_data *)data;
	new_rule = rule_widget_container_create();

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
	gtk_widget_show(GTK_WIDGET(fixed_content));
	gtk_widget_show(GTK_WIDGET(scrolledwindow));
	gtk_widget_show(GTK_WIDGET(fixed_back));
	gtk_widget_show(GTK_WIDGET(container));

	gtk_widget_destroy(top_window->rule);
	gtk_fixed_put(GTK_FIXED(container), fixed_back, 0, 0);
	top_window->rule = fixed_back;
	top_window->page_current = NOTEBOOK_RULE_CREATE_EDIT;
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


void gnftables_rule_details(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data)
{
	int		res;
	GtkTreeIter	iter;
	GtkTreeModel	*model;
	GtkWidget	*container;
	struct rule_create_data	*rule_data = NULL;
	int	family;
	char	*table;
	char	*chain;
	int	handle;

	family = top_window->data->family;
	table = top_window->data->table;
	chain = top_window->data->chain;
	container = top_window->rule_container;
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, RULE_HANDLE, &handle, -1);

	res = gui_get_rule(family, table, chain, handle, &rule_data);
	if (res != RULE_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				rule_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);

		if (res == RULE_NOT_EXIST || res == RULE_TYPE_NOT_SUPPORT)
			gnftables_rule_list();
		else if (res == RULE_CHAIN_NOT_EXIST) {
			gnftables_chain_list();
			gtk_widget_hide(container);
		} else {
			gnftables_table_list();
			gtk_widget_hide(container);
			gtk_widget_hide(top_window->chain_set_container);
		}
	} else {
		top_window->data->handle = handle;
		gnftables_rule_add(NULL, rule_data);
	}
}


void gnftables_rule_delete(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data)
{
	GtkTreeIter	iter;
	GtkTreeModel	*model;
	GtkWidget	*dialog;
	GtkWidget	*container;

	gint	res;
	gint	err;
	int	family;
	gchar	*table;
	gchar	*chain;
	gint	handle;

	family = top_window->data->family;
	table = top_window->data->table;
	chain = top_window->data->chain;
	container = top_window->rule_container;
	dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
                                 0,
                                 GTK_MESSAGE_WARNING,
                                 GTK_BUTTONS_OK_CANCEL,
                                 "The rule will be deleted. Are you sure?"
                                 );
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, RULE_HANDLE, &handle, -1);

		err = gui_delete_rule(family, table, chain, handle);
		if (err != RULE_SUCCESS) {
			gtk_widget_destroy(dialog);
			dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
				"%s", rule_error[err]);
			gtk_dialog_run(GTK_DIALOG(dialog));
		}
		if (err == RULE_NOT_EXIST || err == RULE_SUCCESS)
			gnftables_rule_list();
		else if (err == RULE_CHAIN_NOT_EXIST) {
			gnftables_chain_list();
			gtk_widget_hide(container);
		} else {
			gnftables_table_list();
			gtk_widget_hide(container);
			gtk_widget_hide(top_window->chain_set_container);
		}
	}
	gtk_widget_destroy(dialog);
	return;
}


void gnftables_rule_update(struct page_info *args, GtkTreeStore *store)
{
	uint32_t	index = 0;
	GtkTreeIter	iter;
	int	res;
	int	family;
	char	*table;
	char	*chain;
	GdkPixbuf *icon_details = NULL;
	GdkPixbuf *icon_delete = NULL;

	struct gui_rule   *rule, *r;
	LIST_HEAD(rule_list);
	family = args->family;
	table = args->table;
	chain = args->chain;
	icon_details = gdk_pixbuf_new_from_file(
			DEFAULT_DATAROOT_PATH"/pixmaps/preferences-system.png",
			NULL);
	icon_delete = gdk_pixbuf_new_from_file(
			DEFAULT_DATAROOT_PATH"/pixmaps/user-trash.png",
			NULL);

	res = gui_get_rules_list(&rule_list, family, table, chain);
	if (res != RULE_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				rule_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	// display rules in treeview 
	gtk_tree_store_clear(store);
	list_for_each_entry_safe(rule, r, &rule_list, list) {
		list_del(&rule->list);
		index++;
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter,
			RULE_ID, index,
			RULE_HANDLE, rule->handle,
			RULE_TABLE, rule->table,
			RULE_CHAIN, rule->chain,
			RULE_CONTENT, rule->stmt,
			RULE_DETAIL, icon_details,
			RULE_DELETE, icon_delete,
			-1);
		gui_rule_free(rule);	
	}
}


void gnftables_rule_list(void)
{
	GtkWidget	*notebook;
	GtkWidget	*container;
	GtkWidget	*fixed;
	GtkWidget	*create_rule;
	GtkWidget	*list_rules;
	GtkWidget	*scrolledwindow;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer_details;
	GtkCellRenderer	*renderer_delete;
	GtkTreeViewColumn	*column;
	int	res;
	int	family;
	char	*table;
	char	*chain;
	GtkCellRendererMode     mode = GTK_CELL_RENDERER_MODE_ACTIVATABLE;
	GValue val = {mode, };

	notebook = top_window->notebook;
	container = top_window->rule_container;
	family = top_window->data->family;
	table = top_window->data->table;
	chain = top_window->data->chain;
	top_window->data->handle = 0;

	res = gui_check_chain_exist(family, table, chain);
	if (res != CHAIN_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				chain_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		if (top_window->rule) {
			gtk_widget_destroy(top_window->rule);
			top_window->rule = NULL;
		}
		if (res == CHAIN_NOT_EXIST) {
			gnftables_chain_list();
			gtk_widget_hide(container);
		} else {
			gnftables_table_list();
			gtk_widget_hide(container);
			gtk_widget_hide(top_window->chain_set_container);
		}
		return;
	}

	store = gtk_tree_store_new(RULE_TOTAL, G_TYPE_INT, G_TYPE_INT,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			GDK_TYPE_PIXBUF, GDK_TYPE_PIXBUF);

	fixed = gtk_fixed_new();

    	create_rule = gtk_button_new_with_label("Create Rule");
	gtk_widget_set_size_request(create_rule, 150, 10);
	g_signal_connect(G_OBJECT(create_rule), "clicked",
			G_CALLBACK(gnftables_rule_add), NULL);
	gtk_fixed_put(GTK_FIXED(fixed), create_rule, 700, 10);


	// treeview style
	list_rules = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
//	g_signal_connect(list_rules, "button-press-event",
//			G_CALLBACK(show_treeview_menu), NULL); 
	renderer = gtk_cell_renderer_text_new();

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


	renderer_details = gtk_cell_renderer_pixbuf_clicked_new();
	g_object_set(G_OBJECT(renderer_details), "mode", val, "activatable",
			TRUE, NULL);
	g_signal_connect(renderer_details, "clicked",
			G_CALLBACK(gnftables_rule_details), list_rules) ;
	column = gtk_tree_view_column_new_with_attributes("Details",
			renderer_details, "pixbuf", RULE_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_max_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_rules), column);

	renderer_delete = gtk_cell_renderer_pixbuf_clicked_new();
	g_object_set(G_OBJECT(renderer_delete), "mode", val, "activatable",
			TRUE, NULL);
	g_signal_connect(renderer_delete, "clicked",
			G_CALLBACK(gnftables_rule_delete), list_rules);
	column = gtk_tree_view_column_new_with_attributes("Delete",
			renderer_delete, "pixbuf", RULE_DELETE, NULL);
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
	gtk_fixed_put(GTK_FIXED(fixed), scrolledwindow, 0, 50);

	if (top_window->rule)
		gtk_widget_destroy(top_window->rule);
	top_window->rule = fixed;
	gtk_fixed_put(GTK_FIXED(container), fixed, 0, 0);
	gtk_widget_show_all(container);
	top_window->silent = 1;
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
	top_window->page_current = NOTEBOOK_RULE_LIST;
	top_window->silent = 0;
	gnftables_rule_update(top_window->data, store);
}


void gnftables_addpage_rule(void)
{
	GtkWidget	*title;
	GtkWidget	*notebook;
	GtkWidget	*container;

	title = gtk_label_new("Rules");
	gtk_widget_set_size_request(title, 200, 10);

	notebook = top_window->notebook;
	container = top_window->rule_container;
	
	top_window->silent = 1;
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), container, title, 2);
}


static void set_element_type_changed(GtkComboBoxText *widget, gpointer data)
{
	gtk_tree_store_clear(GTK_TREE_STORE(data));
}


static void set_add_element(GtkButton *button, gpointer  info)
{
	char	*value;
	GtkEntry	*add;
	GtkTreeIter	iter;
	GtkTreeStore	*store;
	struct set_submit_argsnnn *widgets;

	widgets = (struct set_submit_argsnnn *)info;
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
	struct set_submit_argsnnn *widgets;

	widgets = (struct set_submit_argsnnn *)info;
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


void gnftables_set_submit(GtkButton *button, gpointer info)
{
	int		res;
	struct elem_create_data		*elem_data, *next;
	struct set_submit_argsnnn	*widget;
	struct set_create_data		*data = NULL;
	widget = (struct set_submit_argsnnn *)info;

	// check table exists
	res = gui_check_table_exist(widget->family, widget->table);
	if (res != TABLE_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), table_error[res]);
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

	list_for_each_entry_safe(elem_data, next, &data->elems, list) {
		list_del(&elem_data->list);
		xfree(elem_data->key);
		xfree(elem_data->data);
		xfree(elem_data);
	}
	xfree(data->table);
	xfree(data->set);
	xfree(data);
	if (res != SET_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), set_error[res]);
		return;
	}
	gnftables_set_list();
}


void gnftables_set_add(GtkButton *button, gpointer data)
{
	GtkWidget	*container;
	GtkWidget	*fixed;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	GtkWidget	*frame;
	GtkWidget	*fixed_chain;
	GtkWidget	*name;
	GtkWidget	*name_value;
	GtkWidget	*type;
	GtkWidget	*type_value;
	GtkWidget	*new;
	GtkWidget	*elem_label;
	GtkWidget	*new_value;
	GtkWidget	*remove;
	GtkWidget	*notebook;
	GtkWidget	*msg;
	GtkWidget	*scrolledwindow;
	GtkWidget	*elems;
	GtkWidget	*trash;
	GtkCellRenderer	*renderer;
	GtkTreeViewColumn	*column;
	GtkTreeStore	*store;
	GtkTreeIter	iter;

	int	res;
	int	family;
	char	*table;
	struct set_submit_argsnnn *widgets;
	struct set_create_data	*set_data;
	struct elem_create_data	*elem_data, *next;

	set_data = (struct set_create_data *)data;
	notebook = top_window->notebook;
	container = top_window->chain_set_container;
	family = top_window->data->family;
	table = top_window->data->table;

	res = gui_check_table_exist(family, table);
	if (res != TABLE_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				table_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		gnftables_table_list();
		gtk_widget_hide(container);
		return;
	}

	widgets = xzalloc(sizeof(struct set_submit_argsnnn));
	widgets->family = family;
	widgets->table = xstrdup(table);
	if (!set_data)
		widgets->create = 1;

	fixed = gtk_fixed_new();
	if (!set_data)
		frame = gtk_frame_new("Create a new set");
	else
		frame = gtk_frame_new("Edit set");
	gtk_container_set_border_width (GTK_CONTAINER(frame), 0);
	gtk_widget_set_size_request(frame, 770, 420);
	gtk_fixed_put(GTK_FIXED(fixed), frame, 50, 20);

	fixed_chain = gtk_fixed_new();
	gtk_container_add(GTK_CONTAINER(frame), fixed_chain);

	name = gtk_label_new("Name:");
	gtk_fixed_put(GTK_FIXED(fixed_chain), name, 30, 30);
	name_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(name_value), 30);
	gtk_entry_set_max_length(GTK_ENTRY(name_value), 15);
	if (set_data) {
		gtk_entry_set_text(GTK_ENTRY(name_value), xstrdup(set_data->set));
		gtk_widget_set_sensitive(name_value, FALSE);
	}
	gtk_fixed_put(GTK_FIXED(fixed_chain), name_value, 100, 30);
	widgets->name = name_value;

	type = gtk_label_new("Type:");
	gtk_fixed_put(GTK_FIXED(fixed_chain), type, 30, 80);
	type_value = gtk_combo_box_text_new();
	gtk_widget_set_size_request(type_value, 250, 10);
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
	gtk_fixed_put(GTK_FIXED(fixed_chain), type_value, 100, 80);
	widgets->type = type_value;

    	new = gtk_button_new_with_label("==>");
	gtk_fixed_put(GTK_FIXED(fixed_chain), new, 370, 130);
	elem_label = gtk_label_new("Element:");
	gtk_fixed_put(GTK_FIXED(fixed_chain), elem_label, 30, 130);
	new_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(new_value), 30);
	gtk_fixed_put(GTK_FIXED(fixed_chain), new_value, 100, 130);
	widgets->add = new_value;
    	remove = gtk_button_new_with_label("<==");
	gtk_fixed_put(GTK_FIXED(fixed_chain), remove, 370, 210);
	trash = gtk_image_new_from_file(DEFAULT_DATAROOT_PATH"/pixmaps/gnftables_trash.png");
	gtk_fixed_put(GTK_FIXED(fixed_chain), trash, 200, 180);

	store = gtk_tree_store_new(1, G_TYPE_STRING);
	widgets->store = store;
	elems = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(elems), FALSE);
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Id", renderer,
			"text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(elems), column);
	if (set_data) {
		list_for_each_entry_safe(elem_data, next, &(set_data->elems), list) {
			list_del(&elem_data->list);
			gtk_tree_store_append(store, &iter, NULL);
			gtk_tree_store_set(store, &iter, 0, xstrdup(elem_data->key), -1);
			xfree(elem_data->key);
			xfree(elem_data->data);
			xfree(elem_data);
		}
		xfree(set_data->table);
		xfree(set_data->set);
		xfree(set_data);
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

	gtk_fixed_put(GTK_FIXED(fixed_chain), scrolledwindow, 450, 30);

	g_signal_connect(type_value, "changed",
			G_CALLBACK(set_element_type_changed), store);
	g_signal_connect(G_OBJECT(new), "clicked", G_CALLBACK(set_add_element), widgets);
	g_signal_connect(G_OBJECT(remove), "clicked", G_CALLBACK(set_remove_element), widgets);


	msg = gtk_label_new("");
	gtk_fixed_put(GTK_FIXED(fixed_chain), msg, 30, 280);
	widgets->msg = msg;

    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(gnftables_set_list), NULL);
	gtk_fixed_put(GTK_FIXED(fixed_chain), cancel, 480, 360);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(gnftables_set_submit), widgets);
	gtk_fixed_put(GTK_FIXED(fixed_chain), ok, 600, 360);

	if (top_window->chain_set)
		gtk_widget_destroy(top_window->chain_set);
	top_window->chain_set = fixed;
	top_window->page_current = NOTEBOOK_SET_CREATE_EDIT;
	gtk_fixed_put(GTK_FIXED(container), fixed, 0, 0);

	gtk_widget_show_all(container);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


void gnftables_set_details(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data)
{
	int		res;
	GtkTreeIter	iter;
	gchar		*set;
	GtkTreeModel	*model;
	GtkWidget	*container;
	struct set_create_data	*set_data;

	container = top_window->chain_set_container;
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, SET_NAME, &set, -1);
	set_data = xzalloc(sizeof(struct set_create_data));
	init_list_head(&(set_data->elems));
	set_data->family = top_window->data->family;
	set_data->table = xstrdup(top_window->data->table);
	set_data->set = set;

	res = gui_get_set(set_data, 1);
	if (res != SET_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				set_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		xfree(set_data->table);
		xfree(set_data->set);
		xfree(set_data);

		if (res == SET_NOT_EXIST || res == SET_TYPE_NOT_SUPPORT)
			gnftables_set_list();
		else {
			gnftables_table_list();
			gtk_widget_hide(container);
		}
	} else {
		top_window->data->set = set;
		gnftables_set_add(NULL, set_data);
	}
}


void gnftables_set_delete(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data)
{
	GtkTreeIter	iter;
	int		family;
	gchar		*table;
	gchar		*set;
	GtkTreeModel	*model;
	GtkWidget	*container;
	gint	err;
	gint	res;
	GtkWidget *dialog;

	family = top_window->data->family;
	table = top_window->data->table;
	container = top_window->chain_set_container;
	dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
		0,
		GTK_MESSAGE_WARNING,
		GTK_BUTTONS_OK_CANCEL,
		"The set will be deleted. Are you sure?"
		);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, SET_NAME, &set, -1);

		err = gui_delete_set(family, table, set);
		if (err != SET_SUCCESS) {
			gtk_widget_destroy(dialog);
			dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
				"%s", set_error[err]);
			gtk_dialog_run(GTK_DIALOG(dialog));
		}
		if (err == SET_NOT_EXIST || err == SET_SUCCESS)
			gnftables_set_list();
		else {
			gnftables_table_list();
			gtk_widget_hide(container);
		}
	}
	gtk_widget_destroy(dialog);
	return;
}


void gnftables_set_update(struct page_info *args, GtkTreeStore *store)
{
	uint32_t	index = 0;
	GtkTreeIter	iter;
	struct set_list_data   *set, *s;
	gint	family = args->family;
	gchar	*table = args->table;
	gchar	*type = args->type;
	int		res;
	GdkPixbuf *icon_details = NULL;
	GdkPixbuf *icon_delete = NULL;

	LIST_HEAD(set_list);
	icon_details = gdk_pixbuf_new_from_file(
			DEFAULT_DATAROOT_PATH"/pixmaps/preferences-system.png",
			NULL);
	icon_delete = gdk_pixbuf_new_from_file(
			DEFAULT_DATAROOT_PATH"/pixmaps/user-trash.png",
			NULL);

	res = gui_get_sets_list(&set_list, family, table, type, 1);
	if (res != SET_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				set_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	gtk_tree_store_clear(store);
	// display sets in treeview
	list_for_each_entry_safe(set, s, &set_list, list) {
		list_del(&set->list);
		index++;
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter,
			SET_ID, index,
			SET_NAME, xstrdup(set->name),
			SET_KEYTYPE, xstrdup(set->keytype),
			SET_DATATYPE, set->datatype ? xstrdup(set->datatype) : "X",
			SET_ELEMS, set->nelems,
			SET_DETAIL, icon_details,
			SET_DELETE, icon_delete, -1);
		xfree(set->table);
		xfree(set->name);
		xfree(set);
	}
}


//void gnftables_set_list(GtkButton *button, gpointer  data)
void gnftables_set_list(void)
{
	GtkWidget	*container;
	GtkWidget	*title;
	GtkWidget	*fixed;
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

	int	res;
	int	family;
	char	*table;
	GtkCellRendererMode	mode = GTK_CELL_RENDERER_MODE_ACTIVATABLE;
	GValue val = {mode, };

	notebook = top_window->notebook;
	container = top_window->chain_set_container;
	family = top_window->data->family;
	table = top_window->data->table;
	res = gui_check_table_exist(family, table);
	if (res != TABLE_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				table_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		gnftables_table_list();
		gtk_widget_hide(container);
		return;
	}

	store = gtk_tree_store_new(SET_TOTAL, G_TYPE_INT, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT,
			GDK_TYPE_PIXBUF, GDK_TYPE_PIXBUF);

	title = gtk_label_new("Sets");
	gtk_widget_set_size_request(title, 200, 10);
	fixed = gtk_fixed_new();

    	chain_list = gtk_button_new_with_label("Go to chain list page");
	gtk_widget_set_size_request(chain_list, 150, 10);
	g_signal_connect(G_OBJECT(chain_list), "clicked",
			G_CALLBACK(gnftables_chain_list), NULL);
	gtk_fixed_put(GTK_FIXED(fixed), chain_list, 530, 10);

    	create_set = gtk_button_new_with_label("Create Set");
	gtk_widget_set_size_request(create_set, 150, 10);
	g_signal_connect(G_OBJECT(create_set), "clicked",
			G_CALLBACK(gnftables_set_add), NULL);
	gtk_fixed_put(GTK_FIXED(fixed), create_set, 700, 10);

	// treeview style
	list_sets = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();

	column = gtk_tree_view_column_new_with_attributes("Id", renderer,
			"text", SET_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer,
			"text", SET_NAME, NULL);
	gtk_tree_view_column_set_min_width(column, 250);
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

	renderer_details = gtk_cell_renderer_pixbuf_clicked_new();
	g_object_set(G_OBJECT(renderer_details), "mode", val, "activatable",
			TRUE, NULL);
	g_signal_connect(renderer_details, "clicked",
			G_CALLBACK(gnftables_set_details), list_sets) ;
	column = gtk_tree_view_column_new_with_attributes("Details",
			renderer_details, "pixbuf", SET_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 110);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_sets), column);

	renderer_delete = gtk_cell_renderer_pixbuf_clicked_new();
	g_object_set(G_OBJECT(renderer_delete), "mode", val, "activatable",
			TRUE, NULL);
	g_signal_connect(renderer_delete, "clicked",
			G_CALLBACK(gnftables_set_delete), list_sets);
	column = gtk_tree_view_column_new_with_attributes("Delete",
			renderer_delete, "pixbuf", SET_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 110);
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
	gtk_fixed_put(GTK_FIXED(fixed), scrolledwindow, 0, 50);

	if (top_window->chain_set)
		gtk_widget_destroy(top_window->chain_set);
	top_window->chain_set = fixed;
	top_window->page_current = NOTEBOOK_SET_LIST;
	gnftables_set_update(top_window->data, store);

	gtk_fixed_put(GTK_FIXED(container), fixed, 0, 0);
	gtk_widget_show_all(container);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


static void basechain_selected(GtkWidget *check_button, gpointer data) 
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


/*
static void chain_list_type_changed(GtkComboBoxText *widget, gpointer data)
{
	struct chain_list_args  *args;
	args = (struct chain_list_args *)data;
	args->type = gtk_combo_box_text_get_active_text(widget);
	gnftables_chain_list();
}
*/

static void chain_create_type_changed(GtkComboBoxText *widget, gpointer data)
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
 * Get data from chain creating page and send NFT_MSG_NEWCHAIN message to kernel.
 */
void gnftables_chain_submit(GtkButton *button, gpointer info)
{
	int		res;
	struct chain_submit_argsnnn	*widget;
	struct chain_create_data	*data = NULL;
	widget = (struct chain_submit_argsnnn *)info;

	// check table exists
	res = gui_check_table_exist(widget->family, widget->table);
	if (res != CHAIN_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(widget->msg), table_error[res]);
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
	gnftables_chain_list();
}

/*
 * Goto chain creating page
 *
 */
void gnftables_chain_add(GtkButton *button, gpointer data)
{
	GtkWidget	*fixed;
	GtkWidget	*container;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	GtkWidget	*frame;
	GtkWidget	*fixed_chain;
	GtkWidget	*name;
	GtkWidget	*name_value;
	GtkWidget	*base;
	GtkWidget	*base_value;
	GtkWidget	*type;
	GtkWidget	*type_value;
	GtkWidget	*hook;
	GtkWidget	*hook_value;
	GtkWidget	*priority;
	GtkWidget	*priority_value;
	GtkWidget	*notebook;
	GtkWidget	*msg;

	int	res;
	int	family;
	char	*table;
	struct  basechain_info  *basechain;
	struct chain_submit_argsnnn *widgets;

	container = top_window->chain_set_container;
	notebook = top_window->notebook;
	family = top_window->data->family;
	table = top_window->data->table;
	res = gui_check_table_exist(family, table);
	if (res != TABLE_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				table_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		gnftables_table_list();
		gtk_widget_hide(container);
		return;
	}

	top_window->page_current = NOTEBOOK_CHAIN_CREATE;
	basechain = xzalloc(sizeof(*basechain));
	widgets = xzalloc(sizeof(struct chain_submit_argsnnn));
	notebook = top_window->notebook;
	widgets->family = family;
	widgets->table = table;

	fixed = gtk_fixed_new();
	frame = gtk_frame_new ("Create a new chain");
	gtk_container_set_border_width(GTK_CONTAINER(frame), 0);
	gtk_widget_set_size_request(frame, 600, 371);
	gtk_fixed_put(GTK_FIXED(fixed), frame, 150, 40);

	fixed_chain = gtk_fixed_new();
	gtk_container_add(GTK_CONTAINER(frame), fixed_chain);

	name = gtk_label_new("Name:");
	gtk_fixed_put(GTK_FIXED(fixed_chain), name, 30, 30);
	name_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(name_value), 30);
	gtk_entry_set_max_length(GTK_ENTRY(name_value), 30);
	gtk_fixed_put(GTK_FIXED(fixed_chain), name_value, 100, 30);
	widgets->name = name_value;

	base = gtk_label_new("basechain:");
	gtk_fixed_put(GTK_FIXED(fixed_chain), base, 30, 80);

	base_value = gtk_check_button_new();
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(base_value), TRUE);
	gtk_fixed_put(GTK_FIXED(fixed_chain), base_value, 100, 80);
	g_signal_connect(base_value, "toggled", G_CALLBACK(basechain_selected), basechain);
	widgets->basechain = base_value;


	type = gtk_label_new("Type:");
	gtk_fixed_put(GTK_FIXED(fixed_chain), type, 30, 130);

	type_value = gtk_combo_box_text_new();
	gtk_widget_set_size_request(type_value, 150, 10);
	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_value),
			"filter", "filter");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_value),
//			"nat", "nat");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_value),
//			"route", "route");
	gtk_combo_box_set_active(GTK_COMBO_BOX(type_value), 0);
	gtk_fixed_put(GTK_FIXED(fixed_chain), type_value, 100, 130);
	basechain->type = type;
	basechain->type_value = type_value;
	widgets->type = type_value;

	hook = gtk_label_new("Hook:");
	gtk_fixed_put(GTK_FIXED(fixed_chain), hook, 30, 180);

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
	gtk_fixed_put(GTK_FIXED(fixed_chain), hook_value, 100, 180);
	basechain->hook = hook;
	basechain->hook_value = hook_value;
	widgets->hook = hook_value;

	g_signal_connect(type_value, "changed",
			G_CALLBACK(chain_create_type_changed), hook_value);

	priority = gtk_label_new("Priority:");
	gtk_fixed_put(GTK_FIXED(fixed_chain), priority, 30, 230);
	priority_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(priority_value), 30);
	gtk_fixed_put(GTK_FIXED(fixed_chain), priority_value, 100, 230);
	basechain->priority = priority;
	basechain->priority_value = priority_value;
	widgets->priority = priority_value;

	msg = gtk_label_new("");
	gtk_fixed_put(GTK_FIXED(fixed_chain), msg, 30, 280);
	widgets->msg = msg;

    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked", G_CALLBACK(gnftables_chain_list), NULL);
	gtk_fixed_put(GTK_FIXED(fixed_chain), cancel, 360, 310);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked", G_CALLBACK(gnftables_chain_submit), widgets);
	gtk_fixed_put(GTK_FIXED(fixed_chain), ok, 480, 310);

	gtk_widget_destroy(top_window->chain_set);
	gtk_fixed_put(GTK_FIXED(container), fixed, 0, 0);
	top_window->chain_set = fixed;
	gtk_widget_show_all(container);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


void gnftables_chain_details(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data)
{
	int	res;
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*chain;
	GtkTreeModel		*model;
	GtkWidget		*container;

	family = top_window->data->family;
	table = top_window->data->table;
	container = top_window->chain_set_container;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, CHAIN_NAME, &chain, -1);

	res = gui_check_chain_exist(family, table, chain);
	if (res != CHAIN_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				chain_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		xfree(chain);
		if (res == CHAIN_NOT_EXIST)
			gnftables_chain_list();
		else {
			gnftables_table_list();
			gtk_widget_hide(container);
		}
		return;
	} else {
		top_window->data->chain = chain;
		gnftables_rule_list();
	}
}


void gnftables_chain_delete(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	int			family;
	gchar			*table;
	gchar			*chain;
	GtkTreeModel		*model;
	gint	err;
	gint	res;
	GtkWidget *dialog;
	GtkWidget	*container;

	family = top_window->data->family;
	table = top_window->data->table;
	container = top_window->chain_set_container;
	dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
		0,
		GTK_MESSAGE_WARNING,
		GTK_BUTTONS_OK_CANCEL,
		"The chain and all rules in the chain will be deleted."
		" Are you sure?"
		);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, CHAIN_NAME, &chain, -1);

		err = gui_delete_chain(family, table, chain);
		if (err != CHAIN_SUCCESS) {
			gtk_widget_destroy(dialog);
			dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
				"%s", chain_error[err]);
			gtk_dialog_run(GTK_DIALOG(dialog));
		}
		if (err == CHAIN_NOT_EXIST || err == CHAIN_SUCCESS)
			gnftables_chain_list();
		else {
			gnftables_table_list();
			gtk_widget_hide(container);
		}
	}
	gtk_widget_destroy(dialog);
	return;
}


/*
 * Get chains from kernel and display in chain list page
 */
void gnftables_chain_update(struct page_info *args, GtkTreeStore *store)
{
	int	res;
	int	index = 0;
	gint	family = args->family;
	gchar	*table = args->table;
	gchar	*type = args->type;
	GtkTreeIter	iter;
	struct chain_list_data   *chain, *c;
	GdkPixbuf *icon_details = NULL;
	GdkPixbuf *icon_delete = NULL;

	LIST_HEAD(chain_list);
	icon_details = gdk_pixbuf_new_from_file(
			DEFAULT_DATAROOT_PATH"/pixmaps/folder.png",
			NULL);
	icon_delete = gdk_pixbuf_new_from_file(
			DEFAULT_DATAROOT_PATH"/pixmaps/user-trash.png",
			NULL);

	res = gui_get_chains_list(&chain_list, family, table, type, 1);
	if (res != CHAIN_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				chain_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	gtk_tree_store_clear(store);
	// display chains in treeview
	list_for_each_entry_safe(chain, c, &chain_list, list) {
		list_del(&chain->list);
		index++;
		gtk_tree_store_append(store, &iter, NULL);
		if (chain->basechain) {
			char	priority[50];
			sprintf(priority, "%d", chain->priority);
			gtk_tree_store_set(store, &iter,
				CHAIN_ID, index,
				CHAIN_NAME, xstrdup(chain->chain),
				CHAIN_RULES, chain->nrules,
				CHAIN_BASECHAIN, "yes",
				CHAIN_TYPE, xstrdup(chain->type),
				CHAIN_HOOK, hooknum2str(family, chain->hook),
				CHAIN_PRIORITY, priority,
				CHAIN_DETAIL, icon_details,
				CHAIN_DELETE, icon_delete, -1);
		} else 
			gtk_tree_store_set(store, &iter,
				CHAIN_ID, index,
				CHAIN_NAME, xstrdup(chain->chain), 
				CHAIN_RULES, chain->nrules, 
				CHAIN_BASECHAIN, "no",
				CHAIN_TYPE, "x",
				CHAIN_HOOK, "x",
				CHAIN_PRIORITY, "x",
				CHAIN_DETAIL, icon_details,
				CHAIN_DELETE, icon_delete, -1);
		gui_chain_free(chain);	
	}
}


/*
 * Add chains list page in notebook
 */
void gnftables_chain_list(void)
{
	GtkWidget	*fixed;
//	GtkWidget	*type;
//	GtkWidget	*combo_type;
	GtkWidget	*set_list;
	GtkWidget	*create_chain;
	GtkWidget	*list_chains;
	GtkWidget	*scrolledwindow;
	GtkWidget	*notebook;
	GtkWidget	*container;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer_details;
	GtkCellRenderer	*renderer_delete;
	GtkTreeViewColumn	*column;
	GtkCellRendererMode	mode = GTK_CELL_RENDERER_MODE_ACTIVATABLE;
	GValue val = {mode, };

	int	res;
	struct page_info     *list_args;
	list_args = (struct page_info *)top_window->data;
	notebook = top_window->notebook;
	container = top_window->chain_set_container;

	res = gui_check_table_exist(list_args->family, list_args->table);
	if (res != TABLE_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				table_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		if (top_window->chain_set) {
			gtk_widget_destroy(top_window->chain_set);
			top_window->chain_set = NULL;
		}
		gnftables_table_list();
		gtk_widget_hide(container);
		return;
	}

	store = gtk_tree_store_new(CHAIN_TOTAL, G_TYPE_INT, G_TYPE_STRING,
			G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, GDK_TYPE_PIXBUF,
			GDK_TYPE_PIXBUF);

	fixed = gtk_fixed_new();

//	type = gtk_label_new("Type");
//	gtk_fixed_put(GTK_FIXED(fixed), type, 20, 10);
//	combo_type = gtk_combo_box_text_new();
//	gtk_widget_set_size_request(combo_type, 100, 10);
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
//			"all", "all");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
//			"user", "user");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
//			"filter", "filter");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
//			"nat", "nat");
//	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo_type),
//			"route", "route");
//	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_type), 0);
//	chain_arg->type = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo_type));
//	gtk_fixed_put(GTK_FIXED(fixed), combo_type, 60, 10);

    	set_list = gtk_button_new_with_label("Go to set list page");
	gtk_widget_set_size_request(set_list, 150, 10);
	g_signal_connect(G_OBJECT(set_list), "clicked",
			G_CALLBACK(gnftables_set_list), NULL);
	gtk_fixed_put(GTK_FIXED(fixed), set_list, 530, 10);

    	create_chain = gtk_button_new_with_label("Create Chain");
	gtk_widget_set_size_request(create_chain, 150, 10);
	g_signal_connect(G_OBJECT(create_chain), "clicked",
			G_CALLBACK(gnftables_chain_add), NULL);
	gtk_fixed_put(GTK_FIXED(fixed), create_chain, 700, 10);

	// treeview style
	list_chains = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();
//	g_signal_connect(combo_type, "changed",
//			G_CALLBACK(chain_list_type_changed), NULL);

	column = gtk_tree_view_column_new_with_attributes("Id", renderer,
			"text", CHAIN_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 40);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer,
			"text", CHAIN_NAME, NULL);
	gtk_tree_view_column_set_min_width(column, 320);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Rules", renderer,
			"text", CHAIN_RULES, NULL);
	gtk_tree_view_column_set_min_width(column, 50);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Base Chain",
			renderer, "text", CHAIN_BASECHAIN, NULL);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Type", renderer,
			"text", CHAIN_TYPE, NULL);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Hook", renderer,
			"text", CHAIN_HOOK, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);
	column = gtk_tree_view_column_new_with_attributes("Priority", renderer,
			"text", CHAIN_PRIORITY, NULL);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);

	renderer_details = gtk_cell_renderer_pixbuf_clicked_new();
	g_object_set(G_OBJECT(renderer_details), "mode", val, "activatable",
			TRUE, NULL);
	g_signal_connect(renderer_details, "clicked",
			G_CALLBACK(gnftables_chain_details), list_chains) ;
	column = gtk_tree_view_column_new_with_attributes("Details",
			renderer_details, "pixbuf", CHAIN_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_chains), column);

	renderer_delete = gtk_cell_renderer_pixbuf_clicked_new();
	g_object_set(G_OBJECT(renderer_delete), "mode", val, "activatable",
			TRUE, NULL);
	g_signal_connect(renderer_delete, "clicked",
			G_CALLBACK(gnftables_chain_delete), list_chains) ;
	column = gtk_tree_view_column_new_with_attributes("Delete",
			renderer_delete, "pixbuf", CHAIN_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 60);
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

	gtk_fixed_put(GTK_FIXED(fixed), scrolledwindow, 0, 50);
	gtk_fixed_put(GTK_FIXED(container), fixed, 0, 0);

	if (top_window->chain_set)
		gtk_widget_destroy(top_window->chain_set);
	top_window->chain_set = fixed;
	top_window->page_current = NOTEBOOK_CHAIN_LIST;

	gnftables_chain_update(top_window->data, store);
	gtk_widget_show_all(container);
	top_window->silent = 1;
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
	top_window->silent = 0;
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}


void gnftables_addpage_chain(void)
{
	GtkWidget	*title;
	GtkWidget	*notebook;
	GtkWidget	*container;

	title = gtk_label_new("Chains/Sets");
	gtk_widget_set_size_request(title, 200, 10);

	notebook = top_window->notebook;
	container = top_window->chain_set_container;
	
	top_window->silent = 1;
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), container, title, 1);
}


/*
void select_family(GtkComboBox *widget, gpointer data)
{
	GtkTreeModel	*model;
	GtkTreeIter	iter;
	uint32_t	family;
	GtkTreeStore	*store = GTK_TREE_STORE(data);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget));
	gtk_combo_box_get_active_iter(GTK_COMBO_BOX(widget), &iter);
	gtk_tree_model_get(model, &iter, 0, &family, -1);
	gnftables_table_update(family, store);
}
*/


static GtkWidget *create_family_list(gint list, void (*callback)(GtkComboBox *widget, gpointer data), gpointer data)
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
 * Get data from table creating page, and send netlink message to kernel.
 * @button:  OK button in table creating page
 * @info:    instance of struct table_create_widget
 */
void gnftables_table_submit(GtkButton *button, gpointer info)
{
	int  res;
	struct  table_submit_argsnnn	*args;
	struct	table_create_data	*data = NULL;
	args = (struct table_submit_argsnnn *)info;

	// get data
	res = table_create_getdata(args, &data);
	if (res != TABLE_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(args->msg), table_error[res]);
		return;
	}

	// if all data is valid, submit to kernel.
	res = gui_add_table(data);
	xfree(data->table);
	xfree(data);
	if (res != TABLE_SUCCESS) {
		gtk_label_set_text(GTK_LABEL(args->msg), table_error[res]);
		return;
	}

	// back to table list
	xfree(args);
	gnftables_table_list();
}

/*
 * Page in which you can create a new table.
 * button: "Create Table" button in table list page
 */
void gnftables_table_add(GtkButton *button, gpointer data)
{
	GtkWidget	*notebook;
	GtkWidget	*container;
	GtkWidget	*fixed;
	GtkWidget	*fixed_info;
	GtkWidget	*ok;
	GtkWidget	*cancel;
	GtkWidget	*frame;
	GtkWidget	*name;
	GtkWidget	*name_value;
	GtkWidget	*family;
	GtkWidget	*family_value;
	GtkWidget	*msg;

	struct table_submit_argsnnn  *args;

	top_window->page_current = NOTEBOOK_TABLE_CREATE;
	notebook = top_window->notebook;
	container = top_window->table_container;
	fixed = gtk_fixed_new();
	args = xzalloc(sizeof(struct table_submit_argsnnn));

	frame = gtk_frame_new ("Create a new table");
	gtk_container_set_border_width(GTK_CONTAINER(frame), 0);
	gtk_widget_set_size_request(frame, 600, 371);
	gtk_fixed_put(GTK_FIXED(fixed), frame, 150, 40);

	fixed_info = gtk_fixed_new();
	gtk_container_add(GTK_CONTAINER(frame), fixed_info);

	name = gtk_label_new("Name:");
	gtk_fixed_put(GTK_FIXED(fixed_info), name, 30, 60);
	name_value = gtk_entry_new();
	gtk_entry_set_width_chars(GTK_ENTRY(name_value), 30);
	gtk_entry_set_max_length(GTK_ENTRY(name_value), 30);
	gtk_fixed_put(GTK_FIXED(fixed_info), name_value, 100, 60);
	args->name = name_value;

	family = gtk_label_new("Family:");
	gtk_fixed_put(GTK_FIXED(fixed_info), family, 30, 110);
	family_value = create_family_list(0, NULL, NULL);
	gtk_widget_set_size_request(family_value, 30, 10);
	gtk_combo_box_set_active(GTK_COMBO_BOX(family_value), 0);
	gtk_fixed_put(GTK_FIXED(fixed_info), family_value, 100, 110);
	args->family = family_value;

	msg = gtk_label_new("");
	gtk_fixed_put(GTK_FIXED(fixed_info), msg, 30, 250);
	args->msg = msg;

    	cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_set_size_request(cancel, 100, 10);
	g_signal_connect(G_OBJECT(cancel), "clicked",
			G_CALLBACK(gnftables_table_list), NULL);
	gtk_fixed_put(GTK_FIXED(fixed_info), cancel, 360, 310);

    	ok = gtk_button_new_with_label("OK");
	gtk_widget_set_size_request(ok, 100, 10);
	g_signal_connect(G_OBJECT(ok), "clicked",
			G_CALLBACK(gnftables_table_submit), args);
	gtk_fixed_put(GTK_FIXED(fixed_info), ok, 480, 310);

	gtk_widget_destroy(top_window->table);
	top_window->table = fixed;
	gtk_fixed_put(GTK_FIXED(container), fixed, 0, 0);
	gtk_widget_show_all(container);
	gtk_widget_queue_draw(GTK_WIDGET(notebook));
}

/*
 * Check whether the table still exist. If so, add chain list page.
 *
 */
void gnftables_table_details(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data)
{
	gchar		*name;
	gchar		*family_str;
	int		family;
	int		res;
	GtkTreeModel	*model;
	GtkTreeIter	iter;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
	gtk_tree_model_get_iter_from_string(model, &iter, path_str);
	gtk_tree_model_get(model, &iter, TABLE_NAME, &name, TABLE_FAMILY,
				&family_str, -1);
	family = str2family(family_str);
	xfree(family_str);

	// Check whether the table exists first. If it still exists,
	// goto chains list page. If not, live in table list page.
	res = gui_check_table_exist(family, name);
	if (res == TABLE_SUCCESS) {
		top_window->data->table = name;
		top_window->data->type = xstrdup("all");
		gnftables_chain_list();
	} else {
		GtkWidget *dialog;
		xfree(name);
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
				table_error[res]
				);

		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		gnftables_table_list();
	}
}

/*
 * Delete a table, and all rules in the table.
 */
void gnftables_table_delete(GtkCellRendererToggle *cell,
			gchar *path_str, gpointer data)
{
	GtkTreeIter		iter;
	gchar			*name;
	gchar			*family_str;
	int			family;
	GtkTreeModel		*model;

	gint	res;
	gint	err = RULE_SUCCESS;
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
		0, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK_CANCEL,
		"The table and all rules in the table will be deleted."
		" Are you sure?"
		);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		model = gtk_tree_view_get_model(GTK_TREE_VIEW(data));
		gtk_tree_model_get_iter_from_string(model, &iter, path_str);
		gtk_tree_model_get(model, &iter, TABLE_NAME, &name,
				TABLE_FAMILY, &family_str, -1);
		family = str2family(family_str);
		err = gui_delete_table(family, name);
		xfree(name);
		xfree(family_str);
		if (err != TABLE_SUCCESS) {
			gtk_widget_destroy(dialog);
			dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
				"%s", table_error[err]);
			gtk_dialog_run(GTK_DIALOG(dialog));
		}
		gnftables_table_list();
	}
	gtk_widget_destroy(dialog);
}


/*
 * Get basic information of tables from kernel and display in treeview.
 * @family: nftable family
 * @store:  container used to store data from kernel
 */
void gnftables_table_update(gint family, GtkTreeStore *store)
{
	gint		index = 0;
	GtkTreeIter	iter;
	gint		res;
	GdkPixbuf *icon_details = NULL;
	GdkPixbuf *icon_delete = NULL;

	struct table_list_data   *table, *tmp;
	LIST_HEAD(table_list);
	icon_details = gdk_pixbuf_new_from_file(
			DEFAULT_DATAROOT_PATH"/pixmaps/folder.png",
			NULL);
	icon_delete = gdk_pixbuf_new_from_file(
			DEFAULT_DATAROOT_PATH"/pixmaps/user-trash.png",
			NULL);

	// only ipv4 is supported now.
	// top_window->data->family = family;
	top_window->data->family = NFPROTO_IPV4;
	res = gui_get_tables_list(&table_list, NFPROTO_IPV4);
	if (res != TABLE_SUCCESS) {
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(GTK_WINDOW(top_window->window),
				0,
				GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK,
				"%s",
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
		gtk_tree_store_append(store, &iter, NULL);
		if (table->family == NFPROTO_IPV4)
			gtk_tree_store_set(store, &iter,
				TABLE_ID, index, TABLE_NAME, xstrdup(table->table),
				TABLE_FAMILY, "ipv4", TABLE_SETS, table->nsets,
				TABLE_CHAINS, table->nchains, TABLE_DETAIL,
				icon_details, TABLE_DELETE, icon_delete, -1);
		else
			gtk_tree_store_set(store, &iter,
				TABLE_ID, index, TABLE_NAME, xstrdup(table->table),
				TABLE_FAMILY, family2str(table->family),
				TABLE_SETS, table->nsets, TABLE_CHAINS,
				table->nchains, TABLE_DETAIL, icon_details,
				TABLE_DELETE, icon_delete, -1);
		xfree(table->table);
		xfree(table);
	}
}


/*
 * Table list page, list all tables.
 */
void gnftables_table_list(void)
{
	GtkWidget	*notebook;
	GtkWidget	*container;
	GtkWidget	*fixed;
//	GtkWidget	*family;
//	GtkWidget	*combo;
	GtkWidget	*create_table;
	GtkWidget	*list_tables;
	GtkWidget	*scrolledwindow;
	GtkTreeStore	*store;
	GtkCellRenderer	*renderer;
	GtkCellRenderer	*renderer_details;
	GtkCellRenderer	*renderer_delete;
	GtkTreeViewColumn *column;
	GtkCellRendererMode     mode = GTK_CELL_RENDERER_MODE_ACTIVATABLE;
	GValue val = {mode, };

	notebook = top_window->notebook;
	container = top_window->table_container;
	fixed = gtk_fixed_new();

	// Bug: Some messages as follows are printed when top_window->table
	// is released. I don't know how to fix it.
	// (gnftables:5021): Gtk-CRITICAL **: gtk_adjustment_get_value:
	// assertion 'GTK_IS_ADJUSTMENT (adjustment)' failed
	if (top_window->table)
		gtk_widget_destroy(top_window->table);

	top_window->table = fixed;
	if (top_window->data) {
		xfree(top_window->data->table);
		xfree(top_window->data->chain);
		xfree(top_window->data->set);
		xfree(top_window->data->type);
		top_window->data->handle = 0;
	} else
		top_window->data = xzalloc(sizeof(struct page_info));
	gtk_fixed_put(GTK_FIXED(container), fixed, 0, 0);

	store = gtk_tree_store_new(TABLE_TOTAL, G_TYPE_INT, G_TYPE_STRING, 
			G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT, GDK_TYPE_PIXBUF,
			GDK_TYPE_PIXBUF);


	/* family and combo are hidden for only ipv4 is supported now */
	// only show talbes in selected family.
//	family = gtk_label_new("Family");
//	gtk_fixed_put(GTK_FIXED(fixed), family, 30, 10);
//	combo = create_family_list(1, select_family, store);
//	gtk_fixed_put(GTK_FIXED(fixed), combo, 90, 10);

	// create a new table.
    	create_table = gtk_button_new_with_label("Create Table");
	gtk_widget_set_size_request(create_table, 150, 10);
	g_signal_connect(G_OBJECT(create_table), "clicked",
			G_CALLBACK(gnftables_table_add), NULL);
	gtk_fixed_put(GTK_FIXED(fixed), create_table, 700, 10);

	// treeview style
	list_tables = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Id", renderer, 
			"text", TABLE_ID, NULL);
	gtk_tree_view_column_set_clickable(column, TRUE);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Name", renderer,
			"text", TABLE_NAME, NULL);
	gtk_tree_view_column_set_min_width(column, 340);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Family", renderer,
			"text", TABLE_FAMILY, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Sets", renderer,
			"text", TABLE_SETS, NULL);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);
	column = gtk_tree_view_column_new_with_attributes("Chains", renderer,
			"text", TABLE_CHAINS, NULL);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

	renderer_details = gtk_cell_renderer_pixbuf_clicked_new();
	g_object_set(G_OBJECT(renderer_details), "mode", val, "activatable",
			TRUE, NULL);
	g_signal_connect(renderer_details, "clicked",
			G_CALLBACK(gnftables_table_details), list_tables) ;
	column = gtk_tree_view_column_new_with_attributes("Details",
			renderer_details, "pixbuf", TABLE_DETAIL, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

	renderer_delete = gtk_cell_renderer_pixbuf_clicked_new();
	g_object_set(G_OBJECT(renderer_delete), "mode", val, "activatable",
			TRUE, NULL);
	g_signal_connect(renderer_delete, "clicked",
			G_CALLBACK(gnftables_table_delete), list_tables) ;
	column = gtk_tree_view_column_new_with_attributes("Delete",
			renderer_delete, "pixbuf", TABLE_DELETE, NULL);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_alignment(column, 0.0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_tables), column);

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
	gtk_fixed_put(GTK_FIXED(fixed), scrolledwindow, 0, 50);

	gtk_widget_show_all(container);
	top_window->silent = 1;
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);
	top_window->silent = 0;
	gtk_widget_queue_draw(GTK_WIDGET(notebook));

	// get information of all tables from kernel.
	gnftables_table_update(NFPROTO_UNSPEC, store);
	top_window->page_current = NOTEBOOK_TABLE_LIST;
}


void gnftables_addpage_table(void)
{
	GtkWidget	*title;
	GtkWidget	*notebook;
	GtkWidget	*container;

	title = gtk_label_new("Tables");
	gtk_widget_set_size_request(title, 200, 10);
	notebook = top_window->notebook;
	container = top_window->table_container;
	
	top_window->silent = 1;
	gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), container, title, 0);
}


void gnftables_addpage_about(void)
{
	GtkWidget	*content;
	GtkWidget	*label;

	const gchar *text = "gnftables 0.1\n\n"
		"gnftables is a gui tool aimed to simplify the configuration "
		"of nftables from command line. This is the first release. If you\n"
		"need help, please visit <a href=\"http://ycnian.org/projects/gnftables.php\">gnftables home site</a>.\n\n"
		"This program is free software; you can redistribute it and/or "
		"modify it under the terms of the GNU General Public License\n"
		"version 2 as published by the Free Software Foundation.\n\n"
		"This program is distributed in the hope that it will be useful,"
		" but WITHOUT ANY WARRANTY; without even the implied\n"
		"warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
		" See the <a href=\"http://www.gnu.org/licenses/gpl-2.0.html\">"
		"GNU General Public License version 2</a> \nfor more details.\n\n"
		"Copyright (c) 2014  Yanchuan Nian (ycnian at gmail dot com)";

	content = gtk_label_new(NULL);
	gtk_label_set_width_chars(GTK_LABEL(content), 100);
	gtk_misc_set_alignment(GTK_MISC(content), 0.5, 0.3);
	gtk_label_set_line_wrap(GTK_LABEL(content), TRUE);
	gtk_label_set_selectable(GTK_LABEL(content), FALSE);
	gtk_label_set_markup(GTK_LABEL(content), text);

	label = gtk_label_new("About gnftables");
	gtk_widget_set_size_request(label, 200, 10);
	top_window->silent = 1;
	gtk_notebook_append_page(GTK_NOTEBOOK(top_window->notebook), content, label);      
	gtk_widget_show_all(content);
}


int main(int argc, char *argv[])
{
	GtkWidget	*fixed;
	GtkWidget	*button;
	GtkWidget	*notebook;
	GtkWidget	*window;
	GtkWidget	*table_container;
	GtkWidget	*chain_set_container;
	GtkWidget	*rule_container;

	gtk_init(&argc, &argv);
	top_window = xzalloc(sizeof(struct top_window));

	/* Create toplevel window. */
        window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(window), "gnftables");
        gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(window, 900, 556);
	gtk_window_set_icon(GTK_WINDOW(window),
		create_pixbuf(DEFAULT_DATAROOT_PATH"/pixmaps/gnftables.png"));
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	gtk_container_set_border_width(GTK_CONTAINER (window), 10);
	top_window->window = window;

	fixed = gtk_fixed_new();
	gtk_container_add(GTK_CONTAINER(window), fixed);

	notebook = gtk_notebook_new();
	gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
	gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook), TRUE);
	gtk_notebook_set_show_border(GTK_NOTEBOOK(notebook), TRUE);
	gtk_widget_set_size_request(notebook, 880, 500);
	gtk_widget_show(notebook);
	gtk_fixed_put(GTK_FIXED(fixed), notebook, 0, 0);
	top_window->notebook = notebook;

	table_container = gtk_fixed_new();
	chain_set_container = gtk_fixed_new();
	rule_container = gtk_fixed_new();
	top_window->table_container = table_container;
	top_window->chain_set_container = chain_set_container;
	top_window->rule_container = rule_container;

	/* At the beginning, there are only two tabs: table tab and about tab,
	 * other tabs are added and deleted dynamicly.
	 */
	gnftables_addpage_table();
	gnftables_addpage_chain();
	gnftables_addpage_rule();
	gnftables_addpage_about();

	g_signal_connect(G_OBJECT(notebook), "switch-page",
		G_CALLBACK(select_page), NULL);

	button = gtk_button_new_with_label("Load rules from file");
	g_signal_connect(G_OBJECT(button), "clicked", 
		G_CALLBACK(load_rules), notebook);
	gtk_widget_set_size_request(button, 435, 10);
	gtk_fixed_put(GTK_FIXED(fixed), button, 0, 500);
	gtk_widget_show(button);

	button = gtk_button_new_with_label("Save rules to file");
	g_signal_connect(G_OBJECT (button), "clicked", 
		G_CALLBACK(save_rules), notebook);
	gtk_widget_set_size_request(button, 435, 10);
	gtk_fixed_put(GTK_FIXED(fixed), button, 445, 500);
	gtk_widget_show(button);

	gtk_widget_show(fixed);
	gtk_widget_show(window);

	gnftables_table_list();
	gtk_main();

	return 0;
}
