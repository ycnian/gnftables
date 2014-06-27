#ifndef NFTABLES_GUI_NFTABLES_H
#define NFTABLES_GUI_NFTABLES_H

#include <stdint.h>
#include <gtk/gtk.h>
#include <list.h>


#define   TABLE_ID		0
#define   TABLE_NAME		1
#define   TABLE_FAMILY		2
#define   TABLE_SETS		3
#define   TABLE_CHAINS		4
#define   TABLE_DETAIL		5
#define   TABLE_DELETE		6
#define   TABLE_TOTAL		7


#define   CHAIN_ID		0
#define   CHAIN_NAME		1
#define   CHAIN_RULES		2
#define   CHAIN_BASECHAIN	3
#define   CHAIN_TYPE		4
#define   CHAIN_HOOK		5
#define   CHAIN_PRIORITY	6
#define   CHAIN_DETAIL		7
#define   CHAIN_DELETE		8
#define   CHAIN_TOTAL		9


#define   RULE_ID		0
#define   RULE_HANDLE		1
#define   RULE_TABLE		2
#define   RULE_CHAIN		3
#define   RULE_CONTENT		4
#define   RULE_DETAIL		5
#define   RULE_DELETE		6
#define   RULE_TOTAL		7



struct table_create_widget {
	GtkWidget       *notebook;
	GtkWidget       *name;
	GtkWidget       *family;
	GtkWidget	*msg;
};

struct list_sets_and_chains {
	GtkWidget	*treeview;
	GtkWidget	*notebook;
};


struct basechain_info {
	GtkWidget	*type;
	GtkWidget	*type_value;
	GtkWidget	*hook;
	GtkWidget	*hook_value;
	GtkWidget	*priority;
	GtkWidget	*priority_value;
};

struct chain_create_widget {
	GtkWidget	*notebook;
	GtkWidget	*name;
	GtkWidget	*basechain;
	GtkWidget	*type;
	GtkWidget	*hook;
	GtkWidget	*priority;
	GtkWidget	*msg;
	gint		family;
	gchar		*table;
};

struct chain_list_args {
	GtkWidget	*notebook;
	GtkWidget	*model;
	GtkWidget	*store;
	gint		family;
	gchar		*table;
	gchar		*chain;
	gchar		*type;
};


struct rule_list_args {
	GtkWidget	*notebook;
	GtkWidget	*list_rules;
	GtkWidget	*store;
	gint		family;
	gchar		*table;
	gchar		*chain;
	gint		handle;
};

enum transport_type {
	TRANSPORT_ALL,
	TRANSPORT_TCP,
	TRANSPORT_UDP,
};

enum address_type {
	ADDRESS_EXACT,
	ADDRESS_SUBNET,
	ADDRESS_RANGE,
	ADDRESS_SET,
};

struct transport_info {
	enum transport_type	type;
	struct {
		struct {
			GtkWidget	*sport;
			GtkWidget	*sport_value;
			GtkWidget	*dport;
			GtkWidget	*dport_value;
		}tcp;
		struct {
			GtkWidget	*sport;
			GtkWidget	*sport_value;
			GtkWidget	*dport;
			GtkWidget	*dport_value;
		}udp;
	};
};

struct ip_address {
	enum address_type	type;
	struct {
		struct {
			GtkWidget	*ip;
		}exact_ip;
		struct {
			GtkWidget	*ip;
			GtkWidget	*mask;
		}subnet;
		struct {
			GtkWidget	*from;
			GtkWidget	*to;
		}range;
		struct {
			GtkWidget	*set;
			GtkWidget	*value;
		}sets;
	};
};

struct  match_header {
	GtkWidget	*expander;
	GtkWidget	*fixed;
	int		expanded;
	struct {
		GtkWidget		*type;
		struct ip_address	*value;
	}saddr;
	struct {
		GtkWidget		*type;
		struct ip_address	*value;
	}daddr;
	struct {
		GtkWidget		*type;
		struct transport_info	*value;
	}transport;
};

struct match_pktmeta {
	GtkWidget	*expander;
	int		expanded;
	GtkWidget	*iifname;
	GtkWidget	*oifname;
	GtkWidget	*iiftype;
	GtkWidget	*oiftype;
	GtkWidget	*skuid;
	GtkWidget	*skgid;
};

struct match_trackmeta {

};

struct rule_create_widget {
	GtkWidget       *notebook;
	GtkWidget	*fixed;
	gint		family;
	gchar		*table;
	gchar		*chain;
	struct match_header	*header;
	struct match_pktmeta	*meta;
	struct match_trackmeta	*track;
	GtkWidget	*cancel;
	GtkWidget	*ok;
};


void remove_book(GtkButton *button, GtkNotebook *notebook);
void select_page(GtkNotebook *notebook, GtkWidget *page, guint page_num, gpointer user_data);
gint load_rules(GtkWidget *widget, GtkWidget *event, gpointer data);
gint save_rules(GtkWidget *widget, GtkWidget *event, gpointer data);
GdkPixbuf  *create_pixbuf(const gchar *filename);
void back_to_table_list (GtkButton *button, gpointer  notebook);
void create_new_chain(GtkButton *button, gpointer  notebook);
void begin_create_new_table(GtkButton *button, gpointer  info);
void back_to_table_list (GtkButton *button, gpointer  notebook);
void create_new_table(GtkButton *button, gpointer  notebook);
void gnftables_about_init(GtkWidget *notebook);
void gnftables_set_chain_init(gint family, gchar *table_name, GtkWidget *notebook);
void gnftables_table_init(GtkWidget *notebook);
void select_family(GtkComboBox *widget, gpointer user_data);
GtkWidget *create_family_list(gint list, void (*callback)(GtkComboBox *widget, gpointer data), gpointer data);
void table_update_data(gint family, GtkTreeStore *store);


int  get_table_list(struct list_head *table_list, uint32_t family);
int gui_delete_table(int family, char *name);

int str2family(const char *family);


void table_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data);
void table_callback_detail(GtkCellRendererToggle *cell, gchar *path_str, gpointer data);
gboolean show_treeview_menu(GtkWidget *widget, GdkEvent  *event, gpointer   user_data);


void chain_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data);
void chain_callback_detail(GtkCellRendererToggle *cell, gchar *path_str, gpointer data);
void chain_update_data(struct chain_list_args *args);
void basechain_selected(GtkWidget *check_button, gpointer data);
void back_to_chain_list(GtkButton *button, gpointer  info);
void begin_create_new_chain(GtkButton *button, gpointer  info);


void gnftables_rule_init(gint family, gchar *table_name, gchar *chain_name, GtkWidget *notebook);
void rule_update_data(struct rule_list_args *args);

void rule_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data);
int gui_check_table_exist(int family, char *name);


void create_new_rule(GtkButton *button, gpointer  data);

void transport_all(void);
void transport_tcp(void);
void transport_udp(void);
void transport_callback(GtkComboBoxText *widget, gpointer data);
void back_to_rule_list(GtkButton *button, gpointer  info);
void begin_create_new_rule(GtkButton *button, gpointer  info);
void chain_list_type_changed(GtkComboBoxText *widget, gpointer data);
void chain_create_type_changed(GtkComboBoxText *widget, gpointer data);

void transport_callback_do(struct rule_create_widget  *widget);
void update_pktmeta_position(struct match_pktmeta *pktmeta);
void update_header_transport_widgets(GtkWidget *fixed, struct transport_info *transport);
void header_transport_show_all(GtkWidget *fixed, struct transport_info *transport);
void header_transport_show_tcp(GtkWidget *fixed, struct transport_info *transport);
void header_transport_show_udp(GtkWidget *fixed, struct transport_info *transport);

#endif
