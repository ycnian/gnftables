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


struct chain_list_args {
	GtkWidget	*notebook;
	GtkWidget	*model;
	GtkWidget	*store;
	gint		family;
	gchar		*table;
	gchar		*chain;
	gchar		*type;
};



struct new_chain {
	GtkWidget       *notebook;
	GtkWidget       *chain;
	GtkWidget       *basechain;
	GtkWidget       *type;
	GtkWidget       *hook;
	GtkWidget       *priority;
	gint		family;
	gchar		*table;
};


struct rule_list_args {
	GtkWidget	*notebook;
	GtkWidget	*list_rules;
	gint		family;
	gchar		*table;
	gchar		*chain;
	gint		handle;
};



struct packet_tcp {
	GtkWidget	*sport;
	GtkWidget	*dport;
};

struct packet_udp {
	GtkWidget	*sport;
	GtkWidget	*dport;
};


struct transport_callback_args {
	GtkWidget	*background;
	GtkWidget	*header;
	GtkWidget	*meta;
	GtkWidget	*fixed;
	struct {
		struct {
			GtkWidget	*sport;
			GtkWidget	*dport;
		}tcp;
		struct {
			GtkWidget	*sport;
			GtkWidget	*dport;
		}udp;
	};
};

struct  packet_header {
	GtkWidget	*saddr;
	GtkWidget	*daddr;
	GtkWidget	*protocol;
	struct transport_callback_args  *args;
};

struct packet_meta {
	GtkWidget	*iifname;
	GtkWidget	*oifname;
	GtkWidget	*iiftype;
	GtkWidget	*oiftype;
	GtkWidget	*skuid;
	GtkWidget	*skgid;
};

struct rule_create_widget {
	GtkWidget       *notebook;
	gint		family;
	gchar		*table;
	gchar		*chain;
	struct packet_header	*header;
	struct packet_meta	*meta;
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


void gnftables_set_rule_init(gint family, gchar *table_name, gchar *chain_name, GtkWidget *notebook);
void rule_update_data(gint family, gchar *table_name, gchar *chain_name, GtkTreeStore *store);

void rule_callback_delete(GtkCellRendererToggle *cell, gchar *path_str, gpointer data);
int gui_check_table_exist(int family, char *name);


void create_new_rule(GtkButton *button, gpointer  data);

void transport_all(void);
void transport_tcp(void);
void transport_udp(void);
void transport_callback(GtkComboBox *widget, gpointer data);
void back_to_rule_list(GtkButton *button, gpointer  info);
void begin_create_new_rule(GtkButton *button, gpointer  info);
void nftables_type_changed(GtkComboBoxText *widget, gpointer data);

#endif
