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

#define   SET_ID		0
#define   SET_NAME		1
#define   SET_KEYTYPE		2
#define   SET_DATATYPE		3
#define   SET_ELEMS		4
#define   SET_DETAIL		5
#define   SET_DELETE		6
#define   SET_TOTAL		7

#define   RULE_ID		0
#define   RULE_HANDLE		1
#define   RULE_TABLE		2
#define   RULE_CHAIN		3
#define   RULE_CONTENT		4
#define   RULE_DETAIL		5
#define   RULE_DELETE		6
#define   RULE_TOTAL		7


#define  NOTEBOOK_TABLE_LIST		(1 << 0)
#define  NOTEBOOK_TABLE_CREATE		(1 << 1)
#define  NOTEBOOK_CHAIN_LIST		(1 << 2)
#define  NOTEBOOK_CHAIN_CREATE		(1 << 3)
#define  NOTEBOOK_SET_LIST		(1 << 4)
#define  NOTEBOOK_SET_CREATE_EDIT	(1 << 5)
#define  NOTEBOOK_RULE_LIST		(1 << 6)
#define  NOTEBOOK_RULE_CREATE_EDIT	(1 << 7)
#define  NOTEBOOK_ABOUT_GNFTABLES	(1 << 8)
#define  NOTEBOOK_PAGES			9

#define  NOTEBOOK_TABLE (NOTEBOOK_TABLE_LIST | NOTEBOOK_TABLE_CREATE)
#define  NOTEBOOK_CHAIN_SET (NOTEBOOK_CHAIN_LIST | NOTEBOOK_CHAIN_CREATE | NOTEBOOK_SET_LIST | NOTEBOOK_SET_CREATE_EDIT)
#define  NOTEBOOK_RULE (NOTEBOOK_RULE_LIST | NOTEBOOK_RULE_CREATE_EDIT)

struct page_info {
	int	family;
	char	*table;
	char	*chain;
	char	*set;
	char	*type;
	int	handle;
};
struct top_window {
	int	silent;
	int	page_current;
	int	page_next;
	GtkWidget	*window;
	GtkWidget	*notebook;
	GtkWidget	*table_container;
	GtkWidget	*chain_set_container;
	GtkWidget	*rule_container;
	GtkWidget	*table;
	GtkWidget	*chain_set;
	GtkWidget	*rule;
	struct page_info	*data;
};

/**
 * widgets containg values used in table creating procedure
 * @notebook: the notebook, used to jump to table list page.
 * @name: table name
 * @family: table family
 * @msg:  error message is displayed here if values are invalid.
 */
struct table_submit_argsnnn {
	GtkWidget       *name;
	GtkWidget       *family;
	GtkWidget	*msg;
};

struct chain_list_argsnnn {
	int	family;
	char	*table;
	char	*type;
};

struct chain_create_argsnnn {
	int	family;
	char	*table;
};

struct chain_submit_argsnnn {
	GtkWidget	*name;
	GtkWidget	*basechain;
	GtkWidget	*type;
	GtkWidget	*hook;
	GtkWidget	*priority;
	GtkWidget	*msg;
	gint		family;
	gchar		*table;
};


struct set_submit_argsnnn {
	GtkWidget	*name;
	GtkWidget	*type;
	GtkWidget	*add;
	GtkTreeStore	*store;
	GtkWidget	*treeview;
	GtkWidget	*msg;
	gint		family;
	gchar		*table;
	int		create;
};


/**
 * widgets containg values used in table creating procedure
 * @notebook: the notebook, used to jump to table list page.
 * @name: table name
 * @family: table family
 * @msg:  error message is displayed here if values are invalid.
 */
struct table_create_widget {
	GtkWidget       *name;
	GtkWidget       *family;
	GtkWidget	*msg;
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
	GtkTreeModel	*model;
	GtkTreeStore	*store;
	gint		family;
	gchar		*table;
	gchar		*chain;
	gchar		*type;
};

struct set_create_widget {
	GtkWidget	*notebook;
	GtkWidget	*name;
	GtkWidget	*type;
	GtkWidget	*add;
	GtkTreeStore	*store;
	GtkWidget	*treeview;
	GtkWidget	*msg;
	gint		family;
	gchar		*table;
	int		create;
};

struct set_list_args {
	GtkWidget	*notebook;
	GtkTreeModel	*model;
	GtkTreeStore	*store;
	gint		family;
	gchar		*table;
	gchar		*set;
	gchar		*type;
	struct set_create_data	*data;
};

struct rule_list_args {
	GtkWidget	*notebook;
	GtkWidget	*list_rules;
	GtkTreeStore	*store;
	gint		family;
	gchar		*table;
	gchar		*chain;
	gint		handle;
	struct rule_create_data	*data;
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

enum port_type {
	PORT_EXACT,
	PORT_RANGE,
	PORT_SET,
};

struct transport_port_details {
	enum port_type		type;
	int			exclude;
	struct {
		struct {
			GtkWidget	*port;
		}portlist;
		struct {
			GtkWidget	*from;
			GtkWidget	*dash;
			GtkWidget	*to;
		}range;
		struct {
			GtkWidget	*set;
		}sets;
	};
};

struct transport_port_info {
	int	family;
	char	*table;
	GtkWidget	*label;
	GtkWidget	*type;
	struct transport_port_details	*value;
	GtkWidget	*exclude;
};

struct transport_tcp {
	int		len;
	struct transport_port_info	*sport;
	struct transport_port_info	*dport;
};

struct transport_udp {
	int		len;
	struct transport_port_info	*sport;
	struct transport_port_info	*dport;
};

struct transport_all {
	int		len;
	GtkWidget	*fixed;
};

struct transport_info {
	GtkWidget	*fixed;
	enum transport_type	type;
	struct	transport_all	*all;
	struct	transport_tcp	*tcp;
	struct	transport_udp	*udp;
};

struct ip_address {
	enum address_type	type;
	int			exclude;
	struct {
		struct {
			GtkWidget	*ip;
		}exact_ip;
		struct {
			GtkWidget	*ip;
			GtkWidget	*slash;
			GtkWidget	*mask;
		}subnet;
		struct {
			GtkWidget	*from;
			GtkWidget	*dash;
			GtkWidget	*to;
		}range;
		struct {
			GtkWidget	*set;
		}sets;
	};
};

struct  match_header {
	int		family;
	char		*table;
	int		offset;
	int		len;
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
	int		offset;
	int		len;
	GtkWidget	*expander;
	GtkWidget	*fixed;
	int		expanded;
	GtkWidget	*iifname;
	GtkWidget	*oifname;
	GtkWidget	*iiftype;
	GtkWidget	*oiftype;
	GtkWidget	*skuid;
	GtkWidget	*skgid;
};

enum action_type {
	ACTION_ACCEPT,
	ACTION_DROP,
	ACTION_JUMP,
	ACTION_COUNTER,
};

struct action_elem {
	struct list_head	list;
	enum action_type	type;
	struct rule_create_widget	*rule;
	GtkWidget	*label;
	GtkWidget	*widget1;
	GtkWidget	*widget2;
	GtkWidget	*widget3;
	GtkWidget	*widget4;
	GtkWidget	*remove;
};

struct actions_all {
	int		offset;
	int		len;
	GtkWidget	*expander;
	GtkWidget	*fixed;
	int		expanded;
	struct list_head	list;
	GtkWidget	*accept;
	GtkWidget	*drop;
	GtkWidget	*jump;
	GtkWidget	*jump_to;
	GtkWidget	*counter;
	GtkWidget	*counter_value;
	GtkWidget	*index;
};

struct match_trackmeta {

};

struct rule_create_widget {
	GtkWidget       *notebook;
	GtkWidget	*fixed;
	gint		family;
	gchar		*table;
	gchar		*chain;
	uint64_t	handle;
	struct match_header	*header;
	struct match_pktmeta	*meta;
	struct match_trackmeta	*track;
	struct actions_all	*actions;
	GtkWidget	*index;
	GtkWidget	*index_value;
	GtkWidget	*cancel;
	GtkWidget	*ok;
	GtkWidget	*msg;
};


void gnftables_rule_submit(GtkButton *button, gpointer info);
void gnftables_rule_add(GtkButton *button, gpointer data);
void gnftables_rule_details(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data);
void gnftables_rule_delete(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data);
void gnftables_rule_update(struct page_info *args, GtkTreeStore *store);
void gnftables_rule_list(void);
void gnftables_addpage_rule(void);


void gnftables_set_submit(GtkButton *button, gpointer info);
void gnftables_set_add(GtkButton *button, gpointer data);
void gnftables_set_details(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data);
void gnftables_set_delete(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data);
void gnftables_set_update(struct page_info *args, GtkTreeStore *store);
void gnftables_set_list(void);


void gnftables_chain_submit(GtkButton *button, gpointer info);
void gnftables_chain_add(GtkButton *button, gpointer data);
void gnftables_chain_details(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data);
void gnftables_chain_delete(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data);
void gnftables_chain_update(struct page_info *args, GtkTreeStore *store);
void gnftables_chain_list(void);
void gnftables_addpage_chain(void);


void gnftables_table_submit(GtkButton *button, gpointer info);
void gnftables_table_add(GtkButton *button, gpointer data);
void gnftables_table_details(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data);
void gnftables_table_delete(GtkCellRendererToggle *cell,
		gchar *path_str, gpointer data);
void gnftables_table_update(gint family, GtkTreeStore *store);
void gnftables_table_list(void);
void gnftables_addpage_table(void);
void gnftables_addpage_about(void);

#endif
