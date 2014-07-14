#ifndef  GUI_RULE_H
#define  GUI_RULE_H

#include <rule.h>
#include <list.h>
#include <gui_datacheck.h>

struct table_list_data {
	int		family;
	char		*table;
	int		nsets;
	int		nchains;
	struct list_head	list;
};


struct chain_list_data {
	int		family;
	char		*table;
	char		*chain;
	int		nrules;
	int		basechain;
	char		*type;
	char		hook;
	int		priority;
	struct list_head	list;
};

struct set_list_data {
	int		family;
	char		*table;
	char		*name;
	char		*keytype;
	char		*datatype;
	int		nelems;
	struct list_head	list;
};

struct gui_rule {
	int		handle;		// NOTE: handle in struct handle is 8 bytes.
	int		position;
	int		family;
	char		*table;
	char		*chain;
	char		*stmt;		// rule content
	struct list_head	list;
};



int gui_get_tables_list(struct list_head *head, int family);


void gui_chain_free(struct chain_list_data *chain);
int gui_get_chains_list(struct list_head *head, int family, char *table, char *type);
int gui_add_chain(struct chain_create_data *gui_chain);
int gui_delete_chain(int family, const char *table, const char *chain);

int gui_flush_table(int family, char *name);

int gui_get_rules_list(struct list_head *head, int family, char *table, char *chain);
int get_rule_data(struct rule *rule, char *file);
void gui_rule_free(struct gui_rule *rule);
int gui_delete_rule(int family, const char *table, const char *chain, int handle);
int gui_add_rule(struct rule_create_data *data);
int gui_get_rule(int family, const char *table, const char *chain, int handle);


int gui_get_sets_number(int family, char *table, int *nsets);


int gui_add_table(struct table_create_data *data);
int gui_get_rules_number(int family, char *table, char *chain, int *nrules);
int gui_check_chain_exist(int family, char *table, char *chain);

int gui_get_sets_list(struct list_head *head, int family, char *table);

int table_list_sets(struct table *table);
#endif
