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
int gui_get_chains_list(struct list_head *head, int family, char *table, const char *type, int rules);
int gui_add_chain(struct chain_create_data *gui_chain);
int gui_delete_chain(int family, const char *table, const char *chain);

int gui_flush_table(int family, char *name);

int gui_get_rules_list(struct list_head *head, int family, char *table, char *chain);
void gui_rule_free(struct gui_rule *rule);
int gui_delete_rule(int family, const char *table, const char *chain, int handle);
int gui_add_rule(struct rule_create_data *data);
int gui_check_rule_exist(int family, const char *table, const char *chain, int handle);
int gui_get_rule(int family, const char *table, const char *chain, int handle_no, struct rule_create_data  **content);

int gui_get_sets_number(int family, char *table, int *nsets);


int gui_add_table(struct table_create_data *data);
int gui_delete_table(int family, char *name);
int gui_check_table_exist(int family, const char *name);
int gui_get_rules_number(int family, char *table, char *chain, int *nrules);
int gui_check_chain_exist(int family, const char *table, const char *chain);
int gui_get_sets_list(struct list_head *head, int family, char *table, const char *desc, int elements);


int gui_add_set(struct set_create_data *gui_set);
int gui_get_set(struct set_create_data *gui_set, int getelement);
int gui_delete_set(int family, char *table, char *set);
int gui_flush_set(int family, char *table, char *name);
int gui_edit_set(struct set_create_data *gui_set);
void gui_set_free(struct set_list_data *set);

int tables_fprint(char *filename);
int tables_load(char *filename);

int str2family(const char *family);
#endif
