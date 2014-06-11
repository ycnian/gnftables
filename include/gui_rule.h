#ifndef  GUI_RULE_H
#define  GUI_RULE_H


struct gui_table {
	int		family;
	char		*table;
	int		nsets;
	int		nchains;
	struct list_head	list;
};


struct gui_chain {
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

struct gui_rule {
	int		handle;		// NOTE: handle in struct handle is 8 bytes.
	int		family;
	char		*table;
	char		*chain;
	char		*stmt;
	struct list_head	list;
};



int gui_get_tables_list(struct list_head *head, uint32_t family);


void gui_chain_free(struct gui_chain *chain);
int gui_get_chains_list(struct list_head *head, int family, char *table);
int gui_add_chain(struct gui_chain *gui_chain);
int gui_delete_chain(int family, const char *table, const char *chain);
int gui_get_chains_number(int family, char *table);

int gui_flush_table(int family, char *name);

int gui_get_rules_list(struct list_head *head, int family, char *table, char *chain);
int get_rule_data(struct rule *rule, char *file);
void gui_rule_free(struct gui_rule *rule);
int gui_get_rules_number(int family, char *table, char *chain);


int gui_get_sets_number(int family, char *table);

#endif
