#ifndef  GUI_RULE_H
#define  GUI_RULE_H


struct gui_table {
	uint32_t        family;
	const char      *table;
	uint32_t        nsets;
	uint32_t        nchains;
	struct list_head        list;
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





int gui_get_tables_list(struct list_head *head, uint32_t family);


void gui_chain_free(struct gui_chain *chain);
int gui_get_chains_list(struct list_head *head, int family, char *table);
int gui_add_chain(struct gui_chain *gui_chain);
int gui_delete_chain(int family, const char *table, const char *chain);

int gui_flush_table(int family, char *name);


#endif
