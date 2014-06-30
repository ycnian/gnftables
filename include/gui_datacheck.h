#ifndef NFTABLES_GUI_DATACHECK_H
#define NFTABLES_GUI_DATACHECK_H

#include <gui_nftables.h>

struct table_create_data {
	int 	family;
	char	*table;
};

struct chain_create_data {
	int	family;
	char	*table;
	char	*chain;
	int	basechain;
	char	*type;
	int	hook;
	int	priority;
};


struct ip_addr_data {
	int	ip_type;
	union {
		struct {
			char	*iplist;
		}iplist;
		struct {
			char	*ip;
			char	*mask;
		}subnet;
		struct {
			char	*from;
			char	*to;
		}range;
	};
};

struct trans_port_data {
	int	port_type;
	union {
		struct {
			char	*portlist;
		}portlist;
		struct {
			char	*from;
			char	*to;
		}range;
	};
};

struct trans_all_data {

};

struct trans_tcp_data {
	int			protocol;
	struct trans_port_data	*sport;
	struct trans_port_data	*dport;
};

struct trans_udp_data {
	int			protocol;
	struct trans_port_data	*sport;
	struct trans_port_data	*dport;
};

struct transport_data {
	int	trans_type;
	union {
		struct trans_all_data	*all;
		struct trans_tcp_data	*tcp;
		struct trans_udp_data	*udp;
	};
};

struct header {
	struct ip_addr_data	*saddr;
	struct ip_addr_data	*daddr;
	struct transport_data	*transport_data;
};

struct pktmeta {
	char	*iifname;
	char	*oifname;
	int	iiftype;
	int	oiftype;
	int	skuid;
	int	skgid;
};

struct rule_create_data {
	int		family;
	char		*table;
	char		*chain;
	struct header	*header;
	struct pktmeta	*pktmeta;
	struct list_head exprs;
};


int name_check(char *name, int *start, int *end);
int integer_check(char *integer);

int table_name_check(char *name, int *start, int *end);
int table_create_getdata(struct table_create_widget  *widget,
		struct table_create_data **data);

int chain_name_check(char *name, int *start, int *end);
int chain_priority_check(char *priority);
int chain_create_getdata(struct chain_create_widget  *widget,
		struct chain_create_data **data);

int rule_create_getdata(struct rule_create_widget  *widget,
                struct rule_create_data **data);

int get_header_addr_from_page(struct ip_address  *widget,
                struct ip_addr_data *data);
int get_header_data_from_page(struct match_header  *widget,
                struct header *data);
int get_pktmeta_data_from_page(struct match_pktmeta  *widget,
                struct pktmeta *data);
int get_data_from_page(struct rule_create_widget  *widget,
                struct rule_create_data *data);
int get_data_from_page(struct rule_create_widget  *widget,
                struct rule_create_data *data);
void rule_free_data(struct rule_create_data *data);
#endif
