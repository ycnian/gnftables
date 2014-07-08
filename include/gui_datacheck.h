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

struct ip_convert {
	char	ip[4];
	struct list_head  list;
};

struct port_convert {
	unsigned short	port;
	struct list_head  list;
};

struct ip_addr_data {
	enum address_type	ip_type;
	int	exclude;
	union {
		struct {
			struct list_head ips;
		}iplist;
		struct {
			unsigned char	ip[4];
			int	mask;
		}subnet;
		struct {
			unsigned char	from[4];
			unsigned char	to[4];
		}range;
	};
};

struct trans_port_data {
	enum port_type	port_type;
	int	exclude;
	union {
		struct {
			struct list_head ports;
		}portlist;
		struct {
			unsigned short	from;
			unsigned short	to;
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
	enum transport_type	trans_type;
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
	struct list_head sets;
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
int get_header_iplist_from_page(struct ip_address  *widget,
                struct ip_addr_data *data);
int get_header_ipsubnet_from_page(struct ip_address  *widget,
                struct ip_addr_data *data);
int get_header_iprange_from_page(struct ip_address  *widget,
                struct ip_addr_data *data);
int ipv4_addr_cmp(unsigned char *ip1, unsigned char *ip2);
int string_is_null(char *str);
int ipv4_addr_mask_sub(unsigned char token);
int ipv4_addr_mask(char *str, int *interger);
int unsigned_int_check(char *integer);
char *get_data_from_entry(GtkEntry *entry);
int get_header_portlist_from_page(struct transport_port_details *widget,
                struct trans_port_data *data);
int get_header_portrange_from_page(struct transport_port_details *widget,
                struct trans_port_data *data);
int get_header_port_from_page(struct transport_port_info *widget,
                struct trans_port_data *data);
int get_header_transall_from_page(struct transport_all * widget,
                struct trans_all_data *data);
int get_header_transtcp_from_page(struct transport_tcp * widget,
                struct trans_tcp_data *data);
int get_header_transudp_from_page(struct transport_udp * widget,
                struct trans_udp_data *data);
int get_header_trans_from_page(struct transport_info * widget,
                struct transport_data *data);

#endif
