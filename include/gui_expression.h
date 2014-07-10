#ifndef NFTABLES_GUI_EXPRESSION_H
#define NFTABLES_GUI_EXPRESSION_H

#include <gui_rule.h>
#include <gui_nftables.h>

int rule_addrlist_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source);
int rule_addrsubnet_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source);
int rule_addrrange_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source);
int rule_addr_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source);
int rule_portlist_gen_exprs(struct rule_create_data *data,
                struct trans_port_data *port);
int rule_portrange_gen_exprs(struct rule_create_data *data,
                struct trans_port_data *port);
int rule_port_gen_exprs(struct rule_create_data *data, struct trans_port_data *port);
int rule_transall_gen_exprs(struct rule_create_data *data, struct trans_all_data *all);
int rule_transtcp_gen_exprs(struct rule_create_data *data, struct trans_tcp_data *tcp);
int rule_transudp_gen_exprs(struct rule_create_data *data, struct trans_udp_data *udp);
int rule_trans_gen_exprs(struct rule_create_data *data, struct transport_data *trans);
int rule_header_gen_exprs(struct rule_create_data *data, struct header *header);
int rule_pktmeta_gen_exprs(struct rule_create_data *data, struct pktmeta *pktmeta);

int rule_counter_gen_exprs(struct rule_create_data *data);
int rule_gen_expressions(struct rule_create_data *data);

#endif
