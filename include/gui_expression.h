#ifndef NFTABLES_GUI_EXPRESSION_H
#define NFTABLES_GUI_EXPRESSION_H

#include <gui_rule.h>
#include <gui_nftables.h>

int rule_addrlist_gen_exprs(struct list_head *head, struct ip_addr_data *addr);
int rule_addrsubnet_gen_exprs(struct list_head *head, struct ip_addr_data *addr);
int rule_addrrange_gen_exprs(struct list_head *head, struct ip_addr_data *addr);
int rule_addr_gen_exprs(struct list_head *head, struct ip_addr_data *addr);
int rule_portlist_gen_exprs(struct list_head *head,
                struct trans_port_data *port);
int rule_portrange_gen_exprs(struct list_head *head,
                struct trans_port_data *port);
int rule_port_gen_exprs(struct list_head *head, struct trans_port_data *port);
int rule_transall_gen_exprs(struct list_head *head, struct trans_all_data *data);
int rule_transtcp_gen_exprs(struct list_head *head, struct trans_tcp_data *data);
int rule_transudp_gen_exprs(struct list_head *head, struct trans_udp_data *data);
int rule_trans_gen_exprs(struct list_head *head, struct transport_data *trans);
int rule_header_gen_exprs(struct list_head *head, struct header *header);
int rule_pktmeta_gen_exprs(struct list_head *head, struct pktmeta *pktmeta);

int rule_gen_expressions(struct rule_create_data *data);

#endif
