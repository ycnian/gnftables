#ifndef NFTABLES_GUI_EXPRESSION_H
#define NFTABLES_GUI_EXPRESSION_H

#include <gui_rule.h>
#include <gui_nftables.h>

int rule_addrlist_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source);
int rule_addrsubnet_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source);
int rule_addrrange_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source);
int rule_addr_gen_exprs(struct rule_create_data *data, struct ip_addr_data *addr, int source);
int rule_portlist_gen_exprs(struct rule_create_data *data,
                struct trans_port_data *port, enum transport_type type, int source);
int rule_portrange_gen_exprs(struct rule_create_data *data,
                struct trans_port_data *port, enum transport_type type, int source);
int rule_port_gen_exprs(struct rule_create_data *data, struct trans_port_data *port, enum transport_type type, int source);
int rule_transall_gen_exprs(struct rule_create_data *data, struct trans_all_data *all);
int rule_transtcp_gen_exprs(struct rule_create_data *data, struct trans_tcp_data *tcp, enum transport_type type);
int rule_transudp_gen_exprs(struct rule_create_data *data, struct trans_udp_data *udp, enum transport_type type);
int rule_trans_gen_exprs(struct rule_create_data *data, struct transport_data *trans);
int rule_header_gen_exprs(struct rule_create_data *data, struct header *header);
int rule_pktmeta_gen_exprs(struct rule_create_data *data, struct pktmeta *pktmeta);

int rule_counter_gen_exprs(struct rule_create_data *data);
int rule_gen_expressions(struct rule_create_data *data);
int rule_ip_upper_expr(struct rule_create_data *data, enum transport_type upper);


int rule_parse_ip_protocol_expr(struct expr *expr, struct header *header);
int rule_parse_ip_saddr_expr(struct expr *expr, struct header *header);
int rule_parse_ip_daddr_expr(struct expr *expr, struct header *header);
int rule_parse_tcp_sport_expr(struct expr *expr, struct header *header);
int rule_parse_tcp_dport_expr(struct expr *expr, struct header *header);
int rule_parse_udp_sport_expr(struct expr *expr, struct header *header);
int rule_parse_udp_dport_expr(struct expr *expr, struct header *header);
int rule_parse_header_expr(struct expr *expr, struct header *header);
int rule_parse_pktmeta(struct expr *expr, struct pktmeta *pktmeta);
int rule_parse_expr(struct stmt *stmt, struct rule_create_data *p);
int rule_parse_verdict_stmt(struct stmt *stmt, struct rule_create_data *p);
int rule_parse_counter_stmt(struct stmt *stmt, struct rule_create_data *p);
int rule_parse_stmt(struct stmt *stmt, struct rule_create_data *p);
int rule_de_expressions(struct rule *rule, struct rule_create_data **data);
#endif
