#ifndef  GUI_ERROR_H
#define  GUI_ERROR_H



#define  TABLE_SUCCESS		0
#define  TABLE_KERNEL_ERROR	1
#define  TABLE_EXIST		2
#define	 TABLE_NAME_INVALID	3
#define  TABLE_NOT_EXIST	4
#define  TABLE_NAME_EMPTY	5
#define  TABLE_ERROR_NUM	6

#define  CHAIN_SUCCESS		0
#define  CHAIN_KERNEL_ERROR	1
#define  CHAIN_NAME_EMPTY	2
#define  CHAIN_NAME_INVALID	3
#define  CHAIN_PRIORITY_INVALID	4
#define  CHAIN_TABLE_NOT_EXIST	5
#define  CHAIN_EXIST		6
#define  CHAIN_NOT_EXIST	7
#define  CHAIN_PRIORITY_OVERFLOW 8
#define  CHAIN_ERROR_NUM	9

#define  RULE_SUCCESS		0
#define  RULE_KERNEL_ERROR	1
#define  RULE_TABLE_NOT_EXIST	2
#define  RULE_CHAIN_NOT_EXIST	3
#define  RULE_HEADER_IP_INVALID	4
#define  RULE_HEADER_IP_RANGE_INVALID	5
#define  RULE_HEADER_IP_EMPTY	6
#define  RULE_HEADER_MASK_EMPTY	7
#define  RULE_HEADER_MASK_INVALID	8
#define  RULE_HEADER_PORT_INVALID	9
#define  RULE_HEADER_PORT_OVERFLOW	10
#define  RULE_HEADER_PORT_RANGE_INVALID	11
#define  RULE_PKTMETA_IFTYPE_INVALID	12
#define  RULE_PKTMETA_IIFTYPE_INVALID	13
#define  RULE_PKTMETA_OIFTYPE_INVALID	14
#define  RULE_PKTMETA_SKID_INVALID	15
#define  RULE_PKTMETA_SKUID_INVALID	16
#define  RULE_PKTMETA_SKGID_INVALID	17
#define  RULE_HEADER_SET_EMPTY		18
#define  RULE_HEADER_SET_NOT_EXIST	19
#define  RULE_INDEX_INVALID		20
#define  RULE_ERROR_NUM		21

#define  SET_SUCCESS		0
#define  SET_KERNEL_ERROR	1
#define  SET_TABLE_NOT_EXIST	2
#define  SET_ERROR_NUM		3

#define  ELEMENT_SUCCESS	0
#define  ELEMENT_KERNEL_ERROR	1
#define  ELEMENT_ERROR_NUM	2

extern const char *table_error[TABLE_ERROR_NUM];
extern const char *chain_error[CHAIN_ERROR_NUM];
extern const char *rule_error[RULE_ERROR_NUM];
extern const char *set_error[SET_ERROR_NUM];
extern const char *element_error[ELEMENT_ERROR_NUM];

#endif
