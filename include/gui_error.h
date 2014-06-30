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
#define  CHAIN_ERROR_NUM	8

#define  RULE_SUCCESS		0
#define  RULE_KERNEL_ERROR	1
#define  RULE_TABLE_NOT_EXIST	2
#define  RULE_CHAIN_NOT_EXIST	3
#define  RULE_HEADER_IP_INVALID	4
#define  RULE_ERROR_NUM		5

#define  SET_SUCCESS		0
#define  SET_KERNEL_ERROR	1

extern const char *table_error[TABLE_ERROR_NUM];
extern const char *chain_error[CHAIN_ERROR_NUM];
extern const char *rule_error[RULE_ERROR_NUM];


#endif
