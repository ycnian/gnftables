#include <gui_error.h>

const char *table_error[TABLE_ERROR_NUM] = {
        [TABLE_SUCCESS]         = "OK",
        [TABLE_KERNEL_ERROR]    = "Could not receive data from kernel.",
        [TABLE_EXIST]           = "Table with the same name exists.",
        [TABLE_NAME_INVALID]    = "Invalid table name, only letter, number, underscore allowed.",
	[TABLE_NOT_EXIST]	= "Table doesn't exist.",
	[TABLE_NAME_EMPTY]	= "Table name cannot be empty.",
};


const char *chain_error[CHAIN_ERROR_NUM] = {
	[CHAIN_SUCCESS]		= "OK",
	[CHAIN_KERNEL_ERROR]	= "Could not receive data from kernel.",
	[CHAIN_NAME_EMPTY]	= "Chain name cannot be empty.",
	[CHAIN_NAME_INVALID]	= "Invalid chain name, only letter, number, underscore allowed.",
	[CHAIN_PRIORITY_INVALID]= "Invalid priority, only +, -, 0-9 allowed",
	[CHAIN_TABLE_NOT_EXIST] = "Table doesn't exist.",
        [CHAIN_EXIST]           = "Chain with the same name exists.",
	[CHAIN_NOT_EXIST]	= "Chain doesn;t exist.",
	[CHAIN_PRIORITY_OVERFLOW]="Priority is out of range, it must be between -2147483648 and 2147483647.",
};


const char *rule_error[RULE_ERROR_NUM] = {
	[RULE_SUCCESS]		= "OK",
	[RULE_KERNEL_ERROR]	= "Could not receive data from kernel.",
	[RULE_TABLE_NOT_EXIST]	= "Table doesn't exist.",
	[RULE_CHAIN_NOT_EXIST]	= "Chain doesn't exist.",
	[RULE_HEADER_IP_INVALID]= "Network address is invalid.",
	[RULE_HEADER_IP_RANGE_INVALID]	= "Network address range has zero or negative size",
	[RULE_HEADER_IP_EMPTY]	= "Network address is empty",
	[RULE_HEADER_MASK_EMPTY]	= "Network address mask is empty",
	[RULE_HEADER_MASK_INVALID]	= "Network address mask is invalid.",
	[RULE_HEADER_PORT_INVALID]	= "Port is invalid.",
	[RULE_HEADER_PORT_OVERFLOW]	= "Port is out of range, the upper value is 65535.",
	[RULE_HEADER_PORT_RANGE_INVALID]= "Port range has zero or negative size",
};


const char *set_error[SET_ERROR_NUM]  = {
	[SET_SUCCESS]		= "OK",
	[SET_KERNEL_ERROR]	= "Could not receive data from kernel.",
};


const char *element_error[ELEMENT_ERROR_NUM]  = {
	[ELEMENT_SUCCESS]	= "OK",
	[ELEMENT_KERNEL_ERROR]	= "Could not receive data from kernel.",
};
