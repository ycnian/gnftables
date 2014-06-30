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
};


const char *rule_error[RULE_ERROR_NUM] = {
	[RULE_SUCCESS]		= "OK",
	[RULE_KERNEL_ERROR]	= "Could not receive data from kernel.",
	[RULE_TABLE_NOT_EXIST]	= "Table doesn't exist.",
	[RULE_CHAIN_NOT_EXIST]	= "Chain doesn't exist.",
};
