#include <gui_error.h>

const char *table_error[TABLE_ERROR_NUM] = {
        [TABLE_SUCCESS]         = "OK",
        [TABLE_KERNEL_ERROR]    = "Could not receive tables from kernel.",
        [TABLE_EXIST]           = "Table with the same name exists.",
        [TABLE_NAME_INVALID]    = "Invalid table name, only letter, number, underscore allowed.",
	[TABLE_NOT_EXIST]	= "Table doesn't exist.",
	[TABLE_NAME_EMPTY]	= "Table name cannot be empty.",
};


const char *chain_error[CHAIN_ERROR_NUM] = {
	[CHAIN_SUCCESS]		= "OK",
	[CHAIN_KERNEL_ERROR]	= "Could not receive chains from kernel.",
	[CHAIN_NAME_EMPTY]	= "Chain name cannot be empty.",
	[CHAIN_NAME_INVALID]	= "Invalid chain name, only letter, number, underscore allowed.",
	[CHAIN_PRIORITY_INVALID]= "Invalid priority, only +, -, 0-9 allowed",
	[CHAIN_TABLE_NOT_EXIST] = "Table doesn't exist.",
	[CHAIN_TABLE_KERNEL_ERROR] = "Could not receive tables from kernel.",
        [CHAIN_EXIST]           = "Chain with the same name exists.",
};
