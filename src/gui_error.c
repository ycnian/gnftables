#include <gui_error.h>

const char *table_error[TABLE_ERROR_NUM] = {
        [TABLE_SUCCESS]         = "OK.",
        [TABLE_KERNEL_ERROR]    = "Failed due to the kernel.",
        [TABLE_EXIST]           = "Table with the same name exists.",
	[TABLE_NOT_EXIST]	= "Table doesn't exist.",
        [TABLE_NAME_INVALID]    = "Invalid table name",
};

