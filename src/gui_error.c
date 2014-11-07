/*
 * Copyright (c) 2014  Yanchuan Nian <ycnian@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. You may also obtain a copy of the GNU General Public License
 * from the Free Software Foundation by visiting their web site 
 * (http://www.fsf.org/) or by writing to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <gui_error.h>

const char *table_error[TABLE_ERROR_NUM] = {
        [TABLE_SUCCESS]         = "OK",
        [TABLE_KERNEL_ERROR]    = "Could not receive data from kernel.",
        [TABLE_EXIST]           = "Table with the same name exists.",
        [TABLE_NAME_INVALID]    = "Name is invalid, only letter, number, underscore allowed.",
	[TABLE_NOT_EXIST]	= "Table doesn't exist.",
	[TABLE_NAME_EMPTY]	= "Name is empty.",
};


const char *chain_error[CHAIN_ERROR_NUM] = {
	[CHAIN_SUCCESS]		= "OK",
	[CHAIN_KERNEL_ERROR]	= "Could not receive data from kernel.",
	[CHAIN_NAME_EMPTY]	= "Name is empty.",
	[CHAIN_NAME_INVALID]	= "Name is invalid, only letter, number, underscore allowed.",
	[CHAIN_PRIORITY_INVALID]= "Invalid priority, only -, 0-9 allowed",
	[CHAIN_TABLE_NOT_EXIST] = "Table doesn't exist.",
        [CHAIN_EXIST]           = "Chain with the same name exists.",
	[CHAIN_NOT_EXIST]	= "Chain doesn't exist.",
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
	[RULE_PKTMETA_IFTYPE_INVALID]	= "Interface type invalid.",
	[RULE_PKTMETA_IIFTYPE_INVALID]	= "Input interface type invalid.",
	[RULE_PKTMETA_OIFTYPE_INVALID]	= "Output interface type invalid.",
	[RULE_PKTMETA_SKID_INVALID]	= "Id invalid.",
	[RULE_PKTMETA_SKUID_INVALID]	= "User is invalid.",
	[RULE_PKTMETA_SKGID_INVALID]	= "Group is invalid.",
	[RULE_HEADER_SET_EMPTY]		= "Set is empty",
	[RULE_HEADER_SET_NOT_EXIST]	= "Set doesn't exist",
	[RULE_INDEX_INVALID]		= "Index error.",
	[RULE_NOT_EXIST]		= "Rule doesn't exist.",
	[RULE_TYPE_NOT_SUPPORT]		= "I'm sorry, but I cannot parse this rule.",
	[RULE_COUNTER_INVALID]		= "Counter is invalid.",
	[RULE_USER_CHAIN_NOT_EXIST]	= "Target chain doesn't exist",
};


const char *set_error[SET_ERROR_NUM]  = {
	[SET_SUCCESS]		= "OK",
	[SET_KERNEL_ERROR]	= "Could not receive data from kernel.",
	[SET_TABLE_NOT_EXIST]	= "Table doesn't exist.",
	[SET_NOT_EXIST]		= "Set doesn't exist.",
        [SET_EXIST]		= "Set with the same name exists.",
	[SET_ELEMENT_INVALID]	= "Element invalid",
	[SET_NAME_EMPTY]	= "Name is empty.",
	[SET_NAME_INVALID]	= "Name is invalid, only letter, number, underscore allowed.",
	[SET_TYPE_NOT_SUPPORT]	= "I'm sorry, but I cannot parse this set."
};


const char *element_error[ELEMENT_ERROR_NUM]  = {
	[ELEMENT_SUCCESS]	= "OK",
	[ELEMENT_KERNEL_ERROR]	= "Could not receive data from kernel.",
};
