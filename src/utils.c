/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <nftables.h>
#include <utils.h>

void __noreturn memory_allocation_error(void)
{
	fprintf(stderr, "Memory allocation failure\n");
	exit(NFT_EXIT_NOMEM);
}

void xfree(const void *ptr)
{
	free((void *)ptr);
}

void *xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL)
		memory_allocation_error();
	memset(ptr, 0, size);
	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr == NULL && size != 0)
		memory_allocation_error();
	return ptr;
}

void *xzalloc(size_t size)
{
	void *ptr;

	ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}

char *xstrdup(const char *s)
{
	char *res;

	assert(s != NULL);
	res = strdup(s);
	if (res == NULL)
		memory_allocation_error();
	return res;
}

char *xstrndup(const char *s, size_t n)
{
	char *res;

	assert(s != NULL);
	res = strndup(s, n);
	if (res == NULL)
		memory_allocation_error();
	return res;
}

uint32_t str2hooknum(uint32_t family, const char *hook)
{
	switch (family) {
	case NFPROTO_IPV4:
	case NFPROTO_BRIDGE:
	case NFPROTO_IPV6:
	case NFPROTO_INET:
		/* These families have overlapping values for each hook */
		if (!strcmp(hook, "prerouting"))
			return NF_INET_PRE_ROUTING;
		else if (!strcmp(hook, "input"))
			return NF_INET_LOCAL_IN;
		else if (!strcmp(hook, "forward"))
			return NF_INET_FORWARD;
		else if (!strcmp(hook, "postrouting"))
			return NF_INET_POST_ROUTING;
		else if (!strcmp(hook, "output"))
			return NF_INET_LOCAL_OUT;
	case NFPROTO_ARP:
		if (!strcmp(hook, "input"))
			return NF_ARP_IN;
		else if (!strcmp(hook, "forward"))
			return NF_ARP_FORWARD;
		else if (!strcmp(hook, "output"))
			return NF_ARP_OUT;
		default:
			break;
	}

	return NF_INET_NUMHOOKS;
}

int str2unshort(char *str, unsigned short *num)
{
	unsigned int    res = 0;
	int     len;
	int     i;

	if (!str) {
		*num = 0;
		return 0;
	}

	len = strlen(str);
	for (i = 0; i < len; i ++) {
		res = res * 10 + str[i] - '0';
		if (res > USHRT_MAX)
			return -1;
	}
	*num = res;
	return 0;
}


int strtoint(char *str, int *num)
{
	long long int    res = 0;
	int     len;
	int     i;

	if (!str) {
		*num = 0;
		return 0;
	}

	len = strlen(str);
	for (i = 0; i < len; i ++) {
		res = res * 10 + str[i] - '0';
		if (res > INT_MAX || res < INT_MIN)
			return -1;
	}
	*num = res;
	return 0;
}

int strtouint(char *str, unsigned int *num)
{
	unsigned long long int    res = 0;
	int     len;
	int     i;

	if (!str) {
		*num = 0;
		return 0;
	}

	len = strlen(str);
	for (i = 0; i < len; i ++) {
		if(!(isdigit(str[i])))
			return -1;
		res = res * 10 + str[i] - '0';
		if (res > UINT_MAX)
			return -1;
	}
	*num = res;
	return 0;
}
