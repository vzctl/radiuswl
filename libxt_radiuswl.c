// Author: lex@realisticgroup.com (Alexey Lapitsky)

#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include "ipt_radiuswl.h"

static const struct option radiuswl_mt_opts[] = {
	{.name = "radiuswl-any", .has_arg = false, .val = '1'},
	{.name = "radiuswl-reserved", .has_arg = false, .val = '2'},
	{.name = "radiuswl-station-id", .has_arg = true, .val = '3'},
	{.name = "radiuswl-imsi", .has_arg = true, .val = '4'},
	{NULL},
};

static void radiuswl_mt_help(void)
{
	printf(
"radiuswl match options for RADIUS Access requests:\n"
" --radiuswl-any                 Match any request\n"
" --radiuswl-reserved            Match hardcoded list of station ids\n"
" --radiuswl-station-id num      Match particular Calling-Station-ID\n"
" --radiuswl-imsi       num      Match particular 3GPP-IMSI\n"
);
}

static void radiuswl_mt_init(struct xt_entry_match *match)
{
	struct xt_radiuswl_mtinfo *info = (void *)match->data;
}

static int radiuswl_mt_parse(int c, char **argv, int invert,
    unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
	struct xt_radiuswl_mtinfo *info = (void *)(*match)->data;
	struct in_addr *addrs, mask;
	unsigned int naddrs;

	if (info->type != 0)
		xtables_error(PARAMETER_PROBLEM, "xt_radiuswl: "
				"You can use only one param per rule");

	switch (c) {
	case '1': 
	        *flags = info->type = RADIUSWL_ANY;
		return true;

	case '2':
		*flags = info->type = RADIUSWL_RESERVED;
		return true;

	case '3': /* --station-id num */
		if (strlen(optarg) > 12)
			xtables_error(PARAMETER_PROBLEM, "xt_radiuswl: "
				"Max parameter length is 12");
		info->n = atoll(optarg);
		*flags = info->type = RADIUSWL_STATION_ID;
		return true;

	case '4': /* --imsi num */
		if (strlen(optarg) > 15)
			xtables_error(PARAMETER_PROBLEM, "xt_radiuswl: "
				"Max parameter length is 15");
		info->n = atoll(optarg);
		*flags = info->type = RADIUSWL_IMSI;
		return true;
	}

	return false;
}

static void radiuswl_mt_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM, "radiuswl: You need to "
			"specify at least one parameter!!");
}

static void radiuswl_mt_print(const void *entry,
    const struct xt_entry_match *match, int numeric)
{
	const struct xt_radiuswl_mtinfo *info = (const void *)match->data;
	switch (info->type) {
	case RADIUSWL_ANY:
		printf("radiuswl-any");
		return;
	case RADIUSWL_RESERVED:
		printf("radiuswl-reserved");
		return;
	case RADIUSWL_STATION_ID:
		printf("radiuswl-station-id: %llu", (unsigned long long)info->n);
		return;
	case RADIUSWL_IMSI:
		printf("radiuswl-imsi: %llu", (unsigned long long)info->n);
		return;
	}
	return;
}


static void radiuswl_mt_save(const void *entry,
    const struct xt_entry_match *match)
{
	const struct xt_radiuswl_mtinfo *info = (const void *)match->data;
	switch (info->type) {
	case RADIUSWL_ANY:
		printf("--radiuswl-any ");
		return;
	case RADIUSWL_RESERVED:
		printf("--radiuswl-reserved ");
		return;
	case RADIUSWL_STATION_ID:
		printf("--radiuswl-station-id %llu ", (unsigned long long)info->n);
		return;
	case RADIUSWL_IMSI:
		printf("--radiuswl-imsi %llu ", (unsigned long long)info->n);
		return;
	}

	return;

}

static struct xtables_match radiuswl_mt_reg = {
	.version       = XTABLES_VERSION,
	.name          = "radiuswl",
	.revision      = 0,
	.size          = XT_ALIGN(sizeof(struct xt_radiuswl_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_radiuswl_mtinfo)),
	.help          = radiuswl_mt_help,
	.init          = radiuswl_mt_init,
	.parse         = radiuswl_mt_parse,
	.final_check   = radiuswl_mt_check,
	.print         = radiuswl_mt_print,
	.save          = radiuswl_mt_save,
	.extra_opts    = radiuswl_mt_opts,
};

static void _init(void)
{
	xtables_register_match(&radiuswl_mt_reg);
}


