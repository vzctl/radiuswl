// Author: lex@realisticgroup.com (Alexey Lapitsky)

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include "compat_xtables.h"

#include "ipt_radiuswl.h"
#include "whitelist.h"
#include "radius.h"

/* return true if packet is matched. pdata - start of radius header */
static bool match_radius_packet(const void *pdata, uint16_t packet_len, const struct xt_radiuswl_mtinfo *info)
{
	struct radius_hdr *rh = (struct radius_hdr*)pdata;
	struct radius_attr *ra;
	uint32_t offs = sizeof(*rh);
	bool whitelisted = false;

	if (rh->code != RADIUS_ACCESS_REQUEST)
		return false;

	if (info->type == RADIUSWL_ANY)
		return true;

	while((offs < packet_len) && (offs < (sizeof(*rh) + ntohs(rh->len))) && !whitelisted) {
		if (packet_len < offs + 2) break;
                ra = (struct radius_attr *)((uint8_t *)pdata + offs);
		if (ra->len < 2) break;
		offs += ra->len;
		whitelisted = (rad_stationid_match(ra, info) || rad_imsi_match(ra, info));
	}

	return whitelisted;
}


static bool radiuswl_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct iphdr *iph = ip_hdr(skb);
	//const struct ipv6hdr *iph = ipv6_hdr(skb);
	const struct udphdr *udph;
	uint16_t len;

	if (iph->protocol != IPPROTO_UDP) return false;

	udph = (const void *)iph + ip_hdrlen(skb);
	len  = ntohs(udph->len) - sizeof(struct udphdr);

	return match_radius_packet((void *)udph + sizeof(struct udphdr), len, par->matchinfo);
}

static int radiuswl_mt_check(const struct xt_mtchk_param *par)
{
	return 0;
}

static struct xt_match radiuswl_mt_reg[] __read_mostly = {
	{
		.name       = "radiuswl",
		.revision   = 0,
		.match      = radiuswl_mt,
		.checkentry = radiuswl_mt_check,
		.matchsize  = XT_ALIGN(sizeof(struct xt_radiuswl_mtinfo)),
		.me         = THIS_MODULE,
	},
};

static int __init radiuswl_mt_init(void)
{
	return xt_register_matches(radiuswl_mt_reg, ARRAY_SIZE(radiuswl_mt_reg));
}

static void __exit radiuswl_mt_exit(void)
{
	xt_unregister_matches(radiuswl_mt_reg, ARRAY_SIZE(radiuswl_mt_reg));
}

MODULE_AUTHOR("Alexey Lapitsky");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("RADIUS whitelist");

MODULE_ALIAS("xt_radiuswl");
MODULE_ALIAS("ipt_radiuswl");
MODULE_ALIAS("ip6t_radiuswl");
MODULE_ALIAS("arpt_radiuswl");
MODULE_ALIAS("ebt_radiuswl");

module_init(radiuswl_mt_init);
module_exit(radiuswl_mt_exit);

