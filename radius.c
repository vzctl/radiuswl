// Author: lex@realisticgroup.com (Alexey Lapitsky)

#include <linux/netfilter.h>

#include "ipt_radiuswl.h"
#include "radius.h"
#include "whitelist.h"

/* check if this is whitelisted 10415_1 vsa attribute */
bool rad_imsi_match(const struct radius_attr *ra, const struct xt_radiuswl_mtinfo *info)
{
	uint64_t imsi;
	uint32_t vendor;
	struct radius_attr *vsa;

	if (ra == NULL) return false;
	if (ra->type !=  26 ) return false; // vendor-specific
	vendor = *(uint32_t*)ra->value;
	vendor = ntohl(vendor);
	if (vendor != 10415) return false; // 3GPP
	vsa = (struct radius_attr *)&(ra->value[4]);
	if (vsa->type != 1) return false; // 3GPP-IMSI
	if (vsa->len > 20)  return false;  
	imsi = simple_strtoull(vsa->value, NULL, 10);
	//  printk(KERN_INFO "imsi: %llu", (unsigned long long)imsi);
	if (info->type == RADIUSWL_RESERVED)
		return false;
	if ((info->type == RADIUSWL_IMSI) && (info->n == imsi))
		return true;
	return false;
}

bool rad_stationid_match(const struct radius_attr *ra, const struct xt_radiuswl_mtinfo *info)
{
	uint8_t i;
	uint64_t stationid;
	if (ra == NULL) return false;
	if (ra->type !=  31 ) return false; // Caller-Station-Id
	if (ra->len > 15) return false;
	stationid = simple_strtoull(ra->value, NULL, 10);
	// printk(KERN_INFO "stationid: %llu", (unsigned long long)stationid);
	if (info->type == RADIUSWL_RESERVED)
		for(i = 0; i < wl_stationid_size(); i++)
			if ((stationid >= wl_stationid[i].min) && (stationid <= wl_stationid[i].max))
				return true;
	if ((info->type == RADIUSWL_STATION_ID) && (info->n == stationid))
		return true;
	return false;
}

