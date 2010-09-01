// Author: lex@realisticgroup.com (Alexey Lapitsky)

#include "whitelist.h"

// list of whitelisted station ids range
struct wl_range wl_stationid[] = {
//	{111111111111, 122222222229},
};


size_t wl_stationid_size()
{
	return sizeof(wl_stationid) / sizeof(wl_stationid[0]);
}
