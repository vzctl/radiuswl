// Author: lex@realisticgroup.com (Alexey Lapitsky)

#ifndef _LINUX_NETFILTER_XT_RADIUSWL_H
#define _LINUX_NETFILTER_XT_RADIUSWL_H 1

#define RADIUSWL_ANY        1
#define RADIUSWL_RESERVED   2
#define RADIUSWL_STATION_ID 3
#define RADIUSWL_IMSI       4

struct xt_radiuswl_mtinfo {
    uint64_t n, max_n;
    uint8_t type;
};

#endif /* _LINUX_NETFILTER_XT_RADIUSWL_H */

