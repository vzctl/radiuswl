#ifndef _RADIUS_H
#define _RADIUS_H

struct radius_hdr {
  unsigned char code;		/* type of RADIUS packet */
  unsigned char ident;		/* "session" identifier */
  uint16_t len;		/* length in octets of entire packet
				   including RADIUS header */
  unsigned char auth[16];	/* authenticator field */
};

struct radius_attr {
  unsigned char type;		/* attribute type */
  unsigned char len;		/* attribute length in octets,
				   including type and length fields */
  unsigned char value[2];	/* note that value can be arbitrary
				   length, but we make it two bytes
				   for alignment purposes */
};

#define RADIUS_ACCESS_REQUEST       1
#define RADIUS_ACCESS_ACCEPT        2
#define RADIUS_ACCESS_REJECT        3
#define RADIUS_ACCT_REQUEST         4
#define RADIUS_ACCT_RESPONSE        5
#define RADIUS_ACCESS_CHALLENGE    11
#define RADIUS_STATUS_SERVER       12
#define RADIUS_STATUS_CLIENT       13

extern bool rad_imsi_match(const struct radius_attr *ra, const struct xt_radiuswl_mtinfo *info);
extern bool rad_stationid_match(const struct radius_attr *ra, const struct xt_radiuswl_mtinfo *info);

#endif
