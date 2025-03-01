#ifndef _DHCPD_PROBE_H_
#define _DHCPD_PROBE_H_

/**
 * dhcpd_probe - probe dhcpd on local network
 * @interface:   interface of netdevice to bind
 */
int dhcpd_probe(const char *interface);

#endif
