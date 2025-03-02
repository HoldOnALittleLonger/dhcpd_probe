#ifndef _DHCPD_PROBE_H_
#define _DHCPD_PROBE_H_

/**
 * dhcpd_probe - probe dhcpd on local network
 * @interface:   interface of netdevice to bind
 * return:       0 => no error encountered
 *               -1 => failed
 */
int dhcpd_probe(const char *interface);

#endif
