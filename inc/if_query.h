#ifndef _IF_QUERY_H_
#define _IF_QUERY_H_

#include <stdint.h>
#include <stddef.h>

#include <net/ethernet.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

enum IFQUERY_ERROR {
        IFQUERY_EQUERY = 1,
        IFQUERY_EBUFFER = 2,
        IFQUERY_ESIZE = 3
};

/* 10Mb ethernet type number in RFC Assigned Numbers */
static const uint8_t ETHERNET_TYPE = 1;

/**
 * ifquery_info - structure used to store netdevice interface
 *                informations
 * @if_addr:      public address
 * @if_hwaddr:    hardware address
 * @if_index:     interface index
 * @if_mtu:       maximum transport unit
 */
struct ifquery_info {
        uint32_t if_addr;
        struct sockaddr if_hwaddr;
        int if_index;
        int if_mtu;
};

extern struct ifquery_info ifinfo;

/**
 * start_ifquery - start interface information
 *                 query
 * @interface:     interface name
 * return:         0 => succeed
 *                 -error code
 */
int start_ifquery(const char *interface);

static inline 
int restart_ifquery(const char *interface)
{
        return start_ifquery(interface);
}



static inline uint32_t if_pa_addr(void)
{
        return ifinfo.if_addr;
}

static inline int if_hw_addr(uint8_t *buffer, size_t buffer_len)
{
        if (!buffer)
                return -IFQUERY_EBUFFER;
        if (buffer_len != ETHER_ADDR_LEN)
                return -IFQUERY_ESIZE;

        memcpy(buffer, ifinfo.if_hwaddr.sa_data, buffer_len);

        return 0;
}

static inline int if_mtu(void)
{
        return ifinfo.if_mtu;
}

static inline int if_idx(void)
{
        return ifinfo.if_index;
}

#endif
