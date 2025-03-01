#ifndef _DHCP_MSG_H_
#define _DHCP_MSG_H_

#include <stdint.h>
#include <stdlib.h>

/**
 * dhcp_msg_param - enumerated numbers for dhcp message parameters
 */
enum dhcp_msg_param {
        BOOTREQUEST = 1,
        BOOTREPLY = 2,
        UNICAST = 0,
        BROADCAST = 1,
        MAGIC_COOKIE_0 = 99,
        MAGIC_COOKIE_1 = 130,
        MAGIC_COOKIE_2 = 83,
        MAGIC_COOKIE_3 = 99,
        MAGIC_COOKIE_LEN = 4,

        MAX_CHADDR_LEN = 16,
        MAX_SNAME_LEN = 64,
        MAX_FILE_LEN = 128,

        DHCP_MSG_PADDING = 0,
        DHCP_MSG_ENDOPT = 255,

        DHCP_MSG_DISCOVER_CODE = 53,
        DHCP_MSG_DISCOVER_LEN = 1,
        DHCP_MSG_DISCOVER_TYPE = 1
};

/**
 * dhcp_udp_ports - enumerated numbers for dhcpd and dhclinet ports
 */
enum dhcp_udp_ports {
        DHCPS_RECV_PORT = 67,
        DHCPC_RECV_PORT = 68
};

/**
 * dhcp_msg_size - enumerated numbers for sizes of dhcp message parts
 */
enum dhcp_msg_size {
        DHCP_MSG_SIZE_PAYLOAD = 236,
        DHCP_MSG_SIZE_OPTIONS = 312,
        DHCP_MSG_SIZE_REPLY_MINIMUM = 576,
        DHCP_MSG_SIZE_DISCOVER = 244
};

/**
 * dhcp_msg - structure dhcp_msg_payload represent DHCP message
 * @op:       operation
 * @htype:    hardware address type
 * @hlen:     hardware address length
 * @hops:     hardware option
 * @xid:      transcation id
 * @secs:     seconds elapsed since client began addr acquisition or renew
 * @flags:    broadcast flag
 * @ciaddr:   client ip address
 * @yiaddr:   your ip address
 * @siaddr:   next dhcp server address
 * @giaddr:   agent address
 * @chaddr:   client hardware address
 * @sname:    host name of dhcp server
 * @file:     PXE file
 * @options:  variable buffer for message options
 */
struct dhcp_msg {
        uint8_t op;
        uint8_t htype;
        uint8_t hlen;
        uint8_t hops;
        uint32_t xid;
        uint16_t secs;
        uint16_t flags;
        uint32_t ciaddr;
        uint32_t yiaddr;
        uint32_t siaddr;
        uint32_t giaddr;
        uint8_t chaddr[MAX_CHADDR_LEN];
        uint8_t sname[MAX_SNAME_LEN];
        uint8_t file[MAX_FILE_LEN];
        uint8_t options[];
};

#define ALLOC_DHCP_MSG_BUFFER(pmsg, n)                                  \
        do {                                                            \
                pmsg = (struct dhcp_msg *)malloc((n) * sizeof(uint8_t)); \
        } while (0)

#define RELEASE_DHCP_MSG_BUFFER(pmsg)           \
        do {                                    \
                free(pmsg);                     \
        } while (0)


#endif
