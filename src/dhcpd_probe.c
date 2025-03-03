#include "dhcp_msg.h"
#include "dhcp_routines.h"
#include "if_query.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

#define PRINTF_TO_STDERR(str) ({fprintf(stderr, "%s\n", (str));})

int dhcpd_probe(const char *interface)
{
        uint8_t mac_address[ETHER_ADDR_LEN] = {0};
        if (start_ifquery(interface) < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_ESYSCALL));
                return -1;
        }
        if_hw_addr(mac_address, ETHER_ADDR_LEN);

        int ret = 0;

        /* AF_INET UDP for send message */
        int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socketfd < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_ESOCKFD));
                return -1;
        }

        /**
         * AF_PACKET with SOCK_DGRAM,IP packets subcommited by link-level removed
         * ethernet frame header.
         */
        int sockllfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
        if (sockllfd < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_ESOCKFD));
                ret = -1;
                goto quit_nomalloc;
        }

        /* enable broadcast */
        ret = 1;
        if (setsockopt(socketfd, SOL_SOCKET, SO_BROADCAST, &ret, sizeof(ret)) < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_EBROADCAST));
                ret = -1;
                goto quit_nomalloc;
        }

        /* have to bind to netdevice for send packet when no IP address has been assigned */
        if (setsockopt(socketfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_EBIND));
                ret = -1;
                goto quit_nomalloc;
        }

        /**
         * link-level socket address used for bind to network card interface.
         */
        struct sockaddr_ll ll_addr = {0};
        ll_addr.sll_family = AF_PACKET;
        ll_addr.sll_protocol = htons(ETH_P_IP);
        ll_addr.sll_ifindex = if_idx();

        /* bind to network card for receive IP packet */
        if (bind(sockllfd, (struct sockaddr *)&ll_addr, sizeof(struct sockaddr_ll)) < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_EBIND));
                ret = -1;
                goto quit_nomalloc;
        }

        struct dhcp_msg *msg = NULL;
        ALLOC_DHCP_MSG_BUFFER(msg, DHCP_MSG_SIZE_REPLY_MINIMUM);
        if (!msg) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_EMEMORY));
                ret = -1;
                goto quit_nomalloc;
        }

        ret = makeup_dhcpmsg_discover(msg, ETHERNET_TYPE,
                                      mac_address, ETHER_ADDR_LEN);
        if (ret < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(dhcpfunc_error(ret)));
                goto quit_malloc;
        }

        /* broadcast address */
        struct sockaddr_in broadcast_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(DHCPS_RECV_PORT),
                .sin_addr.s_addr = INADDR_BROADCAST
        };
        ret = send_dhcp_message_on(socketfd, msg, DHCP_MSG_SIZE_DISCOVER,
                                   (struct sockaddr *)&broadcast_addr, sizeof(struct sockaddr_in));
        if (ret < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(dhcpfunc_error(ret)));
                ret = -1;
                goto quit_malloc;
        }

        ret = recv_dhcp_reply_on(sockllfd, msg, DHCP_MSG_SIZE_REPLY_MINIMUM, if_mtu());
        if (ret < 0)
                PRINTF_TO_STDERR(dhcpd_probe_error(dhcpfunc_error(ret)));
        
quit_malloc:
        RELEASE_DHCP_MSG_BUFFER(msg);

quit_nomalloc:
        shutdown(sockllfd, SHUT_RDWR);
        shutdown(socketfd, SHUT_RDWR);
        return ret;
}
