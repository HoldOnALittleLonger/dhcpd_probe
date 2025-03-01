#include "dhcp_msg.h"
#include "dhcp_routines.h"
#include "interface_address.h"

#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdio.h>

#include <errno.h>

#define PRINTF_TO_STDERR(str) ({fprintf(stderr, "%s\n", (str));})

int dhcpd_probe(const char *interface)
{
        uint8_t mac_address[HWADDR_802_3_LEN] = {0};
        if (get_hwaddr(interface, mac_address, HWADDR_802_3_LEN) < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_ESYSCALL));
                return -1;
        }

        int ret = 0;
        int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socketfd < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_ESOCKFD));
                return -1;
        }

        if (setsockopt(socketfd, SOL_SOCKET,
                       SO_BINDTODEVICE, interface, strlen(interface))
            < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_ESOCKFD));
                ret = -1;
                goto quit_nomalloc;
        }

        ret = 1;
        if (setsockopt(socketfd, SOL_SOCKET, SO_BROADCAST, &ret, sizeof(ret)) < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_ESOCKFD));
                ret = -1;
                goto quit_nomalloc;
        }

        struct sockaddr_in local_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(DHCPC_RECV_PORT),
                .sin_addr.s_addr = INADDR_ANY
        };

        errno = 0;
        if (bind(socketfd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr_in)) < 0) {
                PRINTF_TO_STDERR(strerror(errno));
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_ESOCKFD));
                ret = -1;
                goto quit_nomalloc;
        }

        struct dhcp_msg *msg = NULL;
        ALLOC_DHCP_MSG_BUFFER(msg, DHCP_MSG_SIZE_REPLY_MINIMUM);
        if (!msg) {
                PRINTF_TO_STDERR(dhcpd_probe_error(DHCPFUNC_EMEMORY));
                return -1;
        }

        ret = makeup_dhcpmsg_discover(msg, HWADDR_802_3_TYPE,
                                      mac_address, HWADDR_802_3_LEN);
        if (ret < 0) {
                PRINTF_TO_STDERR(dhcpd_probe_error(dhcpfunc_error(ret)));
                goto quit_malloc;
        }

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

        ret = recv_dhcp_reply_on(socketfd, msg, DHCP_MSG_SIZE_REPLY_MINIMUM);
        if (ret < 0)
                PRINTF_TO_STDERR(dhcpd_probe_error(dhcpfunc_error(ret)));
        
quit_malloc:
        RELEASE_DHCP_MSG_BUFFER(msg);

quit_nomalloc:
        shutdown(socketfd, SHUT_RDWR);
        return ret;
}
