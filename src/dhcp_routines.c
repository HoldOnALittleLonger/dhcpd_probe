#include "dhcp_routines.h"
#include "dhcp_msg.h"
#include "ip_packet.h"
#include "udp_segment.h"


#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define DHCP_MSG_OPTS_START(pmsg)  ((pmsg)->options + MAGIC_COOKIE_LEN)

void makeup_dhcpmsg_discover(struct dhcp_msg *msg, uint8_t hw_type, 
                            uint8_t *hw_addr, uint8_t hw_addr_len)
{
        msg->op = BOOTREQUEST;
        msg->htype = hw_type;
        msg->hlen = hw_addr_len;
        msg->hops = 0;
        msg->xid = 0;
        msg->secs = 0;
        msg->flags = BROADCAST;

        msg->ciaddr = 0;
        msg->yiaddr = 0;
        msg->siaddr = 0;
        msg->giaddr = 0;

        memset(msg->chaddr, (uint8_t)0, MAX_CHADDR_LEN);
        memcpy(msg->chaddr, hw_addr, hw_addr_len);

        memset(msg->sname, (uint8_t)0, MAX_SNAME_LEN);
        memset(msg->file, (uint8_t)0, MAX_FILE_LEN);

        /* options */

        /* fill magic cookie */
        msg->options[0] = MAGIC_COOKIE_0;
        msg->options[1] = MAGIC_COOKIE_1;
        msg->options[2] = MAGIC_COOKIE_2;
        msg->options[3] = MAGIC_COOKIE_3;

        /* fill dhcp discover options */
        DHCP_MSG_OPTS_START(msg)[0] = DHCP_MSG_DISCOVER_CODE;
        DHCP_MSG_OPTS_START(msg)[1] = DHCP_MSG_DISCOVER_LEN;
        DHCP_MSG_OPTS_START(msg)[2] = DHCP_MSG_DISCOVER_TYPE;
        DHCP_MSG_OPTS_START(msg)[3] = DHCP_MSG_ENDOPT;

}

const char *dhcpd_probe_error(enum DHCPFUNC_ERROR ec)
{
        static const char *error_messages[DHCPFUNC_ERROR_MAX] = {
                [DHCPFUNC_EEXPIRED] = "error : no more msg is available.",
                [DHCPFUNC_ESOCKFD] = "error : open socket failed.",
                [DHCPFUNC_EBIND] = "error : socket binding failed.",
                [DHCPFUNC_EBROADCAST] = "error : broadcast disallowed.",
                [DHCPFUNC_EMEMORY] = "error : no memory is available.",
                [DHCPFUNC_ESYSCALL] = "error : syscall have fault.",
                [DHCPFUNC_EEPOLL] = "error : I/O multiplex have failed.",
                [DHCPFUNC_ERECV] = "error : incomplete dhcp message."
        };

        static const char *undefined_error = "error : undefined error.";

        if (ec < DHCPFUNC_ERROR_MAX)
                return error_messages[ec];
        return undefined_error;
}

void dhcpd_probe_reporter(const struct dhcp_msg *msg, size_t size)
{
        /**
         * maybe data length of @msg > DHCP_MSG_SIZE_PAYLOAD.
         * in this case,dhcp message options have appended,
         * but we dont care about.
         */

        const struct in_addr *addr = (struct in_addr *)&msg->yiaddr;
        char ip_address[IPv4_STRADDR_LEN] = {0};

        if (msg->op != BOOTREPLY) {
                fprintf(stdout, "DHCP message is not reply.\n");
        } else if (inet_ntop(AF_INET, addr, ip_address, 16)) {
                fprintf(stdout, "Assigned IP address : %s\n", ip_address);
                putchar('\n');
        }
}

int recv_dhcp_reply_on(int sockfd, struct dhcp_msg *buffer, size_t buffer_len, int mtu)
{
        /* socket I/O multiplex */
        int epfd = epoll_create(1);
        if (epfd < 0)
                return -DHCPFUNC_EEPOLL;

        int ret = 0;
        struct epoll_event epevent = {
                .events = EPOLLIN
        };
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &epevent) < 0) {
                ret = -DHCPFUNC_EEPOLL;
                goto quit;
        }

        ip_packet *packet = malloc(sizeof(uint8_t) * mtu);
        if (!packet) {
                ret = -DHCPFUNC_EMEMORY;
                goto quit;
        }
        memset(packet, 0, mtu);

        /* prepare msghdr to receive packet */
        struct iovec ivec = {
                .iov_base = packet,
                .iov_len = mtu
        };

        /* receive data from link-level */
        struct msghdr inet_packet = {
                .msg_name = NULL,
                .msg_namelen = 0,
                .msg_iov = &ivec,
                .msg_iovlen = 1,
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0
        };

        for (;;) {
                char ipv4_addr_str[IPv4_STRADDR_LEN] = {0};
                ret = 1;
                ret = epoll_wait(epfd, &epevent, 1, MAX_TIMEOUT * 1000);
                switch (ret) {
                case 0:
                        ret = -DHCPFUNC_EEXPIRED;
                        goto quit_malloc;
                case 1:
                        break;
                default:
                        ret = -DHCPFUNC_EEPOLL;
                        goto quit_malloc;
                }

                /* read */
                ret = recvmsg(sockfd, &inet_packet, 0);
                if (ret < 0) {
                        ret = -DHCPFUNC_ESYSCALL;
                        goto quit_malloc;
                } else if (ret == 0) {
                        ret = -DHCPFUNC_ERECV;
                        goto quit_malloc;
                }

                ip_packet *ipacket = inet_packet.msg_iov->iov_base;

                const struct udp_segment *udpseg = ip_payload(ipacket);

                /* filtering */
                if (ipacket->des == INADDR_BROADCAST ||
                    ipacket->protocol != UDP_OVER_IP || 
                    ntohs(udpseg->udphdr.dport) != DHCPC_RECV_PORT)
                        continue;

                const struct in_addr inaddr = {((struct ip_header *)ipacket)->src};
                fprintf(stdout, "Received IP Packet from %s\n",
                        inet_ntop(AF_INET, &inaddr, ipv4_addr_str, IPv4_STRADDR_LEN));

                size_t data_size = buffer_len < udp_data_length(udpseg) ?
                        buffer_len : udp_data_length(udpseg);
                memcpy(buffer, udpseg->data, data_size);
                dhcpd_probe_reporter(buffer, data_size);
        }

quit_malloc:
        free(packet);

quit:
        close(epfd);
        return ret;
}

int send_dhcp_message_on(int sockfd, const struct dhcp_msg *msg, size_t msg_len,
                         struct sockaddr *addr, socklen_t addr_len)
{
        struct iovec ivec = {
                .iov_base = msg,
                .iov_len = msg_len,
        };
        struct msghdr hdr = {
                .msg_name = addr,
                .msg_namelen = addr_len,
                .msg_iov = &ivec,
                .msg_iovlen = 1,
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0
        };

        if (sendmsg(sockfd, &hdr, 0) < 0)
                return -DHCPFUNC_ESYSCALL;

        return 0;
}
