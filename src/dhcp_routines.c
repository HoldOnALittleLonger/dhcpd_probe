#include "dhcp_routines.h"
#include "dhcp_msg.h"

#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <stdio.h>

#define DHCP_MSG_OPTS_START(pmsg)  ((pmsg)->options + MAGIC_COOKIE_LEN)

int makeup_dhcpmsg_discover(struct dhcp_msg *msg, uint8_t hw_type, 
                            uint8_t *hw_addr, uint8_t hw_addr_len)
{
        if (!msg || !hw_addr) {
                return -DHCPFUNC_EBUFFER;
        }

        if (hw_addr_len > MAX_CHADDR_LEN)
                return -DHCPFUNC_ESIZE;

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
        for (unsigned int idx = 0; idx < hw_addr_len; ++idx) {
                msg->chaddr[idx] = hw_addr[idx];
        }

        memset(msg->sname, (uint8_t)0, MAX_SNAME_LEN);
        memset(msg->file, (uint8_t)0, MAX_FILE_LEN);

        /* options */

        /* fill magic cookie */
        msg->options[0] = MAGIC_COOKIE_0;
        msg->options[1] = MAGIC_COOKIE_1;
        msg->options[2] = MAGIC_COOKIE_2;
        msg->options[3] = MAGIC_COOKIE_3;

        DHCP_MSG_OPTS_START(msg)[0] = DHCP_MSG_DISCOVER_CODE;
        DHCP_MSG_OPTS_START(msg)[1] = DHCP_MSG_DISCOVER_LEN;
        DHCP_MSG_OPTS_START(msg)[2] = DHCP_MSG_DISCOVER_TYPE;
        DHCP_MSG_OPTS_START(msg)[3] = DHCP_MSG_ENDOPT;

        return 0;
}

const char *dhcpd_probe_error(enum DHCPFUNC_ERROR ec)
{
        static char strerr_buf[STRERR_BUF_SIZE] = "NIL";

        switch (ec) {
        case DHCPFUNC_EEXPIRED:
                strncpy(strerr_buf, "error : no more msg is available.",
                        STRERR_BUF_SIZE);
                break;
        case DHCPFUNC_ESOCKFD:
                strncpy(strerr_buf, "error : socket operations failed.",
                        STRERR_BUF_SIZE);
                break;
        case DHCPFUNC_EBUFFER:
                strncpy(strerr_buf, "error : buffer invalid.",
                        STRERR_BUF_SIZE);
                break;
        case DHCPFUNC_EMEMORY:
                strncpy(strerr_buf, "error : no memory is available.",
                        STRERR_BUF_SIZE);
                break;
        case DHCPFUNC_ESYSCALL:
                strncpy(strerr_buf, "error : syscall have fault.",
                        STRERR_BUF_SIZE);
                break;
        case DHCPFUNC_ESIZE:
                strncpy(strerr_buf, "error : incorrect size parameter.",
                        STRERR_BUF_SIZE);
                break;
        case DHCPFUNC_EEPOLL:
                strncpy(strerr_buf, "error : I/O multiplex have failed.",
                        STRERR_BUF_SIZE);
                break;
        case DHCPFUNC_ERECV:
                strncpy(strerr_buf, "error : incomplete dhcp message.",
                        STRERR_BUF_SIZE);
        case DHCPFUNC_EINFO:
                strncpy(strerr_buf, "error : unknown information inside dhcp message.",
                        STRERR_BUF_SIZE);
                break;
        default:
                strncpy(strerr_buf, "error : undefined error.",
                        STRERR_BUF_SIZE);
        }

        return strerr_buf;
}

int dhcpd_probe_reporter(const struct dhcp_msg *msg, size_t size)
{
        if (!msg)
                return -DHCPFUNC_EBUFFER;

        /**
         * maybe data length of @msg > DHCP_MSG_SIZE_PAYLOAD,
         * in this case,dhcp message options have appended,
         * but we dont care about.
         */

        const struct in_addr *addr = (struct in_addr *)msg->siaddr;
        char ip_address[IPv4_STRADDR_LEN] = {0};

        if (inet_ntop(AF_INET, addr, ip_address, 16)) {
                fprintf(stdout, "dhcpd: %s\n", ip_address);
        }

        return 0;
}

int recv_dhcp_reply_on(int sockfd, struct dhcp_msg *buffer, size_t buffer_len)
{
        if (sockfd < 0)
                return -DHCPFUNC_ESOCKFD;
        if (!buffer)
                return -DHCPFUNC_EBUFFER;
        if (buffer_len < DHCP_MSG_SIZE_REPLY_MINIMUM)
                return -DHCPFUNC_ESIZE;

        /* prepare msghdr to receive dgram */
        struct iovec ivec = {
                .iov_base = buffer,
                .iov_len = buffer_len
        };

        /* IPv4 only */
        struct sockaddr_in addr = {0};
        socklen_t addr_len = sizeof(struct sockaddr_in);
        struct msghdr hdr = {
                .msg_name = &addr,
                .msg_namelen = addr_len,
                .msg_iov = &ivec,
                .msg_iovlen = 1,
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0
        };

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

        for (;;) {
                char ipv4_addr_str[IPv4_STRADDR_LEN] = {0};
                ret = epoll_wait(epfd, &epevent, 1, MAX_TIMEOUT * 1000);
                switch (ret) {
                case 0:
                        ret = -DHCPFUNC_EEXPIRED;
                        goto quit;
                case 1:
                        break;
                default:
                        ret = -DHCPFUNC_EEPOLL;
                        goto quit;
                }

                ret = recvmsg(sockfd, &hdr, 0);
                if (ret < 0) {
                        ret = -DHCPFUNC_ESYSCALL;
                        goto quit;
                } else if (ret < DHCP_MSG_SIZE_PAYLOAD) {
                        ret = -DHCPFUNC_ERECV;
                        goto quit;
                }
                fprintf(stdout, "Received UDP Datagram from %s\n",
                        inet_ntop(AF_INET, hdr.msg_name, ipv4_addr_str, IPv4_STRADDR_LEN));
                ret = dhcpd_probe_reporter(buffer, ret);
                if (ret < 0)
                        break;
        }
quit:
        close(epfd);
        return ret;
}

int send_dhcp_message_on(int sockfd, const struct dhcp_msg *msg, size_t msg_len,
                         struct sockaddr *addr, socklen_t addr_len)
{
        if (sockfd < 0)
                return -DHCPFUNC_ESOCKFD;
        if (!msg || !addr)
                return -DHCPFUNC_EBUFFER;
        if (msg_len < DHCP_MSG_SIZE_PAYLOAD)
                return -DHCPFUNC_ESIZE;

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
