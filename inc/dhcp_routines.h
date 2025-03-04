#ifndef _DHCP_ROUTINES_H_
#define _DHCP_ROUTINES_H_

#include <stdint.h>
#include <sys/socket.h>

enum DHCPFUNC_ERROR {
        DHCPFUNC_EEXPIRED = 0,
        DHCPFUNC_ESOCKFD = 1,
        DHCPFUNC_EMEMORY = 2,
        DHCPFUNC_ESYSCALL = 3,
        DHCPFUNC_EEPOLL = 4,
        DHCPFUNC_ERECV = 5,
        DHCPFUNC_EBIND = 6,
        DHCPFUNC_EBROADCAST = 7
};

static enum DHCPFUNC_ERROR dhcpfunc_error(int ec)
{
        return ec < 0 ? -ec: ec;
}

static const uint8_t MAX_TIMEOUT = 32;

struct dhcp_msg;

#define IPv4_STRADDR_LEN  16

/**
 * makeup_dhcpmsg_discover - construct a dhcp message is type of DISCOVER
 * @msg:                     where to store constructed message
 * @hw_type:                 the hardware address type
 * @hw_addr:                 the hardware address
 * @hw_addr_len:             how long the hardware address is
 */
void makeup_dhcpmsg_discover(struct dhcp_msg *msg, uint8_t hw_type, 
                            uint8_t *hw_addr, uint8_t hw_addr_len);

#define STRERR_BUF_SIZE  128
/**
 * dhcpd_probe_error - convert error code to null terminate string
 *                     each calling to this routine will cover the
 *                     old string
 * @ec:                error code
 * return:             pointer to error description string
 */
const char *dhcpd_probe_error(enum DHCPFUNC_ERROR ec);

/**
 * dhcpd_probe_reporter - describe the dhcp message
 * @msg:                  message
 * @size:                 how long message is
 */
void dhcpd_probe_reporter(const struct dhcp_msg *msg, size_t size);

/**
 * recv_dhcp_reply_on - receive dhcp reply dgram on a specified socket
 * @sockfd:             socket
 * @buffer:             where to store message
 * @buffer_len:         how long @buffer is
 * @mtu:                maximum transport unit
 * return:              DHCPFUNC_EEXPIRED => no more reply is available(it's OK)
 *                      -error code => fault
 */
int recv_dhcp_reply_on(int sockfd, struct dhcp_msg *buffer, size_t buffer_len, int mtu);

/**
 * send_dhcp_message_on - send dhcp msg on a specified socket
 * @sockfd:               socket
 * @msg:                  what message to send
 * @msg_len:              how long @msg is
 * @addr:                 where to send dgram
 * @addr_len:             address length
 * return:                0 => succeed
 *                        -error code => fault
 */
int send_dhcp_message_on(int sockfd,  const struct dhcp_msg *msg, size_t msg_len,
                         struct sockaddr *addr, socklen_t addr_len);

#endif
