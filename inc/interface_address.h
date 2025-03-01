#ifndef _INTERFACE_ADDRESS_H_
#define _INTERFACE_ADDRESS_H_

#include <stdint.h>
#include <stddef.h>

/**
 * ethernet_param - enumerated numbers for link-level hardware parameters
 */
enum ethernet_param {
        HWADDR_802_3_TYPE = 6,
        HWADDR_802_3_LEN = 6
};

/**
 * get_hwaddr - get hardware address for a specified interface
 * @interface:  name of interface 
 * @addr_buffer: hardware address buffer
 * @buffer_len: size of @addr_buffer
 * return:      0 => succeed
 *              -1 => failed(OR NULL pointers are given)
 */
int get_hwaddr(const char *interface, uint8_t *addr_buffer, size_t buffer_len);

/**
 * get_paaddr - get public address for a specified interface
 * @interface:  name of interface
 * @pa_addr:    IPv4 address
 * return:      0 => succeed
 *              -1 => failed(OR NULL pointers are given)
 * Note:
 *              the returned public address is in network byte-order
 */
int get_paaddr(const char *interface, uint32_t *pa_addr);

#endif
