#ifndef _UDP_SEGMENT_H_
#define _UDP_SEGMENT_H_

#include <stdint.h>
#include <stddef.h>

#include <arpa/inet.h>

/**
 * udp_header - structure udp_header represent UDP protocol
 *              header
 * @sport:      TSAP source       (network byteorder)
 * @dport:      TSAP destination  (network byteorder)
 * @length:     segment length    (network byteorder)
 * @checksum:   checksum
 */
struct udp_header {
        uint16_t sport;
        uint16_t dport;
        uint16_t length;
        uint16_t checksum;
};

/**
 * udp_segment - structure udp_segment represent UDP segment
 */
struct udp_segment {
        struct udp_header udphdr;
        uint8_t data[];
};

static inline
size_t udp_data_length(const struct udp_segment *udpseg)
{
        return ntohs(udpseg->udphdr.length) - sizeof(struct udp_header);
}

#endif
