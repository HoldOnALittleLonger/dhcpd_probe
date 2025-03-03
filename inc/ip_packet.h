#ifndef _IP_PACKET_H_
#define _IP_PACKET_H_

#include <stdint.h>

#define ip_hdr_DF(hdr) ((hdr)->flags_foffset & 2)
#define ip_hdr_enable_DF(hdr) ((hdr)->flags_foffset |= 2)
#define ip_hdr_disable_DF(hdr) ((hdr)->flags_foffset &= ~2)

#define ip_hdr_MF(hdr) ((hdr)->flags_foffset & 4)
#define ip_hdr_enable_MF(hdr) ((hdr)->flags_foffset |= 4)
#define ip_hdr_disable_MF(hdr) ((hdr)->flags_foffset &= ~4)

#define ip_hdr_foffset(hdr) ((hdr)->flags_foffset >> 3)
#define ip_hdr_set_foffset(hdr, foffset)                        \
        do {                                                    \
                uint8_t flags = (hdr)->flags_foffset & 7;       \
                (hdr)->flags_foffset = (foffset) << 3 | flags;  \
        } while (0)

enum UPPER_PROTOCOL {
        UDP_OVER_IP = 17
};

/**
 * ip_header - structure ip_header represent internet protocol
 *             header
 */
typedef struct ip_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        uint8_t ihl:4;
        uint8_t version:4;
#else
        uint8_t version:4;
        uint8_t ihl:4;
#endif

        uint8_t tos;
        uint16_t tol;
        uint16_t id;
        uint16_t flags_foffset;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t src;
        uint32_t des;
        uint8_t opt_payload[];
} ip_packet;

static inline
uint16_t ip_payload_offset(const ip_packet *packet)
{
        const struct ip_header *hdr = packet;
        return hdr->ihl * 32 / 8;
}

static inline
void *ip_payload(ip_packet *packet)
{
        return (uint8_t *)packet + ip_payload_offset(packet);
}

#endif
