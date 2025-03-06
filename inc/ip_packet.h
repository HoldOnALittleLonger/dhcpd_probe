#ifndef _IP_PACKET_H_
#define _IP_PACKET_H_

#include <stdint.h>


/* Now suppose fields of ip_packet is network byte-order */

#define IP_HDR_DF_MASK 0b0100000000000000
#define IP_HDR_MF_MASK 0b0010000000000000
#define IP_HDR_FOFFSET_MASK 0b0001111111111111


#define ip_hdr_DF(hdr) (!!((hdr)->flags_foffset & IP_HDR_DF_MASK))
#define ip_hdr_enable_DF(hdr) ((hdr)->flags_foffset |= IP_HDR_DF_MASK)
#define ip_hdr_disable_DF(hdr) ((hdr)->flags_foffset &= ~IP_HDR_DF_MASK)

#define ip_hdr_MF(hdr) (!!((hdr)->flags_foffset & IP_HDR_MF_MASK))
#define ip_hdr_enable_MF(hdr) ((hdr)->flags_foffset |= IP_HDR_MF_MASK)
#define ip_hdr_disable_MF(hdr) ((hdr)->flags_foffset &= ~IP_HDR_MF_MASK)

#define ip_hdr_foffset(hdr) ((hdr)->flags_foffset & IP_HDR_FOFFSET_MASK)
#define ip_hdr_set_foffset(hdr, foffset) \
        do { \
                uint16_t flags = (hdr)->flags_foffset & (IP_HDR_DF_MASK | IP_HDR_MF_MASK); \
                (hdr)->flags_foffset = foffset | flags; \
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
