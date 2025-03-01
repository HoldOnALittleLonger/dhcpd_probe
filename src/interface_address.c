#include "interface_address.h"

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

int get_hwaddr(const char *interface, uint8_t *addr_buffer, size_t buffer_len)
{
        if (!addr_buffer)
                return -1;

        int ioctl_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (ioctl_socket < 0)
                return -1;

        struct ifreq ifrq = {0};
        strncpy(ifrq.ifr_name, interface, strlen(interface));

        if (ioctl(ioctl_socket, SIOCGIFHWADDR, &ifrq) < 0) {
                shutdown(ioctl_socket, SHUT_RDWR);
                return -1;
        }

        memcpy(addr_buffer, ifrq.ifr_hwaddr.sa_data, buffer_len);

        shutdown(ioctl_socket, SHUT_RDWR);
        return 0;
}

int get_paaddr(const char *interface, uint32_t *pa_addr)
{
        if (!interface || !pa_addr)
                return -1;

        int ioctl_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (ioctl_socket < 0)
                return -1;

        struct ifreq ifrq = {0};
        strncpy(ifrq.ifr_name, interface, strlen(interface));
        
        if (ioctl(ioctl_socket, SIOCGIFADDR, &ifrq) < 0) {
                shutdown(ioctl_socket, SHUT_RDWR);
                return -1;
        }

        *pa_addr = ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr;

        shutdown(ioctl_socket, SHUT_RDWR);
        return 0;
}
