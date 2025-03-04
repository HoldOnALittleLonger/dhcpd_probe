#include "if_query.h"

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>


struct ifquery_info ifinfo = {0};

int start_ifquery(const char *interface)
{
        int ioctl_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (ioctl_socket < 0)
                return -IFQUERY_EQUERY;

        struct ifreq ifrq = {0};
        strncpy(ifrq.ifr_name, interface, IFNAMSIZ);

        if (!ioctl(ioctl_socket, SIOCGIFADDR, &ifrq))
                ifinfo.if_addr = ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr;

        if (!ioctl(ioctl_socket, SIOCGIFHWADDR, &ifrq))
                ifinfo.if_hwaddr = ifrq.ifr_hwaddr;

        if (!ioctl(ioctl_socket, SIOCGIFINDEX, &ifrq))
                ifinfo.if_index = ifrq.ifr_ifindex;

        if (!ioctl(ioctl_socket, SIOCGIFMTU, &ifrq))
                ifinfo.if_mtu = ifrq.ifr_mtu;

        shutdown(ioctl_socket, SHUT_RDWR);
        return 0;
}
