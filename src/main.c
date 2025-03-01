#include "dhcpd_probe.h"

#include <stddef.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
        if (argc < 2) {
                fprintf(stdout, "Usage : dhcpd_probe <interface>\n");
                return 1;
        }

        if (dhcpd_probe(argv[1]) < 0) {
                fprintf(stderr, "Encountered an error.\n");
                return 2;
        }

        return 0;
}
