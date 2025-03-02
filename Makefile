
CC := gcc
CFLAGS := -Iinc -c -D __LITTLE_ENDIAN_BITFIELD
ALL_OBJS := dhcp_routines.o dhcpd_probe.o main.o if_query.o

vpath %.c src

all: dhcpd_probe

dhcpd_probe: $(ALL_OBJS)
	$(CC) -o $@ $^
	install $@ bin/
	unlink $@

dhcp_routines.o: dhcp_routines.c
	$(CC) $(CFLAGS) -o $@ $<

dhcpd_probe.o: dhcpd_probe.c
	$(CC) $(CFLAGS) -o $@ $<

if_query.o: if_query.c
	$(CC) $(CFLAGS) -o $@ $<

main.o: main.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f *.o
