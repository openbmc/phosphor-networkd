sbin_PROGRAMS = netman_watch_dns network_manager

netman_watch_dns_SOURCES = netman_watch_dns.c
netman_watch_dns_LDFLAGS = $(SYSTEMD_LIBS)
netman_watch_dns_CFLAGS = $(SYSTEMD_CFLAGS)

network_manager_SOURCES = \
                ethernet_interface.hpp \
                network_manager_main.cpp

network_manager_LDFLAGS = \
                $(SYSTEMD_LIBS) \
                $(SDBUSPLUS_LIBS) \
                $(PHOSPHOR_DBUS_INTERFACES_LIBS)

network_manager_CXXFLAGS = \
                $(SYSTEMD_CFLAGS) \
                $(SDBUSPLUS_CFLAGS) \
                $(PHOSPHOR_DBUS_INTERFACES_CFLAGS)


