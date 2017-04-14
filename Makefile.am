sbin_PROGRAMS = netman_watch_dns network_manager

netman_watch_dns_SOURCES = netman_watch_dns.c
netman_watch_dns_LDFLAGS = $(SYSTEMD_LIBS)
netman_watch_dns_CFLAGS = $(SYSTEMD_CFLAGS)

network_manager_SOURCES = \
		ethernet_interface.hpp \
		ethernet_interface.cpp \
		network_manager.hpp \
		network_manager_main.cpp \
		xyz/openbmc_project/Network/VLANInterface/Create/server.cpp \

CLEANFILES = \
		xyz/openbmc_project/Network/VLANInterface/Create/server.cpp \
		xyz/openbmc_project/Network/VLANInterface/Create/server.cpp

BUILT_SOURCES = \
		xyz/openbmc_project/Network/VLANInterface/Create/server.cpp \
		xyz/openbmc_project/Network/VLANInterface/Create/server.cpp


network_manager_LDFLAGS = \
		$(SYSTEMD_LIBS) \
		$(SDBUSPLUS_LIBS) \
		$(PHOSPHOR_DBUS_INTERFACES_LIBS)

network_manager_CXXFLAGS = \
		$(SYSTEMD_CFLAGS) \
		$(SDBUSPLUS_CFLAGS) \
		$(PHOSPHOR_DBUS_INTERFACES_CFLAGS)

xyz/openbmc_project/Network/VLANInterface/Create/server.cpp: xyz/openbmc_project/Network/VLANInterface/Create.interface.yaml xyz/openbmc_project/Network/VLANInterface/Create/server.hpp
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(srcdir) interface server-cpp xyz.openbmc_project.Network.VLANInterface.Create > $@

xyz/openbmc_project/Network/VLANInterface/Create/server.hpp: xyz/openbmc_project/Network/VLANInterface/Create.interface.yaml
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(srcdir) interface server-header xyz.openbmc_project.Network.VLANInterface.Create > $@
