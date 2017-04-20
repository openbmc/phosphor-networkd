# Build these headers, don't install them
nobase_nodist_include_HEADERS = \
	xyz/openbmc_project/Network/VLAN/Create/server.hpp \

sbin_PROGRAMS = netman_watch_dns phosphor-network-manager


netman_watch_dns_SOURCES = netman_watch_dns.c
netman_watch_dns_LDFLAGS = $(SYSTEMD_LIBS)
netman_watch_dns_CFLAGS = $(SYSTEMD_CFLAGS)

noinst_HEADERS = \
		ethernet_interface.hpp

phosphor_network_manager_SOURCES = \
		ethernet_interface.cpp \
		ipaddress.hpp \
		network_manager.hpp \
		network_manager.cpp \
		network_manager_main.cpp \
		xyz/openbmc_project/Network/VLAN/Create/server.cpp \

CLEANFILES = \
		xyz/openbmc_project/Network/VLAN/Create/server.cpp \
		xyz/openbmc_project/Network/VLAN/Create/server.hpp

BUILT_SOURCES = \
		xyz/openbmc_project/Network/VLAN/Create/server.cpp \
		xyz/openbmc_project/Network/VLAN/Create/server.hpp


phosphor_network_manager_LDFLAGS = \
		$(SYSTEMD_LIBS) \
		$(SDBUSPLUS_LIBS) \
		$(PHOSPHOR_DBUS_INTERFACES_LIBS)

phosphor_network_manager_CXXFLAGS = \
		$(SYSTEMD_CFLAGS) \
		$(SDBUSPLUS_CFLAGS) \
		$(PHOSPHOR_DBUS_INTERFACES_CFLAGS)

xyz/openbmc_project/Network/VLAN/Create/server.cpp: xyz/openbmc_project/Network/VLAN/Create.interface.yaml xyz/openbmc_project/Network/VLAN/Create/server.hpp
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(srcdir) interface server-cpp xyz.openbmc_project.Network.VLAN.Create > $@

xyz/openbmc_project/Network/VLAN/Create/server.hpp: xyz/openbmc_project/Network/VLAN/Create.interface.yaml
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(srcdir) interface server-header xyz.openbmc_project.Network.VLAN.Create > $@
