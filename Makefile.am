# Build these headers, don't install them
nobase_nodist_include_HEADERS = \
	xyz/openbmc_project/Network/VLAN/Create/server.hpp \
	xyz/openbmc_project/Network/IP/Create/server.hpp

sbin_PROGRAMS = phosphor-network-manager phosphor-dns-updater

phosphor_dns_updater_SOURCES = watch.cpp dns_updater.cpp
phosphor_dns_updater_LDFLAGS = $(SYSTEMD_LIBS) \
		$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
		$(PHOSPHOR_LOGGING_LIBS) \
		-lstdc++fs

phosphor_dns_updater_CFLAGS = $(SYSTEMD_CFLAGS) \
		$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
		$(PHOSPHOR_LOGGING_CFLAGS)

noinst_HEADERS = \
		ethernet_interface.hpp \
		network_config.hpp \
		network_manager.hpp \
		ipaddress.hpp \
		types.hpp \
		util.hpp \
		routing_table.hpp \
		config_parser.hpp \
		system_configuration.hpp \
		dhcp_configuration.hpp \
        vlan_interface.hpp \
		watch.hpp \
		dns_updater.hpp

phosphor_network_manager_SOURCES = \
		ethernet_interface.cpp \
		ipaddress.cpp \
		network_config.cpp \
		network_manager.cpp \
		network_manager_main.cpp \
		system_configuration.cpp \
		xyz/openbmc_project/Network/VLAN/Create/server.cpp \
		xyz/openbmc_project/Network/IP/Create/server.cpp \
		util.cpp \
		routing_table.cpp \
		config_parser.cpp \
		dhcp_configuration.cpp \
        vlan_interface.cpp

CLEANFILES = \
		xyz/openbmc_project/Network/VLAN/Create/server.cpp \
		xyz/openbmc_project/Network/VLAN/Create/server.hpp \
		xyz/openbmc_project/Network/IP/Create/server.cpp \
		xyz/openbmc_project/Network/IP/Create/server.hpp

BUILT_SOURCES = \
		xyz/openbmc_project/Network/VLAN/Create/server.cpp \
		xyz/openbmc_project/Network/VLAN/Create/server.hpp \
		xyz/openbmc_project/Network/IP/Create/server.cpp \
		xyz/openbmc_project/Network/IP/Create/server.hpp

phosphor_network_manager_LDFLAGS = \
		$(SYSTEMD_LIBS) \
		$(SDBUSPLUS_LIBS) \
		$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
		$(PHOSPHOR_LOGGING_LIBS) \
		-lstdc++fs

phosphor_network_manager_CXXFLAGS = \
		$(SYSTEMD_CFLAGS) \
		$(SDBUSPLUS_CFLAGS) \
		$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
		$(PHOSPHOR_LOGGING_CFLAGS)

xyz/openbmc_project/Network/VLAN/Create/server.cpp: xyz/openbmc_project/Network/VLAN/Create.interface.yaml xyz/openbmc_project/Network/VLAN/Create/server.hpp
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(srcdir) interface server-cpp xyz.openbmc_project.Network.VLAN.Create > $@

xyz/openbmc_project/Network/VLAN/Create/server.hpp: xyz/openbmc_project/Network/VLAN/Create.interface.yaml
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(srcdir) interface server-header xyz.openbmc_project.Network.VLAN.Create > $@

xyz/openbmc_project/Network/IP/Create/server.cpp: xyz/openbmc_project/Network/IP/Create.interface.yaml xyz/openbmc_project/Network/IP/Create/server.hpp
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(srcdir) interface server-cpp xyz.openbmc_project.Network.IP.Create > $@

xyz/openbmc_project/Network/IP/Create/server.hpp: xyz/openbmc_project/Network/IP/Create.interface.yaml
	@mkdir -p `dirname $@`
	$(SDBUSPLUSPLUS) -r $(srcdir) interface server-header xyz.openbmc_project.Network.IP.Create > $@
	sed -i '5i #include \"xyz\/openbmc_project\/Network\/IP\/server.hpp\"' $@

SUBDIRS = test
