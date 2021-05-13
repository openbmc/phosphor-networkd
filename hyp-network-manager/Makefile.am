#AM_CPPFLAGS = -I${top_srcdir} -I${top_builddir}

bin_PROGRAMS = \
	phosphor-hyp-network-manager

noinst_HEADERS = \
	hyp_network_manager.hpp \
        hyp_ethernet_interface.hpp \
        hyp_ip_interface.hpp

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	xyz.openbmc_project.Network.Hypervisor.service
endif

phosphor_hyp_network_manager_SOURCES = \
	hyp_network_manager_main.cpp \
	hyp_network_manager.cpp \
        hyp_ethernet_interface.cpp \
        hyp_ip_interface.cpp

phosphor_hyp_network_manager_LDFLAGS = \
        $(SYSTEMD_LIBS) \
        $(STDPLUS_LIBS) \
        $(SDBUSPLUS_LIBS) \
        $(SDEVENTPLUS_LIBS) \
        $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
        $(PHOSPHOR_LOGGING_LIBS) \
	-lstdc++fs

phosphor_hyp_network_manager_CXXFLAGS = \
        $(SDBUSPLUS_CFLAGS) \
        $(SDEVENTPLUS_CFLAGS) \
        $(STDPLUS_CFLAGS) \
        $(SDEVENTPLUS_LIBS) \
        $(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
        $(PHOSPHOR_LOGGING_CFLAGS) \
        -flto

phosphor_hyp_network_manager_LDADD = $(top_builddir)/util.o \
                                     $(top_builddir)/config_parser.o
