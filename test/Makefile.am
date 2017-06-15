AM_CPPFLAGS = -I${top_srcdir} -I${top_builddir}

TESTS = $(check_PROGRAMS)

check_PROGRAMS = test

test_SOURCES = \
	test_util.cpp \
	mock_syscall.cpp \
	test_network_manager.cpp \
	test_ethernet_interface.cpp

test_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS) $(AM_CPPFLAGS)

test_CXXFLAGS = $(PTHREAD_CFLAGS) \
				$(SYSTEMD_CFLAGS) \
				$(SDBUSPLUS_CFLAGS) \
				$(PHOSPHOR_LOGGING_CFLAGS) \
				$(PHOSPHOR_DBUS_INTERFACES_CFLAGS)

test_LDFLAGS =	-lgtest_main -lgtest -lstdc++fs \
				$(OESDK_TESTCASE_FLAGS) \
				$(SYSTEMD_LIBS) \
				$(SDBUSPLUS_LIBS) \
				$(PHOSPHOR_LOGGING_LIBS) \
				$(PHOSPHOR_DBUS_INTERFACES_LIBS)

test_LDADD = $(top_builddir)/ethernet_interface.cpp \
			$(top_builddir)/network_manager.cpp \
			$(top_builddir)/network_config.cpp \
			$(top_builddir)/ipaddress.cpp \
			$(top_builddir)/routing_table.cpp \
			$(top_builddir)/util.cpp \
			$(top_builddir)/system_configuration.cpp \
			$(top_builddir)/xyz/openbmc_project/Network/VLAN/Create/phosphor_network_manager-server.o \
			$(top_builddir)/xyz/openbmc_project/Network/IP/Create/phosphor_network_manager-server.o
