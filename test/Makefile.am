AM_CPPFLAGS = -I${top_srcdir} -I${top_builddir}

TESTS = $(check_PROGRAMS)

check_PROGRAMS = test

test_SOURCES = \
	TestUtil.cpp \
	mock_syscall.cpp \
	TestNetworkManager.cpp \
	TestEthernetInterface.cpp

test_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS) $(AM_CPPFLAGS)
test_CXXFLAGS = $(PTHREAD_CFLAGS) $(PHOSPHOR_LOGGING_CFLAGS)

test_LDFLAGS =	-lgtest_main -lgtest -lstdc++fs \
				$(OESDK_TESTCASE_FLAGS) \
				$(SYSTEMD_LIBS) \
				$(SDBUSPLUS_LIBS) \
				$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
				$(PHOSPHOR_LOGGING_LIBS)

test_LDADD = $(top_builddir)/ethernet_interface.cpp \
			$(top_builddir)/network_manager.cpp \
			$(top_builddir)/ipaddress.cpp \
			$(top_builddir)/routing_table.cpp \
			$(top_builddir)/util.cpp \
			$(top_builddir)/xyz/openbmc_project/Network/VLAN/Create/phosphor_network_manager-server.o \
			$(top_builddir)/xyz/openbmc_project/Network/IP/Create/phosphor_network_manager-server.o
