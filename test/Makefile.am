AM_CPPFLAGS = -I${top_srcdir}

TESTS = $(check_PROGRAMS)

check_PROGRAMS = test

test_SOURCES = \
	TestConfigParser.cpp \
	TestUtil.cpp

test_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS) $(AM_CPPFLAGS)
test_CXXFLAGS = $(PTHREAD_CFLAGS)

test_LDFLAGS =	-lgtest_main -lgtest -lstdc++fs \
				$(OESDK_TESTCASE_FLAGS) \
				$(SYSTEMD_LIBS) \
				$(SDBUSPLUS_LIBS)

test_LDADD = $(top_builddir)/config_parser.cpp \
			$(top_builddir)/util.cpp
