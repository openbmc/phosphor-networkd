AM_CPPFLAGS = -I${top_srcdir}

TESTS = $(check_PROGRAMS)

check_PROGRAMS = test

test_SOURCES = \
	TestConfigParser.cpp

test_CPPFLAGS = -Igtest $(GTEST_CPPFLAGS) $(AM_CPPFLAGS)
test_CXXFLAGS = $(PTHREAD_CFLAGS)
test_LDFLAGS = -lgtest_main -lgtest $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS)
test_LDADD = $(top_builddir)/config_parser.cpp
test_LDFLAGS += $(SYSTEMD_LIBS)
