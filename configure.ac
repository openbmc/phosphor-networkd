# Initializaion
AC_PREREQ([2.69])
AC_INIT([phosphor-networkd], [1.0], [https://github.com/openbmc/phosphor-networkd/issues])
AC_LANG([C++])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])


# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_17([noext])
AX_APPEND_COMPILE_FLAGS([-fpic -Wall -Werror], [CXXFLAGS])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Download ncsi.h from github if necessary.
AC_CHECK_HEADER(linux/ncsi.h,[HAVE_LINUX_NCSI_H=""],[HAVE_LINUX_NCSI_H="-I linux/ncsi.h"])
AS_IF([test "$HAVE_LINUX_NCSI_H" != ""],
    AC_MSG_WARN([Could not find linux/ncsi.h: Attempting to download locally for building from https://raw.githubusercontent.com/openbmc/linux/dev-4.13/include/uapi/linux/ncsi.h])
    AC_SUBST([BT_BMC_DL],[`mkdir -p linux;wget https://raw.githubusercontent.com/openbmc/linux/dev-4.13/include/uapi/linux/ncsi.h -O linux/ncsi.h`])
)

# Suppress the --with-libtool-sysroot error
LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 221])
PKG_CHECK_MODULES([SDBUSPLUS], [sdbusplus])
PKG_CHECK_MODULES([SDEVENTPLUS], [sdeventplus])
AC_PATH_PROG([SDBUSPLUSPLUS], [sdbus++])
PKG_CHECK_MODULES([PHOSPHOR_LOGGING], [phosphor-logging])
PKG_CHECK_MODULES([PHOSPHOR_DBUS_INTERFACES], [phosphor-dbus-interfaces])

# Checks for header files.
AC_CHECK_HEADER(systemd/sd-bus.h, ,\
[AC_MSG_ERROR([Could not find systemd/sd-bus.h...systemd development package required])])

# Checks for typedefs, structures, and compiler characteristics.
AX_APPEND_COMPILE_FLAGS([-Wall -Werror -Wno-unused-result], [CFLAGS])

PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],
     [],
     [with_systemdsystemunitdir=auto]
)
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"],
    [def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
           [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
                  [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])]
            )
            with_systemdsystemunitdir=no],
           [with_systemdsystemunitdir="$def_systemdsystemunitdir"]
     )]
)
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])]
)
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_ARG_WITH([dbuspolicydir],
    AS_HELP_STRING([--with-dbuspolicydir=DIR], [Directory for D-Bus system policy files])
)
AS_IF([test "x$with_dbuspolicydir" = "x"],
      [with_dbuspolicydir='${sysconfdir}/dbus-1/system.d']
)
AC_SUBST([dbuspolicydir], [$with_dbuspolicydir])

# Check/set gtest specific functions.
AX_PTHREAD([GTEST_CPPFLAGS="-DGTEST_HAS_PTHREAD=1"],[GTEST_CPPFLAGS="-GTEST_HAS_PTHREAD=0"])
AC_SUBST(GTEST_CPPFLAGS)

AC_ARG_ENABLE([oe-sdk],
    AS_HELP_STRING([--enable-oe-sdk], [Link testcases absolutely against OE SDK so they can be ran within it.])
)
AC_ARG_VAR(OECORE_TARGET_SYSROOT,
    [Path to the OE SDK SYSROOT])
AS_IF([test "x$enable_oe_sdk" == "xyes"],
    AS_IF([test "x$OECORE_TARGET_SYSROOT" == "x"],
          AC_MSG_ERROR([OECORE_TARGET_SYSROOT must be set with --enable-oe-sdk])
    )
    AC_MSG_NOTICE([Enabling OE-SDK at $OECORE_TARGET_SYSROOT])
    [
        testcase_flags="-Wl,-rpath,\${OECORE_TARGET_SYSROOT}/lib"
        testcase_flags="${testcase_flags} -Wl,-rpath,\${OECORE_TARGET_SYSROOT}/usr/lib"
        testcase_flags="${testcase_flags} -Wl,-dynamic-linker,`find \${OECORE_TARGET_SYSROOT}/lib/ld-*.so | sort -r -n | head -n1`"
    ]
    AC_SUBST([OESDK_TESTCASE_FLAGS], [$testcase_flags])
)

# If set, auto-configure a link-local address on the NIC.
AC_ARG_ENABLE([link-local-autoconfiguration],
    AS_HELP_STRING([--disable-link-local-autoconfiguration], [Disable link-local IP address autoconfiguration])
)

AC_ARG_VAR(LINK_LOCAL_AUTOCONFIGURATION, [Enable link-local address autoconfiguration])

AS_IF([test "x$enable_link_local_autoconfiguration" != "xno"],
      [LINK_LOCAL_AUTOCONFIGURATION="yes"]
      AC_DEFINE_UNQUOTED([LINK_LOCAL_AUTOCONFIGURATION], ["$LINK_LOCAL_AUTOCONFIGURATION"], [Enable link-local IP address autoconfiguration])
)

AC_ARG_VAR(DNS_ENTRY_FILE, [File having DNS entries supplied by DHCP])
AS_IF([test "x$DNS_ENTRY_FILE" == "x"], [DNS_ENTRY_FILE="/run/systemd/netif/state"])
AC_DEFINE_UNQUOTED([DNS_ENTRY_FILE], ["$DNS_ENTRY_FILE"], [File having DNS entries supplied by DHCP])

AC_ARG_VAR(BUSNAME_NETWORK, [The Dbus busname to own])
AS_IF([test "x$BUSNAME_NETWORK" == "x"], [BUSNAME_NETWORK="xyz.openbmc_project.Network"])
AC_DEFINE_UNQUOTED([BUSNAME_NETWORK], ["$BUSNAME_NETWORK"], [The DBus busname to own])

AC_ARG_VAR(OBJ_NETWORK, [The network manager DBus object path])
AS_IF([test "x$OBJ_NETWORK" == "x"], [OBJ_NETWORK="/xyz/openbmc_project/network"])
AC_DEFINE_UNQUOTED([OBJ_NETWORK], ["$OBJ_NETWORK"], [The network manager DBus object path])

AC_ARG_VAR(NETWORK_CONF_DIR, [Network configuration directory])
AS_IF([test "x$NETWORK_CONF_DIR" == "x"], [NETWORK_CONF_DIR="/etc/systemd/network"])
AC_DEFINE_UNQUOTED([NETWORK_CONF_DIR], ["$NETWORK_CONF_DIR"], [Network configuration directory])

AC_ARG_VAR(SYSTEMD_TARGET, "Target for starting this service")
AS_IF([test "x$SYSTEMD_TARGET" == "x"], [SYSTEMD_TARGET="multi-user.target"])

AC_DEFINE(SYSTEMD_BUSNAME, "org.freedesktop.systemd1", [systemd busname.])
AC_DEFINE(SYSTEMD_PATH, "/org/freedesktop/systemd1", [systemd path.])
AC_DEFINE(SYSTEMD_INTERFACE, "org.freedesktop.systemd1.Manager", [systemd interface.])

# Create configured output.
AC_CONFIG_FILES([Makefile test/Makefile])
AC_CONFIG_FILES([xyz.openbmc_project.Network.service])
AC_CONFIG_FILES([xyz.openbmc_project.Network.conf])
AC_OUTPUT
