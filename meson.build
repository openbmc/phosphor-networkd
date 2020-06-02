project('phosphor-networkd',
	 'cpp',
	 version: '0.1',
	 meson_version: '>=0.53.0',
         default_options: [ 'warning_level=3',
			    'werror=true',
	  		    'cpp_std=c++17' ])

########################################################################
# Project Links

project_pretty_name = 'phosphor-networkd'
project_url = 'https://github.com/openbmc/' + project_pretty_name
project_issues_url = project_url + '/issues/new'

summary('Issue',project_issues_url, section : 'Report Issues')

#####################################################################

# Validate the c++ Standard

if get_option('cpp_std') != 'c++17'
    error('This project requires cpp std to be in c++17 mode')
endif

#########################################################################
# Get Compiler and default build type
compiler = meson.get_compiler('cpp')
build = get_option('buildtype')

#########################################################################
# Find the dependencies

cppfs		=	compiler.find_library('stdc++fs')
systemd		=	dependency ('systemd', version: '>=221')
dbuspkg		=	dependency ('dbus-1')
sdbusplus	=       dependency ('sdbusplus')
sdeventplus	=	dependency ('sdeventplus')
logging		=       dependency ('phosphor-logging')
dbus		=       dependency ('phosphor-dbus-interfaces')
libnl		=       dependency ('libnl-3.0')
libnlgenl	=       dependency ('libnl-genl-3.0')
gtest		=	dependency('gtest', main: true, disabler: true,required : get_option('tests'))
gmock		=	dependency('gmock',required : get_option('tests'))
thread_dep	=	dependency('threads')
deps		=	[systemd,sdbusplus,sdeventplus,logging,dbus,libnl,libnlgenl,cppfs]
sdbuspp		=	find_program('sdbus++')

if compiler.has_header('linux/ncsi.h')
    ## header is present, Nothing to do
else
    warning('Could not find linux/ncsi.h: Attempting to download locally for building from https://raw.githubusercontent.com/openbmc/linux/dev-4.13/include/uapi/linux/ncsi.h')
    run_command('mkdir','-p','linux')
    run_command('wget','https://raw.githubusercontent.com/openbmc/linux/dev-4.13/include/uapi/linux/ncsi.h','-O', 'linux/ncsi.h')
endif

if compiler.has_header('systemd/sd-bus.h')
    ### Nothing to do
else
    warning('Systemd Development Package Required')
endif

###########################################################################
# Set the compiler flags
add_project_arguments(
  compiler.get_supported_arguments([
	'-Wno-psabi',
	'-Wno-pedantic',
	'-Wno-missing-field-initializers',
	'-fpic',
	'-Wno-unused-result',
	]),
	language : 'cpp')

add_project_link_arguments('-lstdc++fs', language : 'cpp')
if compiler.has_link_argument('-ldl')
	add_project_link_arguments(['-ldl'], language: 'cpp')
endif

############################################################################
# Get the config data and enable options
conf_data = configuration_data()
conf_data.set_quoted('DEFAULT_BUSNAME', 'xyz.openbmc_project.Network')

if(get_option('link-local-config').enabled())
	conf_data.set('LINK_LOCAL_AUTOCONFIGURATION',1)
endif

configure_file(output: 'config.h',
configuration: conf_data)

############################################################################
# Sub Directory to create custom tagets using sdbus++, and trigger the nested
# meson files.
subdir('xyz/openbmc_project/Network')

############################################################################
# Configure and get the options

systemd_system_unit_dir = systemd.get_pkgconfig_variable(
    							'systemdsystemunitdir',
    							define_variable: ['prefix', get_option('prefix')])


dbus_data_root_dir= dbuspkg.get_pkgconfig_variable('datarootdir',define_variable:['prefix',get_option('prefix')])

dbus_policy_dir = dbus_data_root_dir + '/dbus-1/system.d'

features = {
'uboot-env'		: '-DHAVE_UBOOT_ENV',
'ethtool'		: '-DFEATURE_NIC_ETHTOOL'
}

foreach key,value : features
	if(get_option(key).enabled())
		add_project_arguments(value,language : 'cpp')
		summary(key,value, section : 'Enabled Features')
	endif
endforeach


############################################################################
# Gather sources for the target binaries

ncsi_netlink_sources = [
			  'argument.cpp',
			  'ncsi_util.cpp' ]

phosphor_network_manager_sources = [
			            'ethernet_interface.cpp',
				     'neighbor.cpp',
				     'ipaddress.cpp',
				     'netlink.cpp',
				     'network_config.cpp',
				     'network_manager.cpp',
				     'system_configuration.cpp',
				     'util.cpp',
				     'routing_table.cpp',
				     'config_parser.cpp',
				     'dhcp_configuration.cpp',
				     'vlan_interface.cpp',
				     'rtnetlink_server.cpp',
				     vlan_c,ip_create_c,neighbor_c
				     ]

libnetworkd = static_library('libnetworkd',
			       phosphor_network_manager_sources,
		               dependencies:deps)


netlinklib = static_library('libnetlink',
			    ncsi_netlink_sources,
			    dependencies:deps)



############################################################################
if get_option('oe-sdk').enabled()
  # Setup OE SYSROOT
  OECORE_TARGET_SYSROOT = run_command('sh', '-c', 'echo $OECORE_TARGET_SYSROOT').stdout().strip()
  if OECORE_TARGET_SYSROOT == ''
    error('Unable to get $OECORE_TARGET_SYSROOT, check your environment.')
  endif
  message('OE_SYSROOT: ' + OECORE_TARGET_SYSROOT)
  rpath = ':'.join([OECORE_TARGET_SYSROOT + '/lib', OECORE_TARGET_SYSROOT + '/usr/lib'])
  ld_so = run_command('sh', '-c', 'find ' + OECORE_TARGET_SYSROOT + '/lib/ld-*.so | sort -r -n | head -n1').stdout().strip()
  dynamic_linker = ['-Wl,-dynamic-linker,' + ld_so]
else
  dynamic_linker = []
endif


###########################################################################
# Install the files into the build directory


configure_file(input : 'xyz.openbmc_project.Network.service.in',
               output : 'xyz.openbmc_project.Network.service',
               copy : true,
               install_dir: systemd_system_unit_dir,
               install : true)

configure_file(input : 'xyz.openbmc_project.Network.conf.in',
               output : 'xyz.openbmc_project.Network.conf',
               install_dir: dbus_policy_dir,
               copy : true,
	       install : true)

############################################################################
# Build binaries for nsci and networkd
#phosphor_network_manager_sources += 'network_manager_main.cpp'
#ncsi_netlink_sources += 'ncsi_netlink_main.cpp'
executable('ncsi-netlink',
	   'ncsi_netlink_main.cpp',
	   link_with:[netlinklib],
	   dependencies:deps,
	   install:true)

executable('phosphor-network-manager',
	    [
	    'network_manager_main.cpp',
	    'dns_updater.cpp',
	    'watch.cpp'],
	    link_with:[libnetworkd],
	    dependencies:[deps],
	    install:true)

if get_option('tests').enabled()
    subdir('test')
endif
