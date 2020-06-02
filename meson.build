project('phosphor-networkd','cpp',
        version: '0.1',
	meson_version: '>=0.54.1',
        default_options: [
          'warning_level=3',
	  'werror=true',
	  'cpp_std=c++17',
          'buildtype=debugoptimized']
        )

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

summary('Build Type',build, section : 'Build Info')

#########################################################################
# Find the dependencies

systemd        =	dependency ('systemd', version: '>=221')
dbuspkg        =	dependency ('dbus-1')
sdbusplus      =        dependency ('sdbusplus')
sdeventplus    =	dependency ('sdeventplus')
logging        =        dependency ('phosphor-logging')
dl_dep         =        compiler.find_library('dl', required : get_option('tests'))
dbus_interface =        dependency ('phosphor-dbus-interfaces')
libnl          =        dependency ('libnl-3.0')
libnlgenl      =        dependency ('libnl-genl-3.0')
gtest          =	dependency('gtest', main: true, disabler: true,required : get_option('tests'))
gmock          =	dependency('gmock',required : get_option('tests'))
thread_dep     =	dependency('threads')
sdbuspp        =	find_program('sdbus++')
sdbusgen_prog  =        find_program('sdbus++-gendir')
deps           =	[
                          systemd, sdbusplus, sdeventplus,
			  logging, dbus_interface, libnl,libnlgenl
			]

# Enforce the test dependencies when tests are enabled 
dl_dep         =        compiler.find_library('dl', required : get_option('tests'))
gtest          =	dependency('gtest', main: true, disabler: true,required : get_option('tests'))
gmock          =	dependency('gmock',required : get_option('tests'))
thread_dep     =	dependency('threads', required : get_option('tests'))

if compiler.has_header('linux/ncsi.h')
    ## header is present, Nothing to do
else
    warning('Could not find linux/ncsi.h: Attempting to download locally for building from https://raw.githubusercontent.com/openbmc/linux/dev-4.13/include/uapi/linux/ncsi.h')
    run_command('mkdir','-p','linux')
    run_command('wget','https://raw.githubusercontent.com/openbmc/linux/dev-5.4/include/uapi/linux/ncsi.h','-O', 'linux/ncsi.h')
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

############################################################################
# Get the config data and enable options
conf_data = configuration_data()

if(get_option('link-local-config').enabled())
    conf_data.set('LINK_LOCAL_AUTOCONFIGURATION',1)
endif
conf_data.set_quoted('DEFAULT_BUSNAME',get_option('bus-name'))
configure_file(output: 'config.h',
configuration: conf_data)

############################################################################
# Enable the respective features based on meson options

features = {
'uboot-env'             : '-DHAVE_UBOOT_ENV',
'ethtool'               : '-DFEATURE_NIC_ETHTOOL'
}

foreach key,value : features
    if(get_option(key).enabled())
       add_project_arguments(value,language : 'cpp')
       summary(key,value, section : 'Enabled Features')
    endif
endforeach

############################################################################
# Generate the custom targets 

custom_gen_files = files(
    run_command(
        sdbusgen_prog,
        '--tool', sdbuspp,
        '--output', meson.current_build_dir(),
        'xyz',
        check: true
    ).stdout().strip().split('\n')
)


############################################################################
# Gather sources for the target binaries

ncsi_netlink_sources = [
                          'argument.cpp',
                          'ncsi_netlink_main.cpp',
                          'ncsi_util.cpp'
                       ]

phosphor_network_manager_sources = [
                                     custom_gen_files,
                                     'config_parser.cpp',
                        	     'dhcp_configuration.cpp',
			             'ethernet_interface.cpp',
			             'ipaddress.cpp',
			             'neighbor.cpp',
			             'netlink.cpp',
			             'network_config.cpp',
			             'network_manager.cpp',
			             'routing_table.cpp',
			             'rtnetlink_server.cpp',
			             'system_configuration.cpp',
			             'util.cpp',
			             'vlan_interface.cpp',
                                     ]


##############################################################################
# construct the libnetwork

libnetworkd = static_library('libnetworkd',phosphor_network_manager_sources,
                              dependencies:deps)


############################################################################
# Configure and get the options

systemd_system_unit_dir = systemd.get_pkgconfig_variable('systemdsystemunitdir',
                                                         define_variable: ['prefix',
                                                                           get_option('prefix')
                                                                          ])


dbus_data_root_dir= dbuspkg.get_pkgconfig_variable('datarootdir',define_variable:['prefix',get_option('prefix')])

dbus_policy_dir = dbus_data_root_dir + '/dbus-1/system.d'

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

executable('ncsi-netlink',
            ncsi_netlink_sources,
	    dependencies:deps,
	    install:true)

executable('phosphor-network-manager',
           [
             'dns_updater.cpp',
	     'network_manager_main.cpp',
	     'watch.cpp',
           ],
	   link_with:libnetworkd,
	   dependencies:deps ,
	   install:true)

if get_option('tests').enabled()
    subdir('test')
endif
