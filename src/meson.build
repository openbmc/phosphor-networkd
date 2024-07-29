src_includes = include_directories('.')

stdplus_dep = dependency('stdplus')

executable(
  'ncsi-netlink',
  'argument.cpp',
  'ncsi_netlink_main.cpp',
  'ncsi_util.cpp',
  'ncsi_util_getvid.cpp',
  implicit_include_directories: false,
  include_directories: src_includes,
  dependencies: [
    dependency('libnl-3.0'),
    dependency('libnl-genl-3.0'),
    dependency('phosphor-logging'),
    stdplus_dep,
  ],
  install: true,
  install_dir: get_option('bindir'))

main_deps = []
main_srcs = []
if get_option('sync-mac')
  main_srcs += [
    'inventory_mac.cpp',
  ]
  main_deps += [
    dependency('nlohmann_json', include_type: 'system')
  ]
endif

networkd_deps = [
  phosphor_dbus_interfaces_dep,
  dependency('phosphor-logging'),
  networkd_dbus_dep,
  sdbusplus_dep,
  stdplus_dep,
]

conf_header = configure_file(
  output: 'config.h',
  configuration: conf_data)

networkd_lib = static_library(
  'networkd',
  conf_header,
  'ethernet_interface.cpp',
  'neighbor.cpp',
  'ipaddress.cpp',
  'netlink.cpp',
  'network_manager.cpp',
  'rtnetlink.cpp',
  'system_configuration.cpp',
  'system_queries.cpp',
  'types.cpp',
  'util.cpp',
  'config_parser.cpp',
  'dhcp_configuration.cpp',
  'dns_updater.cpp',
  implicit_include_directories: false,
  include_directories: src_includes,
  dependencies: networkd_deps)

networkd_dep = declare_dependency(
  sources: conf_header,
  dependencies: networkd_deps,
  include_directories: src_includes,
  link_with: networkd_lib)

executable(
  'phosphor-network-manager',
  'network_manager_main.cpp',
  'rtnetlink_server.cpp',
  main_srcs,
  implicit_include_directories: false,
  dependencies: main_deps + [
    networkd_dep,
    dependency('sdeventplus'),
  ],
  install: true,
  install_dir: get_option('bindir'))

if (get_option('hyp-nw-config') == true)
  subdir('ibm')
endif
