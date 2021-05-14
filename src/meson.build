phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')

src_includes = include_directories('.')

executable(
  'ncsi-netlink',
  'argument.cpp',
  'ncsi_netlink_main.cpp',
  'ncsi_util.cpp',
  implicit_include_directories: false,
  include_directories: src_includes,
  dependencies: [
    dependency('libnl-3.0'),
    dependency('libnl-genl-3.0'),
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
  ],
  install: true,
  install_dir: get_option('bindir'))

networkd_deps = [
  dependency('phosphor-dbus-interfaces'),
  phosphor_dbus_interfaces_dep,
  phosphor_logging_dep,
  sdbusplus_dep,
  dependency('sdeventplus', fallback: ['sdeventplus', 'sdeventplus_dep']),
  dependency('stdplus', fallback: ['stdplus', 'stdplus_dep']),
]

conf_header = configure_file(
  output: 'config.h',
  configuration: conf_data)

networkd_generated = [
  conf_header,
] + generated_sources

networkd_includes = [
  src_includes,
  generated_includes,
]

networkd_lib = static_library(
  'networkd',
  networkd_generated,
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
  'dns_updater.cpp',
  'watch.cpp',
  implicit_include_directories: false,
  include_directories: networkd_includes,
  dependencies: networkd_deps)

networkd_dep = declare_dependency(
  sources: networkd_generated,
  dependencies: networkd_deps,
  include_directories: networkd_includes,
  link_with: networkd_lib)

executable(
  'phosphor-network-manager',
  'network_manager_main.cpp',
  implicit_include_directories: false,
  dependencies: networkd_dep,
  install: true,
  install_dir: get_option('bindir'))
