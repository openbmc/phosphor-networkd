project(
  'phosphor-networkd',
  'cpp',
  version: '0.1',
  meson_version: '>=0.57.0',
  default_options: [
    'warning_level=3',
    'cpp_std=c++20',
  ])

conf_data = configuration_data()
conf_data.set_quoted('DEFAULT_BUSNAME', 'xyz.openbmc_project.Network')
conf_data.set_quoted('SYSTEMD_TARGET', 'multi-user.target')
conf_data.set('HAVE_UBOOT_ENV', get_option('uboot-env'))
conf_data.set(
  'LINK_LOCAL_AUTOCONFIGURATION',
  get_option('default-link-local-autoconf'))
conf_data.set(
  'ENABLE_IPV6_ACCEPT_RA',
  get_option('default-ipv6-accept-ra'))
conf_data.set('NIC_SUPPORTS_ETHTOOL', get_option('nic-ethtool'))
conf_data.set('SYNC_MAC_FROM_INVENTORY', get_option('sync-mac'))
conf_header = configure_file(
  output: 'config.h',
  configuration: conf_data)

sdbusplus_dep = dependency('sdbusplus', required: false)
if sdbusplus_dep.found()
  sdbusplusplus_prog = find_program('sdbus++', native: true)
  sdbuspp_gen_meson_prog = find_program('sdbus++-gen-meson', native: true)
else
  sdbusplus_proj = subproject('sdbusplus', required: true)
  sdbusplus_dep = sdbusplus_proj.get_variable('sdbusplus_dep')
  sdbusplusplus_prog = sdbusplus_proj.get_variable('sdbusplusplus_prog')
  sdbuspp_gen_meson_prog = sdbusplus_proj.get_variable('sdbuspp_gen_meson_prog')
endif

phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')

generated_sources = [ conf_header ]
generated_others = []
yaml_sources = []
subdir('gen')
subdir('gen/xyz')

networkd_headers = include_directories('.', 'gen')

executable(
  'ncsi-netlink',
  'argument.cpp',
  'ncsi_netlink_main.cpp',
  'ncsi_util.cpp',
  implicit_include_directories: false,
  include_directories: networkd_headers,
  dependencies: [
    dependency('libnl-3.0'),
    dependency('libnl-genl-3.0'),
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
  ],
  install: true,
  install_dir: get_option('bindir'))

json_dep = declare_dependency()
if get_option('sync-mac')
  # nlohmann_json might not have a pkg-config. It is header only so just make
  # sure we can access the needed symbols from the header.
  has_json = meson.get_compiler('cpp').has_header_symbol(
    'nlohmann/json.hpp',
    'nlohmann::json::string_t',
    required: false)
  if not has_json
    json_dep = dependency(
      'nlohmann_json',
      fallback: ['nlohmann_json', 'nlohmann_json_dep'],
      required: true)
  endif
endif

networkd_deps = [
  json_dep,
  phosphor_dbus_interfaces_dep,
  phosphor_logging_dep,
  sdbusplus_dep,
  dependency('sdeventplus', fallback: ['sdeventplus', 'sdeventplus_dep']),
  dependency('stdplus', fallback: ['stdplus', 'stdplus_dep']),
]

networkd_lib = static_library(
  'networkd',
  generated_sources,
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
  include_directories: networkd_headers,
  dependencies: networkd_deps)

networkd_dep = declare_dependency(
  sources: generated_sources,
  dependencies: networkd_deps,
  include_directories: networkd_headers,
  link_with: networkd_lib)

executable(
  'phosphor-network-manager',
  'network_manager_main.cpp',
  implicit_include_directories: false,
  dependencies: networkd_dep,
  install: true,
  install_dir: get_option('bindir'))

configure_file(
  input: 'xyz.openbmc_project.Network.service.in',
  output: 'xyz.openbmc_project.Network.service',
  configuration: conf_data,
  install: true,
  install_dir: dependency('systemd').get_variable(
    pkgconfig: 'systemdsystemunitdir'))

configure_file(
  input: 'xyz.openbmc_project.Network.conf.in',
  output: 'xyz.openbmc_project.Network.conf',
  configuration: conf_data,
  install: true,
  install_dir: get_option('datadir') / 'dbus-1' / 'system.d')

if not get_option('tests').disabled()
  subdir('test')
endif
