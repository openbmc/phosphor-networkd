hyp_default_busname = 'xyz.openbmc_project.Network.Hypervisor'

configure_file(
  input: 'xyz.openbmc_project.Network.Hypervisor.service.in',
  output: 'xyz.openbmc_project.Network.Hypervisor.service',
  configuration: {
    'SYSTEMD_TARGET': 'multi-user.target',
    'HYP_DEFAULT_NETWORK_BUSNAME': hyp_default_busname,
  },
  install: true,
  install_dir: dependency('systemd').get_variable(
    'systemdsystemunitdir'))

hyp_src_includes = include_directories('.')

hyp_networkd_lib = static_library(
  'hyp-networkd',
  'hyp_network_manager.cpp',
  'hyp_sys_config.cpp',
  'hyp_ethernet_interface.cpp',
  'hyp_ip_interface.cpp',
  implicit_include_directories: false,
  include_directories: [src_includes, hyp_src_includes],
  dependencies: networkd_deps)

executable(
  'hyp-network-manager',
  'hyp_network_manager_main.cpp',
  link_with: hyp_networkd_lib,
  implicit_include_directories: false,
  dependencies: [
    networkd_dep,
    dependency('sdeventplus'),
  ],
  install: true,
  install_dir: get_option('bindir'))
