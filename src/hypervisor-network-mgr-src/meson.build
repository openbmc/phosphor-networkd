hyp_default_busname = 'xyz.openbmc_project.Network.Hypervisor'

hyp_networkd_dep = declare_dependency(
  include_directories: networkd_includes,
  link_with: networkd_lib)

configure_file(
  input: 'xyz.openbmc_project.Network.Hypervisor.service.in',
  output: 'xyz.openbmc_project.Network.Hypervisor.service',
  configuration: {
    'SYSTEMD_TARGET': 'multi-user.target',
    'HYP_DEFAULT_BUSNAME': hyp_default_busname,
  },
  install: true,
  install_dir: dependency('systemd').get_variable(
    pkgconfig: 'systemdsystemunitdir'))

executable(
  'hyp-network-manager',
  'hyp_network_manager_main.cpp',
  'hyp_network_manager.cpp',
  'hyp_ethernet_interface.cpp',
  'hyp_ip_interface.cpp',
  implicit_include_directories: false,
  dependencies: hyp_networkd_dep,
  install: true,
  install_dir: get_option('bindir'))

