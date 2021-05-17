project(
  'phosphor-networkd',
  'cpp',
  version: '0.1',
  meson_version: '>=0.57.0',
  default_options: [
    'warning_level=3',
    'cpp_std=c++20',
  ])

default_busname = 'xyz.openbmc_project.Network'

conf_data = configuration_data()
conf_data.set_quoted('DEFAULT_BUSNAME', default_busname)
conf_data.set('HAVE_UBOOT_ENV', get_option('uboot-env'))
conf_data.set(
  'LINK_LOCAL_AUTOCONFIGURATION',
  get_option('default-link-local-autoconf'))
conf_data.set(
  'ENABLE_IPV6_ACCEPT_RA',
  get_option('default-ipv6-accept-ra'))
conf_data.set('NIC_SUPPORTS_ETHTOOL', get_option('nic-ethtool'))
conf_data.set('SYNC_MAC_FROM_INVENTORY', get_option('sync-mac'))

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

generated_sources = []
generated_others = []
yaml_sources = []
subdir('gen')
subdir('gen/xyz')
networkd_dbus_includes = include_directories('gen')

phosphor_dbus_interfaces_dep = dependency(
  'phosphor-dbus-interfaces',
  fallback: ['phosphor-dbus-interfaces', 'phosphor_dbus_interfaces_dep'])

networkd_dbus_deps = [
  phosphor_dbus_interfaces_dep,
  sdbusplus_dep,
]

networkd_dbus_lib = static_library(
  'networkd_dbus',
  generated_sources,
  implicit_include_directories: false,
  include_directories: networkd_dbus_includes,
  dependencies: networkd_dbus_deps)

generated_files_headers = []
foreach s : generated_sources
    foreach f : s.to_list()
        p = f.full_path()
        if p.endswith('.hpp')
            generated_files_headers += f
        endif
    endforeach
endforeach

networkd_dbus_dep = declare_dependency(
  sources: generated_files_headers,
  include_directories: networkd_dbus_includes,
  link_with: networkd_dbus_lib,
  dependencies: networkd_dbus_deps)

subdir('src')

configure_file(
  input: 'xyz.openbmc_project.Network.service.in',
  output: 'xyz.openbmc_project.Network.service',
  configuration: {
    'SYSTEMD_TARGET': 'multi-user.target',
    'DEFAULT_BUSNAME': default_busname,
  },
  install: true,
  install_dir: dependency('systemd').get_variable(
    pkgconfig: 'systemdsystemunitdir'))

configure_file(
  input: 'xyz.openbmc_project.Network.conf.in',
  output: 'xyz.openbmc_project.Network.conf',
  configuration: {'DEFAULT_BUSNAME': default_busname},
  install: true,
  install_dir: get_option('datadir') / 'dbus-1' / 'system.d')

if not get_option('tests').disabled()
  subdir('test')
endif
