inc_dir = include_directories('.', '../../../src/ibm/hypervisor-network-mgr-src/')

hyp_tests = [
  'hyp_network_manager',
  'hyp_sys_config',
  'hyp_ethernet_interface',
]

foreach t : hyp_tests
  test(
    t,
    executable(
      t.underscorify(),
      'test_' + t + '.cpp',
      implicit_include_directories: false,
      include_directories: inc_dir,
      link_with: hyp_networkd_lib,
      dependencies: test_dep))
endforeach
