inc_dir = include_directories('../../../src/ibm/hypervisor-network-mgr-src/')

hyp_tests = [
  'hyp_network_manager',
  'hyp_sys_config',
  'hyp_ethernet_interface',
]

hyp_test_src = declare_dependency(
              sources: [
                '../../../src/ibm/hypervisor-network-mgr-src/hyp_network_manager.cpp',
                '../../../src/ibm/hypervisor-network-mgr-src/hyp_sys_config.cpp',
                '../../../src/ibm/hypervisor-network-mgr-src/hyp_ip_interface.cpp',
                '../../../src/ibm/hypervisor-network-mgr-src/hyp_ethernet_interface.cpp'])

foreach t : hyp_tests
  test(
    t,
    executable(
      t.underscorify(),
      'test_' + t + '.cpp',
      implicit_include_directories: false,
      include_directories: inc_dir,
      dependencies: [test_dep, hyp_test_src]))
endforeach
